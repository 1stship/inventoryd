package inventoryd

// DLTS1.2における以下の要求は現時点では実装しない
// Handshakeの再送
// Handshakeの並び替え
// Handshakeの断片化の対応

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"time"
)

// 暗号スイートはTLS_PSK_WITH_AES_128_CCM_8で固定
// Lwm2mで最低限サポートしなければならない暗号スイートとして規定されている
// OMA-TS-LightweightM2M-V1_0_2-20180209-A 7.1.7 Pre-Shared Keys参照
// TLS_PSK_WITH_AES_128_CCM_8 : RFC6655 4. PSK-Based AES-CCM Cipher Suites参照
const (
	dtlsVersion          uint16        = 0xfefd // DTLS1.2
	dtlsCipherSuite      uint16        = 0xc0a8 // TLS_PSK_WITH_AES_128_CCM_8
	dtlsCompress         byte          = 0x00   // None
	dtlsPacketSize       int           = 1024
	dtlsHandshakeTimeout time.Duration = 5 * time.Second
)

// Dtls : Dtls接続管理
type Dtls struct {
	Connection     net.Conn // 接続
	ServerEpoch    uint16
	ClientEpoch    uint16
	ServerSequence uint64
	ClientSequence uint64
	ServerWriteKey []byte
	ClientWriteKey []byte
	ServerIV       []byte
	ClientIV       []byte
	ClientEncrypt  bool
	ServerEncrypt  bool
	Handshake      *DtlsHandshakeParams
}

// DTLS Content Type
// RFC5246 A.1 Record Layer参照
// (Content TypeはTLS1.2と同一のため、RFC6347内に記載が無い)
const (
	dtlsContentTypeChangeCipherSpec byte = 20
	dtlsContentTypeHandshake        byte = 22
	dtlsContentTypeApplicationData  byte = 23
)

// DtlsPacket : DTLSのパケット
type DtlsPacket struct {
	Type          byte
	Epoch         uint16
	Sequence      uint64
	ContentLength uint16
	Content       []byte
}

const (
	dtlsAesCcmMACLength byte = 8 // Number of octets in authentication field(MACのバイト長)
	dtlsAesCCMLength    byte = 3 // Number of octets in length field(15 - nonceのバイト長)
)

// DtlsDial : DLTSの初期化
func DtlsDial(host string, identity []byte, psk []byte) (*Dtls, error) {
	rand.Seed(time.Now().UnixNano())

	conn, err := net.Dial("udp", host)
	if err != nil {
		return nil, err
	}
	dtls := &Dtls{Connection: conn}
	handshake := &DtlsHandshakeParams{Identity: identity}
	handshake.PreMasterSecret = DtlsPreMasterSecretFromPSK(psk)
	handshake.ClientRandom = DtlsClientRandom()
	dtls.Handshake = handshake
	ctx, cancel := context.WithTimeout(context.Background(), dtlsHandshakeTimeout)
	notifyCh := make(chan bool)
	defer cancel()
	go dtls.processHandshake(ctx, notifyCh)
	select {
	case <-ctx.Done():
		// タイムアウトした場合
		conn.Close()
		return nil, errors.New("DTLSの接続がタイムアウトしました")
	case isSuccess := <-notifyCh:
		if isSuccess {
			return dtls, nil
		} else {
			conn.Close()
			return nil, errors.New("DTLSの接続が失敗しました")
		}
	}
}

func (dtls *Dtls) Read(data []byte) (int, error) {
	buf := make([]byte, dtlsPacketSize)
	readLen, err := dtls.Connection.Read(buf)
	if err != nil {
		return 0, err
	}
	packet := dtls.ParsePacket(buf[:readLen])
	if packet == nil {
		return 0, errors.New("不正なDTLSパケットを検出しました")
	}
	copy(data, packet.Content)
	return len(packet.Content), nil
}

func (dtls *Dtls) Write(data []byte) (int, error) {
	buf := make([]byte, len(data))
	copy(buf, data)

	packet := &DtlsPacket{
		Type:     dtlsContentTypeApplicationData,
		Epoch:    dtls.ClientEpoch,
		Sequence: dtls.ClientSequence}
	packet.Content = dtls.encrypt(buf, packet.Type)
	dtls.Connection.Write(packet.ToBytes())
	dtls.ClientSequence++
	return len(buf), nil
}

// Close : 接続を閉じる
func (dtls *Dtls) Close() error {
	ret := dtls.Connection.Close()
	return ret
}

// LocalAddr : 接続元アドレス
func (dtls *Dtls) LocalAddr() net.Addr {
	return dtls.Connection.LocalAddr()
}

// RemoteAddr : 接続元先アドレス
func (dtls *Dtls) RemoteAddr() net.Addr {
	return dtls.Connection.RemoteAddr()
}

// SetDeadline : デッドラインの設定
func (dtls *Dtls) SetDeadline(t time.Time) error {
	return dtls.Connection.SetDeadline(t)
}

// SetReadDeadline : 読み出しデッドラインの設定
func (dtls *Dtls) SetReadDeadline(t time.Time) error {
	return dtls.Connection.SetReadDeadline(t)
}

// SetWriteDeadline : 書き込みデッドラインの設定
func (dtls *Dtls) SetWriteDeadline(t time.Time) error {
	return dtls.Connection.SetWriteDeadline(t)
}

// encrypt : AES_128_CCM_8で暗号化する
func (dtls *Dtls) encrypt(data []byte, contentType byte) []byte {
	epochSequence := make([]byte, 8)
	binary.BigEndian.PutUint64(epochSequence, dtls.ClientSequence)
	binary.BigEndian.PutUint16(epochSequence[0:2], dtls.ClientEpoch)
	aad := dtlsGenerateAAD(epochSequence, contentType, (uint16)(len(data)))
	nonce := dtlsGenerateNonce(dtls.ClientIV, epochSequence)
	paddingLength := (aes.BlockSize - (len(data) % aes.BlockSize)) % aes.BlockSize
	paddedData := append(data, make([]byte, paddingLength)...)
	mac := dtlsGenerateMAC(aad, nonce, (uint16)(len(data)), paddedData, dtls.ClientWriteKey)

	plainText := append(mac, paddedData...)
	block, err := aes.NewCipher(dtls.ClientWriteKey)
	if err != nil {
		panic(err)
	}
	counterIV := make([]byte, aes.BlockSize)
	counterIV[0] = dtlsAesCCMLength - 1
	copy(counterIV[1:13], nonce)
	cipherText := make([]byte, len(plainText))

	stream := cipher.NewCTR(block, counterIV)
	stream.XORKeyStream(cipherText, plainText)
	encryptedMac := cipherText[0:dtlsAesCcmMACLength]
	encryptedData := cipherText[aes.BlockSize:(aes.BlockSize + len(data))]
	ret := make([]byte, len(epochSequence)+len(data)+(int)(dtlsAesCcmMACLength))
	copy(ret[0:len(epochSequence)], epochSequence)
	copy(ret[len(epochSequence):(len(epochSequence)+len(data))], encryptedData)
	copy(ret[(len(epochSequence)+len(data)):], encryptedMac)

	return ret
}

// decrypt : AES_128_CCM_8で検証および復号する
func (dtls *Dtls) decrypt(data []byte, contentType byte) ([]byte, bool) {
	epochSequence := make([]byte, 8)
	copy(epochSequence, data[0:8])
	encryptedData := make([]byte, len(data)-(int)(dtlsAesCcmMACLength)-8)
	copy(encryptedData, data[8:(len(data)-(int)(dtlsAesCcmMACLength))])
	encryptedMAC := make([]byte, (int)(dtlsAesCcmMACLength))
	copy(encryptedMAC, data[(len(data)-(int)(dtlsAesCcmMACLength)):])

	paddingLength := (aes.BlockSize - (len(encryptedData) % aes.BlockSize)) % aes.BlockSize
	paddedData := append(encryptedData, make([]byte, paddingLength)...)
	nonce := dtlsGenerateNonce(dtls.ServerIV, epochSequence)

	cipherText := append(append(encryptedMAC, make([]byte, aes.BlockSize-dtlsAesCcmMACLength)...), paddedData...)
	block, err := aes.NewCipher(dtls.ServerWriteKey)
	if err != nil {
		panic(err)
	}
	counterIV := make([]byte, aes.BlockSize)
	counterIV[0] = dtlsAesCCMLength - 1
	copy(counterIV[1:13], nonce)
	plainText := make([]byte, len(cipherText))

	stream := cipher.NewCTR(block, counterIV)
	stream.XORKeyStream(plainText, cipherText)
	decryptedMac := plainText[0:dtlsAesCcmMACLength]
	decryptedData := plainText[aes.BlockSize:(aes.BlockSize + len(encryptedData))]

	aad := dtlsGenerateAAD(epochSequence, contentType, (uint16)(len(decryptedData)))
	decryptedPaddedData := append(decryptedData, make([]byte, paddingLength)...)
	mac := dtlsGenerateMAC(aad, nonce, (uint16)(len(decryptedData)), decryptedPaddedData, dtls.ServerWriteKey)
	macForVerify := mac[0:dtlsAesCcmMACLength]

	for i := 0; i < (int)(dtlsAesCcmMACLength); i++ {
		if decryptedMac[i] != macForVerify[i] {
			return nil, false
		}
	}
	return decryptedData, true
}

// dtlsGenerateAAD : AAD(Additional authenticated data)を生成する
// RFC5246 6.2.3.3 AEAD Ciphers参照
// additional_data = seq_num || TLSCompressed.type || TLSCompressed.version || TLSCompressed.length;
// 基本はTLS1.2と同じだが、seq_numがDTLSではepochとsequenceに分かれている
func dtlsGenerateAAD(epochSequence []byte, contentType byte, length uint16) []byte {
	ret := make([]byte, 13)
	copy(ret[0:8], epochSequence)
	ret[8] = contentType
	binary.BigEndian.PutUint16(ret[9:11], dtlsVersion)
	binary.BigEndian.PutUint16(ret[11:13], length)
	return ret
}

// dtlsGenerateNonce : nonce(number used once)を生成する
// 一度しか使用されないことを保証するため、epochとsequenceを使用する
// RFC6655 : 3. RSA-Based AES-CCM Cipher Suites参照
// struct {
//   uint32 client_write_IV; // low order 32-bits
//   uint64 seq_num;         // TLS sequence number
// } CCMClientNonce.
// In DTLS, the 64-bit seq_num is the 16-bit epoch concatenated with the 48-bit seq_num.
func dtlsGenerateNonce(iv []byte, epochSequence []byte) []byte {
	nonce := make([]byte, 16)
	copy(nonce[0:4], iv)
	copy(nonce[4:16], epochSequence)
	return nonce
}

// dtlsGenerateMAC : MAC(Message Authentucation Code)を生成する
// RFC3610 2.2.  Authentication参照
// aadは2^64まで拡張可能だが、DTLSとの組み合わせの使用においては13byte固定と考えてよいため、
// aadの長さによる場合分けは省略する
// Golangの標準パッケージにはCBC-MACがないため、CBC暗号化の最終ブロックを取得することにより代用する
func dtlsGenerateMAC(aad []byte, nonce []byte, length uint16, paddedData []byte, key []byte) []byte {
	flag := (1 << 6) + (((dtlsAesCcmMACLength)-2)/2)<<3 + ((dtlsAesCCMLength) - 1)
	blocksForMAC := make([]byte, 2*aes.BlockSize)
	blocksForMAC[0] = flag
	copy(blocksForMAC[1:13], nonce)
	binary.BigEndian.PutUint16(blocksForMAC[14:16], length)

	binary.BigEndian.PutUint16(blocksForMAC[16:18], (uint16)(len(aad)))
	copy(blocksForMAC[18:(18+len(aad))], aad)
	blocksForMAC = append(blocksForMAC, paddedData...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	// CBC-MACのIVは全て0の16byte
	iv := make([]byte, aes.BlockSize)
	cbc := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, len(blocksForMAC))
	cbc.CryptBlocks(cipherText, []byte(blocksForMAC))

	return cipherText[len(cipherText)-aes.BlockSize:]
}

// ParsePacket : パケット生データからDTLSパケットを生成する
func (dtls *Dtls) ParsePacket(raw []byte) *DtlsPacket {
	if len(raw) < 13 {
		return nil
	}
	packet := &DtlsPacket{}
	packet.Type = raw[0]
	packet.Epoch = binary.BigEndian.Uint16(raw[3:5])
	packet.Sequence = binary.BigEndian.Uint64(append([]byte{0, 0}, raw[5:11]...))
	packet.ContentLength = binary.BigEndian.Uint16(raw[11:13])

	if len(raw) < 13+(int)(packet.ContentLength) {
		return nil
	}

	if dtls.ServerEncrypt {
		decrypted, verify := dtls.decrypt(raw[13:(13+packet.ContentLength)], packet.Type)
		if verify {
			packet.Content = decrypted
		} else {
			return nil
		}
	} else {
		packet.Content = raw[13:(13 + packet.ContentLength)]
	}
	switch packet.Type {
	case dtlsContentTypeHandshake:
		handshake := &DtlsHandshake{Params: dtls.Handshake}
		handshake.Parse(packet.Content)
	case dtlsContentTypeChangeCipherSpec:
		dtls.ServerEncrypt = true
	case dtlsContentTypeApplicationData:
		// 処理は必要ない
	default:
	}
	return packet
}

// ToBytes : DTLSのパケットをバイトスライスに変換する
func (packet *DtlsPacket) ToBytes() []byte {
	ret := make([]byte, 13)
	ret[0] = packet.Type
	binary.BigEndian.PutUint16(ret[1:3], dtlsVersion)
	binary.BigEndian.PutUint64(ret[3:11], packet.Sequence)
	binary.BigEndian.PutUint16(ret[3:5], packet.Epoch)
	packet.ContentLength = (uint16)(len(packet.Content))
	binary.BigEndian.PutUint16(ret[11:13], packet.ContentLength)
	ret = append(ret, (packet.Content)...)
	return ret
}

// Length : DTLSパケット全体の長さ
func (packet *DtlsPacket) Length() uint16 {
	return packet.ContentLength + 13
}
