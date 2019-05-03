package inventoryd

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/rand"
	"time"
)

// DtlsHandshakeParams : Dtlsのハンドシェイクパラメータ
type DtlsHandshakeParams struct {
	ServerSequence  uint16
	ClientSequence  uint16
	Identity        []byte
	Cookie          []byte
	Session         []byte
	ClientRandom    []byte
	ServerRandom    []byte
	PreMasterSecret []byte
	MasterSecret    []byte
	Messages        []byte
	Verified        bool
}

// DtlsHandshake : Dtlsのハンドシェイク
type DtlsHandshake struct {
	Type     byte
	Sequence uint16
	Params   *DtlsHandshakeParams
}

// HandshakeType
// RFC6347 4.3.2 Handshake Protocol参照
const (
	dtlsHandshakeTypeClientHello        byte = 1
	dtlsHandshakeTypeServerHello        byte = 2
	dtlsHandshakeTypeHelloVerifyRequest byte = 3
	dtlsHandshakeTypeServerHelloDone    byte = 14
	dtlsHandshakeTypeClientKeyExchange  byte = 16
	dtlsHandshakeTypeFinished           byte = 20
)

const dtlsChangeCipherSpecMessage byte = 1

// processHandshake : ハンドシェイクを実行する
func (dtls *Dtls) processHandshake(ctx context.Context, successNotify chan bool) {
	if err := dtls.GetCookie(); err != nil {
		successNotify <- false
	}
	if err := dtls.GetSession(); err != nil {
		successNotify <- false
	}
	if err := dtls.SendClientKeyExchange(); err != nil {
		successNotify <- false
	}
	if err := dtls.SendChangeCipherSpec(); err != nil {
		successNotify <- false
	}
	dtls.GenerateSecurityParams()
	if err := dtls.SendFinished(); err != nil {
		successNotify <- false
	}
	successNotify <- true
}

// DtlsPreMasterSecretFromPSK : PSKからPreMasterSecretを生成する
// 生成方法 : PSKのバイト長をNとすると、uint16(N) || 0をNバイト || uint16(N) || PSK
// RFC4279 2. PSK Key Exchange Algorithmの以下の記述より
// The premaster secret is formed as follows:
// if the PSK is N octets long, concatenate a uint16 with the value N, N zero octets, a second uint16 with the value N, and the PSK itself.
func DtlsPreMasterSecretFromPSK(psk []byte) []byte {
	ret := []byte{}
	var length = (uint16)(len(psk))
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, length)
	ret = append(ret, lenBytes...)
	ret = append(ret, make([]byte, length)...)
	ret = append(ret, lenBytes...)
	ret = append(ret, psk...)
	return ret
}

// DtlsClientRandom : ClientRandomを生成する
// 先頭4byteをUNIX timestamp
// そのあとの28byteをランダムのbyteとする
// RFC5246 7.4.1.2 ClientHello参照
func DtlsClientRandom() []byte {
	now := time.Now().Unix()
	ret := make([]byte, 4)
	binary.BigEndian.PutUint32(ret, (uint32)(now))
	randomBytes := make([]byte, 28)
	rand.Read(randomBytes)
	ret = append(ret, randomBytes...)
	return ret
}

// GenerateSecurityParams : Master Secret / KeyBlockを生成する
func (dtls *Dtls) GenerateSecurityParams() {
	dtls.Handshake.MasterSecret = dtlsPrf(
		dtls.Handshake.PreMasterSecret,
		[]byte("master secret"),
		append(dtls.Handshake.ClientRandom, dtls.Handshake.ServerRandom...),
		48)

	keyBlock := dtlsPrf(
		dtls.Handshake.MasterSecret,
		[]byte("key expansion"),
		append(dtls.Handshake.ServerRandom, dtls.Handshake.ClientRandom...),
		40)

	dtls.ClientWriteKey = keyBlock[0:16]
	dtls.ServerWriteKey = keyBlock[16:32]
	dtls.ClientIV = keyBlock[32:36]
	dtls.ServerIV = keyBlock[36:40]
}

// GenerateClientVerifyData : ClientからのFinishedのVerify Dataを生成する
func (handshake *DtlsHandshakeParams) GenerateClientVerifyData() []byte {
	messageHash := sha256.Sum256(handshake.Messages)
	return dtlsPrf(
		handshake.MasterSecret,
		[]byte("client finished"),
		messageHash[:],
		12)
}

// GenerateServerVerifyData : ServerからのFinishedのVerify Dataを生成する
func (handshake *DtlsHandshakeParams) GenerateServerVerifyData() []byte {
	messageHash := sha256.Sum256(handshake.Messages)
	return dtlsPrf(
		handshake.MasterSecret,
		[]byte("server finished"),
		messageHash[:],
		12)
}

// dtlsPrf : DTLSで使用する疑似乱数生成関数(Pseudorandom Function)
// TLS1.2と同じ関数であるため、DTLSのRFCには記載なし
// RFC5246 5. HMAC and the Pseudorandom Function参照
// HMAC_HASH : SHA-256
// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) + HMAC_hash(secret, A(2) + seed)...
// A(0) = seed
// A(i) = HMAC_hash(secret, A(i-1))
// Master Secret生成時       : secret = Pre Master Secret / label = "master secret" / seed = クライアントランダム || サーバーランダム
// Key Block生成時           : secret = Master Secret / label = "key expansion" / seed = サーバーランダム || クライアントランダム
// ClientのVerify Data生成時 : secret = Master Secret / label = "client finished" / seed = ハンドシェイクメッセージのハッシュ(SHA256)
// ServerのVerify Data生成時 : secret = Master Secret / label = "server finished" / seed = ハンドシェイクメッセージのハッシュ(SHA256)
func dtlsPrf(secret []byte, label []byte, seed []byte, length int) []byte {
	ret := []byte{}
	a := []([]byte){append(label, seed...)}
	for i := 0; len(ret) < length; i++ {
		hashA := hmac.New(sha256.New, secret)
		hashA.Write(a[i])
		a = append(a, make([]byte, 32))
		a[i+1] = hashA.Sum(nil)
		hashRet := hmac.New(sha256.New, secret)
		hashRet.Write(append(a[i+1], a[0]...))
		ret = append(ret, (hashRet.Sum(nil))...)
	}
	return ret[:length]
}

// GetCookie : stateless cookieを取得する
// RFC6347 4.2.1 Denial-of-Service Contermeasures参照
// Cookie 取得までのHandshakeはFinishedの際のVerify Data算出には含めない
// If HelloVerifyRequest is used, the initial ClientHello and HelloVerifyRequest are not included
// in the calculation of the handshake_messages (for the CertificateVerify message) and
// verify_data (for the Finished message).
func (dtls *Dtls) GetCookie() error {
	packet := &DtlsPacket{
		Type:     dtlsContentTypeHandshake,
		Epoch:    dtls.ClientEpoch,
		Sequence: dtls.ClientSequence}
	handshake := &DtlsHandshake{
		Type:     dtlsHandshakeTypeClientHello,
		Sequence: dtls.Handshake.ClientSequence,
		Params:   dtls.Handshake}
	packet.Content = handshake.ToBytes()
	dtls.Connection.Write(packet.ToBytes())
	dtls.ClientSequence++
	dtls.Handshake.ClientSequence++

	buf := make([]byte, dtlsPacketSize)
	readLen, err := dtls.Connection.Read(buf)
	if err != nil {
		return err
	}
	helloVerifyRequest := dtls.ParsePacket(buf[:readLen])
	if helloVerifyRequest == nil {
		return errors.New("不正なDTLSハンドシェイクを検出しました")
	}
	return nil
}

// GetSession : Session IDを取得する
func (dtls *Dtls) GetSession() error {
	packet := &DtlsPacket{
		Type:     dtlsContentTypeHandshake,
		Epoch:    dtls.ClientEpoch,
		Sequence: dtls.ClientSequence}
	handshake := &DtlsHandshake{
		Type:     dtlsHandshakeTypeClientHello,
		Sequence: dtls.Handshake.ClientSequence,
		Params:   dtls.Handshake}
	packet.Content = handshake.ToBytes()
	dtls.Handshake.Messages = append(dtls.Handshake.Messages, (packet.Content)...)

	dtls.Connection.Write(packet.ToBytes())
	dtls.ClientSequence++
	dtls.Handshake.ClientSequence++

	buf := make([]byte, dtlsPacketSize)
	readLen, err := dtls.Connection.Read(buf)
	if err != nil {
		return err
	}
	serverHello := dtls.ParsePacket(buf[:readLen])
	if serverHello == nil {
		return errors.New("不正なDTLSハンドシェイクを検出しました")
	}
	serverHelloDone := dtls.ParsePacket(buf[(serverHello.Length()):readLen])
	if serverHelloDone == nil {
		return errors.New("不正なDTLSハンドシェイクを検出しました")
	}
	return nil
}

// SendClientKeyExchange : Client Key Exchangeを送信する
func (dtls *Dtls) SendClientKeyExchange() error {
	packet := &DtlsPacket{
		Type:     dtlsContentTypeHandshake,
		Epoch:    dtls.ClientEpoch,
		Sequence: dtls.ClientSequence}
	handshake := &DtlsHandshake{
		Type:     dtlsHandshakeTypeClientKeyExchange,
		Sequence: dtls.Handshake.ClientSequence,
		Params:   dtls.Handshake}
	packet.Content = handshake.ToBytes()
	dtls.Handshake.Messages = append(dtls.Handshake.Messages, (packet.Content)...)
	dtls.Connection.Write(packet.ToBytes())
	dtls.ClientSequence++
	dtls.Handshake.ClientSequence++
	return nil
}

// SendChangeCipherSpec : Change Cipher Specを送信する
// Change Cipher Specの際にEpochを加算し、Sequenceはクリアする
// The epoch number is initially zero and is incremented each time a ChangeCipherSpec message is sent.
// Sequence numbers are maintained separately for each epoch, with each sequence_number initially being 0 for each epoch.
// 詳細はRFC6347 4.1 Record Layer参照
// なお、Change Cipher SpecはHandshakeではないため、Finishedの際のVerify Dataの算出には含めない
func (dtls *Dtls) SendChangeCipherSpec() error {
	packet := &DtlsPacket{
		Type:     dtlsContentTypeChangeCipherSpec,
		Epoch:    dtls.ClientEpoch,
		Sequence: dtls.ClientSequence}
	packet.Content = []byte{dtlsChangeCipherSpecMessage}
	dtls.Connection.Write(packet.ToBytes())
	dtls.ClientEpoch++
	dtls.ClientSequence = 0
	dtls.ClientEncrypt = true
	return nil
}

// SendFinished : Finishedを送信する
func (dtls *Dtls) SendFinished() error {
	packet := &DtlsPacket{
		Type:     dtlsContentTypeHandshake,
		Epoch:    dtls.ClientEpoch,
		Sequence: dtls.ClientSequence}
	handshake := &DtlsHandshake{
		Type:     dtlsHandshakeTypeFinished,
		Sequence: dtls.Handshake.ClientSequence,
		Params:   dtls.Handshake}
	plainHandshake := handshake.ToBytes()
	dtls.Handshake.Messages = append(dtls.Handshake.Messages, plainHandshake...)
	packet.Content = dtls.encrypt(plainHandshake, packet.Type)
	dtls.Connection.Write(packet.ToBytes())
	dtls.ClientSequence++
	dtls.Handshake.ClientSequence++

	buf := make([]byte, dtlsPacketSize)
	readLen, err := dtls.Connection.Read(buf)
	if err != nil {
		return err
	}
	changeCipherSpec := dtls.ParsePacket(buf[:readLen])
	if changeCipherSpec == nil {
		return errors.New("不正なDTLSハンドシェイクを検出しました")
	}
	serverVefiry := dtls.ParsePacket(buf[(changeCipherSpec.Length()):readLen])
	if serverVefiry == nil {
		return errors.New("不正なDTLSハンドシェイクを検出しました")
	}
	return nil
}

// ToBytes : DTLSのハンドシェイクをバイトスライスに変換する
func (handshake *DtlsHandshake) ToBytes() []byte {
	ret := make([]byte, 12)
	ret[0] = handshake.Type
	binary.BigEndian.PutUint16(ret[4:6], handshake.Sequence)
	copy(ret[6:9], []byte{0, 0, 0})
	switch handshake.Type {
	case dtlsHandshakeTypeClientHello:
		ret = append(ret, make([]byte, 2)...)
		binary.BigEndian.PutUint16(ret[12:14], dtlsVersion)
		ret = append(ret, handshake.Params.ClientRandom...)
		ret = append(ret, (byte)(len(handshake.Params.Session)))
		ret = append(ret, handshake.Params.Session...)
		ret = append(ret, (byte)(len(handshake.Params.Cookie)))
		ret = append(ret, handshake.Params.Cookie...)
		cipherSuiteBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(cipherSuiteBytes, dtlsCipherSuite)
		ret = append(ret, []byte{0x00, 0x02}...)
		ret = append(ret, cipherSuiteBytes...)
		ret = append(ret, []byte{0x01, dtlsCompress}...)
	case dtlsHandshakeTypeClientKeyExchange:
		ret = append(ret, make([]byte, 2)...)
		binary.BigEndian.PutUint16(ret[12:14], (uint16)(len(handshake.Params.Identity)))
		ret = append(ret, handshake.Params.Identity...)
	case dtlsHandshakeTypeFinished:
		ret = append(ret, handshake.Params.GenerateClientVerifyData()...)
	default:
	}
	fragmentLength := len(ret) - 12
	fragmentLengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(fragmentLengthBytes, (uint32)(fragmentLength))
	copy(ret[1:4], fragmentLengthBytes[1:4])
	copy(ret[9:12], fragmentLengthBytes[1:4])
	return ret
}

// Parse : 生データのハンドシェイク部を解析する
func (handshake *DtlsHandshake) Parse(raw []byte) {
	handshake.Type = raw[0]
	length := binary.BigEndian.Uint32(append([]byte{0}, raw[1:4]...))
	handshake.Sequence = binary.BigEndian.Uint16(raw[4:6])
	handshake.Params.ServerSequence = handshake.Sequence
	switch handshake.Type {
	case dtlsHandshakeTypeHelloVerifyRequest:
		handshake.Params.Cookie = raw[15:47]
	case dtlsHandshakeTypeServerHello:
		handshake.Params.ServerRandom = raw[14:46]
		handshake.Params.Session = raw[47:79]
		handshake.Params.Messages = append(handshake.Params.Messages, raw[:(12+length)]...)
	case dtlsHandshakeTypeServerHelloDone:
		handshake.Params.Messages = append(handshake.Params.Messages, raw[:(12+length)]...)
	case dtlsHandshakeTypeFinished:
		verifyData := handshake.Params.GenerateServerVerifyData()
		serverVerify := raw[12:24]
		handshake.Params.Verified = true
		for i := 0; i < len(verifyData); i++ {
			if verifyData[i] != serverVerify[i] {
				handshake.Params.Verified = false
			}
		}
	default:
	}
}
