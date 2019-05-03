package inventoryd

import (
	"encoding/binary"
	"math/rand"
	"net"
	"sort"
	"time"
)

// Coap : Coap接続に関わるパラメータ
type Coap struct {
	Connection    net.Conn // 接続
	NextMessageID uint16
	ChInProcess   map[uint16]chan int
	RecvHandler   func(*CoapMessage)
	recvStopCh    chan bool
}

// CoapMessage : Coapのメッセージ
// RFC7252 3. Message Format参照
type CoapMessage struct {
	Version     byte
	Type        byte
	TokenLength byte
	Code        CoapCode
	MessageID   uint16
	Token       []byte
	Options     []CoapOption
	Payload     []byte
}

// Coap Type
// RFC7252 3. Message Format Type(T)参照
const (
	CoapTypeConfirmable     = 0
	CoapTypeNonConfirmable  = 1
	CoapTypeAcknowledgement = 2
	CoapTypeReset           = 3
)

type CoapCode byte

// Coap Method Code
// RFC7252 12.1.1 Method Codes参照
const (
	CoapCodeGet    CoapCode = 1
	CoapCodePost   CoapCode = 2
	CoapCodePut    CoapCode = 3
	CoapCodeDelete CoapCode = 4
)

// Coap Response Code
// RFC7252 12.1.2 Response Codes参照
const (
	CoapCodeEmpty      CoapCode = 0   // 0.00 Empty
	CoapCodeCreated    CoapCode = 65  // 2.01 Created
	CoapCodeDeleted    CoapCode = 66  // 2.02 Deleted
	CoapCodeChanged    CoapCode = 68  // 2.04 Changed
	CoapCodeContent    CoapCode = 69  // 2.05 Content
	CoapCodeBadRequest CoapCode = 128 // 4.00 Bad Request
	CoapCodeNotFound   CoapCode = 132 // 4.04 Not Found
	CoapCodeNotAllowed CoapCode = 133 // 4.05 Method Not Allowed
)

// CoAP Content Format
// RFC7252 12.3 CoAP Content-Formats Registry参照
const (
	coapContentFormatLinkFormat = 40
	coapContentFormatLwm2mTLV   = 11542
	coapContentFormatLwm2mJSON  = 11543
)

const (
	coapDefaultTokenLength byte = 8
)

// CoapOption : Coapのオプション
// RFC7252 5.10参照
type CoapOption struct {
	No    uint
	Value []byte
}

// CoAP Option
// RFC7252 5.10参照
const (
	coapOptionNoObserve       = 6
	coapOptionNoLocationPath  = 8
	coapOptionNoURIPath       = 11
	coapOptionNoContentFormat = 12
	coapOptionNoURIQuery      = 15
)

// CoAP Observe Option
// RFC7641 2. The Observe Option参照
const (
	coapObserveRegister   byte = 0
	coapObserveDeregister byte = 1
)

// CoAP Optionの解析パラメータ
// RFC7252 5.10参照
const (
	coapOptCodeByte = 13
	coapOptCodeWord = 14
	coapOptByteBase = 13
	coapOptWordBase = 269
)

// Initialize : Coap構造体を初期化する
func (coap *Coap) Initialize(conn net.Conn, recvHandler func(*CoapMessage)) {
	rand.Seed(time.Now().UnixNano())
	coap.NextMessageID = (uint16)(rand.Intn(65536))
	coap.Connection = conn
	coap.ChInProcess = make(map[uint16]chan int)
	coap.recvStopCh = make(chan bool)
	coap.RecvHandler = recvHandler
	go coap.ReadCoapMessage(coap.recvStopCh)
}

// Close : Coap接続を閉じる
// メッセージ受信に関わるgorutineを止める
func (coap *Coap) Close() {
	coap.recvStopCh <- true
	coap.Connection.Close()
}

// ReadCoapMessage : メッセージを受信する
// stopChを受信すると受信動作を停止する
func (coap *Coap) ReadCoapMessage(stopCh chan bool) {
	for {
		buf := make([]byte, 1500)
		readLenCh := make(chan int)
		go func() {
			len, _ := coap.Connection.Read(buf)
			readLenCh <- len
		}()
		var readLen int
		select {
		case <-stopCh:
			return
		case readLen = <-readLenCh:
		}
		raw := make([]byte, readLen)
		copy(raw, buf[:readLen])
		message := coap.ParseMessage(raw)
		if message == nil {
			continue
		}
		coap.RecvHandler(message)
		if message.Type == CoapTypeAcknowledgement {
			ch := coap.ChInProcess[message.MessageID]
			ch <- 1
			delete(coap.ChInProcess, message.MessageID)
		}
	}
}

// SendRequest : リクエスト(CON)を送信する
// ACKが返ってきたらチャネルに1を送る
// メッセージIDを返す
func (coap *Coap) SendRequest(code CoapCode, options []CoapOption, payload []byte, ch chan int) uint16 {
	message := &CoapMessage{
		Version:     1,
		Type:        CoapTypeConfirmable,
		Code:        code,
		MessageID:   coap.NextMessageID,
		Token:       make([]byte, coapDefaultTokenLength),
		TokenLength: coapDefaultTokenLength,
		Options:     options,
		Payload:     payload}
	coap.NextMessageID = (coap.NextMessageID + 1) & 0xFFFF
	rand.Read(message.Token)
	coap.ChInProcess[message.MessageID] = ch
	coap.Connection.Write(message.ConvertToBytes())
	return message.MessageID
}

// SendResponse : レスポンス(ACK)を送信する
func (coap *Coap) SendResponse(request *CoapMessage, code CoapCode, options []CoapOption, payload []byte) {
	message := &CoapMessage{
		Version:     1,
		Type:        CoapTypeAcknowledgement,
		Code:        code,
		MessageID:   request.MessageID,
		Token:       request.Token,
		TokenLength: request.TokenLength,
		Options:     options,
		Payload:     payload}
	coap.Connection.Write(message.ConvertToBytes())
}

// SendRelatedMessage : 関連メッセージ(新規メッセージだがトークンが同じ)を送信する
// Lwm2m Notifyメッセージで使用する
// メッセージIDを返す
func (coap *Coap) SendRelatedMessage(code CoapCode, token []byte, options []CoapOption, payload []byte) uint16 {
	message := &CoapMessage{
		Version:     1,
		Type:        CoapTypeNonConfirmable,
		Code:        code,
		MessageID:   coap.NextMessageID,
		Token:       token,
		TokenLength: (byte)(len(token)),
		Options:     options,
		Payload:     payload}
	coap.NextMessageID = (coap.NextMessageID + 1) & 0xFFFF
	coap.Connection.Write(message.ConvertToBytes())
	return message.MessageID
}

// ParseMessage : 受信生データを解析してCoapMessageを生成する
// 生成できない場合はnilを返す
func (coap *Coap) ParseMessage(raw []byte) *CoapMessage {
	if len(raw) < 4 {
		return nil
	}
	ret := &CoapMessage{}
	ret.Version = raw[0] >> 6
	ret.Type = (raw[0] >> 4) & 0x03
	ret.TokenLength = raw[0] & 0x0F
	ret.Code = (CoapCode)(raw[1])
	ret.MessageID = ((uint16)(raw[2]) << 8) + (uint16)(raw[3])
	if len(raw) < 4+(int)(ret.TokenLength) {
		return nil
	}
	ret.Token = raw[4 : 4+ret.TokenLength]
	optionsLength := ret.ParseOptions(raw[(4 + ret.TokenLength):])
	ret.Payload = raw[(4 + (int)(ret.TokenLength) + optionsLength):]
	return ret
}

// ConvertToBytes : Messageを[]byteに変換する
func (message *CoapMessage) ConvertToBytes() []byte {
	ret := make([]byte, 4)
	ret[0] = (message.Version << 6) + (message.Type << 4) + message.TokenLength
	ret[1] = (byte)(message.Code)
	binary.BigEndian.PutUint16(ret[2:4], message.MessageID)
	ret = append(ret, message.Token...)
	ret = append(ret, message.BuildOptions()...)
	if len(message.Payload) > 0 {
		ret = append(ret, 0xFF)
		ret = append(ret, message.Payload...)
	}
	return ret
}

// IsObserve : Observeメッセージかを判定する
func (message *CoapMessage) IsObserve() bool {
	for _, option := range message.Options {
		if option.No == coapOptionNoObserve {
			return true
		}
	}
	return false
}

// ParseOptions : 生データのオプション部以降を解析しオプションをセットする
// 戻り値：オプション部の長さ
func (message *CoapMessage) ParseOptions(raw []byte) int {
	length := 0
	var base uint
	// 全データを解析し終わるか(Payloadが無い場合)
	// OxFFを確認する(Optionの終端を表すコード)までオプションを解析する
	for len(raw) > length && raw[length] != 0xFF {
		option := &CoapOption{}
		optionLength := option.ParseOption(raw[length:], base)
		message.Options = append(message.Options, *option)
		length += optionLength
		base = option.No
	}

	// オプション終端がある場合はその部分までオプション部とする
	if len(raw) > length && raw[length] == 0xFF {
		length++
	}
	return length
}

// ParseOption : 生データの各オプションをセットする
// 戻り値:オプションの長さ
func (option *CoapOption) ParseOption(raw []byte, base uint) int {
	var delta uint
	var length uint

	deltaLength := 0
	delta = (uint)(raw[0]) >> 4
	if delta == coapOptCodeByte {
		delta = (uint)(raw[1] + coapOptByteBase)
		deltaLength = 1
	} else if delta == coapOptCodeWord {
		delta = (uint)(raw[1])>>8 + (uint)(raw[2]) + coapOptWordBase
		deltaLength = 2
	}
	option.No = base + delta

	lengthLength := 0
	length = (uint)(raw[0]) & 0x0F
	if length == coapOptCodeByte {
		length = (uint)(raw[1+deltaLength] + coapOptByteBase)
		lengthLength = 1
	} else if length == coapOptCodeWord {
		length = (uint)(raw[1+deltaLength])>>8 + (uint)(raw[2+deltaLength]) + coapOptWordBase
		lengthLength = 2
	}

	option.Value = raw[1+deltaLength+lengthLength : 1+deltaLength+lengthLength+(int)(length)]

	return (1 + deltaLength + lengthLength + (int)(length))
}

// BuildOptions : Coapのオプション部を生成する
func (message *CoapMessage) BuildOptions() []byte {
	ret := make([]byte, 0)
	sort.Slice(message.Options, func(i, j int) bool { return message.Options[i].No < message.Options[j].No })
	var base uint
	for i := range message.Options {
		ret = append(ret, message.Options[i].BuildOption(base)...)
		base = message.Options[i].No
	}
	return ret
}

// BuildOption : Coapの各オプション部を生成する
// RFC7252 3.1 Option Format参照
func (option *CoapOption) BuildOption(base uint) []byte {
	delta := option.No - base
	length := len(option.Value)
	ret := make([]byte, 1)
	if delta < coapOptByteBase {
		ret[0] += (byte)(delta << 4)
	} else if delta < coapOptWordBase {
		ret[0] += (byte)(coapOptCodeByte << 4)
		ret = append(ret, (byte)(delta-coapOptByteBase))
	} else {
		ret[0] += (byte)(coapOptCodeWord << 4)
		ret = append(ret, (byte)((delta-coapOptWordBase)>>8), (byte)((delta-coapOptWordBase)&0x00FF))
	}
	if length < coapOptByteBase {
		ret[0] += (byte)(length)
	} else if delta < coapOptWordBase {
		ret[0] += (byte)(coapOptCodeByte)
		ret = append(ret, (byte)(length-coapOptByteBase))
	} else {
		ret[0] += (byte)(coapOptCodeWord)
		ret = append(ret, (byte)((length-coapOptWordBase)>>8), (byte)((length-coapOptWordBase)&0x00FF))
	}
	ret = append(ret, option.Value...)
	return ret
}
