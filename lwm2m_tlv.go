package inventoryd

import (
	"encoding/base64"
	"encoding/binary"
	"math"
	"strconv"
	"strings"
)

// Lwm2mTLV : データ形式TLV
// OMA-TS-LightweightM2M-V1_0_2-20180209-A 6.4.3 TLV参照
type Lwm2mTLV struct {
	TypeOfID byte
	ID       uint16
	Length   uint32
	Value    []byte
	Contents []*Lwm2mTLV
}

// Twm2m TLV形式のType of Identifier
const (
	lwm2mTLVTypeObjectInstance  byte = 0
	lwm2mTLVTypeResouceInstance byte = 1
	lwm2mTLVTypeMultipleResouce byte = 2
	lwm2mTLVTypeResouce         byte = 3
)

// Marshal : TLVデータをバイト配列に変換
func (tlv *Lwm2mTLV) Marshal() []byte {
	ret := make([]byte, 1)
	ret[0] = tlv.TypeOfID << 6
	if tlv.ID <= 0xFF {
		ret = append(ret, (byte)(tlv.ID))
	} else {
		ret[0] += 1 << 5
		ret = append(ret, (byte)(tlv.ID>>8), (byte)(tlv.ID&0x00FF))
	}
	if tlv.Length <= 0x07 {
		ret[0] += (byte)(tlv.Length)
	} else if tlv.Length <= 0xFF {
		ret[0] += 1 << 3
		ret = append(ret, (byte)(tlv.Length))
	} else if tlv.Length >= 0xFFFF {
		ret[0] += 2 << 3
		ret = append(ret, (byte)(tlv.Length>>8), (byte)(tlv.Length&0x0000FF))
	} else {
		ret[0] += 3 << 3
		ret = append(ret, (byte)(tlv.Length>>16), (byte)((tlv.Length>>8)&0x0000FF), (byte)(tlv.Length&0x0000FF))
	}
	ret = append(ret, tlv.Value...)

	return ret
}

// Unmarshal : バイト配列からTLVデータを取得する
// 取得出来た場合はtlvデータ長を返す
// 取得できなかった場合は-1を返す
func (tlv *Lwm2mTLV) Unmarshal(raw []byte) int {
	length := len(raw)
	parsedIndex := 0
	if length < parsedIndex+1 {
		return -1
	}
	tlv.TypeOfID = (raw[0] >> 6) & 0x03
	parsedIndex++

	if ((raw[0] >> 5) & 0x01) == 0 {
		if length < parsedIndex+1 {
			return -1
		}
		tlv.ID = (uint16)(raw[1])
		parsedIndex++
	} else {
		if length < parsedIndex+2 {
			return -1
		}
		tlv.ID = binary.BigEndian.Uint16(raw[1:3])
		parsedIndex += 2
	}
	lengthType := (raw[0] >> 3) & 0x03
	if lengthType == 0 {
		tlv.Length = (uint32)(raw[0] & 0x07)
	} else if lengthType == 1 {
		if length < parsedIndex+1 {
			return -1
		}
		tlv.Length = (uint32)(raw[parsedIndex])
		parsedIndex++
	} else if lengthType == 2 {
		if length < parsedIndex+2 {
			return -1
		}
		tlv.Length = (uint32)(binary.BigEndian.Uint16(raw[parsedIndex : parsedIndex+2]))
		parsedIndex += 2
	} else if lengthType == 3 {
		if length < parsedIndex+3 {
			return -1
		}
		tlv.Length = binary.BigEndian.Uint32(append([]byte{0}, raw[parsedIndex:parsedIndex+3]...))
		parsedIndex += 3
	}
	if length < parsedIndex+(int)(tlv.Length) {
		return -1
	}
	tlv.Value = make([]byte, tlv.Length)
	copy(tlv.Value, raw[parsedIndex:parsedIndex+(int)(tlv.Length)])
	parsedIndex += (int)(tlv.Length)
	return parsedIndex
}

// TotalLength : TLVデータの長さを取得する
func (tlv *Lwm2mTLV) TotalLength() int {
	ret := 1
	if tlv.ID <= 0xFF {
		ret++
	} else {
		ret += 2
	}
	if tlv.Length <= 0x07 {
		// 加算バイト無し
	} else if tlv.Length <= 0xFF {
		ret++
	} else if tlv.Length >= 0xFFFF {
		ret += 2
	} else {
		ret += 3
	}
	ret += len(tlv.Value)
	return ret
}

func convertTLVValueToString(buf []byte, resourceType byte) string {
	var ret string
	switch resourceType {
	case lwm2mResourceTypeInteger, lwm2mResourceTypeTime:
		length := len(buf)
		if length == 1 {
			ret = strconv.Itoa((int)(buf[0]))
		} else if length == 2 {
			num := (int16)(binary.BigEndian.Uint16(buf[0:2]))
			ret = strconv.FormatInt((int64)(num), 10)
		} else if length == 4 {
			num := (int32)(binary.BigEndian.Uint32(buf[0:4]))
			ret = strconv.FormatInt((int64)(num), 10)
		} else if length == 8 {
			num := (int64)(binary.BigEndian.Uint64(buf[0:8]))
			ret = strconv.FormatInt((int64)(num), 10)
		}
	case lwm2mResourceTypeFloat:
		length := len(buf)
		if length == 4 {
			bits := binary.BigEndian.Uint32(buf)
			num := math.Float32frombits(bits)
			ret = strconv.FormatFloat((float64)(num), 'g', 6, 32)
		} else if length == 8 {
			bits := binary.BigEndian.Uint64(buf)
			num := math.Float64frombits(bits)
			ret = strconv.FormatFloat(num, 'g', 6, 64)
		}
	case lwm2mResourceTypeBoolean:
		if buf[0] == 1 {
			ret = "true"
		} else {
			ret = "false"
		}
	case lwm2mResourceTypeOpaque:
		ret = base64.StdEncoding.EncodeToString(buf)
	case lwm2mResourceTypeObjlnk:
		objLinkNum := (int16)(binary.BigEndian.Uint16(buf[0:2]))
		instanceLinkNum := (int16)(binary.BigEndian.Uint16(buf[2:4]))
		ret = strconv.Itoa((int)(objLinkNum)) + ":" + strconv.Itoa((int)(instanceLinkNum))
	default: // string/Noneはそのままでよい
		ret = string(buf)
	}
	return ret
}

func convertStringToTLVValue(str string, resourceType byte) []byte {
	var ret []byte
	switch resourceType {
	case lwm2mResourceTypeInteger, lwm2mResourceTypeTime:
		num, _ := strconv.ParseInt(str, 10, 64)
		if num < (1<<7) && num >= -(1<<7) {
			ret = []byte{(byte)(num)}
		} else if num < (1<<15) && num >= -(1<<15) {
			ret = make([]byte, 2)
			binary.BigEndian.PutUint16(ret, (uint16)(num))
		} else if num < (1<<31) && num >= -(1<<31) {
			ret = make([]byte, 4)
			binary.BigEndian.PutUint32(ret, (uint32)(num))
		} else {
			ret = make([]byte, 8)
			binary.BigEndian.PutUint64(ret, (uint64)(num))
		}
	case lwm2mResourceTypeFloat:
		num, _ := strconv.ParseFloat(str, 64)
		bits := math.Float64bits(num)
		ret = make([]byte, 8)
		binary.BigEndian.PutUint64(ret, bits)
	case lwm2mResourceTypeBoolean:
		if str == "true" {
			ret = []byte{1}
		} else {
			ret = []byte{0}
		}
	case lwm2mResourceTypeOpaque:
		decoded, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			ret = []byte{}
		}
		ret = make([]byte, len(decoded))
		copy(ret, decoded)
	case lwm2mResourceTypeObjlnk:
		links := strings.Split(str, ":")
		objLinkNum, _ := strconv.ParseInt(links[0], 10, 16)
		instanceLinkNum, _ := strconv.ParseInt(links[1], 10, 16)
		ret = make([]byte, 4)
		binary.BigEndian.PutUint16(ret[0:2], (uint16)(objLinkNum))
		binary.BigEndian.PutUint16(ret[2:4], (uint16)(instanceLinkNum))
	default: // string/Noneはそのまま
		ret = []byte(str)
	}
	return ret
}
