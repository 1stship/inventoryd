package inventoryd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
)

// lwm2mBootstrap : ブートストラップの管理
type lwm2mBootstrap struct {
	finishNotify chan int
	connection   *Coap
	definitions  lwm2mObjectDefinitions
	handler      Lwm2mHandler
}

// Bootstrap : Bootstrap Operation
func (lwm2m *lwm2mBootstrap) Bootstrap(
	bootstrapHost string,
	endpointClientName string,
	definitions []*Lwm2mObjectDefinition,
	handler Lwm2mHandler) error {
	conn, err := net.Dial("udp", bootstrapHost)
	if err != nil {
		return errors.New("failed to access bootstrap host")
	}
	coap := &Coap{}
	coap.Initialize(conn, lwm2m.BootstrapReceiveMessage)
	lwm2m.connection = coap
	lwm2m.finishNotify = make(chan int)
	lwm2m.definitions = definitions
	lwm2m.handler = handler
	lwm2m.connection = coap

	ctx, cancel := context.WithTimeout(context.Background(), lwm2mBootstrapTimeout)
	defer cancel()
	err = lwm2m.requestBootStrap(endpointClientName)
	if err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		// タイムアウトした場合
		return errors.New("ブートストラップ処理がタイムアウトしました")
	case <-lwm2m.finishNotify:
	}

	fmt.Println("Bootstrap finish")
	return nil
}

// requestBootStrap : ブートストラップを要求する
// OMA-TS-LightweightM2M-V1_0_2-20180209-A 5.2.7.1 BOOTSTRAP-REQUEST参照
func (lwm2m *lwm2mBootstrap) requestBootStrap(endpointClientName string) error {
	log.Print("Start Bootstrap")

	ctx, cancel := context.WithTimeout(context.Background(), lwm2mBootstrapTimeout)
	defer cancel()
	options := []CoapOption{
		CoapOption{coapOptionNoURIPath, []byte("bs")},
		CoapOption{coapOptionNoURIQuery, []byte("ep=" + endpointClientName)}}
	requestCh := make(chan int)
	lwm2m.connection.SendRequest(CoapCodePost, options, []byte{}, requestCh)
	select {
	case <-ctx.Done():
		// タイムアウトした場合
		return errors.New("ブートストラップ処理がタイムアウトしました")
	case <-requestCh:
	}
	return nil
}

// BootstrapReceiveMessage : Bootstrap用メッセージ受信ハンドラ
func (lwm2m *lwm2mBootstrap) BootstrapReceiveMessage(message *CoapMessage) {
	if message.Type == CoapTypeAcknowledgement {
		switch message.Code {
		case CoapCodeChanged:
			lwm2m.BootstrapRequestDone(message)
		}
	} else if message.Type == CoapTypeConfirmable {
		switch message.Code {
		case CoapCodePut:
			_, objectID, instanceID, _, _ := message.extractResourceID()
			lwm2m.processBootstrapWrite(objectID, instanceID, message)
		case CoapCodePost:
			lwm2m.processBootstrapFinishRequest(message)
		case CoapCodeDelete:
			lwm2m.processBootstrapDeleteRequest(message)
		}
	}
}

// processBootstrapWrite : BOOTSTRAP WRITE の処理
// OMA-TS-LightweightM2M-V1_0_2-20180209-A 5.2.7.4 BOOTSTRAP WRITE参照
// SORACOM Inventoryにおいては、Object ID と Instancd IDで書き込まれる
// Read Onlyなリソースに対しても書き込みが発生するため、
// Device Managermentのハンドラと共用はしないこととする
func (lwm2m *lwm2mBootstrap) processBootstrapWrite(objectID uint16, instanceID uint16, message *CoapMessage) error {
	code := lwm2m.handler.CreateInstance(&Lwm2mInstance{objectID: objectID, ID: instanceID})
	if code != CoapCodeCreated {
		lwm2m.connection.SendResponse(message, code, []CoapOption{}, []byte{})
		return errors.New("インスタンスの生成に失敗しました")
	}

	objectDefinition := lwm2m.definitions.findObjectDefinitionByID(objectID)
	payload := message.Payload
	parsedIndex := 0
	for {
		tlv := &Lwm2mTLV{}
		tlvLength := tlv.Unmarshal(payload[parsedIndex:])
		if tlvLength == -1 {
			break
		}
		parsedIndex += tlvLength

		resourceID := tlv.ID
		resourceDefinition := objectDefinition.findResourceByID(resourceID)
		value := convertTLVValueToString(tlv.Value, resourceDefinition.Type)
		code := lwm2m.handler.WriteResource(
			&Lwm2mResource{objectID: objectID, instanceID: instanceID, ID: resourceID, Definition: resourceDefinition},
			value)
		if code != CoapCodeChanged {
			lwm2m.connection.SendResponse(message, code, []CoapOption{}, []byte{})
			return errors.New("リソースの登録に失敗しました")
		}
	}
	lwm2m.connection.SendResponse(message, CoapCodeChanged, []CoapOption{}, []byte{})
	return nil
}

// BootstrapRequestDone : Request Bootstrap 終了メッセージの処理
func (lwm2m *lwm2mBootstrap) BootstrapRequestDone(message *CoapMessage) {
	log.Print("Request Bootstrap accepted")
}

// processBootstrapFinishRequest : BOOTSTRAP FINISHの処理
// OMA-TS-LightweightM2M-V1_0_2-20180209-A 5.2.7.2 BOOTSTRAP-FINISH参照
func (lwm2m *lwm2mBootstrap) processBootstrapFinishRequest(message *CoapMessage) {
	log.Print("Bootstrap finished")
	lwm2m.connection.SendResponse(message, CoapCodeChanged, []CoapOption{}, []byte{})
	lwm2m.finishNotify <- 1
}

// processBootstrapDeleteRequest : BOOTSTRAP DELETEの処理
// OMA-TS-LightweightM2M-V1_0_2-20180209-A 5.2.7.5 BOOTSTRAP DELETE参照
// Bootstrapは現在のセキュリティ設定の消去を要求する
// Object ID / Instancd IDともに省略されたDELETE 要求の場合、
// 本来は全てのリソースを削除しなければならない(MUST be removed)が、
// 実用を考えてSecurity(ID:0)とServer(ID:1)のみ消去することとする
// When the Delete operation is used without any parameter (i.e. without Object ID parameter),
// all Instances of all Objects in the LwM2M Client MUST be removed
func (lwm2m *lwm2mBootstrap) processBootstrapDeleteRequest(message *CoapMessage) {
	lwm2m.handler.DeleteObject(&Lwm2mObject{ID: lwm2mObjectIDSecurity})
	lwm2m.handler.DeleteObject(&Lwm2mObject{ID: lwm2mObjectIDServer})
	lwm2m.connection.SendResponse(message, CoapCodeDeleted, []CoapOption{}, []byte{})
}
