package inventoryd

import (
	"errors"
	"log"
	"strconv"
	"time"
)

// Lwm2m : Lwm2m対応
type Lwm2m struct {
	endpointClientName   string
	dmSecurityInstanceID uint16
	dmServerInstanceID   uint16
	handler              Lwm2mHandler
	Connection           *Coap
	Location             string
	definitions          lwm2mObjectDefinitions
	observedInstance     []*Lwm2mObservedInstance
	observedResource     []*Lwm2mObservedResource
	lifetime             int
	registered           bool
}

// LWM2M関係の定数
const (
	lwm2mRegisterTimeout      time.Duration = 10 * time.Second
	lwm2mUpdateTimeout        time.Duration = 10 * time.Second
	lwm2mBootstrapTimeout     time.Duration = 30 * time.Second
	lwm2mDefaultLifetime      int           = 60
	lwm2mDefaultDMServerURL   string        = "coaps://jp.inventory.soracom.io:5684"
	lwm2mDefaultShortServerID int           = 123
)

// Lwm2mHandler : Lwm2mの各種Operationの処理ハンドラ
// OMA-TS-LightweightM2M-V1_0_2-20180209-A
// Read    : 5.4.1 Read参照(Objectに対するReadはInventoryのAPIに無いため対象外)
// Write   : 5.4.3 Write参照
// Execute : 5.4.5 Execute参照
// Discover / Write-Attributes は対象外
// Create / DeleteはBootstrapにて限定的に対応
type Lwm2mHandler interface {

	// 通常CoapCodeDeleteを返す
	DeleteObject(object *Lwm2mObject) CoapCode

	// 通常CoapCodeCreatedを返す
	CreateInstance(instance *Lwm2mInstance) CoapCode

	// 通常CoapCodeContentを返す
	ListObjectIDs() ([]uint16, CoapCode)

	// 通常CoapCodeContentを返す
	ListInstanceIDs(object *Lwm2mObject) ([]uint16, CoapCode)

	// 通常CoapCodeContentを返す
	ListResourceIDs(instance *Lwm2mInstance) ([]uint16, CoapCode)

	// 通常CoapCodeContentを返す
	ReadResource(resource *Lwm2mResource) (string, CoapCode)

	// 通常CoapCodeChangedを返す
	WriteResource(resource *Lwm2mResource, value string) CoapCode

	// 通常CoapCodeChangedを返す
	ExecuteResource(resource *Lwm2mResource, value string) CoapCode
}

// Initialize : Lwm2m構造体を初期化する
func (lwm2m *Lwm2m) Initialize(
	endpointClientName string,
	definitions lwm2mObjectDefinitions,
	handler Lwm2mHandler) error {
	lwm2m.endpointClientName = endpointClientName
	lwm2m.definitions = definitions
	lwm2m.handler = handler
	if !lwm2m.searchDMSecurityInstance() {
		return errors.New("セキュリティ設定が見つかりませんでした")
	}
	if !lwm2m.searchDMServerInstance() {
		return errors.New("サーバー設定が見つかりませんでした")
	}
	lwm2m.Connection = nil
	lwm2m.registered = false
	return nil
}

func (lwm2m *Lwm2m) CheckSecurityParams() error {
	identity := lwm2m.getIdentity()
	psk := lwm2m.getSecretKey()
	if len(identity) == 0 || len(psk) == 0 {
		return errors.New(`セキュリティパラメータが不足しています。
-bオプションにてブートストラップを実行するか、
--psk string(base64) --identity stringオプションにてセキュリティパラメータを指定してください`)
	}
	return nil
}

// StartUpdate : Update動作を開始する
// stopChを受信したら停止する
func (lwm2m *Lwm2m) StartUpdate(interval time.Duration, stopCh chan bool) {

	err := lwm2m.Register()
	if err != nil {
		log.Print(err)
	}

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			err := lwm2m.Update()
			if err != nil {
				log.Print(err)
			}
		case <-stopCh:
			lwm2m.close()
			return
		}
	}
}

// StartObserving : Observe動作を開始する
// stopChを受信したら停止する
func (lwm2m *Lwm2m) StartObserving(interval time.Duration, stopCh chan bool) {

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			lwm2m.Observe()
		case <-stopCh:
			return
		}
	}
}

// ReceiveMessage : メッセージ受信ハンドラ
func (lwm2m *Lwm2m) ReceiveMessage(message *CoapMessage) {
	if message.Type == CoapTypeAcknowledgement {
		switch message.Code {
		case CoapCodeCreated:
			lwm2m.RegisterDone(message)
		case CoapCodeChanged:
			lwm2m.UpdateDone(message)
		}
	} else if message.Type == CoapTypeConfirmable {
		switch message.Code {
		case CoapCodeGet:
			// READとOBSERVEがGET Codeで要求されるが、
			// Observeも値を返すのでREADの変形として処理する
			lwm2m.ReadRequest(message)
		case CoapCodePut:
			lwm2m.WriteRequest(message)
		case CoapCodePost:
			lwm2m.ExecuteRequest(message)
		}
	} else if message.Type == CoapTypeReset {
		// Resetが発生するのはObserveが解除されているリソースに対してNotifyした時
		lwm2m.ObserveDeregister(message)
	}
}

// extractResourceID : メッセージからリソースIDを抽出する
// IDの数, オブジェクトID, インスタンスID, リソースID, エラーの順に返す
// エラーはパスが整数でない、IDが4つ以上の場合に発生する
func (message *CoapMessage) extractResourceID() (int, uint16, uint16, uint16, error) {
	idCount := 0
	idList := [3]uint16{0, 0, 0}
	for i := range message.Options {
		if message.Options[i].No == coapOptionNoURIPath {
			if idCount > 2 {
				return 0, 0, 0, 0, errors.New("too many IDs")
			}
			id, err := strconv.Atoi(string(message.Options[i].Value))
			if err != nil {
				return 0, 0, 0, 0, err
			}
			idList[idCount] = (uint16)(id)
			idCount++
		}
	}
	return idCount, idList[0], idList[1], idList[2], nil
}

// searchDMSecurityInstance : 登録インスタンスからDevice Managermentサーバーのセキュリティインスタンスを検索する
// 発見したらtrue、発見できなければfalseを返す
func (lwm2m *Lwm2m) searchDMSecurityInstance() bool {
	definition := lwm2m.definitions.findObjectDefinitionByID(lwm2mObjectIDSecurity)
	instanceIDs, code := lwm2m.handler.ListInstanceIDs(&Lwm2mObject{ID: lwm2mObjectIDSecurity, Definition: definition})
	if code != CoapCodeContent {
		return false
	}

	for _, instanceID := range instanceIDs {
		resource := lwm2m.findResource(lwm2mObjectIDSecurity, instanceID, lwm2mResourceIDSecurityBootstrap)
		bootstrapFlag, code := lwm2m.handler.ReadResource(resource)
		if code != CoapCodeContent {
			continue
		}
		if bootstrapFlag == "false" {
			lwm2m.dmSecurityInstanceID = instanceID
			return true
		}
	}
	return false
}

// searchDMServerInstance : 登録インスタンスからDevice Managermentサーバーのサーバーインスタンスを検索する
// 発見したらtrue、発見できなければfalseを返す
func (lwm2m *Lwm2m) searchDMServerInstance() bool {
	definition := lwm2m.definitions.findObjectDefinitionByID(lwm2mObjectIDServer)
	instanceIDs, code := lwm2m.handler.ListInstanceIDs(&Lwm2mObject{ID: lwm2mObjectIDServer, Definition: definition})
	if code != CoapCodeContent {
		return false
	}

	shortServerID := lwm2m.getShortServerID()
	for _, instanceID := range instanceIDs {
		resource := lwm2m.findResource(lwm2mObjectIDServer, instanceID, lwm2mResourceIDServerShortServerID)
		id, code := lwm2m.handler.ReadResource(resource)
		if code != CoapCodeContent {
			continue
		}
		if id == strconv.Itoa(shortServerID) {
			lwm2m.dmServerInstanceID = instanceID
			return true
		}
	}
	return false
}

// getShortServerID : shortServerIDを取得する
// 取得できない場合は123とする
func (lwm2m *Lwm2m) getShortServerID() int {
	resource := lwm2m.findResource(lwm2mObjectIDSecurity, lwm2m.dmSecurityInstanceID, lwm2mResourceIDSecurityShortServerID)
	shortServerIDStr, code := lwm2m.handler.ReadResource(resource)
	if code != CoapCodeContent {
		return lwm2mDefaultShortServerID
	}
	shoftServerID, err := strconv.Atoi(shortServerIDStr)
	if err != nil {
		return lwm2mDefaultShortServerID
	}
	return shoftServerID
}

// findInstance : インスタンスを検索する
func (lwm2m *Lwm2m) findInstance(objectID, instanceID uint16) *Lwm2mInstance {
	objectIDs, code := lwm2m.handler.ListObjectIDs()
	if code != CoapCodeContent {
		return nil
	}
	exist := false
	for _, id := range objectIDs {
		if id == objectID {
			exist = true
			break
		}
	}
	if !exist {
		return nil
	}

	definition := lwm2m.definitions.findObjectDefinitionByID(objectID)
	instanceIDs, code := lwm2m.handler.ListInstanceIDs(&Lwm2mObject{ID: objectID, Definition: definition})
	if code != CoapCodeContent {
		return nil
	}

	exist = false
	for _, id := range instanceIDs {
		if id == instanceID {
			exist = true
			break
		}
	}
	if !exist {
		return nil
	}

	instance := &Lwm2mInstance{
		ID:       instanceID,
		objectID: objectID}

	return instance
}

// findResource : リソースを検索する
func (lwm2m *Lwm2m) findResource(objectID, instanceID, resourceID uint16) *Lwm2mResource {
	objectIDs, code := lwm2m.handler.ListObjectIDs()
	if code != CoapCodeContent {
		return nil
	}

	exist := false
	for _, id := range objectIDs {
		if id == objectID {
			exist = true
			break
		}
	}
	if !exist {
		return nil
	}

	definition := lwm2m.definitions.findObjectDefinitionByID(objectID)
	instanceIDs, code := lwm2m.handler.ListInstanceIDs(&Lwm2mObject{ID: objectID, Definition: definition})
	if code != CoapCodeContent {
		return nil
	}

	exist = false
	for _, id := range instanceIDs {
		if id == instanceID {
			exist = true
			break
		}
	}
	if !exist {
		return nil
	}

	resourceIDs, code := lwm2m.handler.ListResourceIDs(&Lwm2mInstance{objectID: objectID, ID: instanceID})
	if code != CoapCodeContent {
		return nil
	}

	exist = false
	for _, id := range resourceIDs {
		if id == resourceID {
			exist = true
			break
		}
	}
	if !exist {
		return nil
	}

	resourceDefinition := lwm2m.definitions.findResourceDefinitionByIDs(objectID, resourceID)
	resource := &Lwm2mResource{
		ID:         resourceID,
		objectID:   objectID,
		instanceID: instanceID,
		Definition: resourceDefinition}

	return resource
}
