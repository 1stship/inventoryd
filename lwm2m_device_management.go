package inventoryd

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"log"
)

// Observe : Observe中リソースのチェックおよび変化があった場合のNotifyを実行する
// OMA-TS-LightweightM2M-V1_0_2-20180209-A 5.5.1 Observe参照
// オブジェクトレベルのObserveも可能だが、現時点では対応しない
// 接続がない場合、Registerが終了していない場合は何もしない
func (lwm2m *Lwm2m) Observe() {
	if lwm2m.Connection == nil || !lwm2m.registered {
		return
	}
	for _, observe := range lwm2m.observedInstance {
		lwm2m.NotifyInstance(observe)
	}
	for _, observe := range lwm2m.observedResource {
		lwm2m.NotifyResource(observe)
	}
}

// ObserveDeregister : Coap Resetを受信したらObserveを解除する
// OMA-TS-LightweightM2M-V1_0_2-20180209-A 8.2.6 Information Reporting Interface参照
// ResetはMessageIDのみ存在するため、メッセージIDとつきあわせて確認する
func (lwm2m *Lwm2m) ObserveDeregister(message *CoapMessage) {
	foundIndex := -1
	for i, observe := range lwm2m.observedInstance {
		if observe.messageID == message.MessageID {
			log.Printf("CANCEL-OBSERVE /%d/%d", observe.instance.objectID, observe.instance.ID)
			foundIndex = i
		}
	}
	if foundIndex >= 0 {
		// スライスの関数が存在しないため、コピーにて対応する
		deletedSlice := make([]*Lwm2mObservedInstance, len(lwm2m.observedInstance)-1)
		copy(deletedSlice[0:foundIndex], lwm2m.observedInstance[0:foundIndex])
		copy(deletedSlice[foundIndex:len(deletedSlice)], lwm2m.observedInstance[foundIndex+1:len(lwm2m.observedInstance)])
		lwm2m.observedInstance = deletedSlice
		return
	}

	for i, observe := range lwm2m.observedResource {
		if observe.messageID == message.MessageID {
			log.Printf("CANCEL-OBSERVE /%d/%d/%d", observe.resource.objectID, observe.resource.instanceID, observe.resource.ID)
			foundIndex = i
		}
	}
	if foundIndex >= 0 {
		// スライスの関数が存在しないため、コピーにて対応する
		deletedSlice := make([]*Lwm2mObservedResource, len(lwm2m.observedResource)-1)
		copy(deletedSlice[0:foundIndex], lwm2m.observedResource[0:foundIndex])
		copy(deletedSlice[foundIndex:len(deletedSlice)], lwm2m.observedResource[foundIndex+1:len(lwm2m.observedResource)])
		lwm2m.observedResource = deletedSlice
		return
	}
}

// NotifyInstance : インスタンスに対するNotifyを実行する
// OMA-TS-LightweightM2M-V1_0_2-20180209-A 5.5.2 Notify参照
func (lwm2m *Lwm2m) NotifyInstance(observe *Lwm2mObservedInstance) {
	instance := observe.instance
	payload := make([]byte, 0)
	for _, resourceObserve := range observe.resources {
		resource := resourceObserve.resource
		if !resource.Definition.Readable {
			continue
		}
		resourceValue, code := lwm2m.handler.ReadResource(resource)
		if code != CoapCodeContent {
			continue
		}
		// 値が前回と変わっていないリソースは送らない
		if resourceValue == resourceObserve.lastValue {
			continue
		}

		resourceObserve.lastValue = resourceValue
		resourceTLVValue := convertStringToTLVValue(resourceValue, resource.Definition.Type)
		tlv := &Lwm2mTLV{
			TypeOfID: lwm2mTLVTypeResouce,
			ID:       (uint16)(resource.ID),
			Length:   (uint32)(len(resourceTLVValue)),
			Value:    resourceTLVValue}
		payload = append(payload, tlv.Marshal()...)
	}

	// 値がひとつも変わっていない場合は何もしない
	if len(payload) == 0 {
		return
	}
	log.Printf("Notify /%d/%d", instance.objectID, instance.ID)

	contentFormat := make([]byte, 2)
	binary.BigEndian.PutUint16(contentFormat, coapContentFormatLwm2mTLV)
	observeCountBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(observeCountBuf, observe.observeCount)
	if observe.observeCount <= 0xff {
		observeCountBuf = observeCountBuf[3:4]
	} else if observe.observeCount <= 0xffff {
		observeCountBuf = observeCountBuf[2:4]
	} else if observe.observeCount <= 0xffffff {
		observeCountBuf = observeCountBuf[1:4]
	}
	observe.observeCount++
	options := []CoapOption{
		CoapOption{coapOptionNoContentFormat, contentFormat},
		CoapOption{coapOptionNoObserve, observeCountBuf}}
	observe.messageID = lwm2m.Connection.SendRelatedMessage(CoapCodeContent, observe.token, options, payload)
}

// NotifyResource : リソースに対するNotifyを実行する
// OMA-TS-LightweightM2M-V1_0_2-20180209-A 5.5.2 Notify参照
func (lwm2m *Lwm2m) NotifyResource(observe *Lwm2mObservedResource) {
	resource := observe.resource

	if !resource.Definition.Readable {
		return
	}
	value, code := lwm2m.handler.ReadResource(resource)
	if code != CoapCodeContent {
		return
	}
	// 前回と値が同じ場合はNotifyしない
	if value == observe.lastValue {
		return
	}

	log.Printf("Notify /%d/%d/%d", resource.objectID, resource.instanceID, resource.ID)
	observe.lastValue = value
	resourceTLVValue := convertStringToTLVValue(value, resource.Definition.Type)
	tlv := &Lwm2mTLV{
		TypeOfID: lwm2mTLVTypeResouce,
		ID:       (uint16)(resource.ID),
		Length:   (uint32)(len(resourceTLVValue)),
		Value:    resourceTLVValue}
	payload := tlv.Marshal()

	contentFormat := make([]byte, 2)
	binary.BigEndian.PutUint16(contentFormat, coapContentFormatLwm2mTLV)
	observeCountBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(observeCountBuf, observe.observeCount)
	if observe.observeCount <= 0xff {
		observeCountBuf = observeCountBuf[3:4]
	} else if observe.observeCount <= 0xffff {
		observeCountBuf = observeCountBuf[2:4]
	} else if observe.observeCount <= 0xffffff {
		observeCountBuf = observeCountBuf[1:4]
	}
	observe.observeCount++
	options := []CoapOption{
		CoapOption{coapOptionNoContentFormat, contentFormat},
		CoapOption{coapOptionNoObserve, observeCountBuf}}
	observe.messageID = lwm2m.Connection.SendRelatedMessage(CoapCodeContent, observe.token, options, payload)
}

// ReadRequest : Readを処理する
func (lwm2m *Lwm2m) ReadRequest(message *CoapMessage) error {
	idCount, objectID, instanceID, resourceID, err := message.extractResourceID()
	if err != nil {
		return err
	}

	if idCount == 2 {
		err := lwm2m.processReadInstance(objectID, instanceID, message)
		if err != nil {
			return err
		}
	} else if idCount == 3 {
		err := lwm2m.processReadResource(objectID, instanceID, resourceID, message)
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteRequest : Writeを処理する
func (lwm2m *Lwm2m) WriteRequest(message *CoapMessage) error {
	idCount, objectID, instanceID, resourceID, err := message.extractResourceID()
	if err != nil {
		return err
	}

	if idCount == 3 {
		err := lwm2m.processWriteResource(objectID, instanceID, resourceID, message)
		if err != nil {
			return err
		}
	}
	return nil
}

// ExecuteRequest : Executeを処理する
func (lwm2m *Lwm2m) ExecuteRequest(message *CoapMessage) error {
	idCount, objectID, instanceID, resourceID, err := message.extractResourceID()
	if err != nil {
		return err
	}

	if idCount == 3 {
		err := lwm2m.processExecuteResource(objectID, instanceID, resourceID, message)
		if err != nil {
			return err
		}
	}
	return nil
}

// processReadInstance : インスタンスに対するReadを処理する
// 例 : READ /1/0
func (lwm2m *Lwm2m) processReadInstance(objectID uint16, instanceID uint16, message *CoapMessage) error {
	instance := lwm2m.findInstance(objectID, instanceID)
	if instance == nil {
		log.Printf("READ /%d/%d Not Found", objectID, instanceID)
		lwm2m.Connection.SendResponse(message, CoapCodeNotFound, []CoapOption{}, []byte{})
		return nil
	}

	isObserve := message.IsObserve()
	observedInstance := &Lwm2mObservedInstance{}
	if isObserve {
		log.Printf("OBSERVE /%d/%d", objectID, instanceID)
		observedInstance.token = message.Token
		observedInstance.instance = instance
		observedInstance.resources = make([]*Lwm2mObservedResource, 0)
	} else {
		log.Printf("READ /%d/%d", objectID, instanceID)
	}

	resourceIDs, code := lwm2m.handler.ListResourceIDs(instance)
	if code != CoapCodeContent {
		lwm2m.Connection.SendResponse(message, CoapCodeNotAllowed, []CoapOption{}, []byte{})
		return errors.New("リソースが取得できませんでした")
	}

	payload := make([]byte, 0)
	for _, resourceID := range resourceIDs {
		resource := lwm2m.findResource(objectID, instanceID, resourceID)
		if resource.Definition.Readable {
			resourceValue, code := lwm2m.handler.ReadResource(resource)
			if code != CoapCodeContent {
				continue
			}

			resourceTLVValue := convertStringToTLVValue(resourceValue, resource.Definition.Type)
			tlv := &Lwm2mTLV{
				TypeOfID: lwm2mTLVTypeResouce,
				ID:       (uint16)(resourceID),
				Length:   (uint32)(len(resourceTLVValue)),
				Value:    resourceTLVValue}
			payload = append(payload, tlv.Marshal()...)

			if isObserve {
				observedResource := &Lwm2mObservedResource{resource: resource, lastValue: resourceValue, observeCount: 0}
				observedInstance.resources = append(observedInstance.resources, observedResource)
			}
		}
	}

	contentFormat := make([]byte, 2)
	binary.BigEndian.PutUint16(contentFormat, coapContentFormatLwm2mTLV)

	var options []CoapOption
	// Observe Registerの場合はObserveオプションをつけ、そうでなければつけない
	if isObserve {
		options = []CoapOption{
			CoapOption{coapOptionNoContentFormat, contentFormat},
			CoapOption{coapOptionNoObserve, []byte{coapObserveRegister}}}
		lwm2m.observedInstance = append(lwm2m.observedInstance, observedInstance)
	} else {
		options = []CoapOption{CoapOption{coapOptionNoContentFormat, contentFormat}}
	}
	lwm2m.Connection.SendResponse(message, CoapCodeContent, options, payload)
	return nil
}

// processReadResource : リソースに対するReadを処理する
// 例 : READ /1/0/1
func (lwm2m *Lwm2m) processReadResource(objectID, instanceID, resourceID uint16, message *CoapMessage) error {
	resource := lwm2m.findResource(objectID, instanceID, resourceID)
	if resource == nil {
		log.Printf("READ /%d/%d/%d Not Found", objectID, instanceID, resourceID)
		lwm2m.Connection.SendResponse(message, CoapCodeNotFound, []CoapOption{}, []byte{})
		return nil
	}

	isObserve := message.IsObserve()
	observedResource := &Lwm2mObservedResource{}
	if isObserve {
		log.Printf("OBSERVE /%d/%d/%d", objectID, instanceID, resourceID)
		observedResource.token = message.Token
		observedResource.resource = resource
	} else {
		log.Printf("READ /%d/%d/%d", objectID, instanceID, resourceID)
	}

	if !resource.Definition.Readable {
		lwm2m.Connection.SendResponse(message, CoapCodeNotAllowed, []CoapOption{}, []byte{})
		return nil
	}

	resourceValue, code := lwm2m.handler.ReadResource(resource)
	if code != CoapCodeContent {
		lwm2m.Connection.SendResponse(message, CoapCodeNotAllowed, []CoapOption{}, []byte{})
		return errors.New("リソースの読み出しに失敗しました")
	}

	resourceTLVValue := convertStringToTLVValue(resourceValue, resource.Definition.Type)
	tlv := &Lwm2mTLV{
		TypeOfID: lwm2mTLVTypeResouce,
		ID:       (uint16)(resourceID),
		Length:   (uint32)(len(resourceTLVValue)),
		Value:    resourceTLVValue}
	payload := tlv.Marshal()

	contentFormat := make([]byte, 2)
	binary.BigEndian.PutUint16(contentFormat, coapContentFormatLwm2mTLV)

	var options []CoapOption
	// Observe Registerの場合はObserveオプションをつけ、そうでなければつけない
	if isObserve {
		options = []CoapOption{
			CoapOption{coapOptionNoContentFormat, contentFormat},
			CoapOption{coapOptionNoObserve, []byte{coapObserveRegister}}}
		observedResource.lastValue = resourceValue
		lwm2m.observedResource = append(lwm2m.observedResource, observedResource)
	} else {
		options = []CoapOption{CoapOption{coapOptionNoContentFormat, contentFormat}}
	}
	lwm2m.Connection.SendResponse(message, CoapCodeContent, options, payload)

	return nil
}

// processWriteResource : リソースに対するWriteを処理する
// 例 : WRITE /1/0/1
// 親インスタンスが存在しない場合、リソース定義が存在しない場合はエラー
// 対象リソースが存在しない場合は作成する
func (lwm2m *Lwm2m) processWriteResource(objectID uint16, instanceID uint16, resourceID uint16, message *CoapMessage) error {
	log.Printf("WRITE /%d/%d/%d", objectID, instanceID, resourceID)
	instance := lwm2m.findInstance(objectID, instanceID)
	if instance == nil {
		lwm2m.Connection.SendResponse(message, CoapCodeNotFound, []CoapOption{}, []byte{})
		return errors.New("インスタンスが存在しません")
	}

	resource := lwm2m.findResource(objectID, instanceID, resourceID)
	if resource == nil {
		resourceDefinition := lwm2m.definitions.findResourceDefinitionByIDs(objectID, resourceID)
		if resourceDefinition == nil {
			return errors.New("リソース定義が存在しません")
		}
		resource = &Lwm2mResource{
			ID:         resourceID,
			objectID:   objectID,
			instanceID: instanceID,
			Definition: resourceDefinition}
	}

	if !resource.Definition.Writable {
		lwm2m.Connection.SendResponse(message, CoapCodeNotAllowed, []CoapOption{}, []byte{})
		return nil
	}

	tlv := &Lwm2mTLV{}
	tlv.Unmarshal(message.Payload)
	value := convertTLVValueToString(tlv.Value, resource.Definition.Type)
	code := lwm2m.handler.WriteResource(resource, value)
	if code != CoapCodeChanged {
		lwm2m.Connection.SendResponse(message, code, []CoapOption{}, []byte{})
		return errors.New("リソースの登録に失敗しました")
	}

	lwm2m.Connection.SendResponse(message, CoapCodeChanged, []CoapOption{}, []byte{})
	return nil
}

// processExecuteResource : リソースに対するExecuteを処理する
// 例 : EXECUTE /1/0/4
func (lwm2m *Lwm2m) processExecuteResource(objectID uint16, instanceID uint16, resourceID uint16, message *CoapMessage) error {
	log.Printf("EXECUTE /%d/%d/%d", objectID, instanceID, resourceID)
	resource := lwm2m.findResource(objectID, instanceID, resourceID)
	if resource == nil {
		lwm2m.Connection.SendResponse(message, CoapCodeNotFound, []CoapOption{}, []byte{})
		return nil
	}

	if !resource.Definition.Excutable {
		lwm2m.Connection.SendResponse(message, CoapCodeNotAllowed, []CoapOption{}, []byte{})
		return nil
	}

	value := base64.StdEncoding.EncodeToString(message.Payload)
	code := lwm2m.handler.ExecuteResource(resource, value)
	if code != CoapCodeChanged {
		lwm2m.Connection.SendResponse(message, code, []CoapOption{}, []byte{})
		return errors.New("リソースの実行に失敗しました")
	}

	lwm2m.Connection.SendResponse(message, CoapCodeChanged, []CoapOption{}, []byte{})
	return nil
}
