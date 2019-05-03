package inventoryd

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"strconv"
	"strings"
)

// Register時のパラメータ
// OMA-TS-LightweightM2M-V1_0_2-20180209-A 5.3.1参照
// BingindModeはU/UQ/S/SQ/USがあるが、Uしか使わない
const (
	lwm2mVersion     string = "1.0"
	lwm2mBindingMode string = "U"
)

// Register : Register Operation
// OMA-TS-LightweightM2M-V1_0_2-20180209-A 5.3.1 Register参照
func (lwm2m *Lwm2m) Register() error {
	log.Print("Registering...")
	err := lwm2m.connect()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), lwm2mRegisterTimeout)
	defer cancel()
	registerCh := make(chan int)
	lwm2m.Connection.SendRequest(CoapCodePost, lwm2m.buildRegisterOptions(lwm2m.getLifetime()), lwm2m.registerLinkFormat(), registerCh)
	select {
	case <-ctx.Done():
		// タイムアウトした場合
		lwm2m.close()
		return errors.New("Register処理がタイムアウトしました")
	case <-registerCh:
		// Registerが正常に終了した場合
		lwm2m.registered = true
		log.Printf("Register finished. Location is %s\n", lwm2m.Location)
	}
	return nil
}

// connect : DTLS + Coap接続する
func (lwm2m *Lwm2m) connect() error {
	identity := lwm2m.getIdentity()
	psk := lwm2m.getSecretKey()
	uri := lwm2m.getDMServerURI()
	host := strings.Replace(uri, "coaps://", "", 1)

	// 接続が残っていたら閉じる
	if lwm2m.Connection != nil {
		lwm2m.close()
	}

	coap := &Coap{}
	conn, err := DtlsDial(host, identity, psk)
	if err != nil {
		log.Print(err)
		return errors.New("DTLSの接続に失敗しました")
	}
	coap.Initialize(conn, lwm2m.ReceiveMessage)
	lwm2m.Connection = coap
	return nil
}

// close : 接続を閉じる
func (lwm2m *Lwm2m) close() {
	lwm2m.Connection.Close()
	lwm2m.Connection = nil
	lwm2m.registered = false
}

// Update : Update Operation
// OMA-TS-LightweightM2M-V1_0_2-20180209-A 5.3.2 Update参照
func (lwm2m *Lwm2m) Update() error {
	// Register状態でなければRegisterする
	if lwm2m.Connection == nil {
		err := lwm2m.Register()
		if err != nil {
			return err
		}
		return nil
	}

	log.Print("Updating...")
	ctx, cancel := context.WithTimeout(context.Background(), lwm2mUpdateTimeout)
	defer cancel()
	updateCh := make(chan int)
	lwm2m.Connection.SendRequest(CoapCodePost, lwm2m.buildUpdateOptions(), []byte{}, updateCh)
	select {
	case <-ctx.Done():
		// タイムアウトした場合
		lwm2m.close()
		return errors.New("Update処理がタイムアウトしました")
	case <-updateCh:
		// Updateが正常に終了した場合
		log.Print("Update finished")
	}

	return nil
}

// RegisterDone : Register 終了メッセージの処理
func (lwm2m *Lwm2m) RegisterDone(message *CoapMessage) {
	locationPathIndex := 0
	for i := range message.Options {
		if message.Options[i].No == coapOptionNoLocationPath {
			if locationPathIndex == 0 {
				locationPathIndex++
			} else if locationPathIndex == 1 {
				lwm2m.Location = string(message.Options[i].Value)
				locationPathIndex++
			}
		}
	}
}

// UpdateDone : Update 終了メッセージの処理
func (lwm2m *Lwm2m) UpdateDone(message *CoapMessage) {
	// 処理必要なし
}

// buildRegisterOptions : Register Operationに使用するオプションを生成する
func (lwm2m *Lwm2m) buildRegisterOptions(lifetime int) []CoapOption {
	ret := []CoapOption{
		CoapOption{coapOptionNoURIPath, []byte("rd")},
		CoapOption{coapOptionNoContentFormat, []byte{coapContentFormatLinkFormat}},
		CoapOption{coapOptionNoURIQuery, []byte("lwm2m=" + lwm2mVersion)},
		CoapOption{coapOptionNoURIQuery, []byte("ep=" + lwm2m.endpointClientName)},
		CoapOption{coapOptionNoURIQuery, []byte("b=" + lwm2mBindingMode)},
		CoapOption{coapOptionNoURIQuery, []byte("lt=" + strconv.Itoa(lifetime))}}

	return ret
}

// registerLinkFormat : Registerに使用するリンクフォーマットを生成する
// LinkFormatの説明 : RFC6690
// rt(Resource Type) : oma.lwm2m
// ct(Content Type) : 11543(application/vnd.oma.lwm2m+json)
// 参照 : https://www.iana.org/assignments/core-parameters/core-parameters.xhtml
func (lwm2m *Lwm2m) registerLinkFormat() []byte {
	return []byte("</>;rt=\"oma.lwm2m\";ct=" + strconv.Itoa(coapContentFormatLwm2mJSON) + ",<" + strings.Join(lwm2m.instanceIDList(), ">,<") + ">")
}

// buildUpdateOptions : Update Operationに使用するオプションを生成する
func (lwm2m *Lwm2m) buildUpdateOptions() []CoapOption {
	ret := []CoapOption{
		CoapOption{coapOptionNoURIPath, []byte("rd")},
		CoapOption{coapOptionNoURIPath, []byte(lwm2m.Location)}}

	return ret
}

// instanceIDList : 登録インスタンスのリストを取得する
// objectID: 0(Security)はRegister時のインスタンスに含めない
// The Security Object ID:0 MUST NOT be part of the Registration Objects and Object Instances list.
// OMA-TS-LightweightM2M-V1_0_2-20180209-A 5.3.1 Register参照
func (lwm2m *Lwm2m) instanceIDList() []string {
	ret := make([]string, 0)
	objectIDs, code := lwm2m.handler.ListObjectIDs()
	if code != CoapCodeContent {
		return []string{}
	}
	for _, objectID := range objectIDs {
		if objectID == 0 {
			continue
		}
		definition := lwm2m.definitions.findObjectDefinitionByID(objectID)
		instanceIDs, code := lwm2m.handler.ListInstanceIDs(&Lwm2mObject{ID: objectID, Definition: definition})
		if code != CoapCodeContent {
			continue
		}
		for _, instanceID := range instanceIDs {
			ret = append(ret, "/"+strconv.Itoa((int)(objectID))+"/"+strconv.Itoa((int)(instanceID)))
		}
	}
	return ret
}

// getIdentity : Identityを取得する
func (lwm2m *Lwm2m) getIdentity() []byte {
	resource := lwm2m.findResource(lwm2mObjectIDSecurity, lwm2m.dmSecurityInstanceID, lwm2mResourceIDSecurityIdentity)

	identityStr, code := lwm2m.handler.ReadResource(resource)
	if code != CoapCodeContent {
		return []byte{}
	}

	identity, err := base64.StdEncoding.DecodeString(identityStr)
	if err != nil {
		return []byte{}
	}

	return identity
}

// getSecretKey : Secret Key(PSK)を取得する
func (lwm2m *Lwm2m) getSecretKey() []byte {
	resource := lwm2m.findResource(lwm2mObjectIDSecurity, lwm2m.dmSecurityInstanceID, lwm2mResourceIDSecuritySecretKey)

	secretKeyStr, code := lwm2m.handler.ReadResource(resource)
	if code != CoapCodeContent {
		return []byte{}
	}

	secretKey, err := base64.StdEncoding.DecodeString(secretKeyStr)
	if err != nil {
		return []byte{}
	}

	return secretKey
}

// getLifetime : lifetimeを取得する
// 取得できない場合は60とする
func (lwm2m *Lwm2m) getLifetime() int {
	resource := lwm2m.findResource(lwm2mObjectIDServer, lwm2m.dmServerInstanceID, lwm2mResourceIDServerLifetime)
	lifetimeStr, code := lwm2m.handler.ReadResource(resource)
	if code != CoapCodeContent {
		return lwm2mDefaultLifetime
	}

	lifetime, err := strconv.Atoi(lifetimeStr)
	if err != nil {
		return lwm2mDefaultLifetime
	}
	return lifetime
}

// getDMServerURI : Device management serverのURIを取得する
// 取得できない場合はデフォルト(coaps://jp.inventory.soracom.io:5684)とする
func (lwm2m *Lwm2m) getDMServerURI() string {
	resource := lwm2m.findResource(lwm2mObjectIDSecurity, lwm2m.dmSecurityInstanceID, lwm2mResourceIDSecurityURI)
	dmServerURIStr, code := lwm2m.handler.ReadResource(resource)
	if code != CoapCodeContent {
		return lwm2mDefaultDMServerURL
	}
	return dmServerURIStr
}
