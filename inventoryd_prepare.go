package inventoryd

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:generate go-bindata -pkg inventoryd ./models/

// CreateDefaultConfig : デフォルトの設定ファイルを生成する
func CreateDefaultConfig(configPath string) error {
	rootPath := filepath.Join(configPath, "..")
	endpointClientName := "inventoryd-" + time.Now().Format("20060102030405")
	config := &Config{
		RootPath:           rootPath,
		ObserveInterval:    5,
		BootstrapServer:    "bootstrap.soracom.io:5683",
		EndpointClientName: endpointClientName}
	_, err := os.Stat(rootPath)
	if os.IsNotExist(err) {
		err := os.MkdirAll(rootPath, 0755)
		if err != nil {
			return err
		}
	}

	modelsPath := filepath.Join(rootPath, inventorydModelsDir)
	_, err = os.Stat(modelsPath)
	if os.IsNotExist(err) {
		err := os.MkdirAll(modelsPath, 0755)
		if err != nil {
			return err
		}
	}

	modelFiles, err := AssetDir(inventorydModelsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "定義ファイルが展開できませんでした")
	} else {
		for _, modelFile := range modelFiles {
			modelData, err := Asset(filepath.Join(inventorydModelsDir, modelFile))
			if err == nil {
				err = ioutil.WriteFile(filepath.Join(modelsPath, modelFile), modelData, 0644)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "定義ファイル(%s)が展開できませんでした\n", modelFile)
			}
		}
	}

	resourcesPath := filepath.Join(rootPath, inventorydResourcesDir)
	_, err = os.Stat(resourcesPath)
	if os.IsNotExist(err) {
		err := os.MkdirAll(resourcesPath, 0755)
		if err != nil {
			return err
		}
	}

	jsonStr, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(configPath, jsonStr, 0644)
	if err != nil {
		return err
	}
	return nil
}

// Prepare : 使用前準備
func (daemon *Inventoryd) Prepare(config *Config) error {
	daemon.Config = config
	objectDefinitions, err := LoadLwm2mDefinitions(filepath.Join(daemon.Config.RootPath, inventorydModelsDir))
	if err != nil {
		return err
	}

	// 自動設定モードの設定
	autoMode := false
	fmt.Println("オブジェクト、インスタンス、リソースの初期設定を行います")
	fmt.Println("インスタンス生成時はリソースは以下の初期値が設定されます")
	fmt.Println("Integer: 0 / Float: 0.0 / String: \"\" / Time: 0 / Boolean: false / Opaque: 空データ / Objlnk: 0:0")
	fmt.Println("Executeのリソースはデフォルトのシェルスクリプトを生成します")
	fmt.Println("自動初期設定モード: 定義のあるモデルのインスタンスを1つずつ生成\n手動初期設定モード: インスタンスの個数を問い合わせながら生成")
	fmt.Print("自動初期設定モードを使用しますか？ [ Y / n ] : ")
	scanner := bufio.NewScanner(os.Stdin)
	done := scanner.Scan()
	if done {
		input := strings.ToLower(scanner.Text())
		if input == "" || input == "y" || input == "yes" {
			autoMode = true
		}
	} else {
		return errors.New("入力が中断されました")
	}

	for _, objectDefinition := range objectDefinitions {
		err := daemon.prepareObject(objectDefinition, autoMode)
		if err != nil {
			return err
		}
	}
	return nil
}

// SetSecurityParams : コマンドラインで指定されたデバイスID、PSKを設定する
// 既存のデバイスID、PSKは削除する
func SetSecurityParams(config *Config, handler Lwm2mHandler, identity string, pskOpaque string) error {
	identityOpaque := base64.StdEncoding.EncodeToString([]byte(identity))
	definitions, err := LoadLwm2mDefinitions(filepath.Join(config.RootPath, inventorydModelsDir))
	if err != nil {
		return err
	}
	securityDefinition := definitions.findObjectDefinitionByID(lwm2mObjectIDSecurity)
	serverDefinition := definitions.findObjectDefinitionByID(lwm2mObjectIDServer)

	code := handler.DeleteObject(&Lwm2mObject{ID: lwm2mObjectIDSecurity, Definition: securityDefinition})
	if code != CoapCodeDeleted {
		return errors.New("セキュリティオブジェクトの削除に失敗しました")
	}
	code = handler.DeleteObject(&Lwm2mObject{ID: lwm2mObjectIDServer, Definition: serverDefinition})
	if code != CoapCodeDeleted {
		return errors.New("サーバーオブジェクトの削除に失敗しました")
	}
	code = handler.CreateInstance(&Lwm2mInstance{objectID: lwm2mObjectIDSecurity, ID: 0})
	if code != CoapCodeCreated {
		return errors.New("サーバーインスタンスの登録に失敗しました")
	}
	code = handler.CreateInstance(&Lwm2mInstance{objectID: lwm2mObjectIDServer, ID: 0})
	if code != CoapCodeCreated {
		return errors.New("サーバーインスタンスの登録に失敗しました")
	}

	code = setSecurityResource(
		handler, lwm2mObjectIDSecurity, 0, lwm2mResourceIDSecurityURI, securityDefinition, lwm2mDefaultDMServerURL)
	if code != CoapCodeChanged {
		return errors.New("サーバーURIの登録に失敗しました")
	}

	code = setSecurityResource(
		handler, lwm2mObjectIDSecurity, 0, lwm2mResourceIDSecurityBootstrap, securityDefinition, "false")
	if code != CoapCodeChanged {
		return errors.New("ブートストラップ種別の登録に失敗しました")
	}

	code = setSecurityResource(
		handler, lwm2mObjectIDSecurity, 0, lwm2mResourceIDSecurityIdentity, securityDefinition, identityOpaque)
	if code != CoapCodeChanged {
		return errors.New("デバイスIDの登録に失敗しました")
	}

	code = setSecurityResource(
		handler, lwm2mObjectIDSecurity, 0, lwm2mResourceIDSecuritySecretKey, securityDefinition, pskOpaque)
	if code != CoapCodeChanged {
		return errors.New("PSKの登録に失敗しました")
	}

	code = setSecurityResource(
		handler, lwm2mObjectIDSecurity, 0, lwm2mResourceIDSecurityShortServerID, securityDefinition, strconv.Itoa(lwm2mDefaultShortServerID))
	if code != CoapCodeChanged {
		return errors.New("サーバIDの登録に失敗しました")
	}

	code = setSecurityResource(
		handler, lwm2mObjectIDServer, 0, lwm2mResourceIDServerShortServerID, serverDefinition, strconv.Itoa(lwm2mDefaultShortServerID))
	if code != CoapCodeChanged {
		return errors.New("サーバIDの登録に失敗しました")
	}

	code = setSecurityResource(
		handler, lwm2mObjectIDServer, 0, lwm2mResourceIDServerLifetime, serverDefinition, strconv.Itoa(lwm2mDefaultLifetime))
	if code != CoapCodeChanged {
		return errors.New("サーバIDの登録に失敗しました")
	}

	return nil
}

func (daemon *Inventoryd) prepareObject(objectDefinition *Lwm2mObjectDefinition, autoMode bool) error {
	objectDirPath := filepath.Join(daemon.Config.RootPath, inventorydResourcesDir, strconv.Itoa((int)(objectDefinition.ID)))
	dir, err := os.Stat(objectDirPath)
	objectExist := false
	if !os.IsNotExist(err) && dir.IsDir() {
		objectExist = true
	}
	if !os.IsNotExist(err) && !dir.IsDir() {
		if err := os.Remove(objectDirPath); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "オブジェクトのパスにファイルがあるため削除しました")
	}

	if autoMode {
		if !objectExist {
			os.Mkdir(objectDirPath, 0755)
		}
		daemon.createDefaultInstance(objectDefinition, 0, objectDirPath)
		return nil
	}

	fmt.Printf("オブジェクトNo.%d(%s)のインスタンスをいくつ生成しますか？ [ default: 0 ] : ", objectDefinition.ID, objectDefinition.Name)
	var instanceNum int
	for {
		scanner := bufio.NewScanner(os.Stdin)
		done := scanner.Scan()
		if done {
			input := strings.ToLower(scanner.Text())
			if input == "" {
				instanceNum = 0
				break
			} else {
				inputNum, err := strconv.Atoi(input)
				if err != nil {
					fmt.Fprintln(os.Stderr, "入力値が不正です。整数値を入力してください")
					continue
				}
				instanceNum = inputNum
				break
			}
		} else {
			return errors.New("入力が中断されました")
		}
	}
	if !objectExist && instanceNum > 0 {
		os.Mkdir(objectDirPath, 0755)
	}
	for i := 0; i < instanceNum; i++ {
		daemon.createDefaultInstance(objectDefinition, (uint16)(i), objectDirPath)
	}
	return nil
}

func (daemon *Inventoryd) createDefaultInstance(
	objectDefinition *Lwm2mObjectDefinition,
	instanceID uint16,
	objectDirPath string) {
	instanceDirPath := filepath.Join(objectDirPath, strconv.Itoa((int)(instanceID)))
	dir, err := os.Stat(instanceDirPath)
	if !os.IsNotExist(err) && dir.IsDir() {
		return
	}
	if !os.IsNotExist(err) && !dir.IsDir() {
		if err := os.Remove(instanceDirPath); err != nil {
			return
		}
		fmt.Fprintf(os.Stderr, "インスタンスのパスにファイルがあるため削除しました")
	}
	fmt.Printf("オブジェクトNo.%d(%s)のインスタンスNo.%dを生成します\n", objectDefinition.ID, objectDefinition.Name, instanceID)
	os.Mkdir(instanceDirPath, 0755)

	for _, resourceDefinition := range objectDefinition.Resources {
		resourcePath := filepath.Join(instanceDirPath, strconv.Itoa((int)(resourceDefinition.ID)))
		file, err := os.Stat(resourcePath)
		if !os.IsNotExist(err) && !file.IsDir() {
			return
		}
		if resourceDefinition.Excutable {
			defaultScript := fmt.Sprintf("#/bin/bash\necho \"execute %s script\"", resourceDefinition.Name)
			ioutil.WriteFile(resourcePath, []byte(defaultScript), 0755)
			continue
		}
		switch resourceDefinition.Type {
		case lwm2mResourceTypeString, lwm2mResourceTypeOpaque:
			ioutil.WriteFile(resourcePath, []byte{}, 0644)
		case lwm2mResourceTypeInteger, lwm2mResourceTypeTime:
			ioutil.WriteFile(resourcePath, []byte("0"), 0644)
		case lwm2mResourceTypeFloat:
			ioutil.WriteFile(resourcePath, []byte("0.0"), 0644)
		case lwm2mResourceTypeBoolean:
			ioutil.WriteFile(resourcePath, []byte("false"), 0644)
		case lwm2mResourceTypeObjlnk:
			ioutil.WriteFile(resourcePath, []byte("0:0"), 0644)
		}
	}
}

func setSecurityResource(
	handler Lwm2mHandler,
	objectID, instanceID, resourceID uint16,
	objectDefinition *Lwm2mObjectDefinition,
	value string) CoapCode {

	code := handler.WriteResource(&Lwm2mResource{
		objectID:   objectID,
		instanceID: instanceID,
		ID:         resourceID,
		Definition: objectDefinition.findResourceByID(resourceID)},
		value)
	return code
}

func SaveConfig(configPath string, config *Config) error {
	jsonStr, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(configPath, jsonStr, 0644)
	if err != nil {
		return err
	}
	return nil
}
