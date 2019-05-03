package inventoryd

import (
	"encoding/base64"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// HandlerFile : ファイルベースのハンドラ
type HandlerFile struct {
	ResourceDirPath string
}

// DeleteObject : オブジェクトを削除する
func (handler *HandlerFile) DeleteObject(object *Lwm2mObject) CoapCode {
	objectPath := filepath.Join(
		handler.ResourceDirPath,
		strconv.Itoa((int)(object.ID)))
	err := os.RemoveAll(objectPath)
	if err != nil {
		return CoapCodeNotAllowed
	}
	return CoapCodeDeleted
}

// CreateInstance : 空インスタンスを生成する
// 親オブジェクトが存在しない場合は生成する
func (handler *HandlerFile) CreateInstance(instance *Lwm2mInstance) CoapCode {
	objectPath := filepath.Join(
		handler.ResourceDirPath,
		strconv.Itoa((int)(instance.objectID)))

	// 親オブジェクトがなければ生成する
	// 親オブジェクトの位置にファイルがあれば、削除してから生成する
	dir, err := os.Stat(objectPath)
	if !os.IsNotExist(err) && !dir.IsDir() {
		if err := os.Remove(objectPath); err != nil {
			return CoapCodeNotAllowed
		}
		if err := os.Mkdir(objectPath, 0755); err != nil {
			return CoapCodeNotAllowed
		}
	} else if os.IsNotExist(err) {
		if err := os.Mkdir(objectPath, 0755); err != nil {
			return CoapCodeNotAllowed
		}
	}

	// インスタンス用の空ディレクトリを生成する
	// インスタンスの位置にファイルがあれば、削除してから生成する
	instancePath := filepath.Join(
		objectPath,
		strconv.Itoa((int)(instance.ID)))
	dir, err = os.Stat(instancePath)
	if !os.IsNotExist(err) && !dir.IsDir() {
		if err := os.Remove(instancePath); err != nil {
			return CoapCodeNotAllowed
		}
		if err := os.Mkdir(instancePath, 0755); err != nil {
			return CoapCodeNotAllowed
		}
	} else if os.IsNotExist(err) {
		if err := os.Mkdir(instancePath, 0755); err != nil {
			return CoapCodeNotAllowed
		}
	}
	return CoapCodeCreated
}

// ListObjectIDs : 利用可能なオブジェクトIDを取得する
func (handler *HandlerFile) ListObjectIDs() ([]uint16, CoapCode) {
	ret := make([]uint16, 0)
	files, err := ioutil.ReadDir(handler.ResourceDirPath)
	if err != nil {
		return []uint16{}, CoapCodeNotAllowed
	}

	for _, file := range files {
		if file.IsDir() {
			objectID, err := strconv.Atoi(file.Name())
			if err == nil {
				ret = append(ret, (uint16)(objectID))
			}
		}
	}
	sort.Slice(ret, func(i, j int) bool { return ret[i] < ret[j] })
	return ret, CoapCodeContent
}

// ListInstanceIDs : オブジェクト下にあるインスタンスIDを取得する
func (handler *HandlerFile) ListInstanceIDs(object *Lwm2mObject) ([]uint16, CoapCode) {
	ret := make([]uint16, 0)
	objectPath := filepath.Join(
		handler.ResourceDirPath,
		strconv.Itoa((int)(object.ID)))
	files, err := ioutil.ReadDir(objectPath)
	if err != nil {
		return []uint16{}, CoapCodeNotAllowed
	}

	for _, file := range files {
		if file.IsDir() {
			instanceID, err := strconv.Atoi(file.Name())
			if err == nil {
				ret = append(ret, (uint16)(instanceID))
			}
		}
	}
	sort.Slice(ret, func(i, j int) bool { return ret[i] < ret[j] })
	return ret, CoapCodeContent
}

// ListResourceIDs : インスタンス下にあるリソースIDを取得する
func (handler *HandlerFile) ListResourceIDs(instance *Lwm2mInstance) ([]uint16, CoapCode) {
	ret := make([]uint16, 0)
	instancePath := filepath.Join(
		handler.ResourceDirPath,
		strconv.Itoa((int)(instance.objectID)),
		strconv.Itoa((int)(instance.ID)))
	files, err := ioutil.ReadDir(instancePath)
	if err != nil {
		return []uint16{}, CoapCodeNotAllowed
	}

	for _, file := range files {
		if !file.IsDir() {
			resourceID, err := strconv.Atoi(file.Name())
			if err == nil {
				ret = append(ret, (uint16)(resourceID))
			}
		}
	}
	sort.Slice(ret, func(i, j int) bool { return ret[i] < ret[j] })
	return ret, CoapCodeContent
}

// ReadResource : Resourceに対するRead
// ResourceをReadした結果を返す
// リソースIDに拡張子.readが付いたファイルが存在し、かつ実行可能であれば、
// 通常のリソースに優先して実行し、結果を返す
func (handler *HandlerFile) ReadResource(resource *Lwm2mResource) (string, CoapCode) {
	instancePath := filepath.Join(
		handler.ResourceDirPath,
		strconv.Itoa((int)(resource.objectID)),
		strconv.Itoa((int)(resource.instanceID)))

	// .readファイルの存在確認と実行
	executableResourcePath := filepath.Join(instancePath, strconv.Itoa((int)(resource.ID))+".read")
	file, err := os.Stat(executableResourcePath)
	if !os.IsNotExist(err) && !file.IsDir() {
		_, err := exec.LookPath(executableResourcePath)
		if err != nil {
			log.Printf("実行不可能なファイルです %s\n", err)
			return "", CoapCodeNotAllowed
		}
		cmd := exec.Command("/bin/sh", "-c", executableResourcePath)
		out, err := cmd.Output()
		if err != nil {
			log.Printf("リソースの読み取りにて実行に失敗しました %s\n", err)
			return "", CoapCodeNotAllowed
		}

		var ret string
		if resource.Definition.Type == lwm2mResourceTypeOpaque {
			ret = base64.StdEncoding.EncodeToString(out)
		} else if resource.Definition.Type != lwm2mResourceTypeString {
			ret = string(out)
			ret = strings.TrimSpace(ret)
		} else {
			ret = string(out)
		}
		return ret, CoapCodeContent
	}

	resourcePath := filepath.Join(instancePath, strconv.Itoa((int)(resource.ID)))
	buf, err := ioutil.ReadFile(resourcePath)
	if err != nil {
		return "", CoapCodeNotAllowed
	}

	if resource.Definition.Type == lwm2mResourceTypeOpaque {
		return base64.StdEncoding.EncodeToString(buf), CoapCodeContent
	}
	return string(buf), CoapCodeContent
}

// WriteResource : Resourceに対するWrite
// ResourceにWriteする
// リソースIDに拡張子.writeが付いたファイルが存在し、かつ実行可能であれば、
// 通常のリソースに優先して実行する
// サーバからの入力値は標準入力に渡す
func (handler *HandlerFile) WriteResource(resource *Lwm2mResource, value string) CoapCode {
	var buf []byte
	var err error
	if resource.Definition.Type == lwm2mResourceTypeOpaque {
		buf, err = base64.StdEncoding.DecodeString(value)
		if err != nil {
			return CoapCodeNotAllowed
		}
	} else {
		buf = []byte(value)
	}

	instancePath := filepath.Join(
		handler.ResourceDirPath,
		strconv.Itoa((int)(resource.objectID)),
		strconv.Itoa((int)(resource.instanceID)))

	// .writeファイルの存在確認と実行
	executableResourcePath := filepath.Join(instancePath, strconv.Itoa((int)(resource.ID))+".write")
	file, err := os.Stat(executableResourcePath)
	if !os.IsNotExist(err) && !file.IsDir() {
		_, err := exec.LookPath(executableResourcePath)
		if err != nil {
			log.Printf("実行不可能なファイルです %s\n", err)
			return CoapCodeNotAllowed
		}
		cmd := exec.Command("/bin/sh", "-c", executableResourcePath)
		stdin, _ := cmd.StdinPipe()
		io.WriteString(stdin, string(buf))
		stdin.Close()
		_, err = cmd.Output()
		if err != nil {
			log.Printf("リソースの書き込みにて実行に失敗しました %s\n", err)
			return CoapCodeNotAllowed
		}
		return CoapCodeChanged
	}

	resourcePath := filepath.Join(
		handler.ResourceDirPath,
		strconv.Itoa((int)(resource.objectID)),
		strconv.Itoa((int)(resource.instanceID)),
		strconv.Itoa((int)(resource.ID)))
	err = ioutil.WriteFile(resourcePath, buf, 0644)
	if err != nil {
		return CoapCodeNotAllowed
	}
	return CoapCodeChanged
}

// ExecuteResource : Resourceに対するExecute
// ResourceにExecuteする
// 実行可能形式ではないファイル(シェルスクリプトなど)は直接実行できないため、
// シェル経由でコマンドを実行する
// UNIX (Like) OSでの実行は要検討
func (handler *HandlerFile) ExecuteResource(resource *Lwm2mResource, value string) CoapCode {
	resourcePath := filepath.Join(
		handler.ResourceDirPath,
		strconv.Itoa((int)(resource.objectID)),
		strconv.Itoa((int)(resource.instanceID)),
		strconv.Itoa((int)(resource.ID)))
	_, err := exec.LookPath(resourcePath)
	if err != nil {
		log.Printf("実行不可能なファイルです %s\n", err)
		return CoapCodeNotAllowed
	}
	if len(value) > 0 {
		buf, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			log.Printf("Executeにてbase64のデコードに失敗しました %s\n", err)
			return CoapCodeBadRequest
		}
		cmd := exec.Command("/bin/sh", "-c", resourcePath)
		stdin, _ := cmd.StdinPipe()
		io.WriteString(stdin, string(buf))
		stdin.Close()
		out, err := cmd.Output()
		if err != nil {
			log.Printf("Executeにてファイルの実行に失敗しました %s\n", err)
			return CoapCodeNotAllowed
		}
		log.Printf("ファイルの実行結果：%s\n", out)
	} else {
		cmd := exec.Command("/bin/sh", "-c", resourcePath)
		out, err := cmd.Output()
		if err != nil {
			log.Printf("Executeにてファイルの実行に失敗しました %s\n", err)
			return CoapCodeNotAllowed
		}
		log.Printf("ファイルの実行結果：%s\n", out)
	}
	return CoapCodeChanged
}
