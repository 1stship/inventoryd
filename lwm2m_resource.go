package inventoryd

import (
	"encoding/xml"
	"io/ioutil"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// 規定のオブジェクトID
const (
	lwm2mObjectIDSecurity uint16 = 0
	lwm2mObjectIDServer   uint16 = 1
)

// 規定のリソースID
const (
	lwm2mResourceIDSecurityURI           uint16 = 0
	lwm2mResourceIDSecurityBootstrap     uint16 = 1
	lwm2mResourceIDSecurityIdentity      uint16 = 3
	lwm2mResourceIDSecuritySecretKey     uint16 = 5
	lwm2mResourceIDSecurityShortServerID uint16 = 10
	lwm2mResourceIDServerShortServerID   uint16 = 0
	lwm2mResourceIDServerLifetime        uint16 = 1
)

// Lwm2mObject : Lwm2mのオブジェクト
type Lwm2mObject struct {
	ID         uint16
	Definition *Lwm2mObjectDefinition
}

// Lwm2mInstance : LWm2mのインスタンス
type Lwm2mInstance struct {
	ID       uint16
	objectID uint16
}

// Lwm2mResource : Lwm2mのリソース
type Lwm2mResource struct {
	ID         uint16
	objectID   uint16
	instanceID uint16
	Definition *Lwm2mResourceDefinition
}

// Lwm2mObservedInstance : Lwm2mのObserve中のインスタンス
// ObserveはNotifyの際にObserve時と同じTokenを使用する必要がある
// OMA-TS-LightweightM2M-V1_0_2-20180209-A 8.2.6 Information Reporting Interface参照
type Lwm2mObservedInstance struct {
	token        []byte
	messageID    uint16
	observeCount uint32
	instance     *Lwm2mInstance
	resources    []*Lwm2mObservedResource
}

// Lwm2mObservedResource : Lwm2mのObserve中のリソース
// ObserveはNotifyの際にObserve時と同じTokenを使用する必要がある
// OMA-TS-LightweightM2M-V1_0_2-20180209-A 8.2.6 Information Reporting Interface参照
type Lwm2mObservedResource struct {
	token        []byte
	messageID    uint16
	observeCount uint32
	resource     *Lwm2mResource
	lastValue    string
}

// Lwm2mDataTypes
// OMA-TS-LightweightM2M-V1_0_2-20180209-A Appendix C. Data Types参照
const (
	lwm2mResourceTypeString  byte = 0 // UTF-8
	lwm2mResourceTypeInteger byte = 1 // singed 1/2/4/8 bytes
	lwm2mResourceTypeFloat   byte = 2
	lwm2mResourceTypeBoolean byte = 3 // true:1 false:0
	lwm2mResourceTypeOpaque  byte = 4
	lwm2mResourceTypeTime    byte = 5 // UNIX Time
	lwm2mResourceTypeObjlnk  byte = 6 // ObjectID(uint16) : InstanceID(uint16)
	lwm2mResourceTypeNone    byte = 7
)

// Lwm2mObjectDefinition : Lwm2mのオブジェクト定義
type Lwm2mObjectDefinition struct {
	ID        uint16
	Name      string
	Multi     bool
	Mandatory bool
	Resources []*Lwm2mResourceDefinition
}

// lwm2mObjectDefinitions : Lwm2mのオブジェクト定義リスト
type lwm2mObjectDefinitions []*Lwm2mObjectDefinition

// Lwm2mResourceDefinition : Lwm2mのリソース定義
type Lwm2mResourceDefinition struct {
	ID        uint16
	Name      string
	Multi     bool
	Mandatory bool
	Readable  bool
	Writable  bool
	Excutable bool
	Type      byte
}

// findObjectDefinitionByID : 指定したIDのオブジェクト定義を取得する
func (definitions lwm2mObjectDefinitions) findObjectDefinitionByID(objectID uint16) *Lwm2mObjectDefinition {
	var ret *Lwm2mObjectDefinition
	for _, object := range definitions {
		if object.ID == objectID {
			ret = object
			break
		}
	}
	return ret
}

// findResourceDefinitionByIDs : 指定したIDのリソース定義を取得する
func (definitions lwm2mObjectDefinitions) findResourceDefinitionByIDs(objectID, resourceID uint16) *Lwm2mResourceDefinition {
	objectDefinition := definitions.findObjectDefinitionByID(objectID)
	if objectDefinition == nil {
		return nil
	}
	resourceDefinition := objectDefinition.findResourceByID(resourceID)
	return resourceDefinition
}

// findResourceById : 指定したIDのリソース定義を取得する
func (def *Lwm2mObjectDefinition) findResourceByID(resourceID uint16) *Lwm2mResourceDefinition {
	var ret *Lwm2mResourceDefinition
	for _, resource := range def.Resources {
		if resource.ID == resourceID {
			ret = resource
			break
		}
	}
	return ret
}

// Lwm2mDefinitionXML : Lwm2mのオブジェクト定義のXML
type Lwm2mDefinitionXML struct {
	XMLName xml.Name                  `xml:"LWM2M"`
	Object  *Lwm2mObjectDefinitionXML `xml:"Object"`
}

// Lwm2mObjectDefinitionXML : Lwm2mのオブジェクト定義のXMLのオブジェクト部
type Lwm2mObjectDefinitionXML struct {
	Name      string                        `xml:"Name"`
	ID        string                        `xml:"ObjectID"`
	Multi     string                        `xml:"MultipleInstances"`
	Mandatory string                        `xml:"Mandatory"`
	Resources []*Lwm2mResourceDefinitionXML `xml:"Resources>Item"`
}

// Lwm2mResourceDefinitionXML : Lwm2mのオブジェクト定義のXMLのリソース部
type Lwm2mResourceDefinitionXML struct {
	ID         string `xml:"ID,attr"`
	Name       string `xml:"Name"`
	Operations string `xml:"Operations"`
	Multi      string `xml:"MultipleInstances"`
	Mandatory  string `xml:"Mandatory"`
	Type       string `xml:"Type"`
}

// LoadLwm2mDefinitions : 定義ファイルから定義構造体を生成する
func LoadLwm2mDefinitions(modelsPath string) (lwm2mObjectDefinitions, error) {
	definitions := make([]*Lwm2mObjectDefinition, 0)
	files, err := ioutil.ReadDir(modelsPath)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		filePath := filepath.Join(modelsPath, file.Name())
		xmlData, err := ioutil.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
		doc := &Lwm2mDefinitionXML{}
		xml.Unmarshal(xmlData, doc)
		objectDefinition := createObjectDefinitionFromXML(doc.Object)
		definitions = append(definitions, objectDefinition)
	}
	sort.Slice(definitions, func(i, j int) bool { return definitions[i].ID < definitions[j].ID })
	return definitions, nil
}

func createObjectDefinitionFromXML(xml *Lwm2mObjectDefinitionXML) *Lwm2mObjectDefinition {
	ret := &Lwm2mObjectDefinition{}

	objectID, err := strconv.Atoi(xml.ID)
	if err != nil {
		return nil
	}
	ret.ID = (uint16)(objectID)

	ret.Name = xml.Name

	multi := xml.Multi
	if multi == "Multiple" {
		ret.Multi = true
	} else if multi == "Single" {
		ret.Multi = false
	} else {
		return nil
	}

	mandatory := xml.Mandatory
	if mandatory == "Mandatory" {
		ret.Mandatory = true
	} else if mandatory == "Optional" {
		ret.Mandatory = false
	} else {
		return nil
	}

	resources := []*Lwm2mResourceDefinition{}
	for _, resource := range xml.Resources {
		resources = append(resources, createResourceDefinitionFromXML(resource))
	}
	ret.Resources = resources

	return ret
}

func createResourceDefinitionFromXML(xml *Lwm2mResourceDefinitionXML) *Lwm2mResourceDefinition {
	ret := &Lwm2mResourceDefinition{}

	objectID, err := strconv.Atoi(xml.ID)
	if err != nil {
		return nil
	}
	ret.ID = (uint16)(objectID)

	ret.Name = xml.Name

	multi := xml.Multi
	if multi == "Multiple" {
		ret.Multi = true
	} else if multi == "Single" {
		ret.Multi = false
	} else {
		return nil
	}

	mandatory := xml.Mandatory
	if mandatory == "Mandatory" {
		ret.Mandatory = true
	} else if mandatory == "Optional" {
		ret.Mandatory = false
	} else {
		return nil
	}

	operations := xml.Operations
	if strings.Contains(operations, "R") {
		ret.Readable = true
	}
	if strings.Contains(operations, "W") {
		ret.Writable = true
	}
	if strings.Contains(operations, "E") {
		ret.Excutable = true
	}

	switch xml.Type {
	case "String":
		ret.Type = lwm2mResourceTypeString
	case "Integer":
		ret.Type = lwm2mResourceTypeInteger
	case "Float":
		ret.Type = lwm2mResourceTypeFloat
	case "Boolean":
		ret.Type = lwm2mResourceTypeBoolean
	case "Opaque":
		ret.Type = lwm2mResourceTypeOpaque
	case "Time":
		ret.Type = lwm2mResourceTypeTime
	case "Objlnk":
		ret.Type = lwm2mResourceTypeObjlnk
	default:
		ret.Type = lwm2mResourceTypeNone
	}

	return ret
}
