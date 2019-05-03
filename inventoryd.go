package inventoryd

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// 使用するパス
const (
	inventorydModelsDir    string = "models"
	inventorydResourcesDir string = "resources"
)

// Inventoryd : SORACOM Inventory対応
type Inventoryd struct {
	Lwm2m  *Lwm2m
	Config *Config
}

// Config : inventorydの設定
type Config struct {
	RootPath           string `json:"rootPath"`
	ObserveInterval    int    `json:"observeInterval"`
	BootstrapServer    string `json:"bootstrapServer"`
	EndpointClientName string `json:"endpointClientName"`
}

// Initialize : Inventorydの初期化
func (daemon *Inventoryd) Initialize(config *Config, handler Lwm2mHandler) error {
	daemon.Lwm2m = new(Lwm2m)
	daemon.Config = config
	definitions, err := LoadLwm2mDefinitions(filepath.Join(config.RootPath, inventorydModelsDir))
	if err != nil {
		return err
	}
	err = daemon.Lwm2m.Initialize(daemon.Config.EndpointClientName, definitions, handler)
	if err != nil {
		return err
	}
	return nil
}

// LoadInventorydConfig : 設定ファイルから設定を読み出す
func LoadInventorydConfig(configPath string) (*Config, error) {
	config := &Config{}
	// JSONファイル読み込み
	bytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(bytes, config); err != nil {
		return nil, err
	}
	return config, nil
}

// Bootstrap : ブートストラップを実行する
func (daemon *Inventoryd) Bootstrap(config *Config, handler Lwm2mHandler) error {
	bootstrap := new(lwm2mBootstrap)
	daemon.Config = config
	objectDefinitions, err := LoadLwm2mDefinitions(filepath.Join(daemon.Config.RootPath, inventorydModelsDir))
	if err != nil {
		return err
	}
	err = bootstrap.Bootstrap(
		daemon.Config.BootstrapServer,
		daemon.Config.EndpointClientName,
		objectDefinitions,
		handler)
	if err != nil {
		return err
	}
	return nil
}

// Run : 動作を開始する
func (daemon *Inventoryd) Run() error {
	err := daemon.Lwm2m.CheckSecurityParams()
	if err != nil {
		return err
	}

	trapSignals := []os.Signal{
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, trapSignals...)

	updateStopCh := make(chan bool)
	lifetime := daemon.Lwm2m.getLifetime()
	updateInterval := (time.Duration)(lifetime) * 9 / 10 * time.Second
	go daemon.Lwm2m.StartUpdate(updateInterval, updateStopCh)

	observeStopCh := make(chan bool)
	observeInterval := (time.Duration)(daemon.Config.ObserveInterval) * time.Second
	go daemon.Lwm2m.StartObserving(observeInterval, observeStopCh)

	<-sigCh
	log.Print("終了シグナルを受信しました")
	updateStopCh <- true
	observeStopCh <- true

	return nil
}
