package main

import (
	"bufio"
	"flag"
	"fmt"
	"funahara/inventoryd"
	"os"
	"path/filepath"
	"strings"
)

func main() {

	const version = "0.0.1"
	dispVersion := false

	const defalutConfig = "./config.json"
	var configPath string
	prepare := false
	bootstrap := false
	var identity string
	var psk string
	var endpoint string
	var rootPath string
	flag.BoolVar(&dispVersion, "v", false, "バージョン表示")
	flag.BoolVar(&dispVersion, "version", false, "バージョン表示")
	flag.StringVar(&configPath, "c", defalutConfig, "設定ファイルのパス")
	flag.StringVar(&configPath, "config", defalutConfig, "設定ファイルのパス")
	flag.BoolVar(&prepare, "init", false, "初期設定の実行")
	flag.BoolVar(&bootstrap, "b", false, "ブートストラップの実行")
	flag.BoolVar(&bootstrap, "bootstrap", false, "ブートストラップの実行")
	flag.StringVar(&identity, "identity", "", "デバイスID")
	flag.StringVar(&psk, "psk", "", "事前共有鍵(base64)")
	flag.StringVar(&endpoint, "endpoint", "", "エンドポイント名")
	flag.StringVar(&rootPath, "root", "", "ルートパス(定義ファイル/リソースファイルのあるパス)")
	flag.Parse()

	if dispVersion {
		fmt.Printf("inventoryd: Ver %s", version)
		os.Exit(0)
	}

	if !strings.HasPrefix(configPath, "/") {
		currentDir, _ := os.Getwd()
		configPath = filepath.Join(currentDir, configPath)
	}

	if prepare {
		checkConfig(configPath)
	}

	_, err := os.Stat(configPath)
	if os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "設定ファイル %sが存在しません。\n--initオプションにて初期化するか、-cオプションにて設定ファイルを指定してください\n", configPath)
		os.Exit(1)
	}

	config, err := inventoryd.LoadInventorydConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "設定ファイル %sが正常に読み出せませんでした。\n設定ファイルのフォーマットをご確認ください\n", configPath)
		os.Exit(1)
	}

	// エンドポイントの設定
	if endpoint != "" {
		config.EndpointClientName = endpoint
		inventoryd.SaveConfig(configPath, config)
	}

	// ルートパスの設定
	if rootPath != "" {
		config.RootPath = rootPath
		inventoryd.SaveConfig(configPath, config)
	}

	// デフォルトリソース、モデルの登録
	if prepare {
		inventoryd := new(inventoryd.Inventoryd)
		inventoryd.Prepare(config)
		os.Exit(0)
	}

	handler := &inventoryd.HandlerFile{ResourceDirPath: filepath.Join(config.RootPath, "resources")}

	if bootstrap && (identity != "" || psk != "") {
		fmt.Fprintln(os.Stderr, "ブートストラップとデバイスID、事前共有鍵は同時に指定することが出来ません。\nいずれかを指定してください")
		os.Exit(1)
	}

	if bootstrap {
		bootstrap := new(inventoryd.Inventoryd)
		err := bootstrap.Bootstrap(config, handler)
		if err != nil {
			fmt.Fprint(os.Stderr, err)
			fmt.Fprintln(os.Stderr, "ブートストラップが失敗しました。\nSORACOM Airで通信しているかをご確認の上、再度実行してください")
			os.Exit(1)
		}
	}

	if identity != "" && psk != "" {
		err := inventoryd.SetSecurityParams(config, handler, identity, psk)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	} else if (identity == "" && psk != "") || (identity != "" && psk == "") {
		fmt.Fprintln(os.Stderr, "デバイスIDと事前共有鍵は同時に指定してください")
		os.Exit(1)
	}

	inventoryd := new(inventoryd.Inventoryd)
	if err := inventoryd.Initialize(config, handler); err != nil {
		fmt.Println("起動に失敗しました", err)
		os.Exit(1)
	}
	err = inventoryd.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	os.Exit(0)
}

func checkConfig(configPath string) {
	_, err := os.Stat(configPath)
	if os.IsNotExist(err) {
		fmt.Printf("設定ファイル %sが存在しません。\nこのパスにデフォルトの設定ファイルを生成しますか？[ Y / n ] : ", configPath)
		scanner := bufio.NewScanner(os.Stdin)
		done := scanner.Scan()
		if done {
			input := strings.ToLower(scanner.Text())
			if input == "" || input == "y" || input == "yes" {
				err := inventoryd.CreateDefaultConfig(configPath)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
			} else {
				fmt.Println("デフォルト設定ファイルを生成するか、-cオプションにて設定ファイルを指定して起動してください")
				os.Exit(1)
			}
		} else {
			os.Exit(1)
		}
	}
}
