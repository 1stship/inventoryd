# inventoryd
ソラコム社のデバイス管理サービスSORACOM Inventoryにアクセスするためのツールです。SORACOM Inventoryの説明はこちら

https://soracom.jp/services/inventory/

出来るだけ簡単に使用できるようにするため、リソースは全てファイルとして扱います。以下の機能に対応しています。

- SIM経由のブートストラップ
- デバイスIDとデバイスシークレットを利用した接続
- READ / WRITE / EXECUTE / OBSERVE オペレーションの対応
- オブジェクト定義ファイルの認識とデフォルトリソースファイルの自動生成

## 取得方法
go getコマンドで取得できます。
```sh
go get github.com/1stship/inventoryd/cmd/inventoryd
```

## 使用方法
以下のコマンドを実行して、初期設定を実施します。
```sh
inventoryd --init
```

デフォルトではカレントディレクトリに設定ファイルと定義ファイルディレクトリ、リソースディレクトリを生成します。自動初期設定モード:yで初期設定すると、Object ID:0〜9までのインスタンスが１つずつ自動生成されます。

初期設定が終了したら、以下のいずれかで接続を開始します

- SIM経由のブートストラップ(要SORACOM Air通信)
```sh
inventoryd -b
```

- デバイスIDとデバイスシークレットを利用した接続(要デバイスID、シークレットキー)
```sh
inventoryd --identity d-....<払い出されたデバイスID> --psk ABCD....<払い出されたシークレットキー(base64)>
```

デバイスIDとシークレットキーについては、以下のページをご覧ください。

https://dev.soracom.io/jp/start/inventory_registration_with_keys/

接続が開始されると、SORACOM Consoleからリソースの操作ができます。

なお、２回目以降はブートストラップおよびデバイスクID、シークレットキーの指定は不要です。

## リソースファイルについて

このツールではリソースは全てファイルとして扱っています。設定ファイルが配置された場所(デフォルトではカレントディレクトリ)にresourcesフォルダがあり、その中のファイルがリソースの実体です。

（例）ディレクトリを/home/1stshipとすると、/home/1stship/3/0/9はバッテリレベルを示すリソースのファイル

各オペレーションとは以下のように結びつけられています。

- READ : 対象のリソースファイルを読み出す
- WRITE : 対象のリソースファイルを更新する
- EXECUTE : 対象のリソースファイル(実行可能ファイル)を実行する
- OBSERVE : 対象のリソースファイルを定期的(デフォルト5秒ごと)に読み出し、更新があれば通知する

インスタンスに対するREADやOBSERVEは、配下のリソース全てを読み出します。従って、対象のリソースファイルを参照/更新することでデバイス管理ができます。

## 実行可能リソースについて

実行可能なリソースファイルはEXECUTEにて実行することが出来ます。サービスからの入力は標準入力から入ります。

基本的には実行はEXECUTEですが、動的に値を読み出したい場合、READを何らかの実行ファイルと結びつけたい場合があります。たとえば、/3/0/13のCurrent Timeは現在の時間を出力するプログラムとしたいなどの場合、/3/0/13.readという名前で実行可能なファイルを配置することで対応可能です。

たとえば、/3/0/13.readを実行可能な以下のbashスクリプトとすると、/3/0/13へのアクセスが現在時間を返すようになります。

```sh
#/bin/bash
date +%s
```

同様にリソースファイル.writeという名前で実行可能ファイルを配置すると、WRITE動作も実行させることが出来ます。

## 追加オブジェクトの対応について

設定ファイルが配置されたディレクトリ以下にあるmodelsフォルダにLWM2Mのオブジェクト定義ファイルを配置すると、起動時に認識します。

新しい定義ファイルが入った状態で再度初期化(inventoryd --init)を実行することで、追加モデルのデフォルトリソースを生成できます。（既存のリソースは影響しません）

OMAに規定されていないモデルについては、以下のURLを参考に、SORACOM コンソールにてカスタムオブジェクトをご登録ください。

https://dev.soracom.io/jp/start/inventory_custom_object/
