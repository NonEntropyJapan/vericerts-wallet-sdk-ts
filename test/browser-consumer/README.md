# ブラウザで SDK の npm パッケージを検証する

パッケージを新しい consumer にインストールし、Vite の本番ビルドを Chrome / Chromium で実行する。vendor alias と Node の polyfill は不要。SDK のルートから HAIP の固定 JWK・ES256 署名を照合し、SD-JWT VC を発行・検証する。`/experimental` の読み込みも確認する。

同じ検証済みtgzとreceiptを使う自動実行は [配布物検証の手順](../../scripts/packed-consumer/README.md) を参照する。以下は個別比較用の手動手順。

`run.mjs`はbuild前に`boundary-regression.mjs`の小さな実Vite graphを検証する。正常な依存・CJS・CSS/asset・worker・virtual moduleと、browser条件でだけ現れるconsumer外参照を対比し、解決/読込前の境界検査を確かめる。SDK本体のbuildにも同じ`boundary.mjs`を適用する。このmodule境界検査は一般のOS/FS sandboxではない。`boundary.test.mjs`はViteや追加installを使わない純粋なpath境界の単体テスト。

SDK のルートで実行する。Bun は 1.4.4、Node.js は Vite 8 の動作するバージョンを使用する。`CHROME_BIN` には Chrome / Chromium の実行ファイルを指定する。

```sh
sdk_dir=$PWD
consumer_dir=$(mktemp -d)
bun install --frozen-lockfile
npm pack --pack-destination "$consumer_dir"
cp "$sdk_dir"/test/browser-consumer/* "$consumer_dir"/
cd "$consumer_dir"
npm install --omit=peer --ignore-scripts ./*.tgz
CHROME_BIN=/path/to/chrome node run.mjs
```

OpenTelemetry を使う場合は同じ consumer に peer を追加する。追加後は `/otel` から実際に span を開始・終了する。

```sh
npm install --ignore-scripts --save-exact @opentelemetry/api@1.9.1 @opentelemetry/api-logs@0.222.0
CHROME_BIN=/path/to/chrome node run.mjs --otel
```

比較するときは、peer を追加する前に同じ consumer で別の tarball を `npm install --omit=peer --ignore-scripts /path/to/candidate.tgz` し、同じコマンドを実行する。2回の lockfile で SDK 以外の実依存とツールの version・integrity が一致することを確認する。表示するサイズはプローブ用に出力した JavaScript の合計と、各チャンクを gzip したバイト数の合計。
