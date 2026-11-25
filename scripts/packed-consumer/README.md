# 同じSDK tarballの検証とprivate release dry-run

SDK のルートから、`.bun-version` の Bun と Node 24 で実行する。`--browser` を使うローカル実行では、Playwright が使う Chromium をあらかじめ用意する。`CHROME_BIN` で実行ファイルを指定できる。CI は投影先の依存を導入した後、`node scripts/ci/prepared.mjs browser` で固定済み fixture の Chromium を準備する。

以下は SDK の入力を固定した状態から、checkout 外に検証用 tarball を作る手順。

```sh
bun install --frozen-lockfile
SDK_ARTIFACT_DIR=$(mktemp -d)
SDK_VALIDATION_SHA=$(git rev-parse HEAD)
node scripts/packed-consumer/run.mjs \
  --artifact-dir="$SDK_ARTIFACT_DIR" \
  --receipt="$SDK_ARTIFACT_DIR/receipt.json" \
  --source-sha="$SDK_VALIDATION_SHA" --browser --bun
SDK_TARBALL=$(printf '%s\n' "$SDK_ARTIFACT_DIR"/*.tgz)
```

`npm pack`のprepackでbuild・NOTICE・SBOMを生成し、実tgzを一度だけ作る。同じtgzを空のconsumerへinstallし、全exportsのJS・class identity・5つのstrict型mode（`types: []` / `skipLibCheck: false`）を検証する。OTel peerなしとありを別々に検証し、`--bun`は同じJS runtime契約をBunでも実行する。`--browser`は既存のbrowser fixtureを隔離directoryへcopyし、固定lockのtoolingでproduction buildと実Chromiumを実行する。必要に応じて`CHROME_BIN`を指定する。

引数なしの従来の`bun run smoke:pack`は引き続きpackとNode consumerを実行し、artifact/receiptを一時directoryへ保存する。browser/Bun/最低Node版までの完了を意味しない。

残るNode版では**既存のtgzと同じreceipt**を使う。Node 20.19.0とNode 22を実際に切り替え、順番に実行する。consumerごとに再packしない。

```sh
node scripts/packed-consumer/run.mjs --tarball="$SDK_TARBALL" \
  --receipt="$SDK_ARTIFACT_DIR/receipt.json" --source-sha="$SDK_VALIDATION_SHA"
```

receiptはSHA256/SHA512 SRI・実packlist・SDK version・検証したNode/Bun/Chromium・結果を記録する。existing-artifact modeはproducerのGit/package.json/node_modulesを読まず、tgzとreceiptのidentity/digest/source整合を先に検査する。依存は隔離consumerへinstallし、`NODE_PATH` / `NODE_OPTIONS`によるproducer fallbackを使わない。失敗した検証はfailedとして保存し、以前の成功を流用しない。

型検査はconsumer自身にinstallしたTypeScriptで行い、compiler hostのread/resolveと実際のSourceFile集合をrealpath境界で確認する。triple-slash参照、import型、symlinkを含めconsumer外の宣言を検証入力に使わない。SDK自身のJS/d.tsは同じTypeScript ASTで事前解析し、絶対パス・逸脱する相対参照・非literalのmodule bindingを拒否する。

JS実行では新しいNode子processでconsumer rootの実パスを固定し、候補の評価前にCJSキャッシュの全ファイルキーを検査する。既定ESM resolver結果とCJS `require`の解決先を確認する。`Module.prototype.load`に渡るファイルは、標準loaderへの委譲前に実パスを検査する。これらのCJS境界検査による拒否を同期記録し、例外が捕捉されても子processを失敗させる。CJSの検査は子process終了まで有効で、ESMの違反は初回評価後と最初の`beforeExit`で集計する。Bunではconsumer外fileに対して失敗するonLoad filterを付ける。標準loader・CJS namespace・同一consumer内の別SDKコピーは保持する。これらの補助検査の対象はmoduleの参照・読込境界で、一般JavaScriptの権限管理やOS/FS sandboxは対象外。

browser buildも既定Vite resolverの実解決先とload前のrealpathを検査する。CSSの専用resolverは標準alias hook、workerは専用pluginを使い、browser条件の推移依存もconsumer内に制限する。Vite自身のparserで非literal import/asset URLを拒否し、直接assetを読むtransformより先にliteral URLの解決先を確認する。各peer条件のbuild前にown CJS/asset/worker/virtual moduleの正対照と、browser条件・CSS・symlink等の外部参照の実Vite回帰を自動実行する。回帰用Viteは隔離browser fixtureの固定依存だけを使う。

packlistの読取は`npm pack <既存tgz> --dry-run --json --ignore-scripts`による**metadata-only inspection**で行う。この操作が新しいtgzを出力せず、報告するsize/SRIが入力bytesと一致することを検査する。実pack生成とは区別する。展開はsystem tarを使い、path/link/重複と展開後の全filelistを照合する。

SDKの`schemas/`の3正本hashは`sourceSchemas`、実tarballに含まれるschema pathsは`packedSchemaPaths`で区別する。source用JSONを新しくnpm同梱したとは扱わない。

## private validation receiptとdry-run

receipt は `schemaVersion: 2` を使い、`source.validationOrigin` に `committed-projection` または `development-snapshot` を必須とする。`source.context` は `private-validation`、`source.publicRevision` は `null`、`release.publicProvenance` は `not-established` と記録する。Git revision、tree、lockfile、スキーマのハッシュは `source.privateRevision` に保存する。receipt は tarball と別の検証証跡として扱う。

```sh
node scripts/packed-consumer/release.mjs --tarball="$SDK_TARBALL" \
  --receipt="$SDK_ARTIFACT_DIR/receipt.json" --source-sha="$SDK_VALIDATION_SHA"
```

dry-run は `committed-projection` の固定済み入力と、Node 24・20.19.0・22、Bun、ブラウザの peer 2 条件の検証成功を必要とする。検証済み tarball に `npm publish <tgz> --dry-run --ignore-scripts` を適用し、npm が報告する SRI とサイズ、終了後の入力ハッシュを照合する。実行は手元の tarball の検証で完結し、レジストリの状態を変更しない。

編集中は `bun run smoke:pack` を引数なしで実行できる。変更を含む SDK の入力は一時 checkout に固定され、receipt はその revision と `development-snapshot` を記録する。検証中に元入力が変わると失敗する。リリースの検証はコミット後の入力で実行する。

SDK の Git リリースタグは `v<version>` とする。dry-run は検証済み tgz 内の
`package.json` から予定タグを求める（例：`0.1.0` → `v0.1.0`）。
SDK リポジトリの push では、最終 CI ジョブが予定タグ、対象リポジトリ、push したコミット、
同じ tgz の SHA-256 をログに記録する。タグの作成と npm 公開はリリース時に行う。
プレリリース版を npm へ配布する場合は、Git タグに加えて npm の配布タグ（dist-tag）も明示する。

CLIの子環境はPATH・HOME・一時directory・locale・明示browser/tool cache等に限定し、producer由来のGITHUB_/SDK_・認証・NODE_PATH/OPTIONSを渡さない。npm user/global設定は別々の空fileを使う。明示NPM_CONFIG_CACHEは保持するが、既定producerを常にcold cacheとする保証は持たない。
