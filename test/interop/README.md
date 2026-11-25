# SDK 相互運用テスト

VeriCerts Wallet SDK のパッケージをインストールした consumer で、VC 発行・検証、DID 解決、walt.id との OID4VCI と OID4VP を検証する。設定は [pairs.json](pairs.json)、回帰テストが照合する公開契約は [matrix.json](contracts/matrix.json) にある。

## 1. 回帰テストとパッケージ

SDK ルートで Node 24 と `.bun-version` の Bun を使い、`bun run test` を実行する。SDK ソースのテストに続いて、一時ディレクトリの consumer が、同じソースから生成した tarball をインストールして Interop を検証する。`bun run test:coverage` では SDK ソースのカバレッジも出力する。CI では先行するパッケージ検証が生成した tarball をそのまま使う。

Interop 回帰テストは次の6グループで実行される。Veramo の回帰テスト用依存は同梱 lockfile に従ってインストールする。

| グループ | ランタイム | 内容 |
| --- | --- | --- |
| 内部ループ | Bun | SDK の公開 API による実際の発行と検証、結果の判定 |
| walt.id | Bun | モックを使った Offer → Receive → Present、TLS 設定、SD-JWT リクエスト |
| アダプタ | Bun | JWT ヘッダの `kid` と Ed25519 の `did:key` 解決 |
| 実 Veramo | Node.js | 固定依存の Veramo による `kid` 付き JWT-VC の発行 |
| 結果と構造 | Node.js | VC 発行・検証マトリクスの結果、レポート生成 |
| 障害処理と厳格モード | Node.js | ピアの異常応答、ポート解決、DID 解決、非互換、skip 許可リスト、終了コード |

回帰テストに Docker は不要。実ピアの結果は、下記の Docker マトリクスで別に取得する。

## 2. 実ピアとレポート

Docker Compose v2 を使う。SDK の投影と、そのソースから作られた検証済み tarball および receipt が揃っていることが前提。`SDK_CI_WORKSPACE`、`SDK_CI_REVISION`、`SDK_CI_PROJECTION`、`GITHUB_SHA` は、同じソースを指す値を使う。`finalize` には `SDK_CI_ARTIFACT_DIR` も必要。コマンドの bundle と context は新規ディレクトリの絶対パスを指定する。

```sh
node "$SDK_CI_WORKSPACE/scripts/ci/interop/live.mjs" finalize "$interop_bundle"
node "$SDK_CI_WORKSPACE/scripts/ci/interop/live.mjs" materialize "$interop_bundle" "$interop_context"
```

受領済みの bundle を使う場合は `materialize` から実行できる。consumer と Docker は、同じ tarball を使う。Docker の context は同梱ハーネス、検証スクリプト、tarball、receipt、consumer manifest で構成される。

以下は生成した context のルートから Bash で実行する。`COMPOSE_PROJECT_NAME` は run ごとに一意の値を使用し、同じ run の起動、ポート照会、ドライバ、終了処理で揃える。

```sh
cd "$interop_context"
export COMPOSE_PROJECT_NAME="interop-$(date +%s)-$$"
set -euo pipefail
compose=(docker compose -f test/interop/docker-compose.yml)
trap '"${compose[@]}" down -v --remove-orphans' EXIT
"${compose[@]}" up -d --build
"${compose[@]}" build waltid-driver
ready=0
for attempt in $(seq 1 60); do
  if "${compose[@]}" ps -a --format json | node test/interop/wait-peers-healthy.mjs; then
    ready=1
    break
  fi
  sleep 5
done
test "$ready" -eq 1
```

ランナーは `docker compose port` で、run ごとに割り当てられた localhost のポートを引く。ポートを解決できなければ該当するペアは `fail` になる。準備後、各マトリクスの結果 JSON を取得する。以下では `set -e` を解除し、失敗時の終了コードと結果を両方残す。`pipefail` は維持する。

```sh
set +e
node test/interop/run-peer-matrix.mjs | tee matrix.json
vc_status=$?
node test/interop/run-did-resolution-matrix.mjs | tee did-resolution.json
did_status=$?
"${compose[@]}" --progress quiet run --rm --no-deps -T \
  -e WALTID_ISSUER_ADMIN_BASE_URL=http://waltid-issuer:7002 \
  -e WALTID_VERIFIER_ADMIN_BASE_URL=http://waltid-verifier:7003 \
  waltid-driver bun --preload ./scripts/packed-consumer/preload-bun.mjs \
  test/interop/run-waltid-sdjwt.mjs | tee waltid-sdjwt.json
sdjwt_status=$?
set -e
node test/interop/generate-report.mjs matrix.json
node test/interop/generate-report.mjs did-resolution.json did-resolution
node test/interop/generate-report.mjs waltid-sdjwt.json waltid-sdjwt
printf 'VC %s / DID %s / SD-JWT %s\n' "$vc_status" "$did_status" "$sdjwt_status"
```

`generate-report.mjs` は `test/interop/reports/<prefix>-<date>.md` に書き出す。各ランナーに別の prefix を使うと同日の結果を保持できる。新版候補の監視で結果 JSON が空、欠落、または壊れている場合は、`--fallback-pairs=<pair>[,<pair>…]` を指定して対象ペアの `fail` を合成し、同じ JSON とレポートに記録できる。

walt.id の Offer や Present に使う自己参照 URL は、Compose ネットワーク上の `issuer.waltid.interop.example:8097` と `verifier.waltid.interop.example:8098`。テスト CA が署名したサーバー証明書の SAN、Compose の alias、プロキシの `server_name` をこの FQDN に揃える。[TLS fixture](waltid/tls/README.md) を参照。管理 API の URL は `docker compose run -e` でコンテナへ渡す。ホスト検査で全ペアが `skipped` になれば両方が `fail` になる。

## 3. VC 発行・検証

基本の14ペアは、vericerts と veramo の JWT-VC アダプタ、didkit と sphereon のネイティブ VC-API で構成される。JWT-VC アダプタの入口は `POST /vc/issue` と `POST /vc/verify`。ネイティブ VC-API は `POST /credentials/issue` と `POST /credentials/verify` を使う。walt.id の2ペアは別途 Offer → Receive → Present を実駆動する。

`knownIncompatible` は `{ pair, reasonIncludes, note }` を登録する。`pair` は `interop:<issuer>:<verifier>` 形式の公開互換ケース ID。理由が合う `fail` だけを `known-incompatible` として記録する。登録済みペアが通れば `unexpected-pass` の `fail` になる。異なる理由の失敗も `fail` のまま残す。呼び出し側が従来形式の `issue` を明示する場合は正の整数が必要で、理由欄に `#番号` を使う。公開設定では `[pair]` と元の理由を残す。

didkit または sphereon の LD-Proof を JWT-VC アダプタへ送る4ペアは、実際に送信して HTTP 400 の `jwt is required (string)` を照合する。これはアダプタの入力形式検査を確認する。vericerts と veramo が didkit に送る JWT は JWS ヘッダに発行者の `kid` を載せる。didkit の JWT 検証時の pass は、そのヘッダで解決した鍵による署名検証を表す。

EBSI の疎通確認には、Compose とランナーの起動前に `EBSI_SANDBOX_BASE_URL=https://api-pilot.ebsi.eu` を設定する。値はパスや末尾の `/` を省いたオリジンにする。
認証不要の `GET /did-registry/v5/identifiers` をプロキシ経由で呼び、2xx なら `interop:ebsi:smoke` が `pass` になる。

`--fail-on-skipped` を付けた VC マトリクスは、すべての `skipped` を終了コードに反映する。EBSI の `EBSI_SANDBOX_BASE_URL` が未設定の場合は `prerequisite-missing` が報告される。

## 4. DID 解決

公開契約は18セル。`did:key` と `did:jwk` の fixture では DID 自体から導ける公開鍵を、ピアが返した検証メソッドと突き合わせる。`did:ethr` は設定された EIP-1056 レジストリの全バージョンが解決できたときに pass する。既定の2バージョンはチェーン fixture が未整備のため、対応ピアでは `fixture-missing` を返す。didkit は `Accept: application/did+ld+json`、ほかのピアは既定の DID Resolution Result プロファイルを使う。

解決器の未提供、fixture の未整備、接続先の登録待ちは、対応する理由を付けて `skipped` として報告する。`--fail-on-skipped` では、`structuralSkips` に登録された13件のペアと理由の組み合わせだけを許可する。EBSI の二つの DID 解決セルは登録前に `prerequisite-missing` で厳格モードに失敗し、登録後に fixture が未整備なら `fixture-missing` の許可条件を満たす。

## 5. SD-JWT

`run-waltid-sdjwt.mjs` の発行側は issuer が告知した `vct` を Offer と Issuer Metadata から取得し、SDK で SD-JWT VC を受領・検証する。提示側は選択的開示を付けて verifier に送る。要求の `presentation_definition.constraints.fields[].path` は `$.vct` と `$.family_name` を含み、復元したクレームの JSONPath を verifier が評価する。提示側での非互換を検知する回帰テストは [waltid-sdjwt-requests.test.mjs](__tests__/sd-jwt/waltid-sdjwt-requests.test.mjs) にある。

SD-JWT の2ペアは `knownIncompatible` に登録せず、検証が拒否された結果を `fail` として報告する。通常はピン留めされた walt.id イメージを使う。新版候補は `WALTID_ISSUER_IMAGE`、`WALTID_VERIFIER_IMAGE` と `WALTID_SDJWT_PAIR_SUFFIX` を指定して、別 run として結果を記録できる。
