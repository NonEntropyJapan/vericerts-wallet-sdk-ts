# SDK テスト素材

SDK の公開 API を実パッケージで検証するための、合成データと開発用ツールです。
素材形式の版は `1.0.0`。`manifest.json` の `generatedFrom` は生成に使用した SDK の
パッケージ名と版を示し、各ファイルの SHA-256・byte 数・ケース数を記録します。
SDK の通常の npm パッケージとは別に受け渡します。

## 生成と受け渡し

SDK のルートで、リポジトリが指定する Bun 1.4.4 を使用します。

```sh
bun install --frozen-lockfile
bun run export:test-support --out /tmp/sdk-test-support-v1
```

出力先には新規ディレクトリを指定します。生成時には SDK の実装・既存のテスト用 builder を
使います。受取側には出力ディレクトリだけを渡せば、SDK のソースを参照せずに利用できます。
生成に使った commit SHA と、受け渡す `manifest.json` 自体の SHA-256 も別途記録してください。
manifest 内の hash はファイルの一致を検査するもので、配布元の認証を代替しません。

## 素材

| パス                        | 内容                                                                |
| --------------------------- | ------------------------------------------------------------------- |
| `vectors/did.json`          | 固定 seed・時刻から生成した peer/JWT/IPID/webvh の DID と取得応答   |
| `vectors/credential.json`   | 実署名の VC/VP と検証入力                                           |
| `vectors/status-list.json`  | SDK が生成する合成 Bitstring Status List ケース                     |
| `vectors/conformance.json`  | SDK 正本の言語共通コンフォーマンスベクタ                            |
| `tools/did-fixtures.mjs`    | ホスト名・版数などを指定して署名済み DID fixture を作る開発用ツール |
| `tools/inherited-reads.mjs` | TypeScript の型情報を使う独立した継承読み scanner                   |
| `consumer.mjs`              | 公開 npm API だけを使う代表検証                                     |
| `tools-consumer.mjs`        | 独立した生成器・scanner の Node.js 検証                             |
| `verify.mjs`                | manifest とファイルの整合性検査                                     |
| `LICENSE`                   | 本素材に適用する Apache-2.0 ライセンス                              |
| `THIRD_PARTY_NOTICES`       | 開発用 bundle に含まれる第三者ソフトウェアのライセンス              |

鍵は公開を前提にしたテスト専用の固定 seed から生成しています。実在の利用者データ、
production の鍵、アクセス用の認証情報は使用しません。固定時刻は検証オプションへ渡し、
実行日の変化で期限の判定が変わらないようにします。

合成 status-list ケースは他の実装で生成したベクタの複製ではありません。
既存の回帰スイートを置き換える場合は、件数だけでなく個々の正常・異常ケースの対応を確認してください。

## パッケージだけで検証する

配布されたディレクトリを SDK checkout の外に置き、空の consumer へ検証対象の SDK `.tgz` と
TypeScript をインストールして使用します。Node.js 20 以上を使用します。

```sh
consumer_dir=$(mktemp -d)
cp -R /path/to/received-sdk-test-support "$consumer_dir/materials"
cd "$consumer_dir"
npm init -y
npm install --omit=peer --ignore-scripts /path/to/vericerts-wallet-sdk-0.1.0.tgz typescript@5.9.3
node materials/verify.mjs
node materials/consumer.mjs
node materials/tools-consumer.mjs
```

`consumer.mjs` は実際の署名検証・DID 解決を通します。通信が必要なケースでは生成した応答だけを
返し、検証 API 自体は差し替えません。署名改ざん、発行者の不一致、VP の audience・nonce 不一致、
DID のホスト不一致などの拒否も確認します。audience の検査は VP に束縛された検証先の検査であり、
利用アプリケーションの送信元権限チェックは別に必要です。

素材のディレクトリには manifest に登録したファイルだけを置きます。インストール先はその親とし、
`package.json` や `node_modules` を素材の中へ追加しないでください。

## 開発用ツールの利用例

次のコードは素材ディレクトリの親に置く ESM ファイルの例です。

```js
import ts from 'typescript';
import { hostedWebVh, localDids } from './materials/tools/did-fixtures.mjs';
import { findInheritedReads } from './materials/tools/inherited-reads.mjs';

const local = localDids(53);
const hosted = await hostedWebVh({
  host: 'witness.example', versions: 8, seed: 53,
  time: '2026-01-01T00:00:00Z', witness: true,
});
// hosted.did と hosted.bodies を使い、外部通信だけをテストの応答へ置換する。
// local は peer/JWT/IPID の DID と本文を持つ。
const findings = findInheritedReads('/path/to/consumer-project', ts);
console.log(local.peer, hosted.did, findings);
```

生成器の `seed` はテスト専用の整数（0〜254）、`versions` は1〜100です。
scanner は利用者側でインストールした TypeScript API を注入して使います。
allowlist と走査対象は利用者が所有します。SDK runtime の公開 entry にテスト用 hook や
scanner を追加することはありません。
