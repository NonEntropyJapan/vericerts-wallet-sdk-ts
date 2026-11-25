/**
 * CJS ビルド専用の内部エントリ（**公開サブパスではない**。`package.json` の `exports` に載せない）。
 *
 * `bun build` の `--splitting` は `--format cjs` で機能しない（エントリが 0 バイトになる）。そのため
 * メインバレル・`./experimental`・用途別 entry を別々にバンドルすると、**内部モジュールの実体が 2 つ**できる。
 * その状態で両方を `require` した利用者は、サブパス由来のエラーが
 * `main.VericertsError` の `instanceof` に一致せず、`catch (e) { if (e instanceof VericertsError) }`
 * が**無警告で壊れる**（SDK のエラーハンドリング契約そのものが破れる）。
 *
 * そこで CJS は本ファイルを唯一のバンドルエントリとし、全サーフェスを 1 バンドルに束ねる。
 * `dist/index.cjs` と `dist/exports/<name>.cjs` は、そこから該当サーフェスを取り出すだけの
 * 薄い picker として `scripts/emit-cjs-pickers.mjs` が生成する。これで内部実体は 1 つに保たれ、
 * エラークラスの同一性がメインと各サブパスをまたいで成立する。`./otel` は optional peer
 * （`@opentelemetry/*`）を external にするため、ここへは含めず独立した CJS バンドルにする
 * （内部モジュールの実体を共有する必要が無いことは `otel-adapter.ts` が型 import のみである
 * ことによる）。
 *
 * ESM 側は `bun build --splitting` が共有チャンクを切り出すため、この工夫は不要である。
 *
 * @internal
 */

import * as aaNs from './exports/aa.js';
import * as assetNs from './exports/asset.js';
import * as commonNs from './exports/common.js';
import * as credentialNs from './exports/credential.js';
import * as eudiNs from './exports/eudi.js';
import * as experimentalEudiNs from './exports/experimental/eudi.js';
import * as experimentalOid4vciNs from './exports/experimental/oid4vci.js';
import * as experimentalNs from './exports/experimental.js';
import * as gdprNs from './exports/gdpr.js';
import * as identityNs from './exports/identity.js';
import * as keymanagerNs from './exports/keymanager.js';
import * as oid4vciNs from './exports/oid4vci.js';
import * as oid4vpNs from './exports/oid4vp.js';
import * as personaNs from './exports/persona.js';
import * as trustNs from './exports/trust.js';
import * as mainNs from './index.js';

/**
 * 名前空間バインディングをそのまま re-export すると、`bun build --format cjs` が
 * export マップだけを出して実体を出力しない（`main is not defined` になる）。
 * プレーンオブジェクトへ展開して実体の出力を強制する。
 */
export const main = { ...mainNs };
export const experimental = { ...experimentalNs };
export const experimentalEudi = { ...experimentalEudiNs };
export const experimentalOid4vci = { ...experimentalOid4vciNs };
export const aa = { ...aaNs };
export const asset = { ...assetNs };
export const common = { ...commonNs };
export const credential = { ...credentialNs };
export const eudi = { ...eudiNs };
export const gdpr = { ...gdprNs };
export const identity = { ...identityNs };
export const keymanager = { ...keymanagerNs };
export const oid4vci = { ...oid4vciNs };
export const oid4vp = { ...oid4vpNs };
export const persona = { ...personaNs };
export const trust = { ...trustNs };
