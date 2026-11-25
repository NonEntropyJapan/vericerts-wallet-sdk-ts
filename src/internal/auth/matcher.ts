/**
 * 保持クレデンシャルを DCQL 評価対象（`QueryableCredential`）へ正規化し、マッチ VC を選定する。
 *
 * OID4VP の DCQL は format ごとにクレームの所在が異なる:
 * - `jwt_vc_json` / `jwt_vc_json-ld`（W3C JWT-VC）: クレームは `credentialSubject` 配下。`vct` は
 *   持たない。
 * - `dc+sd-jwt` / `vc+sd-jwt`（SD-JWT VC）: クレームは Issuer-signed JWT payload + 開示済み
 *   Disclosure のマージ。`vct` クレームを持つ。
 *
 * `jwt_vc_json` と `jwt_vc_json-ld` は同じ JWS Enveloping Proof で保護され、SDK の
 * `VerifiableCredential` 型が `@context` を無条件に必須とする以上、同じクレームを持つ VC の本文は
 * 両者で**バイト単位で区別できない**。したがって `toQueryableFromVc` は VC 本文から format を推定
 * せず、**呼び出し側が明示的に渡すラベル**として受け取る（`NegotiableCredential.format` /
 * `BackupSourceItem.format` と同じ、外部供給のタグという既存方針）。既定は従来どおり
 * `jwt_vc_json` で、既存の呼び出し側の挙動は変わらない。
 *
 * SD-JWT VC では Issuer-signed JWT の JWS ヘッダ `typ` と OID4VP の credential format 識別子が
 * 同一文字列である（`typ.ts` が SSOT）。発行の既定は `dc+sd-jwt`（draft-ietf-oauth-sd-jwt-vc /
 * HAIP 1.0）で、移行期間中は旧 `vc+sd-jwt` も受理する。したがって SD-JWT VC の format は固定値では
 * なく、保持クレデンシャルの `typ` から導出する（`typ` 欠落は旧 Issuer 由来とみなし `vc+sd-jwt`）。
 *
 * 本モジュールはこの差異を吸収し、`dcql.ts` の `evaluateDcql` が format 非依存で評価できる
 * 正規化済み構造へ変換する。さらに `selectMatchingCredentials` でクエリにマッチした
 * クレデンシャル候補を選定する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` にクレーム値や VC 本文を含めない。
 */

import { recoverClaims } from '../credential/sdjwt/claims.js';
import { parseSdJwt } from '../credential/sdjwt/sdjwt.js';
import {
  ACCEPTED_SD_JWT_VC_TYP_VALUES,
  assertAcceptedSdJwtVcTypIfPresent,
  SD_JWT_VC_TYP,
  SD_JWT_VC_TYP_LEGACY,
} from '../credential/sdjwt/typ.js';
import { decodeCompactJws } from '../credential/vc/jws.js';
import type { VerifiableCredential } from '../credential/vc/vc.js';
import { toFrozenSetView } from '../prototype-safety/frozen-set.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { createDcqlWorkBudget } from './dcql/budget.js';
import {
  type CredentialMatch,
  type DcqlQuery,
  evaluateDcql,
  findMatchingCredentialIndexes,
  type QueryableCredential,
} from './dcql/dcql.js';

/** JWT-VC（W3C）の DCQL format 識別子。 */
export const FORMAT_JWT_VC = 'jwt_vc_json';

/**
 * JSON-LD JWT-VC（W3C）の DCQL format 識別子。
 *
 * 保護機構は `jwt_vc_json` と同一（JWS Enveloping Proof）で、異なるのは
 * 「Verifier が JSON-LD 前提のクレデンシャルを要求している」というネゴシエーション上の意思表示
 * だけである。本モジュールの JSDoc の説明どおり、VC 本文からは推定できないため
 * `toQueryableFromVc` の引数として明示的に渡す。
 */
export const FORMAT_JWT_VC_JSON_LD = 'jwt_vc_json-ld';

/**
 * SD-JWT VC の DCQL format 識別子（既定）。JWS ヘッダの `typ` と同一文字列（`typ.ts` が SSOT）。
 */
export const FORMAT_SD_JWT_VC_DC = SD_JWT_VC_TYP;

/**
 * SD-JWT VC の旧 DCQL format 識別子。
 *
 * @deprecated Since v0.1.0（HAIP 1.0 移行に伴う経過措置）。移行期間の受理専用で、新規コードは
 *   `FORMAT_SD_JWT_VC_DC`（`dc+sd-jwt`）を使う。削除予定は v1.0.0（`@stable` 昇格時）。
 *   撤廃時期は CHANGELOG の `Deprecated` 欄で告知する。
 */
export const FORMAT_SD_JWT_VC = SD_JWT_VC_TYP_LEGACY;

/**
 * SD-JWT VC として扱う format 識別子の集合（新 `dc+sd-jwt` / 旧 `vc+sd-jwt`）。
 *
 * メンバは `typ.ts` の正準リスト `ACCEPTED_SD_JWT_VC_TYP_VALUES` から組み立てる。別モジュールの
 * 公開ビュー（`ACCEPTED_SD_JWT_VC_TYPS`）から派生させると、非権威な公開値を権威扱いする層構造の
 * 反転になるためである。結果として `ACCEPTED_SD_JWT_VC_TYPS` とは別インスタンスの変更不能ビューに
 * なり、片方の公開名を経由した汚染がもう片方へ波及することもない。
 * 「変更不能」は変更操作が経路を問わず `TypeError` になることを指し、`Object.isFrozen()` が
 * `true` になることは意味しない（`frozen-set.ts` の注記を参照）。
 */
export const SD_JWT_VC_FORMATS: ReadonlySet<string> = toFrozenSetView(
  ACCEPTED_SD_JWT_VC_TYP_VALUES,
);

/**
 * W3C VerifiableCredential を DCQL 評価用に正規化する。
 *
 * クレームは VC オブジェクトをそのまま辿れる構造とする（`credentialSubject` も含む）。
 * これにより DCQL の `path: ["credentialSubject", "name"]` がそのまま解決できる。
 *
 * `format` は VC 本文から推定せず呼び出し側が渡す（本モジュールの JSDoc を参照）。DCQL の format
 * 照合は完全一致なので、`jwt_vc_json-ld` を要求する Verifier に応じるには、そのラベルを付けた
 * 正規化クレデンシャルを渡す必要がある。既定は `jwt_vc_json` で、引数を省略した既存の呼び出し側の
 * 挙動は変わらない。
 *
 * @param vc W3C VerifiableCredential。
 * @param format この VC を提示する際の DCQL format ラベル（既定 `jwt_vc_json`）。
 * @returns 指定 format の正規化クレデンシャル。
 */
export function toQueryableFromVc(
  vc: VerifiableCredential,
  format: typeof FORMAT_JWT_VC | typeof FORMAT_JWT_VC_JSON_LD = FORMAT_JWT_VC,
): QueryableCredential {
  return {
    id: ownProperty<string>(vc, 'id') ?? '',
    format,
    claims: vc as unknown as Readonly<Record<string, unknown>>,
  };
}

/**
 * SD-JWT VC 文字列を DCQL 評価用に正規化する。
 *
 * Issuer-signed JWT payload の平文クレームへ、同梱 Disclosure を RFC 9901 §7.1 のとおり**再帰的に**
 * 適用してクレーム object を構成する（`verifySdJwt` と同じ `recoverClaims`。署名検証は行わない）。
 * 入れ子のオブジェクトプロパティ Disclosure は入れ子のまま載り（`path: ["address", "country"]` で
 * 解決でき、最上位の同名クレームを上書きしない）、配列要素 Disclosure（2 要素）は配列要素として載る。
 * `vct` は payload から取り出す。`id` は payload の `jti` を用いる（なければ空文字列）。`_sd` /
 * `_sd_alg` 等の SD-JWT 内部クレームは除外する。
 *
 * format は Issuer-signed JWT の JWS ヘッダ `typ` から導出する（SD-JWT VC では `typ` と format
 * 識別子が同一文字列）。受理対象外の `typ` は `3002` で拒否する（`verifySdJwt` と同じ判定）。
 * `typ` 欠落は受理し、format には**旧識別子 `vc+sd-jwt`** を用いる。`typ` は署名対象なので剥奪・
 * 改変は署名検証失敗を伴い欠落拒否は防御を足さない一方、`typ` を付けない旧 Issuer 発行の保存済み
 * クレデンシャルを選択対象から落としてしまうためである。欠落時に旧識別子を採るのは、署名された
 * 識別子を持たないクレデンシャル＝`dc+sd-jwt` へ改称される前の旧 Issuer 由来であり、意味的に
 * `vc+sd-jwt` 相当だからである。DCQL / format ネゴシエーションの format 照合は完全一致なので、
 * ここで既定 `dc+sd-jwt` を割り当てると移行期間に大多数を占める「`vc+sd-jwt` を要求する Verifier」
 * のクエリに一切マッチせず、「欠落を受理する＝旧 Issuer 発行の保存済みクレデンシャルを壊さない」
 * という設計意図が達成できない。
 *
 * KB-JWT の有無は評価に影響しないため無視する。署名検証は本モジュールのスコープ外。
 *
 * 失敗面の契約: 本関数は保持クレデンシャルを 1 件ずつ正規化する公開 API であり、呼び出し側は
 * 通常クレデンシャル一覧を map する。形式不正（`parseSdJwt` / `decodeCompactJws` 由来）、受理
 * 対象外 `typ`、Disclosure の復元失敗（参照されない Disclosure・同名衝突・digest 重複・未対応の
 * `_sd_alg`。`verifySdJwt` と同じ判定で、いずれも `3010`）では throw するため、1 件の非準拠クレデンシャルで選択処理全体が中断しうる。
 * 呼び出し側は 1 件ずつ try/catch して隔離し、失敗した候補をスキップすることを想定する。
 *
 * @param sdJwt SD-JWT VC 文字列（`<issuerJwt>~<d1>~...~`）。
 * @returns format=`dc+sd-jwt` / `vc+sd-jwt`（`typ` 由来。欠落時は旧識別子 `vc+sd-jwt`）の正規化クレデンシャル。
 * @throws SD-JWT 形式不正時（parseSdJwt / decodeCompactJws 由来の VericertsError）。
 * @throws `typ` が存在し SD-JWT VC として受理対象外の場合（VericertsError、code `3002`）。
 * @throws Disclosure を payload へ復元できない場合（VericertsError、code `3010`）。
 */
export function toQueryableFromSdJwt(sdJwt: string): QueryableCredential {
  const { issuerJwt, disclosures } = parseSdJwt(sdJwt);
  const { header, payload } = decodeCompactJws(issuerJwt);
  // typ 混同（`kb+jwt` / `JWT` 等）を DCQL 評価へ持ち込まないよう入口で塞ぐ（欠落は受理する）。
  assertAcceptedSdJwtVcTypIfPresent(header.typ);
  // assert 済みなので SD-JWT VC の format 識別子として確定している。
  // 欠落時は旧識別子 `vc+sd-jwt` に倒す: 署名された `typ` を持たない＝改称前の旧 Issuer 由来で
  // あり、format 照合は完全一致なので旧 Verifier の `vc+sd-jwt` 要求に被覆させる必要がある
  // （ここで `dc+sd-jwt` を割り当てると移行期間の旧要求に一切マッチしない）。
  const format = header.typ ?? SD_JWT_VC_TYP_LEGACY;

  // 検証（`verifySdJwt`）と同じ再帰復元を、署名検証なしで行う。入れ子の Disclosure は入れ子のまま
  // （最上位の同名平文クレームを上書きしない）、配列要素 Disclosure は配列要素として載り、`_sd` /
  // `_sd_alg` 等の SD-JWT 内部クレームは除かれる。
  const claims = recoverClaims(payload, { issuerJwt, disclosures });

  const vct = typeof payload.vct === 'string' ? payload.vct : undefined;
  const id = typeof payload.jti === 'string' ? payload.jti : '';

  return {
    id,
    format,
    ...(vct !== undefined ? { vct } : {}),
    claims,
  };
}

/**
 * DCQL クエリにマッチする保持クレデンシャルを選定する。
 *
 * 正規化済みクレデンシャル集合に対し `evaluateDcql` を実行し、マッチ結果と、マッチした
 * クレデンシャルの index 一覧（重複排除済み）を返す。呼び出し側はこの index を使って元の
 * クレデンシャル（VC 文字列 / オブジェクト）を VP Token 構築へ渡せる。
 *
 * @param query パース済み DCQL クエリ。
 * @param credentials 正規化済み保持クレデンシャル（呼び出し側の元クレデンシャルと同順）。
 * @returns マッチ結果と、マッチしたクレデンシャルの index 一覧。
 * @throws 要求 format が SDK 未対応の場合（VericertsError、code `8050`）。
 * @throws 仕事量予算を超える場合（VericertsError、code `8030`、`context.reason: 'dcql_work_budget_exceeded'`）。
 */
export function selectMatchingCredentials(
  query: DcqlQuery,
  credentials: readonly QueryableCredential[],
): { matches: CredentialMatch[]; matchedIndexes: number[] } {
  // 2 回の評価（一致の列挙と index の確定）は同じ Presentation Request の処理なので 1 つの予算を共有する。
  const budget = createDcqlWorkBudget();
  // 要件ごとの一致結果を CredentialMatch の配列として返す。
  const matches = evaluateDcql(query, credentials, budget);

  // 選定（matchedIndexes）はクレデンシャル index 単位で判定する。`id` は空・重複し得るため
  // id 経由の逆引きは使わず、各クレデンシャルが単独でいずれかの要件を満たすかを一致を確保せずに確定する
  // （クレデンシャルごとに `evaluateDcql` を呼び直すと、要件の再検査と一致の確保が H 回繰り返される）。
  const matchedIndexes = findMatchingCredentialIndexes(query, credentials, budget);

  return { matches, matchedIndexes };
}
