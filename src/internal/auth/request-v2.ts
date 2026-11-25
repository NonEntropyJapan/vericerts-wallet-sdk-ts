/**
 * DIF Presentation Request v2（`PresentationRequestV2`）の型と `transaction_data` 正規化。
 *
 * 本モジュールは Authorization Request の **v2 表現への写像** と、OID4VP `transaction_data`
 * パラメータ／JAR クレームの **構造検証** を担う:
 *
 * - `PresentationRequestV2` は提示要求のフィールドを snake_case で表す。
 * - `parseTransactionDataClaim` / `parseTransactionDataQueryParam`: `transaction_data` を
 *   生 base64url 文字列配列として検証する（`request.ts` から利用）。
 * - `toPresentationRequestV2`: パース済み `PresentationRequest` を `PresentationRequestV2` へ変換する。
 *
 * スコープ外: `request_uri` の HTTP 取得と JAR 署名検証、
 * `presentation_definition` / `dcql_query` の評価（`dcql.ts` / format-negotiation の責務）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` に Request 本文を含めない。
 * - 検証系は fail-closed。構造が仕様どおりでない `transaction_data` は握り潰さず 8030 で拒否する。
 */

import type { VpFormatRequirement } from '../credential/format-negotiation/types.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../prototype-safety/parse-json.js';
import type { DcqlQuery } from './dcql/dcql.js';
import type { PresentationRequest } from './request.js';

/**
 * OID4VP `transaction_data` の 1 要素。Authorization Request 上に現れる **生の base64url
 * エンコード済み JSON 文字列**そのもの。
 *
 * 意図的にデコードしない。`extractTransactionData`（`eudi/transaction-data`）は
 * `transaction_data_hashes` の計算対象としてこの生文字列を厳密にそのままハッシュするため、
 * 途中でデコード・再エンコードすると Verifier 側のハッシュと一致しなくなる。
 *
 * この別名により `PresentationRequestV2.transaction_data` は
 * `extractTransactionData(readonly string[] | undefined)` へそのまま渡せる。auth → eudi の
 * モジュール依存を持ち込まずに、型の上で接続を表現するのが本別名の役割である。
 *
 * `transaction_data` の各要素は
 * **生の base64url 文字列**として運ばれ、**デコード済み**の構造化表現は別の型
 * `TransactionDataEntry`（`eudi/transaction-data/types.ts`）が担う。仕様側が「デコード済みの
 * オブジェクト」を指して `TransactionData` と呼ぶため、同名にすると 1 つの公開名が 2 つの意味を
 * 持ってしまう。それを避けるためエンコード済みであることを名前に含めている。
 */
export type EncodedTransactionData = string;

/** `PresentationRequestV2.spec_version` の値。 */
export const PRESENTATION_REQUEST_V2_SPEC_VERSION =
  'https://identity.foundation/presentation-exchange/spec/v2.0.0/';

/**
 * DIF Presentation Request v2。
 *
 * パース済みの `PresentationRequest` に対応する snake_case のインターフェース。
 */
export interface PresentationRequestV2 {
  /** リクエスト識別子（`PresentationRequest.state` 由来）。 */
  readonly id: string;
  /** Presentation Exchange の仕様バージョン。`PRESENTATION_REQUEST_V2_SPEC_VERSION` を返す。 */
  readonly spec_version: string;
  /**
   * PEx v2 Presentation Definition の生 JSON。本 SDK は PEx v2 を未パースの不透明な JSON として
   * 扱う（`PresentationRequest.presentationDefinition` と同一の方針）。
   */
  readonly presentation_definition?: Readonly<Record<string, unknown>>;
  /** DCQL クエリ（`dcql_query` 指定時）。 */
  readonly dcql_query?: DcqlQuery;
  /** Verifier の `vp_formats` 要求。 */
  readonly vp_formats: VpFormatRequirement;
  /** リプレイ防止ナンス（`PresentationRequest.nonce` 由来）。 */
  readonly challenge: string;
  /** audience / client_id（`PresentationRequest.clientId` 由来）。 */
  readonly domain: string;
  /** JAR 参照形式の URL。 */
  readonly request_uri?: string;
  /** JAR（JWT Authorization Request）本体。 */
  readonly request?: string;
  /** EUDI / HAIP の Transaction Data（生 base64url 文字列配列）。 */
  readonly transaction_data?: readonly EncodedTransactionData[];
}

/** `transaction_data` の構造不正を 8030 として送出する（本文は載せない）。 */
function rejectTransactionData(reason: string): never {
  throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, { context: { reason } });
}

/**
 * JAR クレーム（または JSON パース済みの値）としての `transaction_data` を検証・正規化する。
 *
 * 未指定（`undefined`）は「Transaction Data 要求なし」として `undefined` を返す。指定された
 * 場合は非空文字列の非空配列であることを要求する。**明示的に置かれた空配列は不正**として
 * 拒否する（要求がないならパラメータ自体を省略するのが仕様上の表現であり、明示的に置かれた
 * 空配列は壊れた／途中で切り詰められた Request の兆候とみなす）。fail-closed。
 *
 * この非対称は意図的である。パース層である本関数は「明示的な空配列」を fail-closed で拒否する
 * 一方、`extractTransactionData`（`eudi/transaction-data`）は空配列を「Transaction Data 要求
 * なし」として受理し空配列を返す。層ごとに入力の由来が異なるため、判定を揃えていない。
 *
 * @param value JAR クレーム値、または url-decoded JSON をパースした値。
 * @returns 生 base64url 文字列配列（未指定なら `undefined`）。
 * @throws 配列でない / 空配列 / 要素が非文字列・空文字列のとき（VericertsError、code `8030`）。
 */
export function parseTransactionDataClaim(
  value: unknown,
): readonly EncodedTransactionData[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    return rejectTransactionData('transaction_data_not_array');
  }
  if (value.length === 0) {
    return rejectTransactionData('transaction_data_empty');
  }
  if (value.some((entry) => typeof entry !== 'string' || entry.length === 0)) {
    return rejectTransactionData('transaction_data_entry_invalid');
  }
  return value as readonly string[];
}

/**
 * URL クエリパラメータ `transaction_data`（url-decoded JSON 文字列）を検証・正規化する。
 *
 * パラメータが存在するときのみ呼ぶ想定のため、戻り値は常に非空配列（`undefined` を返さない）。
 * JSON 構文エラーは `transaction_data_not_array` として 8030 に正規化する。cause は
 * `request.ts` の `decodeJsonParam` と同じく握り潰し、Request 本文を漏らさない。
 *
 * @param raw url-decoded 済みの `transaction_data` クエリ値。
 * @returns 生 base64url 文字列配列。
 * @throws JSON 不正 / 配列でない / 空配列 / 要素が不正のとき（VericertsError、code `8030`）。
 */
export function parseTransactionDataQueryParam(raw: string): readonly EncodedTransactionData[] {
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(raw);
  } catch {
    // 本文を漏らさないため cause は握りつぶす。
    return rejectTransactionData('transaction_data_not_array');
  }
  const value = parseTransactionDataClaim(parsed);
  if (value === undefined) {
    // JSON.parse は undefined を返さないため到達しないが、型を非 undefined へ絞る。
    return rejectTransactionData('transaction_data_not_array');
  }
  return value;
}

/**
 * `client_metadata.vp_formats` を `VpFormatRequirement` として取り出す。
 *
 * プロトタイプを持たないオブジェクト（`Object.create(null)`）へコピーして返す。この表を引く鍵は
 * 候補 VC の format 識別子であり、表の中身は Verifier が自由に指定できる。通常のオブジェクト
 * リテラルのままだと `format: "constructor"` / `"toString"` 等が `Object.prototype` の
 * メンバにヒットし、Verifier が要求していないフォーマットに truthy な「制約」が返る。
 * `format-negotiation/types.ts` の `PRIVACY_TIER` / `formatConstraintOf` と同じ防御である。
 *
 * 入力側も `ownProperty` で own 限定に読む。`parseAuthorizationRequest` /
 * `parseJarRequest` 経由の `clientMetadata` は `parseJsonWithoutPrototype` 由来で
 * null プロトタイプだが、`toPresentationRequestV2` は公開 API であり、呼び出し側が
 * `clientMetadata` を通常のオブジェクトリテラルとして自前で組み立てて渡すこともできる。
 * その場合 `clientMetadata?.vp_formats` は `clientMetadata` 自身が `vp_formats` を持たなくても
 * `Object.prototype` の汚染値を鎖読みしてしまうため、own 限定の読み取りが唯一の防御線になる
 * （`parse-json.ts` の docstring）。
 *
 * `vp_formats` が非オブジェクト・`null`・配列・未指定のときは空の要求表を返す。
 */
function toVpFormats(clientMetadata: Readonly<Record<string, unknown>> | undefined) {
  const raw =
    clientMetadata === undefined ? undefined : ownProperty<unknown>(clientMetadata, 'vp_formats');
  const source = typeof raw === 'object' && raw !== null && !Array.isArray(raw) ? raw : {};
  return Object.assign(Object.create(null) as Record<string, never>, source) as VpFormatRequirement;
}

/**
 * パース済み `PresentationRequest` を `PresentationRequestV2` へ変換する。
 *
 * 写像:
 * - `id` ← `state`（リクエスト識別子）
 * - `spec_version` ← `PRESENTATION_REQUEST_V2_SPEC_VERSION`
 * - `challenge` ← `nonce` / `domain` ← `clientId`
 * - `presentation_definition` / `dcql_query` / `transaction_data` ← 対応するパース済みフィールド。
 *   未指定のものはキー自体を出さない（`undefined` を置かない）
 * - `vp_formats` ← `clientMetadata.vp_formats`。未指定・非オブジェクトなら空の要求表
 *
 * `request_uri` / `request` は `PresentationRequest` が保持しない（パース済みリクエストは
 * 参照解決後の姿である）ため、常に省略する。
 *
 * @param request `parseAuthorizationRequest` / `parseJarRequest` の戻り値。
 * @returns `PresentationRequestV2`。
 */
export function toPresentationRequestV2(request: PresentationRequest): PresentationRequestV2 {
  // 任意メンバは自身のプロパティに限って読む。`request.transactionData !== undefined` はプロトタイプ鎖を辿るため、
  // `Object.prototype.transactionData` 等が汚染された環境では Verifier が要求していない `transaction_data` /
  // `presentation_definition` / `vp_formats` が正規の要求に混ざり、利用者の同意対象が汚染値になる。
  const presentationDefinition = ownProperty<PresentationRequest['presentationDefinition']>(
    request,
    'presentationDefinition',
  );
  const dcqlQuery = ownProperty<DcqlQuery>(request, 'dcqlQuery');
  const transactionData = ownProperty<PresentationRequest['transactionData']>(
    request,
    'transactionData',
  );
  return {
    id: request.state,
    spec_version: PRESENTATION_REQUEST_V2_SPEC_VERSION,
    vp_formats: toVpFormats(
      ownProperty<PresentationRequest['clientMetadata']>(request, 'clientMetadata'),
    ),
    challenge: request.nonce,
    domain: request.clientId,
    ...(presentationDefinition !== undefined
      ? { presentation_definition: presentationDefinition }
      : {}),
    ...(dcqlQuery !== undefined ? { dcql_query: dcqlQuery } : {}),
    ...(transactionData !== undefined ? { transaction_data: transactionData } : {}),
  };
}
