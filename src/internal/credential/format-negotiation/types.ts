/**
 * VC フォーマットネゴシエーションの型定義・定数。
 *
 * Verifier の `vp_formats` 要求に対し、Wallet が保持する複数フォーマットの候補 VC から最適な
 * ものを選択するためのデータモデルを提供する。本ファイルは型と定数のみを持ち、選択ロジックは
 * `select.ts` / `capability.ts` / `multi-format.ts` に分割する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` にクレーム値や VC 本文を含めない。
 */

import { toFrozenSetView } from '../../prototype-safety/frozen-set.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { SD_JWT_VC_TYP, SD_JWT_VC_TYP_LEGACY } from '../sdjwt/typ.js';

/**
 * 対応する VC フォーマット識別子。
 *
 * `(string & {})` により未知の識別子（アドオン提供の `mso_mdoc` 等）も型として許容しつつ、
 * 既知の識別子で補完が効くようにする。
 */
export type VCFormat =
  | 'jwt_vc_json'
  | 'jwt_vc_json-ld'
  | 'ldp_vc'
  | 'vc+sd-jwt'
  | 'dc+sd-jwt'
  | 'vc+cose'
  | 'mso_mdoc'
  | 'bbs+'
  | (string & {});

/** 単一フォーマットに対する制約。 */
export interface FormatConstraint {
  /** JWT / SD-JWT 用の受理署名アルゴリズム（例: `["ES256", "ES384"]`）。先頭が最優先。 */
  readonly alg?: readonly string[];
  /** Data Integrity 用の proof_type。 */
  readonly proof_type?: readonly string[];
  /** Data Integrity v2 用の cryptosuite。 */
  readonly cryptosuite?: readonly string[];
  /** BBS+ 用（実験的）。 */
  readonly '-zkp_suite'?: readonly string[];
}

/**
 * OID4VP・PEx v2 における Verifier の `vp_formats` 要求。
 *
 * キーはフォーマット識別子。オブジェクトの挿入順が優先度（先頭が最優先）を表す。
 */
export type VpFormatRequirement = Readonly<Record<string, FormatConstraint>>;

/**
 * 要求表から当該フォーマットの制約を取り出す（自身のプロパティのみ）。
 *
 * `requested` は Verifier のリクエスト由来の通常のオブジェクトであり `Object.prototype` を持つ。
 * `requested[format]` や `format in requested` で引くと、候補 VC の `format` が `constructor` /
 * `toString` / `valueOf` / `hasOwnProperty` などのときに `Object.prototype` のメンバがヒットし、
 * Verifier が要求していないフォーマットに対して truthy な「制約」が返る。しかもその値は `alg` を
 * 持たないため 署名スイート降格拒否まで素通りし、要求外の VC が適合と判定される。
 * `Object.hasOwn` で自身のプロパティに限定することで、この経路を構造的に断つ。
 *
 * @param requested Verifier の `vp_formats` 要求。
 * @param format 候補 VC のフォーマット識別子（外部入力）。
 * @returns 要求表が自身のプロパティとして持つ制約。持たない場合は `undefined`。
 */
export function formatConstraintOf(
  requested: VpFormatRequirement,
  format: string,
): FormatConstraint | undefined {
  return Object.hasOwn(requested, format) ? requested[format] : undefined;
}

/**
 * 候補 VC の `cnf`（Confirmation Claim、鍵バインディング先）情報のうち、選択ロジックが必要とする
 * 部分のみを持つ型。
 *
 * 公開鍵材料（JWK）そのものは選択ロジックの対象外なので保持しない（KB-JWT の生成・検証は
 * `sdjwt/key-binding.ts` 等の責務）。ここでは鍵の識別子のみを扱う。
 */
export interface CredentialKeyBinding {
  /** cnf が指す鍵の ID（`cnf.kid`、または `cnf.jwk` から導出した鍵 ID）。判定不能なら `undefined`。 */
  readonly kid?: string;
}

/**
 * ネゴシエーション対象として正規化された候補 VC。
 *
 * SDK は VC を W3C `VerifiableCredential` オブジェクト（`jwt_vc_json`）または SD-JWT VC 文字列
 * （既定 `dc+sd-jwt`。移行期間中は旧 `vc+sd-jwt` も扱う）として保持する。両者の差異を吸収し、
 * 選択に必要な属性だけを持つ形へ正規化する。
 */
export interface NegotiableCredential {
  /** 候補 VC の識別子（VC の `id` / `jti` 等）。選択結果・ログで参照する。 */
  readonly id: string;
  /** この VC のフォーマット。 */
  readonly format: VCFormat;
  /** この VC の署名アルゴリズム（JWS `alg` 等。判定不能な場合は `undefined`）。 */
  readonly alg?: string;
  /**
   * Data Integrity VC（`ldp_vc`）の `proof.type`。要求側の `proof_type` と照合する。
   * Data Integrity 以外のフォーマットでは `undefined`。
   */
  readonly proofType?: string;
  /**
   * Data Integrity v2 の `proof.cryptosuite`。要求側の `cryptosuite` と照合する。
   * 対象外のフォーマットでは `undefined`。
   */
  readonly cryptosuite?: string;
  /**
   * BBS+（`bbs+`）の zkp suite。要求側の `-zkp_suite` と照合する（実験的）。
   * 対象外のフォーマットでは `undefined`。
   */
  readonly zkpSuite?: string;
  /** SD-JWT VC の `vct`（JWT-VC では `undefined`）。 */
  readonly vct?: string;
  /** 発行日時（ISO 8601）。同点タイブレークに使う。 */
  readonly issuanceDate?: string;
  /** 有効期限（ISO 8601）。長期有効ほど高スコア。 */
  readonly expirationDate?: string;
  /**
   * この VC が選択的開示（Selective Disclosure）に対応するか。
   *
   * `false` を明示した場合のみプライバシー優先度を Full Disclosure 相当（30）へ降格する
   * （`PRIVACY_TIER` の既定値が 30 を超える場合。`select.ts` の `privacyContribution` を参照）。
   * 省略時は降格せずフォーマット既定値をそのまま用い、識別子からの推定は行わない。
   */
  readonly supportsSelectiveDisclosure?: boolean;
  /**
   * この VC がユーザーによってお気に入り指定されているか。
   *
   * 他の優先条件が同じならお気に入りを優先し、次に直近の利用日時、発行日時を比較する。
   * 省略時は指定なし（`false` 相当）として扱う。
   */
  readonly isFavorite?: boolean;
  /**
   * この VC が直近に利用（提示）された日時（ISO 8601）。
   *
   * `isFavorite` が同値の候補間で、より新しい `lastUsedAt` を持つ候補を優先する。省略時は
   * 利用履歴なしとして扱い、この項目では他候補に劣後する。
   */
  readonly lastUsedAt?: string;
  /**
   * この VC の `cnf`（Confirmation Claim、鍵バインディング先）の情報。
   * KB-JWT 提示に用いる鍵の識別子のみを保持し、公開鍵材料そのものは選択ロジックの対象外とする
   * （鍵の検証・署名は本モジュールの責務ではない）。省略時は鍵バインディングなし、または判定不能。
   */
  readonly cnf?: CredentialKeyBinding;
  /**
   * `cnf.kid` に対応する秘密鍵をウォレットが保持しているか。
   *
   * ウォレットが `cnf` にバインドされた秘密鍵を保持していない VC を選ぶと、後段の Key Binding
   * 提示（KB-JWT 生成）に失敗しうる。判定は呼び出し側が既存の鍵インベントリ（`KeyManager` 等）を
   * 参照して解決し、解決済みの真偽値のみをここに渡す（本モジュールは鍵の探索・生成・検証を行わない）。
   * 省略時は判定不能（cnf なし、または未判定）として中立に扱う（`compare.ts` を参照）。
   */
  readonly hasBoundKey?: boolean;
  /**
   * 元クレデンシャルへの参照（W3C VC オブジェクト / SD-JWT VC 文字列など）。
   * 選択後に VP 構築へ渡すために保持する。ネゴシエーション自体は参照しない。
   */
  readonly source?: unknown;
}

/** `selectBestVC` の選択結果。 */
export interface VCSelection {
  /** この選択が対応する DCQL / descriptor 要件の ID（複数 descriptor 時に区別する）。 */
  readonly descriptorId?: string;
  /** 選択された候補 VC。 */
  readonly chosen: NegotiableCredential;
  /** 次点候補（最大 2 件）。UI での代替提示に使う。 */
  readonly alternatives: readonly NegotiableCredential[];
}

/** `canFulfillFormats` の被覆結果。 */
export interface FormatCoverage {
  /** 要求フォーマットをすべて満たせるか。 */
  readonly fullyCovered: boolean;
  /** 保持 VC で満たせる要求フォーマット識別子。 */
  readonly matchedFormats: readonly string[];
  /** 保持 VC で満たせない要求フォーマット識別子。 */
  readonly unmatchedFormats: readonly string[];
}

/** `evaluateFormatCapability` の結果。 */
export interface FormatCapabilityResult {
  /** 全 descriptor を満たせるか。 */
  readonly fullyCovered: boolean;
  /** descriptor 毎の選択結果。 */
  readonly selections: readonly VCSelection[];
  /** 満たせなかった descriptor の ID。 */
  readonly unmatchedDescriptors: readonly string[];
  /** ダウングレード拒否・部分被覆などの警告メッセージ（クレーム値を含めない）。 */
  readonly warnings: readonly string[];
}

/**
 * フォーマット別プライバシースコア。
 * Unlinkable > Selective Disclosure > Full Disclosure の順。未知フォーマットは 0。
 *
 * プロトタイプを持たないオブジェクト（`Object.create(null)`）として構築する。引く鍵は Verifier の
 * `vp_formats` や候補 VC 由来＝攻撃者が自由に指定できる値であり、通常のオブジェクトリテラルだと
 * `format: "constructor"` / `"toString"` 等が `Object.prototype` のプロパティにヒットする。
 * ヒットするのは関数などの非 undefined 値なので `privacyScore` の `?? 0`（未知フォーマットは 0）を
 * すり抜け、合成スコアが `関数 * 100` = `NaN` になる。`NaN` は比較関数を非全順序にして候補の
 * ソート結果を不定にし、要求を満たさない VC が正当な VC に勝ちうる。プロトタイプを断つことで、
 * 未知フォーマットが構造的に「該当なし＝0」へ落ちる。
 *
 * なお本定数は SDK の公開バレル（`src/exports/`）には出ておらず、内部バレル止まりである。
 * 防いでいるのは「利用者が公開値を書き換えること」ではなく、外部入力の鍵が
 * `Object.prototype` に当たることそのものである。
 */
export const PRIVACY_TIER: Readonly<Record<string, number>> = Object.freeze(
  Object.assign(Object.create(null) as Record<string, number>, {
    'bbs+': 100,
    [SD_JWT_VC_TYP]: 80,
    [SD_JWT_VC_TYP_LEGACY]: 80,
    mso_mdoc: 70,
    ldp_vc: 50,
    'vc+cose': 40,
    jwt_vc_json: 30,
    'jwt_vc_json-ld': 30,
  } satisfies Record<string, number>),
);

/**
 * 選択的開示に対応するフォーマット集合。
 *
 * 可変な `Set` を `ReadonlySet` 型で隠しても実体は共有レジストリのままなので、変更操作が経路を
 * 問わず `TypeError` になるビューとして持つ（`toFrozenSetView` の注記を参照。`Object.isFrozen()`
 * は `false` を返す）。本定数は公開バレル（`src/exports/`）には出ておらず内部バレル止まりなので、
 * 想定するのは SDK 外の利用者による書き換えではなく、内部コードでの取り違えに対する多層防御である。
 */
export const SELECTIVE_DISCLOSURE_FORMATS: ReadonlySet<string> = toFrozenSetView([
  SD_JWT_VC_TYP,
  SD_JWT_VC_TYP_LEGACY,
  'mso_mdoc',
  'bbs+',
]);

/**
 * PEx `constraints.limit_disclosure` の値。
 *
 * `"required"` は選択的開示対応 VC のみ許容（非対応なら VP 不送信）。
 * `"preferred"` は許容するが優先しない（`select.ts` の `privacyContribution` によるプライバシー
 * 優先度スコアリングが既にこれを担うため、本モジュールでは追加のゲートを設けない）。
 */
export type LimitDisclosure = 'required' | 'preferred';

/**
 * 候補 VC が選択的開示（Selective Disclosure）に対応するかを判定する。
 *
 * `supportsSelectiveDisclosure` が明示されていればそれを優先する。省略時は `SELECTIVE_DISCLOSURE_FORMATS`
 * によるフォーマット既定値から推定する（`scoring.ts` の `privacyContribution` と同じ判定方針）。
 *
 * @param vc 判定対象の候補 VC。
 * @returns 選択的開示に対応するなら `true`。
 */
export function isSelectiveDisclosureCapable(vc: NegotiableCredential): boolean {
  // 省略した候補が `Object.prototype` 汚染で選択的開示に対応すると見なされないよう、own のときだけ読む。
  const explicit = ownProperty<boolean>(vc, 'supportsSelectiveDisclosure');
  if (explicit !== undefined) {
    return explicit;
  }
  return SELECTIVE_DISCLOSURE_FORMATS.has(vc.format);
}

/** Multi-format VP で同時提示できる最大フォーマット数。 */
export const MAX_MULTI_FORMAT_COUNT = 3;
