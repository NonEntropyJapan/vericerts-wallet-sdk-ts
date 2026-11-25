/**
 * Issuer facade の発行オプション（`IssueOptions`）と失効管理方式の既定値解決。
 *
 * `statusListType` は VC の失効管理方式を選ぶ。未指定時は `format` から既定値を決める:
 * `jwt` / `sd-jwt` / `cose` は Token Status List（IETF）、`data-integrity` は W3C Bitstring
 * Status List v1.0。`format` も未指定なら既定 `format` は `jwt` のため `token-status-list` になる。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID・クレーム・URL・インデックスを含めない。
 */

import type { EvidenceEntry, TermsOfUseEntry } from '../../credential/evidence-tou/types.js';
import type { RefreshServiceConfig } from '../../credential/vc/vc.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';

/**
 * 発行時の `IssueOptions.format` と受領時の `VerifiableCredential.format` が共有する VC のシリアライズ形式。
 *
 * `credential/format-negotiation/types.ts` の同名型とは**別物**（あちらは OID4VP の
 * `jwt_vc_json` / `dc+sd-jwt` などプロトコル上の識別子で、値集合が重ならない）。
 */
export type VCFormat = 'jwt' | 'sd-jwt' | 'data-integrity' | 'cose';

/** 失効管理方式。 */
export type StatusListType = 'bitstring-v1' | 'statuslist2021' | 'token-status-list';

/** `format` 未指定時の既定形式。 */
export const DEFAULT_VC_FORMAT: VCFormat = 'jwt';

/**
 * `format` → `statusListType` の既定値。
 *
 * `SIGNER_SPECS`（`credential/vc/signer.ts`）と同じ理由でプロトタイプを持たないオブジェクトとして
 * 構築する。通常のオブジェクトリテラルだと `format: 'constructor'` / `'toString'` 等が
 * `Object.prototype` にヒットし、直下の未対応 format ガードをすり抜けて関数オブジェクトが
 * `statusListType` として返ってしまう。
 */
const DEFAULT_STATUS_LIST_TYPES: Record<VCFormat, StatusListType> = Object.assign(
  Object.create(null) as Record<VCFormat, StatusListType>,
  {
    jwt: 'token-status-list',
    'sd-jwt': 'token-status-list',
    cose: 'token-status-list',
    'data-integrity': 'bitstring-v1',
  } satisfies Record<VCFormat, StatusListType>,
);

/** 受理する `statusListType` の集合（型外の値を実行時に弾くため）。 */
const STATUS_LIST_TYPES: ReadonlySet<string> = new Set<StatusListType>([
  'bitstring-v1',
  'statuslist2021',
  'token-status-list',
]);

/**
 * VC 発行オプション。
 *
 * 本 facade（`IssuerModule.issueVC`）は VC 本体の組み立てと失効管理の割り当てまでを担い、
 * 署名・シリアライズは `issueCredential` / `createSdJwt` が担う。`format` は `statusListType` の既定値決定にのみ
 * 用い、返る `VerifiableCredential` の表現は変えない。
 */
export interface IssueOptions {
  /** VC の `type`（先頭の `VerifiableCredential` は自動で付く）。 */
  readonly types?: readonly string[];
  /** VC のシリアライズ形式。既定 `jwt`。`statusListType` の既定値決定に用いる。 */
  readonly format?: VCFormat;
  /** 失効管理方式。未指定時は `format` から既定値を決める。 */
  readonly statusListType?: StatusListType;
  /** 有効期限（ISO 8601）。VC の `expirationDate` になる。 */
  readonly expirationDate?: string;
  /** 失効管理を付与するか。既定 `true`。`false` なら `status` を割り当てない。 */
  readonly credentialStatus?: boolean;
  /** VC の ID（URI）。未指定時は `IssuerModule` が `crypto.randomUUID()` で採番する。 */
  readonly id?: string;
  /** 発行日時（ISO 8601）。未指定時は `IssuerModuleOptions.now` の現在時刻。 */
  readonly issuanceDate?: string;
  /** VC JSON Schema の URL。VC の `credentialSchema`（`type: 'JsonSchema'`）になる。 */
  readonly credentialSchema?: string;
  /** 期限前リフレッシュのエンドポイント参照。VC の `refreshService` になる。 */
  readonly refreshService?: RefreshServiceConfig;
  /** 発行根拠（KYC / 書類確認等）。VC の `evidence` になる。 */
  readonly evidence?: readonly EvidenceEntry[];
  /** 利用条件（ODRL 風の permission / prohibition / obligation）。VC の `termsOfUse` になる。 */
  readonly termsOfUse?: readonly TermsOfUseEntry[];
  /** VC チェーンの親 VC の ID。VC の `derivedFrom` になる。 */
  readonly derivedFrom?: string;
  /** 親 VC 失効時の子 VC への失効伝搬ポリシー。VC の `revocationPropagation` になる。 */
  readonly revocationPropagation?: 'strict' | 'permissive' | 'custom';
}

/**
 * `IssueOptions` から実際に適用する `statusListType` を決める（既定値規則）。
 *
 * @param opts 発行オプション。
 * @returns 適用する失効管理方式。
 * @throws `format` / `statusListType` が受理対象外の場合（VericertsError、code `3002`）。
 */
export function resolveStatusListType(opts: IssueOptions): StatusListType {
  // 任意プロパティは自身のプロパティに限って読む。継承値を拾うと、
  // `statusListType` / `format` を**指定していない**正当な発行でも実効の失効管理方式が
  // 汚染値へ差し替わる。`token-status-list` 以外に化けると `issueVC` の status 確保が
  // 飛ぶため、発行 VC から `credentialStatus` が落ちて**失効不能な VC** が署名される。
  const statusListType = ownProperty<StatusListType>(opts, 'statusListType');
  if (statusListType !== undefined) {
    if (!STATUS_LIST_TYPES.has(statusListType)) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    return statusListType;
  }
  const format = ownProperty<VCFormat>(opts, 'format') ?? DEFAULT_VC_FORMAT;
  const resolved = DEFAULT_STATUS_LIST_TYPES[format];
  // format は閉じた union だが、JS からの型外呼び出しに対する防御として未対応形式を弾く。
  if (resolved === undefined) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  return resolved;
}
