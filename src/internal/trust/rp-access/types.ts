/**
 * RP Access Certificate 検証の公開型（trust/rp-access）。
 *
 * `verifyRpAccessCertificate` の型定義（RequestedClaim /
 * RpAccessVerificationResult / ClaimAuthorization / TrustChainNode）に対応する。SSOT は仕様書。
 */

/** RP が要求する属性（OID4VP Authorization Request 由来）。 */
export interface RequestedClaim {
  /** 属性 ID（例 `eu.europa.ec.eudi.pid.1:family_name`）。 */
  readonly claimPath: string;
  /** 提示目的（RP が宣言した purpose）。 */
  readonly purpose: string;
  /** 属性の用途カテゴリ（ETSI TS 119 475 Annex A）。 */
  readonly category: RpClaimCategory;
}

/** ETSI TS 119 475 Annex A の属性用途カテゴリ。 */
export type RpClaimCategory = 'identification' | 'authorization' | 'authentication' | 'other';

/** 失効チェックの手段。 */
export type RevocationMethod = 'crl' | 'ocsp' | 'trusted-list' | 'none';

/** Trust チェーンの供給元。 */
export type TrustSource = 'etsi-lotl' | 'etsi-tsl' | 'openid-federation' | 'arf-trust-anchor';

/** 要求属性ごとの権限判定。 */
export interface ClaimAuthorization {
  readonly claimPath: string;
  /** RP Access Cert の authorized attributes と一致するか。 */
  readonly authorized: boolean;
  /** purpose が Cert の Authorized Purposes と整合するか。 */
  readonly purposeAligned: boolean;
  /** category が Cert で許可されているか。 */
  readonly categoryAllowed: boolean;
  /** 拒否理由（許可時は undefined）。 */
  readonly reason?: string;
}

/** Trust チェーンの 1 ノード。 */
export interface TrustChainNode {
  readonly subject: string;
  readonly issuer: string;
  readonly validFrom: string;
  readonly validUntil: string;
  readonly source: TrustSource;
}

/** 失効状態。 */
export interface RevocationStatus {
  readonly checked: boolean;
  readonly revoked: boolean;
  readonly method: RevocationMethod;
  /** ISO 8601。 */
  readonly checkedAt: string;
}

/** RP 識別情報（結果用）。 */
export interface RpDescriptor {
  /** 法人名（証明書 Subject 由来）。 */
  readonly legalName: string;
  /** 法人識別子（LEI / EUID / VAT 等）。 */
  readonly legalId: string;
  /** ISO 3166-1 alpha-2。 */
  readonly country: string;
  /** RP サービス URI。 */
  readonly origin: string;
}

/** `verifyRpAccessCertificate` の結果。 */
export interface RpAccessVerificationResult {
  /** 署名・チェーン・有効期間・失効がすべて有効なら true。 */
  readonly valid: boolean;
  readonly rp: RpDescriptor;
  /** 要求属性ごとの権限判定。 */
  readonly claimAuthorization: readonly ClaimAuthorization[];
  /** 信頼判定の根拠（チェーンノード）。 */
  readonly trustChain: readonly TrustChainNode[];
  /** 失効状態。 */
  readonly revocation: RevocationStatus;
  /** Cross-border 転送警告（RP 所在国が EU 域外 / 不明）。 */
  readonly crossBorderWarning: boolean;
  /** 付随エラー（コード文字列）。致命的でない指摘も含む。 */
  readonly errors?: readonly string[];
  /**
   * チェーン検証に使った全証明書（leaf・中間・Trust Anchor）の `notAfter` の最小値（Unix 秒）。
   * チェーンが Trust Anchor に到達したときだけ立つ。判定結果をキャッシュする呼び出し側が、
   * この時刻より先へ有効期限を延ばさないために使う。
   */
  readonly validUntil?: number;
}
