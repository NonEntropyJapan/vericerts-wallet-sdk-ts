/**
 * EUDI Pseudonymous Authentication の型定義。
 *
 * ウォレットはマスター種 `pseudonym_master_seed` から、RP ごとに
 * `HKDF-SHA256(ikm=master_seed, salt=canonicalize(rp_id), info="eudi-pseudonym-v1")` で
 * P-256 鍵ペアを決定的に派生する。同一 RP には毎回同じ Pseudonym を提示し（継続性）、
 * 異なる RP には HKDF の一方向性により相関不能な別鍵を提示する（相関不能性）。
 *
 * 本モジュールは鍵派生（`derive.ts`）・Pseudonym Attestation 発行（`attestation.ts`）・
 * SIOPv2 ログイン（`siop.ts`）の 3 責務を担う。マスター種の WSCD 内生成・保管は SDK 上位層の
 * 責務であり、本モジュールは呼び出し側から `masterSeed` を受け取る純粋関数として実装する。
 */

/** Pseudonym Attestation の VC Type URI（`urn:eudi:pseudonym:1`）。 */
export const PSEUDONYM_VCT = 'urn:eudi:pseudonym:1' as const;

/** HKDF の `info` 固定値（`eudi-pseudonym-v1`）。 */
export const PSEUDONYM_HKDF_INFO = 'eudi-pseudonym-v1' as const;

/** Pseudonym の `sub` 識別子プレフィックス（`urn:pseudonym:<hash(pub)>`）。 */
export const PSEUDONYM_SUBJECT_PREFIX = 'urn:pseudonym:' as const;

/**
 * RP ごとに派生した Pseudonym 鍵ペアと識別子。
 *
 * `privateKey` は WSCD 内で署名にのみ用いる想定の秘密鍵で、エラー message / context / cause
 * に含めてはならない。呼び出し側は署名後速やかに破棄する責務を持つ。
 */
export interface PseudonymKey {
  /** 正規化済みの RP 識別子（`canonicalize(rpIdentifier)` の結果）。派生 salt に用いた値。 */
  readonly rpId: string;
  /** 派生した P-256 秘密鍵（32 バイト）。WSCD 内署名のみに使用し、露出させない。 */
  readonly privateKey: Uint8Array;
  /** 派生した P-256 圧縮公開鍵（33 バイト）。 */
  readonly publicKey: Uint8Array;
  /** Pseudonym の subject 識別子（`urn:pseudonym:<base64url(sha256(publicKey))>`）。 */
  readonly subject: string;
}

/**
 * Pseudonym Attestation JWT の payload クレーム。
 *
 * ユーザー PII は含まない（RP 別の匿名識別子のみ）。値の生成は `attestation.ts` が行う。
 */
export interface PseudonymAttestationClaims {
  /** 発行者（Wallet Instance 識別子、`iss`）。 */
  readonly iss: string;
  /** Pseudonym subject 識別子（`urn:pseudonym:<hash(pub)>`）。 */
  readonly sub: string;
  /** VC Type URI。常に `urn:eudi:pseudonym:1`。 */
  readonly vct: typeof PSEUDONYM_VCT;
  /** 対象 RP 識別子（正規化済み）。 */
  readonly rp_id: string;
  /** 発行時刻（NumericDate、秒）。 */
  readonly iat: number;
  /** 有効期限（NumericDate、秒）。 */
  readonly exp: number;
  /** 確認鍵バインド（派生した Pseudonym 公開鍵）。 */
  readonly cnf: PseudonymConfirmation;
}

/** 確認鍵（`cnf`）バインド。Pseudonym 公開鍵の EC JWK（P-256）。 */
export interface PseudonymConfirmation {
  /** Pseudonym 公開鍵の EC JWK（P-256）。 */
  readonly jwk: Readonly<Record<string, unknown>>;
}

/**
 * SIOPv2 Authorization Request の入力。
 *
 * `presentPseudonym` が ID Token 生成に必要とする最小フィールドのみを受け取る。RP メタデータの
 * 検証（Trust Framework）は本モジュールの責務外。
 */
export interface SiopRequest {
  /** RP のクライアント識別子（ID Token の `aud`）。 */
  readonly clientId: string;
  /** RP が要求した nonce（ID Token の `nonce`。リプレイ防止）。 */
  readonly nonce: string;
}

/**
 * SIOPv2 で生成した Pseudonym ID Token の結果。
 *
 * ウォレットはこの ID Token を `direct_post` で RP に返す。送信自体（HTTP）は上位層の責務。
 */
export interface PseudonymIdToken {
  /** 署名済み ID Token（コンパクト JWS）。 */
  readonly idToken: string;
  /** ID Token の subject 識別子（`urn:pseudonym:<hash(pub)>`）。同一 RP 再訪問で不変。 */
  readonly subject: string;
}

/**
 * Pseudonym Attestation の結果。
 *
 * `subject` は SIOPv2 の ID Token でも使用する RP ごとの識別子。
 */
export interface PseudonymAttestation {
  /** 対応 RP 識別子（正規化済み、`canonicalize(rpIdentifier)` の結果）。 */
  readonly rpIdentifier: string;
  /** 署名済み Attestation JWT（コンパクト JWS）。 */
  readonly jwt: string;
  /** VC Type URI。常に `urn:eudi:pseudonym:1`。 */
  readonly vct: typeof PSEUDONYM_VCT;
  /** 発行日時（ISO 8601）。JWT 本体の `iat`（NumericDate）を変換した表現。 */
  readonly issuedAt: string;
  /** 有効期限（ISO 8601）。JWT 本体の `exp`（NumericDate）を変換した表現。 */
  readonly expiresAt: string;
  /** Attestation の subject 識別子（`urn:pseudonym:<hash(pub)>`）。 */
  readonly subject: string;
}
