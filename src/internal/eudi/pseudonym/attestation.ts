/**
 * Pseudonym Attestation 発行。
 *
 * RP 別に派生した Pseudonym 鍵で `vct=urn:eudi:pseudonym:1` の Attestation JWT に署名する。
 * subject は `urn:pseudonym:<hash(pub)>`、`cnf.jwk` に派生公開鍵をバインドする。発行後、生成した
 * JWT の署名が `cnf.jwk` の公開鍵で検証できることを確認し、バインドが破れている場合は拒否する
 * （code `10010`）。RP はこの `cnf.jwk` で Attestation を検証するため、発行時に自己検証しておくことで
 * 「検証不能な Attestation を配布しない」ことを保証する。
 *
 * セキュリティ上の注意: 例外メッセージ・`context` に privateKey・JWT 本文を
 * 含めない。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { signCompactJws } from '../../credential/vc/compact-jws.js';
import { buildJwsHeader, createPrivateKeySigner } from '../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { jwkToUncompressedPublicKey } from '../../identity/jwt/jwk-key.js';
import { verifyP256 } from '../../keymanager/signer.js';
import { isEpochSeconds, isLifetimeSeconds } from '../../primitives/option-guard.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { derivePseudonym } from './derive.js';
import {
  PSEUDONYM_VCT,
  type PseudonymAttestation,
  type PseudonymAttestationClaims,
} from './types.js';

/** Pseudonym Attestation の既定有効期間（秒）。24h。 */
const DEFAULT_ATTESTATION_LIFETIME_SECONDS = 24 * 60 * 60;

/** `issuePseudonymAttestation` のオプション。 */
export interface PseudonymAttestationOptions {
  /** 発行者識別子（Wallet Instance ID）。`iss` に設定する。 */
  readonly issuer: string;
  /** 発行時刻（NumericDate、秒）。テスト・決定性のため注入する。 */
  readonly nowSeconds: number;
  /** 有効期間（秒）。既定は 24h。 */
  readonly lifetimeSeconds?: number;
}

/**
 * RP 別 Pseudonym Attestation を発行する。
 *
 * `masterSeed` と `rpIdentifier` から Pseudonym 鍵を派生し（`derivePseudonym`）、その秘密鍵で
 * `vct=urn:eudi:pseudonym:1` の Attestation JWT に署名する。`cnf.jwk` は派生公開鍵の EC JWK。
 * 発行した JWT の署名を `cnf.jwk` の公開鍵で検証し、バインドが成立しない場合は拒否する。
 *
 * @param rpIdentifier RP のクライアント識別子（正規化前）。
 * @param masterSeed マスター種（`pseudonym_master_seed`）。
 * @param opts 発行オプション（`issuer` / `nowSeconds` / `lifetimeSeconds`）。
 * @returns 署名済み Attestation JWT と subject 識別子。
 * @throws RP 識別子不正・必須オプション（`issuer` / `nowSeconds`）欠落（code `10201`）、
 *   鍵派生失敗（code `10202`）、
 *   `cnf.jwk` バインド不一致（code `10010`）の場合。
 */
export function issuePseudonymAttestation(
  rpIdentifier: string,
  masterSeed: Uint8Array,
  opts: PseudonymAttestationOptions,
): PseudonymAttestation {
  const key = derivePseudonym(rpIdentifier, masterSeed);
  try {
    const signer = createPrivateKeySigner(key.privateKey, 'ES256');

    // 任意プロパティは自身のプロパティに限って読む。`lifetimeSeconds` を省略した
    // 正当な発行でも継承値を拾うと `exp` が攻撃者の選んだ値になり、**無期限に近い署名済み
    // Attestation** を発行してしまう。
    const lifetime =
      ownProperty<number>(opts, 'lifetimeSeconds') ?? DEFAULT_ATTESTATION_LIFETIME_SECONDS;

    // 必須プロパティも同様に自身のプロパティに限って読む。`issuer` / `nowSeconds` は
    // いずれも署名対象クレーム（`iss` / `iat` / `exp`）であり、鎖読みのままだとそれらを省略した
    // 発行で攻撃者の選んだ発行者・時刻を載せた**署名済み Attestation** を作ってしまう。欠落・型
    // 不正は `as` で下流へ流さず fail-closed に拒否する。
    const issuer = ownProperty<string>(opts, 'issuer');
    const nowSeconds = ownProperty<number>(opts, 'nowSeconds');
    // 非有限・負値・文字列は JWT に `null` 等で載り、`Invalid Date`（RangeError）も招く。寿命は正の有限数に限る。
    if (
      typeof issuer !== 'string' ||
      !isEpochSeconds(nowSeconds) ||
      !isLifetimeSeconds(nowSeconds, lifetime)
    ) {
      throw new VericertsError(ErrorCodes.RP_IDENTIFIER_INVALID);
    }

    const claims: PseudonymAttestationClaims = {
      iss: issuer,
      sub: key.subject,
      vct: PSEUDONYM_VCT,
      rp_id: key.rpId,
      iat: nowSeconds,
      exp: nowSeconds + lifetime,
      cnf: { jwk: signer.publicKeyJwk },
    };

    const jwt = signCompactJws(buildJwsHeader(signer, 'pseudonym+jwt'), claims, signer);

    // 発行した Attestation が cnf.jwk で検証可能であることを自己検証する（バインド不一致 = code 10010）。
    // RP はこの cnf.jwk で署名検証するため、検証不能な Attestation を配布しないことを保証する。
    assertAttestationBoundToCnf(jwt, signer.publicKeyJwk);

    // `PseudonymAttestation` が要求する ISO 8601 表現。JWT 本体の `iat`/`exp`
    // クレーム自体は JWT 標準どおり NumericDate のまま変更しない（復元後の表現のみ変換）。
    return {
      rpIdentifier: key.rpId,
      jwt,
      vct: PSEUDONYM_VCT,
      issuedAt: new Date(nowSeconds * 1000).toISOString(),
      expiresAt: new Date((nowSeconds + lifetime) * 1000).toISOString(),
      subject: key.subject,
    };
  } finally {
    // 派生秘密鍵は署名（および自己検証）完了後、例外発生時も含めて速やかにメモリから消去する。
    // `derivePseudonym` はステートレスな純粋関数で鍵素材の
    // ライフサイクルを見渡せないため、生存期間全体を把握できる唯一の呼び出し元がここで消去する。
    key.privateKey.fill(0);
  }
}

/**
 * 生成した Attestation JWT の署名が `cnf.jwk` の公開鍵で検証できることを確認する。
 *
 * JWT の signing-input（`header.payload`）の SHA-256 に対する署名を、`cnf.jwk`（x / y）から復元した
 * P-256 公開鍵で検証する。検証に失敗した場合は cnf バインド不一致として拒否する（code `10010`）。
 *
 * @param jwt 生成した Attestation JWT（コンパクト JWS）。
 * @param cnfJwk `cnf.jwk` に設定した EC 公開鍵 JWK。
 * @throws バインド不一致の場合（VericertsError、code `10010`）。
 */
function assertAttestationBoundToCnf(jwt: string, cnfJwk: Readonly<Record<string, unknown>>): void {
  const parts = jwt.split('.');
  const [headerSeg, payloadSeg, signatureSeg] = parts;
  if (headerSeg === undefined || payloadSeg === undefined || signatureSeg === undefined) {
    throw new VericertsError(ErrorCodes.PSEUDONYM_BINDING_INVALID);
  }
  // `cnf.jwk` は外部入力ではなく `derivePseudonym` / `createPrivateKeySigner` が内部生成した
  // P-256 公開鍵 JWK であり、曲線は生成側で確定している。よって曲線束縛は行わず
  // （`expectedCrv: null` を明示）、座標のみを検証する。
  const publicKey = jwkToUncompressedPublicKey(cnfJwk, {
    expectedCrv: null,
    errorCode: ErrorCodes.PSEUDONYM_BINDING_INVALID,
  });
  const signingInput = `${headerSeg}.${payloadSeg}`;
  const digest = sha256(new TextEncoder().encode(signingInput));
  let signature: Uint8Array;
  try {
    signature = base64urlnopad.decode(signatureSeg);
  } catch {
    // 署名セグメントが base64url でない = 検証不能。cnf バインド不一致に正規化する。
    throw new VericertsError(ErrorCodes.PSEUDONYM_BINDING_INVALID);
  }
  // 不正な公開鍵点・署名不一致はいずれも verifyP256 が false を返す（例外は送出しない）。
  // JWS 検証ではなく `cnf` 束縛用の独自署名のため、ES256 の high-S 受理の対象外で low-S 固定。
  // `allowHighS: false` を明示する。
  if (!verifyP256(digest, signature, publicKey, { allowHighS: false })) {
    throw new VericertsError(ErrorCodes.PSEUDONYM_BINDING_INVALID);
  }
}
