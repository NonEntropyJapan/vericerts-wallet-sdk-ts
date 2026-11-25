/**
 * DID ベース SIOPv2 自己発行 ID Token の検証（RP 側。SIOPv2 draft 13 §11、OIDC Core §3.1.3.7）。
 *
 * `generateIDToken` が作る ID Token（`iss` = `sub` = DID）を、DID Document だけから検証する。
 * 署名主体は `sub` の DID の DID Document の `authentication` に列挙された検証メソッドで、JWS ヘッダ `kid` がその
 * 検証メソッドの DID URL。**ID Token 内の `sub_jwk` は鍵の根拠に使わない**（攻撃者が好きな鍵を載せられるため）。
 *
 * 委任 DIDの ID Token は `iss` = `sub` = 委任先 DID `D`、`kid` = `D` の検証メソッド `V`（埋め込み、または
 * 委任元ペルソナの `did:key:…#…` など他 DID の検証メソッドへの DID URL 参照）。`D` の `authentication` が `V` を列挙して
 * いなければ（外された・鍵が違う）拒否する。他 DID への参照は DID を解決して辿る（DID Core §5.3）。
 *
 * セキュリティ上の注意: 例外メッセージ・`context` に ID Token 本文・DID を含めない
 * （`context.reason` は固定識別子のみ）。
 */

import {
  documentIdMatches,
  inlineExternalMethods,
} from '../../credential/did-signing/external-methods.js';
import { methodsInRelationship } from '../../credential/did-signing/key-binding.js';
import {
  assertAlg,
  type CredentialSignerAlg,
  type DecodedJws,
  decodeCompactJws,
} from '../../credential/vc/jws.js';
import { verifyWithMethod } from '../../credential/vc/verifier-key.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { DidResolverLike } from '../../identity/bounded-resolver.js';
import { isEpochSeconds } from '../../primitives/option-guard.js';
import { ownProperty } from '../../prototype-safety/own-property.js';

/** 時刻クレームの既定の許容誤差（秒）。 */
const DEFAULT_CLOCK_SKEW_SECONDS = 60;

/** `verifyIDToken` のオプション。 */
export interface VerifyIdTokenOptions {
  /** DID Resolver。`sub` の DID（と他 DID への参照先）を毎回解決する（キャッシュしない）。 */
  readonly resolver: DidResolverLike;
  /** RP の `client_id`。`aud` と一致しなければ拒否する。 */
  readonly expectedAudience: string;
  /** 認可リクエストの `nonce`。一致しなければ拒否する。 */
  readonly expectedNonce: string;
  /** 現在時刻（NumericDate、秒）。 */
  readonly nowSeconds: number;
  /** 時刻クレームの許容誤差（秒、既定 60）。 */
  readonly clockSkewSeconds?: number;
}

/** 検証済みの ID Token。 */
export interface VerifiedIdToken {
  /** 署名主体の DID（`sub`。委任 DID なら委任先 DID）。 */
  readonly did: string;
  /** 署名した検証メソッドの DID URL（JWS ヘッダ `kid`）。 */
  readonly kid: string;
  /** JWS `alg`。 */
  readonly alg: CredentialSignerAlg;
  /** 検証済みの ID Token クレーム。 */
  readonly claims: Readonly<Record<string, unknown>>;
}

/** 検証失敗（`3010`）。`reason` は固定識別子のみ。 */
function invalid(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.SIG_INVALID, { context: { reason } });
}

/**
 * DID ベースの自己発行 ID Token を検証する。
 *
 * 1. 構造（3 セグメント・`alg` が ES256 / ES256K / EdDSA・`kid` が DID URL）と `iss` = `sub`（DID）を確かめる。
 * 2. `aud` = `expectedAudience`、`nonce` = `expectedNonce`、`iat` / `exp` が `nowSeconds` ± 許容誤差に収まることを確かめる。
 * 3. `sub` の DID を解決し、`kid` の検証メソッドが `authentication` に列挙されていることを確かめる
 *    （他 DID の検証メソッドへの DID URL 参照は、その DID を解決して辿る）。失効した DID は拒否する。
 * 4. その検証メソッドの公開鍵で署名を検証する。
 *
 * @returns 検証済みの `sub`（DID）・`kid`・`alg`・クレーム。
 * @throws `RangeError`（`expectedAudience` / `expectedNonce` が空でない文字列でない。検証せずに拒否する）、構造不正・`iss` ≠ `sub`・`aud` 不一致・署名不一致（VericertsError、code `3010`。`context.reason` に固定識別子）、
 *         `alg=none`（`3011`）、`nonce` 不一致（`4012`）、時刻クレームが許容外（`4014`）、`kid` の検証メソッドが
 *         `authentication` に無い・失効（`2017`）、DID 解決の失敗（`2001` / `2002` / `2003`）・参照先を辿れない（`2010`）。
 */
export async function verifyIDToken(
  idToken: string,
  opts: VerifyIdTokenOptions,
): Promise<VerifiedIdToken> {
  // 期待値の欠落（型を無視する JS 呼び出し・空文字）は fail-open にしない: `aud` / `nonce` を持たないトークンが
  // `undefined === undefined` で通ってしまうため、入口で拒否する。
  const expectedAudience = ownProperty<unknown>(opts, 'expectedAudience');
  const expectedNonce = ownProperty<unknown>(opts, 'expectedNonce');
  if (typeof expectedAudience !== 'string' || expectedAudience.length === 0) {
    throw new RangeError('expectedAudience は空でない文字列である必要があります');
  }
  if (typeof expectedNonce !== 'string' || expectedNonce.length === 0) {
    throw new RangeError('expectedNonce は空でない文字列である必要があります');
  }
  let decoded: DecodedJws;
  try {
    decoded = decodeCompactJws(idToken);
  } catch {
    throw invalid('malformed');
  }
  const { header, payload } = decoded;
  const alg = assertAlg(header, { allowEs256kR: true });
  const kid = ownProperty<unknown>(header, 'kid');
  if (typeof kid !== 'string' || !kid.startsWith('did:') || !kid.includes('#')) {
    throw invalid('kid_missing');
  }
  const sub = ownProperty<unknown>(payload, 'sub');
  // Self-Issued: `iss` = `sub`（SIOPv2 §11）。DID 以外の subject syntax（JWK Thumbprint）はここでは扱わない。
  if (
    typeof sub !== 'string' ||
    !sub.startsWith('did:') ||
    ownProperty<unknown>(payload, 'iss') !== sub
  ) {
    throw invalid('subject_invalid');
  }
  if (ownProperty<unknown>(payload, 'aud') !== expectedAudience) {
    throw invalid('aud_mismatch');
  }
  if (ownProperty<unknown>(payload, 'nonce') !== expectedNonce) {
    throw new VericertsError(ErrorCodes.NONCE_BINDING_MISMATCH);
  }
  const skew = ownProperty<number>(opts, 'clockSkewSeconds') ?? DEFAULT_CLOCK_SKEW_SECONDS;
  const iat = ownProperty<unknown>(payload, 'iat');
  const exp = ownProperty<unknown>(payload, 'exp');
  if (!isEpochSeconds(iat) || !isEpochSeconds(exp) || !isEpochSeconds(opts.nowSeconds)) {
    throw invalid('time_claims_invalid');
  }
  if (iat > opts.nowSeconds + skew || exp + skew < opts.nowSeconds) {
    throw new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED);
  }
  const document = await opts.resolver.resolve(sub);
  const documentId = ownProperty<unknown>(document, 'id');
  if (!documentIdMatches(documentId, sub)) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID, {
      context: { reason: 'document_id_mismatch' },
    });
  }
  if (ownProperty<unknown>(document, 'deactivated') === true) {
    throw new VericertsError(ErrorCodes.DID_KEY_MISMATCH, {
      context: { reason: 'deactivated', relationship: 'authentication' },
    });
  }
  const inlined = await inlineExternalMethods(opts.resolver, document, 'authentication', { kid });
  const entry = methodsInRelationship(inlined, 'authentication').find(({ id }) => id === kid);
  if (entry === undefined) {
    throw new VericertsError(ErrorCodes.DID_KEY_MISMATCH, {
      context: { reason: 'relationship_not_granted', relationship: 'authentication' },
    });
  }
  if (!verifyWithMethod(alg, decoded, entry.method)) {
    throw invalid('signature');
  }
  return { did: sub, kid, alg, claims: payload };
}
