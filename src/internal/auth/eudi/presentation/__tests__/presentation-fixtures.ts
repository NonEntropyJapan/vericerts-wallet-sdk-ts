/**
 * eudi/presentation テスト用フィクスチャ。
 *
 * 実鍵素材のみを使う（モック署名器は使わない）。提示対象の SD-JWT VC は Disclosure・digest・
 * Issuer 署名まで実際に計算して組み立てる。`createSdJwt` を使わないのは、PID の属性名
 * （`family_name` 等）が発行経路の GDPR Art.9 ガードで `10607` に落ちるためで、受領済み PID を
 * 提示するというテスト状況を作るには Issuer 側の組み立てを再現する必要がある。
 *
 * VP Token の送信は**グローバル `fetch` を差し替えず** `fetchImpl`（`SubmitFetchLike`）で注入し、
 * 送信 body を記録する。
 */

import { base64urlnopad } from '@scure/base';
import { encodeDisclosure } from '../../../../credential/sdjwt/disclosure.js';
import { type CredentialSigner, createPrivateKeySigner } from '../../../../credential/vc/signer.js';
import type { EAACredential, PIDClaims, PIDCredential } from '../../../../eudi/pid/index.js';
import { PID_VCT } from '../../../../eudi/pid/index.js';
import type { SubmitFetchLike } from '../../../oid4vp/oid4vp-submit.js';
import type { PresentDeps } from '../types.js';

/** Issuer（PID Provider 相当）の決定論的な P-256 秘密鍵。 */
const ISSUER_PRIVATE_KEY = new Uint8Array(32).fill(7);

/** Holder（Wallet）の決定論的な P-256 秘密鍵。 */
const HOLDER_PRIVATE_KEY = new Uint8Array(32).fill(9);

/** Holder の検証鍵 ID（`did#fragment`）。VP の `holder` はこの DID 部分になる。 */
export const HOLDER_KEY_ID = 'did:key:zHolder#key-1';

/** Holder DID。 */
export const HOLDER_DID = 'did:key:zHolder';

/** Verifier の識別子（`client_id`）。 */
export const VERIFIER_CLIENT_ID = 'https://verifier.example.eu';

/** VP Token の送信先（`response_uri`。`client_id` と同一オリジンである必要がある）。 */
export const RESPONSE_URI = `${VERIFIER_CLIENT_ID}/response`;

/** (Q)EAA の VC Type URI。 */
export const EAA_VCT = 'urn:eudi:eaa:diploma:1';

/** ARF PID Rulebook を満たす PID クレーム。 */
export const PID_CLAIMS: Readonly<Record<string, unknown>> = {
  family_name: 'Bianchi',
  given_name: 'Mario',
  birth_date: '1980-05-17',
  issuance_date: '2026-01-10',
  expiry_date: '2031-01-10',
  issuing_authority: 'Ministero dell Interno',
  issuing_country: 'IT',
  // 年齢閾値超過属性。最小開示（生年月日を出さずに成人性だけ示す）に使う。
  age_over_18: true,
};

/** UTF-8 文字列を base64url（パディングなし）エンコードする。 */
function b64url(text: string): string {
  return base64urlnopad.encode(new TextEncoder().encode(text));
}

/**
 * Issuer 署名済みの SD-JWT VC を組み立てる（全クレームを選択的開示にする）。
 *
 * @param vct VC Type URI。
 * @param claims 開示可能なクレーム。
 * @returns SD-JWT VC のコンパクト表現（`<issuerJwt>~<d1>~...~`）。
 */
export function buildSdJwtVc(vct: string, claims: Readonly<Record<string, unknown>>): string {
  const signer = createPrivateKeySigner(ISSUER_PRIVATE_KEY, 'ES256');
  const disclosures = Object.entries(claims).map(([name, value], index) =>
    encodeDisclosure(name, value, `salt-${index}`),
  );
  const payload = {
    iss: 'https://issuer.example.eu',
    vct,
    iat: 1_767_000_000,
    _sd_alg: 'sha-256',
    _sd: disclosures.map((disclosure) => disclosure.digest),
  };
  const signingInput = `${b64url(JSON.stringify({ alg: 'ES256', typ: 'dc+sd-jwt' }))}.${b64url(
    JSON.stringify(payload),
  )}`;
  const signature = signer.sign(new TextEncoder().encode(signingInput));
  const issuerJwt = `${signingInput}.${base64urlnopad.encode(signature)}`;
  return `${issuerJwt}~${disclosures.map((disclosure) => disclosure.encoded).join('~')}~`;
}

/** 受領済み PID Credential（`raw` に生 SD-JWT を保持する）。 */
export function pidCredential(): PIDCredential {
  return {
    vct: PID_VCT,
    claims: PID_CLAIMS as PIDClaims,
    raw: buildSdJwtVc(PID_VCT, PID_CLAIMS),
  };
}

/** 受領済み (Q)EAA Credential。 */
export function eaaCredential(vct: string = EAA_VCT): EAACredential {
  const claims = { degree: 'Laurea Magistrale', institution: 'UniRoma' };
  return { vct, claims, raw: buildSdJwtVc(vct, claims) };
}

/** OID4VP Authorization Request URI（`direct_post`）を組み立てる。 */
export function buildRequestURI(): string {
  const params = new URLSearchParams({
    response_type: 'vp_token',
    client_id: VERIFIER_CLIENT_ID,
    response_mode: 'direct_post',
    response_uri: RESPONSE_URI,
    nonce: 'n-0S6_WzA2Mj-0123456789',
    state: 'state-123',
  });
  return `openid4vp://?${params.toString()}`;
}

/** 1 回の送信の記録。 */
export interface SubmitCall {
  /** 送信先 URL。 */
  readonly url: string;
  /** 送信された form body。 */
  readonly body: string;
}

/** VP Token 送信を記録するスタブ。 */
export interface SubmitStub {
  /** `fetchImpl` として注入する実装。 */
  readonly fetchImpl: SubmitFetchLike;
  /** 送信の記録（送信順）。 */
  readonly calls: SubmitCall[];
}

/** 送信を 200 で受理し、URL と body を記録するスタブを作る。 */
export function createSubmitStub(): SubmitStub {
  const calls: SubmitCall[] = [];
  const fetchImpl: SubmitFetchLike = (url, init) => {
    calls.push({ url, body: init.body });
    return Promise.resolve(new Response('', { status: 200 }));
  };
  return { fetchImpl, calls };
}

/** Holder 署名鍵（ES256、`kid` 付きの実鍵）。 */
export function holderSigner(): CredentialSigner {
  return { ...createPrivateKeySigner(HOLDER_PRIVATE_KEY, 'ES256'), kid: HOLDER_KEY_ID };
}

/** 提示フローの既定の依存。 */
export function presentDeps(
  fetchImpl: SubmitFetchLike,
  consentedTransactionData?: readonly string[],
): PresentDeps {
  // `transaction_data` を含む要求は同意済みの値との照合が必須。照合なしで署名すると、
  // Verifier が `request_uri` の 2 回目の GET で取引内容を差し替えられる。
  return {
    signer: holderSigner(),
    fetchImpl,
    ...(consentedTransactionData !== undefined ? { consentedTransactionData } : {}),
  };
}

/** 送信された body から `vp_token` を取り出す。 */
export function submittedVpToken(call: SubmitCall | undefined): string {
  return new URLSearchParams(call?.body ?? '').get('vp_token') ?? '';
}
