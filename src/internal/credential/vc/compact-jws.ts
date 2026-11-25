/**
 * コンパクト JWS（`base64url(header).base64url(payload).base64url(signature)`）の直列化と署名。
 *
 * 「header / payload を JSON 直列化 → base64url 連結 → signer で署名」の重複実装を集約する
 * `jose` は使わない。本モジュールへ移行済みの経路は次のとおり:
 * `credential/vc/issue.ts`（JWT-VC 発行） / `credential/presentation/issue.ts`（JWT-VP 発行） /
 * `issuer/status-list-token.ts`（Status List Token） / `eudi/wua/proof.ts`（WUA PoP） /
 * `gdpr/dashboard-log/dashboard-log.ts`（署名付き Dashboard ログ） / `eudi/pseudonym/*`（Pseudonym Attestation /
 * SIOP `id_token`）。`credential/sdjwt/sdjwt.ts` は独自実装のままで、移行対象には含まれない。
 *
 * 署名鍵は `CredentialSigner` / `AsyncCredentialSigner` で DI する（生 privateKey を渡さない）。
 * 同期版 `signCompactJws` と非同期版 `signCompactJwsAsync` は signing-input の組み立てを完全に共有し、
 * 署名の `await` 有無だけが異なる。したがって同期 signer を非同期版に渡した場合の出力は
 * 同期版とバイト単位で一致する（後方互換）。
 *
 * JWS ヘッダの組み立て（`alg` / `kid` / `typ`）は `signer.ts` の `buildJwsHeader` が担う。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に privateKey・JWT 本文・署名バイト列を含めない。
 */

import { base64urlnopad } from '@scure/base';
import { base64urlText } from '../../base64url.js';
import type { CredentialSignerAlg } from './jws.js';
import type { AnyCredentialSigner, CredentialSigner } from './signer.js';

/**
 * header と**直列化済み** payload から JWS signing-input を組み立てる。
 *
 * payload だけを「オブジェクト」ではなく「JSON 文字列」で受け取るのは、**発行経路が
 * 「走査した値」と「署名するバイト列」を定義上一致させられるようにするため**である
 * （発行時の GDPR Art.9 ガード。`vc/issue.ts` の `buildSigningInput` を参照）。
 * 呼び出し側が payload を一度だけ直列化し、その文字列を解析した値を検査したうえで**同じ文字列**を
 * base64url すれば、検査と署名の間に payload を読み直す余地がなくなる（own アクセサの二重評価も、
 * 非列挙 own プロパティのすり抜けも原理的に成立しない）。
 *
 * **本モジュールに Art.9 ガードそのものを置いてはならない。** この共有ヘルパは VP 発行 /
 * Status List Token / WUA PoP / Dashboard ログ / Pseudonym からも使われる。ガードは VC を発行する呼び出し側に置く。
 *
 * @param header JWS ヘッダ（`buildJwsHeader` の戻り値など）。
 * @param payloadJson JSON 直列化済みの JWS ペイロード。
 * @returns signing-input（`base64url(header).base64url(payloadJson)`）。
 */
export function buildCompactJwsSigningInputFromPayloadJson(
  header: object,
  payloadJson: string,
): string {
  return `${base64urlText(JSON.stringify(header))}.${base64urlText(payloadJson)}`;
}

/**
 * header / payload を JSON 直列化し、JWS signing-input を組み立てる。
 *
 * `header` / `payload` は `object` を受け取る（クレーム interface は TypeScript の暗黙 index
 * signature を持たないため `Record<string, unknown>` 制約にできない）。
 *
 * @param header JWS ヘッダ（`buildJwsHeader` の戻り値など）。
 * @param payload JWS ペイロード（クレーム）。
 * @returns signing-input（`base64url(header).base64url(payload)`）。
 */
export function buildCompactJwsSigningInput(header: object, payload: object): string {
  return buildCompactJwsSigningInputFromPayloadJson(header, JSON.stringify(payload));
}

/**
 * signing-input と raw 署名からコンパクト JWS を組み立てる。
 *
 * @param signingInput `buildCompactJwsSigningInput` が返した signing-input。
 * @param signature 64 バイトの raw 署名。
 * @returns コンパクト JWS（`header.payload.signature`）。
 */
export function assembleCompactJws(signingInput: string, signature: Uint8Array): string {
  return `${signingInput}.${base64urlnopad.encode(signature)}`;
}

/**
 * header / payload を同期 signer で署名し、コンパクト JWS を返す。
 *
 * @param header JWS ヘッダ（`alg` / `typ` を含む）。
 * @param payload JWS ペイロード（クレーム）。
 * @param signer 署名抽象。`sign` は signing-input のバイト列を受け取り 64B raw 署名を返す。
 * @returns コンパクト JWS（`header.payload.signature`）。
 * @throws signer による署名演算が失敗した場合（VericertsError、code `1020`）。
 */
export function signCompactJws(
  header: object,
  payload: object,
  signer: CredentialSigner<CredentialSignerAlg>,
): string {
  const signingInput = buildCompactJwsSigningInput(header, payload);
  const signature = signer.sign(new TextEncoder().encode(signingInput));
  return assembleCompactJws(signingInput, signature);
}

/**
 * header / payload を同期・非同期いずれの signer でも署名し、コンパクト JWS を返す。
 *
 * KMS / HSM 向けの `AsyncCredentialSigner`（`createRemoteSigner`）を受け付けるための非同期版。
 * signing-input の組み立ては `signCompactJws` と共有するため、同期 signer を渡した場合の出力は
 * 同期版とバイト単位で一致する。
 *
 * @param header JWS ヘッダ（`alg` / `typ` を含む）。
 * @param payload JWS ペイロード（クレーム）。
 * @param signer 同期 `CredentialSigner` / 非同期 `AsyncCredentialSigner`。
 * @returns コンパクト JWS（`header.payload.signature`）の Promise。
 * @throws signer による署名演算・外部署名呼び出しが失敗した場合（VericertsError、code `1020`）。
 */
export async function signCompactJwsAsync(
  header: object,
  payload: object,
  signer: AnyCredentialSigner<CredentialSignerAlg>,
): Promise<string> {
  const signingInput = buildCompactJwsSigningInput(header, payload);
  const signature = await signer.sign(new TextEncoder().encode(signingInput));
  return assembleCompactJws(signingInput, signature);
}
