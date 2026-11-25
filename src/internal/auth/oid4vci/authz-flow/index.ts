/**
 * OID4VCI Authorization Code Flow（PAR + PKCE）オーケストレーション（sub-barrel）。
 *
 * - types.ts:   フローの入力型（4 エンドポイント / 要求内容 / 依存）。
 * - deps.ts:    依存（署名器 / 認可 UI / HTTP / DPoP）の own 限定読みと検証（`eudi/issuance/deps.ts` と同一方針）。
 * - options.ts: 要求内容と 4 エンドポイントの own 限定読み・非空 / HTTPS 検証。
 * - receive.ts: `receiveCredentialViaAuthorizationCode`（PAR → 認可 URL → 認可 → Token → Credential の配線）。
 *
 * 各手順のプリミティブ（`pushAuthorizationRequest` / `buildAuthorizationUrl` /
 * `requestTokenAuthorizationCode` / `generateProofJWT` / `requestCredential`）は本ディレクトリの
 * 外に既にあり、ここでは再実装しない。
 */

export { receiveCredentialViaAuthorizationCode } from './receive.js';
export type {
  AuthorizationCodeEndpoints,
  AuthorizationCodeFlowDeps,
  AuthorizationCodeFlowOptions,
  AuthorizationRedirect,
} from './types.js';
