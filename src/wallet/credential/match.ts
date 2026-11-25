/**
 * Wallet ファサードの `matchCredentials` の実装。
 *
 * `receive.ts` と同じく `ops.ts` から分離した独立ファイル。`matchCredentialsByPresentationDefinitionWith`
 * と同じパターンで `CredentialStore` を唯一保持する `GdprFacade` から呼ばれる（
 * `wallet.ts` に storage を直接走査させない方針）。契約の詳細は `wallet/credential/api.ts` の
 * `PresentationApi.matchCredentials` の JSDoc を参照。
 */

import type { PresentationRequestOptions } from '../../internal/auth/index.js';
import { matchCredentials as matchCredentialsImpl } from '../../internal/auth/index.js';
import type { VerifiableCredential } from '../../internal/credential/index.js';
import type { CredentialStore } from '../../internal/gdpr/index.js';

/**
 * Presentation Request に合致する保有 VC を選定する。
 *
 * `credentials.listActiveCredentials()` で GDPR Art.18 に基づく処理制限中の VC を除外し、
 * 残った候補を `matchCredentials` に渡す。
 */
export async function matchCredentialsWith(
  credentials: CredentialStore,
  requestURI: string,
  opts?: PresentationRequestOptions,
): Promise<VerifiableCredential[]> {
  const heldCredentials = await credentials.listActiveCredentials();
  return matchCredentialsImpl(requestURI, heldCredentials, opts);
}
