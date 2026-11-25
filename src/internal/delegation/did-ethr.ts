/**
 * did:ethr（ERC-1056）の DID 文字列パースと、controller を表す did:ethr の組み立て。
 *
 *   - `did:ethr:<address>`           → Chain ID 1（Mainnet）
 *   - `did:ethr:<chainId>:<address>` → 任意チェーン
 *
 * controller（所有者）はオンチェーンの Ethereum アドレスで表現される。本モジュールは
 * did:ethr 文字列とアドレス／チェーンの相互変換を提供し、delegation の検出・Tx 構築の
 * 共通基盤とする。ethers には依存しない（純粋な文字列処理のみ）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・アドレスを含めない。
 */

import { type ParsedDidEthr, parseDidEthr } from '../identity/ethr/did-url.js';

/** `did:ethr:` メソッドプレフィックス。 */
const DID_ETHR_PREFIX = 'did:ethr:';

/** chainId 省略時の既定チェーン（Ethereum Mainnet）。 */
const DEFAULT_CHAIN_ID = 1;

/**
 * did:ethr のパース結果（`identity/ethr/did-url.ts` の {@link ParsedDidEthr} の別名）。
 *
 * `address` は入力の大文字小文字を保持する（チェックサム検証は ethers アダプタ側で行う）。
 */
export type EthrDidParts = ParsedDidEthr;

/**
 * did:ethr 文字列を chainId とアドレスに分解する。
 *
 * 実装は `identity/ethr/did-url.ts` の `parseDidEthr` で、これはその別名。パース処理を
 * 2 か所に持つと片方だけ直されて挙動が食い違うため、1 つにまとめている。
 *
 * @param did did:ethr 文字列（`did:ethr:<addr>` または `did:ethr:<chainId>:<addr>`）。
 * @returns chainId と 0x アドレス。
 * @throws プレフィックス不正・セグメント数不正・アドレス／chainId 形式不正の場合
 *         （VericertsError、code `2001`）。
 */
export const parseEthrDid: (did: string) => EthrDidParts = parseDidEthr;

/**
 * chainId とアドレスから did:ethr 文字列を組み立てる（`parseEthrDid` の逆変換）。
 *
 * chainId が 1（Mainnet）の場合は `did:ethr:<addr>`、それ以外は
 * `did:ethr:<chainId>:<addr>` を返す。アドレスはそのまま埋め込む
 * （正規化／チェックサムは呼び出し側の責務）。
 *
 * @param parts chainId と 0x アドレス。
 * @returns did:ethr 文字列。
 */
export function formatEthrDid(parts: EthrDidParts): string {
  if (parts.chainId === DEFAULT_CHAIN_ID) {
    return `${DID_ETHR_PREFIX}${parts.address}`;
  }
  return `${DID_ETHR_PREFIX}${parts.chainId}:${parts.address}`;
}
