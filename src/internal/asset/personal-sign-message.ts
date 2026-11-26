/**
 * `personal_sign` の `params[0]` → 署名対象メッセージ（EIP-191 の接頭辞を付ける前）のバイト列、の**唯一の**正規化。
 *
 * 次の 3 か所が同じバイト列を読まなければならない（食い違うと、片方の検査だけが迂回できる）。
 * - 署名時のガード・ペイロード組み立て（`eth-signing.ts` の `personalSignPayload` / `assertPersonalSignAllowed`。ES256K-R の
 *   JWS signing-input の拒否）
 * - 拡張の承認前の SIWE 判定
 * - 拡張の承認ダイアログでのメッセージ表示
 *
 * `@vericerts/vericerts-wallet-sdk/asset` はこの実装を警告付きの公開 API としてラップする。SDK 内部と、現状
 * `vericerts-wallet-sdk/asset-personal-sign-message` の alias を使う extension は素の実装を参照する（公開 entry への移行は）。
 *
 * 依存は `evm-format.ts`（hex 形式判定）と `hex-codec.ts` のみ（ethers / viem を引かない）。
 */

import { isHexString } from '../evm-format.js';
import { decodeHexDigits } from './hex-codec.js';

/**
 * `personal_sign` の `params[0]` を署名対象のメッセージ（prefix 前）のバイト列へ正規化する。
 * 妥当な `0x` hex（偶数長。桁の大小は問わない。`0X` は hex と見なさない）ならそのバイト列、そうでなければ UTF-8 文字列そのもの
 * （MetaMask 等が非 hex 入力を許容する慣行に合わせる）。
 */
export function personalSignMessageBytes(data: string): Uint8Array {
  return isHexString(data, { allowEmpty: true }) && data.length % 2 === 0
    ? decodeHexDigits(data.slice(2))
    : new TextEncoder().encode(data);
}
