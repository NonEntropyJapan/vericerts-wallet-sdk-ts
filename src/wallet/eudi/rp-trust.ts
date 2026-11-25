/**
 * `WalletOptions.rpTrustAnchors` から提示経路の JAR 検証材料への写像。
 *
 * `presentPID` と `presentEAA` は提示要求が `request_uri` 参照形式の場合に、この設定を使って JAR の署名を検証する。
 *
 * `EudiFacade` から切り出しているのは、この写像が**「Trust Anchor を渡していない」と「汚染された
 * 継承値を渡された」を取り違えないための規律**であり、ファサードの委譲ロジックとは独立に読める
 * べきだからである。
 *
 * - 本関数は `JarTrustOptions | undefined` を返すだけで、`jarTrust` プロパティを載せる主体では
 *   ない。載せるのは呼び出し側 `facade.ts` の `presentDeps()` で、そこでは**値が `undefined` でも
 *   own プロパティとして**載せる。下流（`internal/auth/eudi/presentation/request-options.ts`）が
 *   own 限定で読むため、載せずに省略すると `Object.prototype.jarTrust` の汚染値が
 *   「渡された Trust Anchor」に化け、**攻撃者 CA が JAR 署名検証の信頼の起点になる**
 *   （= 任意の提示要求が提示 UI へ通る）。
 * - Trust Anchor 未設定は検証省略ではない。`trustAnchors` が無いまま参照形式の提示要求が届けば
 *   `8030`（`reason: "jar_trust_anchors_unconfigured"`）で fail-closed に拒否される。
 */

import type { JarTrustOptions } from '../../internal/auth/jar/index.js';
import type { QtspServiceCertificate } from '../../internal/trust/etsi-tsl/index.js';

/**
 * 設定された RP Access Certificate の Trust Anchor を `JarTrustOptions` へ包む。
 *
 * `expectedClientId` はここでは載せない。参照形式の deep link に載っていた `client_id` は
 * `parsePresentationRequest` がクエリから読み取って自動で突き合わせるため、
 * ファサードが推測で埋める余地を作らない。
 *
 * @param anchors `createWallet({ rpTrustAnchors })` で受け取った Trust Anchor。未設定なら
 *                `undefined`。
 * @returns `PresentDeps.jarTrust` に載せる値。未設定時は `undefined`（呼び出し側が own
 *          プロパティとして載せる）。
 */
export function jarTrustOf(
  anchors: readonly QtspServiceCertificate[] | undefined,
): JarTrustOptions | undefined {
  return anchors === undefined ? undefined : { trustAnchors: anchors };
}
