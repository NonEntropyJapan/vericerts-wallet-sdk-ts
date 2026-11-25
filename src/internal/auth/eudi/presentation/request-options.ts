/**
 * 提示フローの依存（`PresentDeps`）から提示要求パースのオプションへの写像。
 *
 * HAIP §5.1 の参照形式では `request_uri` から JAR を取得し、検証済みの提示要求を使う。
 *
 * `present.ts` から切り出しているのは、この写像が**「省略」と「汚染された継承値」を取り違えない
 * ための規律そのもの**であり、提示の手続き（VP Token 構成・送信）とは独立に読めるべきだからである。
 *
 * セキュリティ上の注意:
 * - 戻り値のリテラルには**全メンバを own プロパティとして載せる**（値が `undefined` でも載せる）。
 *   載せずに省略すると、このリテラルが `Object.prototype` を継承した状態で下流の DI 解決と
 *   Trust Anchor 読み出しに渡る。`fetchImpl` の汚染値を掴めば Verifier の Request Object ごと
 *   攻撃者の fetch へ委譲され、`trustAnchors` の汚染値を掴めば**攻撃者 CA が JAR 署名検証の
 *   信頼の起点になる**（= 任意の提示要求を注入できる状態に戻る）。
 * - `deps` / `jarTrust` のメンバは分割代入で読まない。`fetchImpl` は class の prototype メソッド
 *   として実装され得るため `bindInjectedFetch`（内部で `nonObjectPrototypeProperty`）、`jarTrust` 以下は純データなので
 *   `ownProperty` で読む（`own-property.ts`「どちらのヘルパーを使うか」）。
 */

import { bindInjectedFetch } from '../../../http/bind-fetch.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import type { JarTrustOptions, parsePresentationRequest } from '../../jar/index.js';
import type { PresentDeps } from './types.js';

/**
 * `parsePresentationRequest` へ渡すオプションを `PresentDeps` から組み立てる。
 *
 * `fetchImpl` は `SubmitFetchLike`（`redirect` を含む init を受ける）を `FetchLike`（含まない）へ
 * 読み替えて渡す。`request_uri` の GET が渡す init が 1 フィールド狭いだけである
 * （`oid4vp-submit.ts` の `postForm` が行う読み替えの逆向き）。呼び出し側に取得用と送信用で 2 つの
 * fetch シームを持たせない ―― 提示は 1 つの HTTP スタックで完結するのが自然であり、シームが
 * 2 つあると片方だけ差し替え忘れてテストが実ネットワークへ出る。
 * 束ねた関数を返すため、下流の合成オプションから呼ばれても元の `deps` がレシーバとなる。
 *
 * `jarTrust` 未指定時も各メンバを `undefined` のまま載せる。参照形式の提示要求が届いた時点で
 * `trustAnchors` が無いことが実行時に判り、`8030`（`reason: "jar_trust_anchors_unconfigured"`）で
 * fail-closed に拒否される。直接形式はそのまま同期解析される。
 *
 * @param deps 提示フローの依存（署名鍵・送信シーム・JAR 検証材料）。
 * @returns `parsePresentationRequest` の第 2 引数。
 */
export function presentationRequestOptions(
  deps: PresentDeps,
): NonNullable<Parameters<typeof parsePresentationRequest>[1]> {
  const jarTrust = ownProperty<JarTrustOptions>(deps, 'jarTrust');
  const trustMember = <T>(key: string): T | undefined =>
    jarTrust === undefined ? undefined : ownProperty<T>(jarTrust, key);
  return {
    trustAnchors: trustMember<JarTrustOptions['trustAnchors']>('trustAnchors') as
      | JarTrustOptions['trustAnchors']
      | undefined,
    expectedClientId: trustMember<string>('expectedClientId'),
    // `federationTrustAnchor` / `arfTrustAnchor` も他のメンバと
    // 同じ `trustMember` 経路で own 限定で読み、`parsePresentationRequest` へ転送する。転送し
    // 忘れると `PresentDeps.jarTrust` に OIDF / ARF 層を設定していても黙って TSL 単独へ縮退する。
    federationTrustAnchor:
      trustMember<JarTrustOptions['federationTrustAnchor']>('federationTrustAnchor'),
    arfTrustAnchor: trustMember<JarTrustOptions['arfTrustAnchor']>('arfTrustAnchor'),
    requestObjectSigningAlgValuesSupported: trustMember<readonly string[]>(
      'requestObjectSigningAlgValuesSupported',
    ),
    revokedSerials: trustMember<ReadonlySet<string>>('revokedSerials'),
    now: trustMember<number>('now'),
    fetchImpl: bindInjectedFetch(deps, 'fetchImpl'),
  };
}
