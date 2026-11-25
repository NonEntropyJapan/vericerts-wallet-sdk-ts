/**
 * 拒否リストのキー組み立て。
 *
 * `context.ts` から切り出したキー組み立て層。同ファイルは「flow / 束縛値の解決と照合」と
 * 「拒否リストのキー組み立て」という別々に読める 2 つの責務を抱えており、かつ 1 ファイル
 * 300 行の上限に達していた。
 *
 * `*Of`（ctx 版）と `*From`（解決済み値版）の使い分け、TOCTOU を避ける**単一読み（read-once）**の
 * 規律、および公開バレルへ載せる判断基準は `context.ts` 冒頭の節に記す（ここでは重複させない）。
 */

import { resolveBinding } from './context.js';
import type { NonceContext, NonceFlow } from './types.js';

/**
 * **解決済みの** flow と束縛値から拒否リストのキー前半を組み立てる。
 *
 * 束縛値（clientId / issuer / audience / jkt）は外部由来で任意の文字を含み得るため、**必ず
 * `encodeURIComponent` でエスケープする**。素の連結にすると、`|` を含む `clientId` を名乗る攻撃者の
 * コンテキストが `NonceCapacityManager` の `enforceCapacity` の `startsWith` によるスコープ判定で
 * 別コンテキストの容量枠に混入し、
 * 被害者の消費済みエントリを LRU 退避させてリプレイを通せる。`encodeURIComponent` は `:` も `|` も
 * パーセントエンコードするため、区切り文字は境界にしか現れない。
 *
 * `ctx` ではなく値を受けるのは、束縛照合を通した**その読み取り結果**からキーを組み立てさせるため。
 * `contextKeyOf` との使い分けと、本関数を公開バレルへ載せる判断基準は冒頭の節に記す。
 *
 * @param flow `resolveBinding` が解決した flow。
 * @param value `resolveBinding` が読んだ束縛値。
 * @returns `<flow>:<エスケープ済み束縛値>` 形式のキー。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.1 で `@stable` 昇格予定）。
 */
export function contextKeyFrom(flow: NonceFlow, value: string): string {
  return `${flow}:${encodeURIComponent(value)}`;
}

/**
 * 容量スコープの接頭辞。エントリキーは常に「この接頭辞 ＋ nonce」である（LRU スコープ判定は
 * 本接頭辞の `startsWith` で行う）。公開バレルには載せない（`store.ts` の不変条件用ヘルパ）。
 *
 * @param flow `resolveBinding` が解決した flow。
 * @param value `resolveBinding` が読んだ束縛値。
 * @returns `<contextKey>|` 形式の接頭辞。
 */
export function entryKeyPrefixFrom(flow: NonceFlow, value: string): string {
  return `${contextKeyFrom(flow, value)}|`;
}

/**
 * **解決済みの** flow と束縛値から拒否リストのエントリキーを組み立てる。
 *
 * 束縛値は `contextKeyFrom` でエスケープ済み、nonce 値には base64url / UUID の文字種しか現れない
 * （`assertWellFormedNonce` で保証）ため、区切り文字 `|` は境界にしか現れず衝突しない。
 * `ctx` ではなく値を受けるのは、束縛照合を通した**その読み取り結果**からキーを組み立てさせるため。
 * `entryKeyOf` との使い分けと公開バレルへ載せる判断基準は冒頭の節に記す。容量スコープの接頭辞も併せて
 * 必要な呼び出し元（`store.ts` の `put` / `checkAndUse`）は `entryKeyPrefixFrom` で接頭辞を 1 度だけ
 * 組み立て、そこへ nonce を継ぐ（同じ文字列を 2 度組み立てない）。
 *
 * @param nonce nonce 値。
 * @param flow `resolveBinding` が解決した flow。
 * @param value `resolveBinding` が読んだ束縛値。
 * @returns エントリキー。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.1 で `@stable` 昇格予定）。
 */
export function entryKeyFrom(nonce: string, flow: NonceFlow, value: string): string {
  return `${entryKeyPrefixFrom(flow, value)}${nonce}`;
}

/**
 * コンテキストを拒否リストのキー前半に正規化する（`contextKeyFrom` の `ctx` 版）。
 *
 * 呼び出しごとに `resolveBinding` が走るため、**1 回だけキーを組み立てる**用途に限る。複数回
 * 組み立てる場合、および束縛照合と併用する場合は `resolveBinding` ＋ `contextKeyFrom` を使う。
 *
 * @param ctx 発行コンテキスト。
 * @returns `<flow>:<エスケープ済み束縛値>` 形式のキー。
 * @throws `NONCE_BINDING_MISMATCH`（4012）`flow` / 束縛メンバを own 読みできない場合。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.1 で `@stable` 昇格予定）。
 */
export function contextKeyOf(ctx: NonceContext): string {
  const { flow, value } = resolveBinding(ctx);
  return contextKeyFrom(flow, value);
}

/**
 * 拒否リストのエントリキーを組み立てる（`entryKeyFrom` の `ctx` 版）。
 *
 * 呼び出しごとに `resolveBinding` が走るため、**1 回だけキーを組み立てる**用途に限る。複数回
 * 組み立てる場合、および束縛照合と併用する場合は `resolveBinding` ＋ `entryKeyFrom` を使う。
 *
 * @param nonce nonce 値。
 * @param ctx 発行コンテキスト。
 * @returns エントリキー。
 * @throws `NONCE_BINDING_MISMATCH`（4012）`flow` / 束縛メンバを own 読みできない場合。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.1 で `@stable` 昇格予定）。
 */
export function entryKeyOf(nonce: string, ctx: NonceContext): string {
  const { flow, value } = resolveBinding(ctx);
  return entryKeyFrom(nonce, flow, value);
}
