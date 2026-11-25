/**
 * 失効伝搬ポリシーの正規化と優先順位解決。
 *
 * 解決に使う 2 つの入力はいずれも**非信頼な外部値**で、`verify.ts` は cast だけで読み出す。
 *
 * - `revocationPropagation`: VC 本文（Issuer 側の宣言）。パース境界を通った任意の JSON 値。
 * - `opts.policy`: 検証者が渡すオプション。型の無い JS からは任意の値が届く。
 *
 * ここで列挙値へ正規化してから比較することで、判定側（`applyPolicy`）が扱う値を必ず
 * `ChainPolicy` に閉じる。`verify.ts` から分離しているのはファイル行数上限（300 行）のため。
 */

import type { ChainPolicy } from './types.js';

/** 妥当な `ChainPolicy` の許可集合。 */
const CHAIN_POLICIES: ReadonlySet<string> = new Set<ChainPolicy>([
  'permissive',
  'custom',
  'strict',
]);

/**
 * ポリシーの保守度。大きいほど失効を伝搬させる側。
 *
 * プロトタイプを持たないオブジェクト（`Object.create(null)`）として構築する。引く鍵は
 * `normalizeChainPolicy` で許可集合に閉じているため `Object.prototype` には当たらないが、
 * 多層防御として `null` プロトタイプを維持する（`revocationPropagation: "constructor"` が
 * `Object.prototype.constructor`（関数）にヒットして「未知は strict」のフォールバックを
 * すり抜け、`opts.policy` 側が無条件に勝った過去の fail-open の回帰防止）。
 */
const POLICY_RANK: Readonly<Record<ChainPolicy, number>> = Object.assign(
  Object.create(null) as Record<ChainPolicy, number>,
  {
    permissive: 0,
    custom: 1,
    strict: 2,
  },
);

/** 値が妥当な `ChainPolicy` か（許可集合による判定）。 */
function isChainPolicy(value: unknown): value is ChainPolicy {
  return typeof value === 'string' && CHAIN_POLICIES.has(value);
}

/**
 * 非信頼な値を `ChainPolicy` へ正規化する。未設定は `undefined`（＝宣言なし）、列挙外は最も
 * 保守的な `strict` に倒す（fail-closed）。
 *
 * 列挙外を `undefined`（宣言なし）に倒してはならない。細工した VC に列挙外の値を入れるだけで
 * Issuer の宣言を消せてしまい、検証者の `policy: "permissive"` が無条件に勝つ（fail-open）。
 *
 * **許可集合で判定する理由**: 以前は `POLICY_RANK[policy]` の計算プロパティキーで
 * 直接引いていたが、キーへの変換（`ToPropertyKey`）は `ToPrimitive` を伴う。パース境界
 * （`parseJsonWithoutPrototype`）を通った VC 本文の `revocationPropagation: {}` は `toString` /
 * `valueOf` を持たないため `TypeError: No default value` になり、`?? POLICY_RANK.strict`
 * （未知は strict）という **fail-closed のフォールバック自体が throw で迂回**されて
 * `verifyCredentialChain` が生の例外を漏らしていた。`typeof === 'string'` だけでは列挙外の
 * 文字列を strict へ倒せないため、許可集合で判定する。
 */
export function normalizeChainPolicy(value: unknown): ChainPolicy | undefined {
  if (value === undefined) {
    return undefined;
  }
  return isChainPolicy(value) ? value : 'strict';
}

/**
 * 適用するポリシーを決める。
 *
 * VC 埋め込みの宣言（Issuer 側）と `opts.policy`（検証者側）の**より保守的な方**を採る。どちらか
 * 一方を無条件に優先すると、それぞれ逆向きの fail-open が生じるため:
 *
 * - `opts.policy` を優先すると、Issuer が署名済み VC に `revocationPropagation: "strict"` を埋め込んで
 *   いても検証者が `policy: "permissive"` を渡すだけで失効伝搬を無効化できる。
 * - VC の宣言を優先すると、Issuer が `"permissive"` を宣言した VC に対して検証者が `policy: "strict"`
 *   を渡しても伝搬を強制できない。
 *
 * 保守度は `permissive < custom < strict`。`custom` を中間に置くのは、`customHandler` が伝搬を
 * 許容し得る（`true` を返せる）一方で `strict` は無条件に無効化するため。どちらも無ければ `strict`
 * （fail-closed）に倒す。
 *
 * @param declared VC 本文の `revocationPropagation`（未検証の値）。
 * @param requested 検証者が渡した `opts.policy`（未検証の値）。
 * @returns 適用する `ChainPolicy`。
 */
export function resolveChainPolicy(declared: unknown, requested: unknown): ChainPolicy {
  const declaredPolicy = normalizeChainPolicy(declared);
  const requestedPolicy = normalizeChainPolicy(requested);
  if (declaredPolicy === undefined) {
    return requestedPolicy ?? 'strict';
  }
  if (requestedPolicy === undefined) {
    return declaredPolicy;
  }
  return POLICY_RANK[declaredPolicy] >= POLICY_RANK[requestedPolicy]
    ? declaredPolicy
    : requestedPolicy;
}
