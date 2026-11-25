/**
 * 発行入力（`claims` / `opts`）の正規化スナップショットと、それを表す**公称型**。
 *
 * ## 何を構造的に防ぐか
 *
 * `build-vc.ts` は `opts` を `ownProperty`（`Object.hasOwn` 判定）で読む。この読み方は
 * **非列挙の own プロパティも読み**、**own アクセサを読むたびに再評価する**。したがって
 * 「検査器が見た値」と「署名済み VC に載る値」は、同じキーを指していてもずれ得る。
 *
 * 1. **キー列挙範囲の非対称**: 走査器が `Object.keys`（own かつ列挙可能）だけを辿ると、
 *    `Object.defineProperty(opts, 'evidence', { value, enumerable: false })` が検査を素通りして
 *    VC に載る。
 * 2. **アクセサの二重評価**: `get evidence()` は検査時と生成時で別の値を返し得る
 *    （1 回目は無害な値、2 回目に Art.9 属性）。
 *
 * 対策そのものは「入力を一度だけ読んでスナップショットし、検査と生成に同じ値を使う」ことで、
 * これは `validate-issue-input.ts` が既に行っている。ただしそれだけでは**規約**にすぎず、
 * 将来の呼び出し側が生の `IssueOptions` を `buildCredential` に直接渡せばずれは即座に復活する。
 * 本モジュールはその抜け道を型で塞ぐ。
 *
 * ## ブランドは型だけの存在にする（重要）
 *
 * {@link NormalizedClaims} / {@link NormalizedIssueOptions} は、本モジュールの正規化関数だけが
 * 生成できる公称型（branded type）である。ブランドキーは `declare const` された
 * モジュールプライベートな `unique symbol` なので、**型検査にしか存在せず実行時のプロパティには
 * 決してならない**。ここは飾りではない。ブランドが実プロパティだと、
 *
 * - `claims` は `build-vc.ts` がスプレッドで `credentialSubject` へ展開するため、ブランドが
 *   そのまま**署名済み VC に載る**。
 * - Art.9 走査器（`special-category.ts`）がブランドキーを属性名として走査する。
 *
 * という副作用が出る。`declare const` は宣言のみで実体を持たないため、この型は
 * 「正規化関数を通った」という事実だけを表す。
 *
 * ## 2 つの正規化関数でキー範囲が違う理由
 *
 * スナップショットの範囲は「その値が下流でどう読まれるか」に揃える。広くても狭くても壊れる。
 *
 * - {@link normalizeClaims} は **own かつ列挙可能**（`{ ...claims }`）だけを写す。`build-vc.ts` は
 *   `claims` をスプレッドで展開するので、非列挙のクレームはそもそも VC に載らない。ここを
 *   `Object.getOwnPropertyNames` に広げると、**今まで VC に載らなかった非列挙クレームが
 *   `credentialSubject` に載る**ようになる（挙動変更であり、範囲を揃える目的にも反する）。
 * - {@link normalizeIssueOptions} は **own の全文字列キー**（`Object.getOwnPropertyNames`。
 *   非列挙も含む）を写す。`ownProperty` が読む範囲がこれだからで、狭めると非列挙 own
 *   プロパティが検査を素通りする。
 *
 * どちらも各プロパティを**ちょうど 1 回だけ**読むため、own アクセサの評価は 1 回で終わり、
 * 結果は通常のデータプロパティに畳まれる。またどちらも **own のみ**でプロトタイプ鎖は辿らないので、
 * 継承値を拾わない既存の方針は変わらない。
 *
 * ## 保証の範囲（深いスナップショット）
 *
 * トップレベルのキー範囲は上記のとおり読み手に合わせて分けるが、**写した値は入れ子まで畳む**
 * 1 段の写しだけだと入れ子のオブジェクトは参照ごとコピーされ、その中の own
 * アクセサが走査時と署名時で 2 回評価されて別の値を返し得たためである。畳み方（何を複製し何を
 * 参照のまま残すか・記述子の引き継ぎ）は `internal/prototype-safety/deep-snapshot.ts` に切り出してある（DID Log 経路の
 * `identity/normalized-log-input.ts` と共有するため `internal/` 直下に置く）。
 */

import { deepSnapshot } from '../../prototype-safety/deep-snapshot.js';
import { defineDataProperty } from '../../prototype-safety/define-data-property.js';
import type { IssueOptions } from './issue-options.js';

/**
 * 公称型のブランドキー。
 *
 * `declare const` なので**実行時には存在しない**（値を生成しないアンビエント宣言）。
 * export しないため、本モジュールの外でこのキーを持つ型を作ることはできない。
 */
declare const NORMALIZED_ISSUE_INPUT: unique symbol;

/** 正規化済みのクレーム（own かつ列挙可能。`build-vc.ts` のスプレッドと同一範囲）。 */
export type NormalizedClaims = Readonly<Record<string, unknown>> & {
  readonly [NORMALIZED_ISSUE_INPUT]: 'claims';
};

/** 正規化済みの発行オプション（own の全文字列キー。`ownProperty` と同一範囲）。 */
export type NormalizedIssueOptions = IssueOptions & {
  readonly [NORMALIZED_ISSUE_INPUT]: 'issue-options';
};

/**
 * クレームを正規化スナップショットへ写す（own かつ列挙可能なプロパティのみ）。
 *
 * アクセサは 1 回だけ評価され、結果は通常のデータプロパティになる。範囲を
 * `build-vc.ts` のスプレッドに揃えてあるため、走査した対象と `credentialSubject` に載る対象が
 * 一致する。入れ子のアクセサも同時に畳む。
 *
 * @param claims 呼び出し側から渡された生のクレーム。
 * @returns 正規化済みクレーム。
 */
export function normalizeClaims(claims: Readonly<Record<string, unknown>>): NormalizedClaims {
  // スプレッドでトップレベルを 1 回だけ読んでキー範囲を確定させ、その**写しを**深く畳む。
  // 生の `claims` を `deepSnapshot` に直接渡さないのは、それがキー範囲を own 全体へ広げてしまい、
  // 非列挙のクレームまで走査対象に入る（上記のとおり範囲を揃える方針に反する）ため。
  // ブランドは型だけの存在なので、実体はプレーンなオブジェクトのまま。公称型を名乗るための
  // キャストは本モジュール内のこの 1 箇所に閉じる（外部からは生成できない）。
  return deepSnapshot({ ...claims }) as NormalizedClaims;
}

/**
 * 発行オプションを正規化スナップショットへ写す（own の全文字列キー。非列挙も含む）。
 *
 * 各プロパティを 1 回だけ読むため、own アクセサの評価も 1 回で終わる。`ownProperty`
 * （`Object.hasOwn`）が読む範囲と一致するので、検査を素通りして VC に載るキーが残らない。
 * 入れ子のアクセサも同時に畳む。`evidence` / `termsOfUse` / `refreshService` は
 * オブジェクトごと VC に写るため、ドリフトの実害はむしろ入れ子側に出る。
 *
 * @param opts 呼び出し側から渡された生の発行オプション。
 * @returns 正規化済み発行オプション。
 */
export function normalizeIssueOptions(opts: IssueOptions): NormalizedIssueOptions {
  const snapshot: Record<string, unknown> = {};
  for (const key of Object.getOwnPropertyNames(opts)) {
    // `Object.defineProperty` で定義する（生代入 `snapshot[key] = …` は使わない）。
    // `snapshot` は `{}` リテラルなので `__proto__` の setter を継承しており、`opts` が own の
    // `__proto__` データプロパティを持つと生代入が**その setter を発火させる**。結果、
    // (1) そのオプションがスナップショットから静かに消え、(2) `snapshot` のプロトタイプが
    // 攻撃者のオブジェクトになるため `deepSnapshot` の `isPlainContainer` 判定が偽になり、
    // **入れ子を畳まずにそのまま返す**（＝ 入れ子の保持と 10607 Art.9 ドリフト防御が
    // `opts` について丸ごと無効化される）。`defineProperty` は `__proto__` でも通常の own
    // データプロパティを作るのでどちらも起きない（`credential/sdjwt/claims.ts` の
    // `defineClaim` と同じ理由）。姉妹経路の `normalizeClaims` はスプレッド
    // （CreateDataProperty）、`identity/normalized-log-input.ts` は `defineProperty` で、
    // いずれも元から安全である。
    defineDataProperty(snapshot, key, (opts as Record<string, unknown>)[key]);
  }
  // ブランドは実行時に存在しないため素の記録型とは「重なりがない」と判定される。実体は
  // プレーンなオブジェクトのまま公称型を名乗らせる（キャストは本モジュール内に閉じる）。
  return deepSnapshot(snapshot) as NormalizedIssueOptions;
}
