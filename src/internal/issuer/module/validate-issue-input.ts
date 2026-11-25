/**
 * `IssuerModule.issueVC` の入力検証と正規化。
 *
 * facade 本体から切り出しているのは、発行の**副作用が始まる前**に済ませるべき検査を 1 箇所に
 * 集めるためである。`issueVC` は検証のあとに Token Status List のビットインデックスを確保し
 * （`allocateStatus`）、`vcId` → `idx` の対応を記録する。この確保は巻き戻せないため、あとから
 * 発行を拒否すると**そのインデックスは誰にも紐付かないまま永久に消費される**。したがって
 * 拒否条件はすべて確保より前で fail closed に判定する。
 *
 * Art.9 の検査対象は `claims` だけでは足りない。`build-vc.ts` は `opts` の複数フィールドを
 * そのまま VC へ写すため、そこにも任意の属性名が入り得る（`EvidenceEntry` / `TermsOfUseEntry` は
 * `[key: string]: unknown` を許し、`RefreshServiceConfig` はオブジェクトごと写される）。個別
 * フィールドを列挙して検査する設計は**フィールドが増えるたびに漏れる**ため採らない。
 *
 * ## 検査した値と VC に載る値を一致させる（スナップショット）
 *
 * 「走査した対象」と「実際に VC へ写る対象」がずれると、ガードを通過した入力から Art.9 属性が
 * 署名済み VC に載る。ずれは「非列挙 own プロパティの見落とし」と「own アクセサの二重評価」の
 * 2 経路で起きるため、本モジュールは入力を**一度だけ読んでスナップショットし、検査と生成の
 * 双方に同じ値を使う**。スナップショットの機構（範囲の決め方・ブランド型による強制）は
 * `normalized-issue-input.ts` に切り出してあり、本モジュールはそれを適用するだけである。
 *
 * `buildCredential` の引数型が正規化済みの公称型になっているため、この不変条件は規約ではなく
 * **型で強制される**（生の `IssueOptions` は渡せない）。スナップショットは**入れ子まで畳む**ので
 * （畳み方は `internal/prototype-safety/deep-snapshot.ts`）、保証はトップレベルの own プロパティに
 * 留まらず深さ 1 以上の own アクセサにも及ぶ。残る限界は `deep-snapshot.ts` が「既知の限界」として
 * 明記する 2 点である。**第 1** は、意味論保全のため参照のまま残す対象（プロトタイプが
 * `Object.prototype` / `null` / `Array.prototype` のいずれでもない `Date` / クラスインスタンス /
 * `Array` サブクラス等、およびそれらを包む `Proxy`）の own アクセサが畳まれないこと。
 * **第 2** は、畳み中に入れ子の own throwing getter が投げた**生の例外がそのまま伝播する**こと。
 * この場合、呼び出し側には元の例外が伝播する。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isValidDidFormat } from '../../identity/did-format.js';
import { assertNoSpecialCategoryInIssuedContent } from '../../special-category.js';
import type { IssueOptions } from './issue-options.js';
import {
  type NormalizedClaims,
  type NormalizedIssueOptions,
  normalizeClaims,
  normalizeIssueOptions,
} from './normalized-issue-input.js';

/** 検証済み・スナップショット済みの発行入力（検査と VC 生成の双方がこれを使う）。 */
export interface ValidatedIssueInput {
  /** クレームのスナップショット（own かつ列挙可能。`build-vc.ts` のスプレッドと同一範囲）。 */
  readonly claims: NormalizedClaims;
  /** 発行オプションのスナップショット（own。`ownProperty` の `Object.hasOwn` と同一範囲）。 */
  readonly opts: NormalizedIssueOptions;
}

/**
 * `issueVC` の引数を検証し、以降の処理で使うスナップショットを返す。
 *
 * 発行する VC に Art.9 の特別カテゴリ属性が含まれていれば、{@link assertNoSpecialCategoryInIssuedContent} が `10607` で拒否する。
 *
 * **戻り値を必ず使うこと。** 呼び出し側が元の `claims` / `opts` を使い続けると、上記の
 * アクセサ二重評価が復活して検査した値と VC に載る値がずれる。`buildCredential` は正規化済みの
 * 公称型しか受け取らないため、生の入力を渡し直す経路は型検査で落ちる。
 *
 * @param holderDID VC の保持者 DID。
 * @param claims VC のクレーム。
 * @param opts 発行オプション。VC へ写るフィールドを持つため、オブジェクトごと検査対象にする。
 * @returns 検証済みの `claims` / `opts` スナップショット。
 * @throws Holder DID の形式が不正な場合（VericertsError、code `3006`）、
 *         クレームまたは発行オプションが Art.9 特別カテゴリ属性を含む場合（code `10607`）。
 */
export function validateIssueInput(
  holderDID: string,
  claims: Readonly<Record<string, unknown>>,
  opts: IssueOptions,
): ValidatedIssueInput {
  if (!isValidDidFormat(holderDID)) {
    // DID 文字列そのものは例外に含めない。
    throw new VericertsError(ErrorCodes.HOLDER_DID_FORMAT_INVALID);
  }
  // `claims` はスプレッド（own かつ列挙可能）で展開されるため同じ範囲で、`opts` は
  // `ownProperty`（own なら非列挙も可）で読まれるため own 全体でスナップショットする
  // （範囲を分ける理由は `normalized-issue-input.ts` のモジュール JSDoc 参照）。
  const claimsSnapshot = normalizeClaims(claims);
  const optsSnapshot = normalizeIssueOptions(opts);
  // 属性名・値はいずれも例外に含めない（属性名だけでも Art.9 該当を示唆するため）。
  // `opts` はフィールドを列挙せずオブジェクトごと渡す。VC に載る `IssueOptions` のフィールドは
  // すべて呼び出し側由来のデータであり、まとめて走査すれば `evidence` / `termsOfUse` /
  // `refreshService` に加えて**後から増えたフィールド**も自動的に覆われる（列挙方式で繰り返した
  // 「1 つ書き忘れる」失敗モードがなくなる）。配列でまとめて渡してよいのは、走査器が配列の
  // 添字を属性名として扱わないためである。
  assertNoSpecialCategoryInIssuedContent([claimsSnapshot, optsSnapshot]);
  return { claims: claimsSnapshot, opts: optsSnapshot };
}
