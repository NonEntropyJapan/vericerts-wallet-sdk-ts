/**
 * Credential Chain の構築。
 *
 * 親 VC を根拠に派生 VC を構築し、監査可能なチェーンエッジ（子 → 親）を `derivedFrom` として形成する。
 * 本モジュールは派生 VC の構築のみを行う。署名・発行には `issueCredential` を使う。
 *
 * 発行時の GDPR Art.9 ガードの走査対象は `child` と `revocationPropagation` だけである。
 * 親由来で戻り値に載るのは `derivedFrom` に入る `parent.id` 文字列のみで、親の属性は発行されない。
 *
 * ## 検査した値と戻り値に載る値を一致させる（スナップショット）
 *
 * 入力を検査時と生成時に 2 回読むと、own アクセサ（`get credentialSubject()`）が 1 回目に無害な値・
 * 2 回目に Art.9 属性を返すことで、ガードを通過した入力から禁止属性が派生 VC に載る。
 * `issuer/module/validate-issue-input.ts` と同じく、**入力を一度だけ読んでスナップショットし、
 * 検査と生成の双方に同じ値を使う**ことでこの経路を塞ぐ。
 *
 * スナップショットは**入れ子まで畳む**。トップレベルだけを写すと入れ子の
 * オブジェクトは参照ごとコピーされ、その中の own アクセサが Art.9 走査時（1 回目）と派生 VC の
 * 直列化時（2 回目）で別の値を返せた。畳み方（何を複製し何を参照のまま残すか・記述子の引き継ぎ・
 * 循環参照）は発行系・DID Log 経路と共有する `internal/prototype-safety/deep-snapshot.ts` が決める。
 * **既知の限界も同モジュールと共通**である: (1) プロトタイプが `Object.prototype` / `null` /
 * `Array.prototype` のいずれでもない対象（`Date` / クラスインスタンス / `Array` サブクラス等、
 * およびそれらを包む `Proxy`）の own アクセサは畳まれない、(2) 畳み中に入れ子の own throwing
 * getter が投げた**生の例外はそのまま伝播する**（`10607` へ正規化しない）。
 *
 * セキュリティ: 例外 message / context に VC 本文を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { deepSnapshot } from '../../prototype-safety/deep-snapshot.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { assertNoSpecialCategoryInIssuedContent } from '../../special-category.js';
import type { VerifiableCredential } from '../vc/vc.js';
import type { ChainPolicy, DerivedCredentialInput } from './types.js';

/**
 * 親 VC を根拠に派生（子）VC を構築し `derivedFrom` に親 ID をセットする。
 *
 * 親 VC は `id` を持つ必要がある（親エッジは親 VC の ID を指す URI のため）。`revocationPropagation` を
 * 指定すると子 VC に埋め込み、検証時の既定ポリシーとなる。
 *
 * 入力に残った親エッジ（`derivedFrom` / `basedOn` / `supersedes` / `amends`）は取り除く。型上は
 * `DerivedCredentialInput` で除外されているが、実行時に混入すると意図しない親エッジとして
 * チェーン検証に辿られるため、構築時に落とす。
 *
 * @param parent 根拠となる親 VC（`id` 必須）。
 * @param child 派生 VC の本体（親エッジを除く）。
 * @param revocationPropagation 失効伝搬ポリシー（省略時は VC に埋め込まない）。
 * @returns `derivedFrom` のみを親エッジとして持つ派生 VC。
 * @throws 親 VC に `id` がない / 文字列でない場合（VericertsError、code `3002`）、子 VC または
 *         失効伝搬ポリシーが Art.9 特別カテゴリ属性を含む場合（code `10607`）。
 *         親 VC は走査しない。**入れ子に own throwing getter を含む `child` を渡した場合は、
 *         その getter が投げた例外が `VericertsError` へ正規化されずそのまま伝播する**
 *         （`internal/prototype-safety/deep-snapshot.ts` の既知の限界）。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export function buildDerivedCredential(
  parent: VerifiableCredential,
  child: DerivedCredentialInput,
  revocationPropagation?: ChainPolicy,
): VerifiableCredential {
  // `parent.id` は**自身のプロパティに限って**一度だけ読む。検証と
  // `derivedFrom` への格納で同じ `parentId` を使い、検証した値と戻り値がずれないようにする。
  // 鎖読みだと `id` を持たない親 VC が `Object.prototype.id` の汚染値を拾い、`3002` のガードを
  // 素通りして**汚染値がそのまま `derivedFrom`（監査可能なチェーンエッジ）に格納される**。
  // 併せて型を明示的に検査する。従来の `parentId.length === 0` は汚染値が非文字列のとき
  // `undefined === 0` が false になるため**ガードが二重に素通り**していた。
  const parentId = ownProperty<unknown>(parent, 'id');
  if (typeof parentId !== 'string' || parentId.length === 0) {
    // 親 ID なしではチェーンエッジ（子 → 親）を確定できないため構造不正とする。
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  // 子 VC も同様に一度だけ読む。列挙範囲にスプレッド（own かつ列挙可能）を選ぶのは、戻り値を
  // 組み立てる下の `...rest` がまさにその範囲だからである。走査範囲と戻り値に載る範囲が完全に
  // 一致するため、「検査した値と戻り値に載る値がずれる」余地が原理的に無くなる。
  // 非列挙の own プロパティは走査対象から外れるが、同じ理由で戻り値にも載らないので
  // 「Art.9 属性が発行物に載らない」不変条件は保たれる。これはガードの緩和ではなく、検査範囲と
  // 反映範囲を一致させた帰結である（`validate-issue-input.ts` が `opts` に
  // `Object.getOwnPropertyNames` を使うのは、あちらの VC 生成側が `Object.hasOwn` 判定で非列挙
  // own も読むためであり、「範囲を合わせる」という原則は同じ）。
  // 写したうえで入れ子まで畳む。生の `child` を `deepSnapshot` へ直接渡さないのは、
  // それがキー範囲を own 全体（非列挙を含む）へ広げてしまい、下の `...rest` が載せない非列挙
  // プロパティまで走査対象に入る（＝ 走査範囲と反映範囲を一致させる方針に反する）ためである。
  const childSnapshot = deepSnapshot({ ...child }) as VerifiableCredential;
  // `revocationPropagation` は文字列 union の `ChainPolicy` かつパラメータ束縛なので、既に単一の
  // 値でありアクセサとして再評価される余地がない。追加のスナップショットは不要である。
  // 発行時の Art.9 ガード。本関数は署名しないため、
  // `IssueChainedCredential` の手順どおり `issueCredential` へ渡して発行すれば `vc/issue.ts`
  // のガードに覆われるが、`IssuerModule.issueVC` が「署名せず VC を返す時点で」拒否するのと対称に
  // し、戻り値を署名せずそのまま保存・転送する使い方も覆うため、構築前に拒否する。
  // `parent` を走査しないのは、本関数が戻り値に載せる親由来のデータが `derivedFrom` に入る
  // `parent.id` 文字列だけであり（判定は属性名に対して行い値は見ない）、親の他の属性は一切発行
  // されないためである。`derivedFrom` の参照先は他者発行の VC であり本 SDK の Issue 時ガードの
  // 守備範囲外でもある。親まで走査すると、外部発行 EUDI PID（`given_name` / `family_name` /
  // `birth_date` を必須で持つ）を親にしたデータ最小化派生が子の内容に
  // よらず拒否され、チェーン機能が使えなくなる。
  // 例外に属性名・VC 本文は載せない。
  assertNoSpecialCategoryInIssuedContent([childSnapshot, revocationPropagation]);
  const {
    derivedFrom: _derivedFrom,
    basedOn: _basedOn,
    supersedes: _supersedes,
    amends: _amends,
    ...rest
  } = childSnapshot;
  return {
    ...rest,
    derivedFrom: parentId,
    ...(revocationPropagation !== undefined ? { revocationPropagation } : {}),
  };
}
