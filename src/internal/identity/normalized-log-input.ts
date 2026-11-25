/**
 * DID Log へ載る入力の正規化スナップショットと、それを表す**公称型**。
 * 発行系の先例は `issuer/module/normalized-issue-input.ts`。
 *
 * ## 何を構造的に防ぐか
 *
 * `webvh/lifecycle/lifecycle.ts` は呼び出し側のオプションを `ownProperty`
 * （`Object.hasOwn` 判定）で読む。この読み方は **own アクセサを読むたびに再評価する**ため、
 * 同じキーを 2 度読むと「検査器が見た値」と「DID Log に載る値」がずれ得る。
 *
 * 1. **ガードの迂回**: `get document()` / `get state()` が 1 回目に無害な値、2 回目に Art.9
 *    属性・別 DID を返すと、Art.9 検査（code `10601`）・state.id 継続性検査を素通りした値が
 *    Log entry に載る。
 * 2. **SCID と state の不一致**: 初版生成では state 組み立てが SCID 用プレースホルダ entry と
 *    最終 entry の 2 回走る。各フィールドがアクセサだと、**SCID が、その SCID の下で公開される
 *    文書とは別の文書に対して計算される**。
 *
 * DID Log は公開・追記専用でありハッシュチェーンで確定するため、載ってしまえば取り消せない。
 * 対策は「入力を一度だけ読んでスナップショットし、検査・SCID 計算・entry 搭載のすべてに同じ値を
 * 使う」ことだが、それだけでは**規約**にすぎない。将来の呼び出し側が生のオプション値を
 * state 組み立てへ直接渡せばずれは即座に復活する。本モジュールはその抜け道を型で塞ぐ。
 *
 * ## ブランドは型だけの存在にする（重要）
 *
 * {@link NormalizedLogInput} は本モジュールの {@link normalizeLogInput} だけが生成できる公称型
 * （branded type）である。ブランドキーは `declare const` されたモジュールプライベートな
 * `unique symbol` なので、**型検査にしか存在せず実行時のプロパティには決してならない**。
 * ここは飾りではない。ブランドが実プロパティだと、
 *
 * - スナップショットはそのまま Log entry へ載るため、ブランドが **canonicalize されて
 *   `versionId` にハッシュされ、公開される DID Log に焼き付く**、
 * - Art.9 走査器（`special-category.ts`）がブランドキーを属性名として走査する、
 *
 * という副作用が出る。`declare const` は宣言のみで実体を持たないため、この型は
 * 「正規化関数を通った」という事実だけを表す。
 *
 * ## 列挙可能性を保持する理由（重要）
 *
 * スナップショットは own の**全**文字列キー（`Object.getOwnPropertyNames`）を写しつつ、各キーの
 * **元の列挙可能性をそのまま引き継ぐ**。写す範囲と列挙可能性のどちらを崩しても、下流の 2 つの
 * 走査範囲が元の入力とずれる。
 *
 * - **own 全域から見る側**: Art.9 走査（`special-category.ts` は
 *   `Object.getOwnPropertyNames`）と、state 組み立てのフィールド読み出し（`ownProperty` =
 *   `Object.hasOwn`）。列挙可能かどうかを問わない。
 * - **own かつ列挙可能から見る側**: `canonicalize`（`webvh/codec.ts` は `Object.keys`）と
 *   JSON 化。Log entry に実際に焼き付く範囲。
 *
 * `Object.getOwnPropertyNames` で写して全部を列挙可能にすると、**これまで canonical 形に現れ
 * なかった非列挙プロパティが公開 Log に載る**。逆に spread（`{ ...value }`）だけで写すと非列挙の
 * own プロパティが落ち、**Art.9 走査の範囲が狭まって 10601 が発生しなくなる**（own 非列挙の
 * `healthData` を持つ入力が素通りする）。列挙可能性を保ったまま畳めば両方の範囲が同時に
 * 元の入力と一致し、挙動を一切変えずにアクセサ再評価だけを潰せる。
 *
 * 各プロパティは**ちょうど 1 回だけ**読むため、own アクセサの評価は 1 回で終わり、結果は通常の
 * データプロパティに畳まれる。また **own のみ**でプロトタイプ鎖は辿らないので、継承値を拾わない
 * 既存の方針は変わらない。
 *
 * ## 保証の範囲（深いスナップショット）
 *
 * トップレベルのキー範囲と列挙可能性は上記のとおり読み手に合わせて写すが、**写した値は入れ子まで
 * 畳む**。1 段の写しだけだと入れ子のオブジェクトは参照ごとコピーされ、その中の own
 * アクセサが Art.9 走査時と `canonicalize` 時で 2 回評価されて別の値を返し得た。
 *
 * 入れ子のアクセサが「値」だけを差し替える形なら Art.9 ガード（10601）は元々外れない。走査器
 * （`special-category.ts`）は各階層の**キー名しか判定材料にせず**、値は入れ子を辿るためだけに
 * 読むからである。塞ぐ必要があったのは**キー集合そのものが読み取りごとに変わる場合**で、入れ子の
 * アクセサが走査時と `canonicalize` 時で別のキーを持つオブジェクトを返せば、走査で見えなかった
 * Art.9 属性が公開・追記専用の DID Log に焼き付いた。深く畳めば走査器と `canonicalize` が**同じ
 * 確定済みデータ**を見るため、この経路が成立しなくなる。
 *
 * 畳み方（何を複製し何を参照のまま残すか・記述子の引き継ぎ・循環参照）は発行系と共有する
 * `internal/prototype-safety/deep-snapshot.ts` が決める。**既知の限界もそこと同一**である: プロトタイプが
 * `Object.prototype` / `null` / `Array.prototype` のいずれでもない対象（`Date` / `Map` / `Set` /
 * TypedArray / 一般のクラスインスタンス / `Array` サブクラス、およびそれらを包む `Proxy`）は
 * 意味論保全のため参照のまま残すので、それらが own アクセサを持つ場合の二重評価は残る。
 * また畳み中に入れ子の own throwing getter が投げた**生の例外はそのまま伝播する**。
 * この例外は公開 API まで伝播し、エラーコード 10601 / 2001 には変換されない。
 * **プレーンなコンテナを `getPrototypeOf` トラップ無しで包む `Proxy` はこの限界に入らない**
 * （複製対象になるため、`ownKeys` を差し替えて読み取りごとに違うキー集合を返す `Proxy` でも
 * トラップは 1 度だけ呼ばれ、確定値に畳まれる）。**`getPrototypeOf` トラップを持つ `Proxy` は
 * この限界に入る**（判定が「プレーンでない」に倒れ参照のまま残る。`Date` を包む `Proxy` と
 * 区別できないための意図した fail-closed）。DID Document は JSON 由来のプレーンなデータであり、参照のまま
 * 残る型を入れ子に置く利用は想定しないため、意識的なトレードオフとして受け入れる。
 */

import { deepSnapshot } from '../prototype-safety/deep-snapshot.js';
import { defineDataProperty } from '../prototype-safety/define-data-property.js';

/**
 * 公称型のブランドキー。
 *
 * `declare const` なので**実行時には存在しない**（値を生成しないアンビエント宣言）。
 * export しないため、本モジュールの外でこのキーを持つ型を作ることはできない。
 */
declare const NORMALIZED_LOG_INPUT: unique symbol;

/**
 * DID Log に載る入力の正規化スナップショット。
 *
 * own の全文字列キーを 1 度ずつ読み、元の列挙可能性を保ったままデータプロパティへ畳んだ値。
 * {@link normalizeLogInput} だけが生成できる。
 */
export type NormalizedLogInput<T extends object> = T & {
  readonly [NORMALIZED_LOG_INPUT]: 'log-input';
};

/**
 * DID Log に載る入力を正規化スナップショットへ写す。
 *
 * own の全文字列キー（非列挙も含む）を 1 度ずつ読み、**元の列挙可能性を保ったまま**データ
 * プロパティへ畳む。読み出した値は `internal/prototype-safety/deep-snapshot.ts` の `deepSnapshot` で**入れ子まで**
 * 畳むため、以降このスナップショットを何度読んでも同じ値が返り、検査器が見た値と
 * SCID 計算・Log entry 搭載に使われる値は必ず一致する。
 *
 * `value` が未指定（`undefined` / `null`）でも空のスナップショットを返す。型の無い JS からの
 * 呼び出しで省略され得るためで、下流（state 組み立ての既定値補完、`id` 未定義による継続性ガード）
 * の従来の挙動をそのまま保つ。
 *
 * @param value 呼び出し側から渡された生の入力。
 * @returns 正規化済みスナップショット。
 */
export function normalizeLogInput<T extends object>(value: T | undefined): NormalizedLogInput<T> {
  const snapshot: Record<string, unknown> = {};
  if (value !== undefined && value !== null) {
    for (const key of Object.getOwnPropertyNames(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      // アクセサはここで 1 度だけ評価され、以降はデータプロパティになる。読み出した値は
      // `deepSnapshot` で入れ子まで畳み、入れ子の own アクセサも 1 度だけ評価する
      // （複製対象外の値はそのまま返るため既存の意味論は変わらない）。
      // 列挙可能性は **own 限定**で読む（`descriptor?.enumerable` の鎖読みだと
      // `Object.prototype.enumerable` の汚染が写しの列挙可能性を書き換え、公開 Log に載る
      // 範囲が変わる）。定義は `defineDataProperty` 経由（記述子を `null` プロトタイプで組む）。
      const enumerable =
        descriptor !== undefined && Object.hasOwn(descriptor, 'enumerable')
          ? descriptor.enumerable !== false
          : true;
      defineDataProperty(snapshot, key, deepSnapshot((value as Record<string, unknown>)[key]), {
        enumerable,
      });
    }
  }
  // ブランドは実行時に存在しないため素の記録型とは「重なりがない」と判定される。実体は
  // プレーンなオブジェクトのまま公称型を名乗らせる（キャストは本モジュール内に閉じる）。
  return snapshot as unknown as NormalizedLogInput<T>;
}
