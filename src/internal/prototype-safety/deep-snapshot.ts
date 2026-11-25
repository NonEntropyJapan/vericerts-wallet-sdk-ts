/**
 * 入れ子の own アクセサを一度だけ評価して確定値へ畳む深いスナップショット。
 *
 * 1 段の写しは、トップレベルの own プロパティについてのみ「検査した値 == 公開される値」を
 * 成立させる。入れ子のオブジェクトは**参照がそのままコピーされる**ため、その中の own アクセサは
 * 生き残り、
 *
 * 1. Art.9 走査器（`special-category.ts`）が辿る際に 1 回目が評価され、
 * 2. 出力時の再シリアライズが 2 回目を評価する、
 *
 * という二重評価で深さ 1 以上のドリフトが成立していた。本モジュールはその入れ子を先に畳み、
 * 走査器と生成側が**同じ確定済みデータ**を見る状態にする。
 *
 * ## 適用先（`internal/` 直下に置く理由）
 *
 * 同じ二重評価は VC 発行経路と DID Log 経路の**両方**にあり、後段の再シリアライズが
 * `JSON.stringify` か `canonicalize` かの違いしかない。したがって本モジュールは 2 つの正規化
 * スナップショットから共有する。
 *
 * - `issuer/module/normalized-issue-input.ts`（`normalizeClaims` / `normalizeIssueOptions`）
 *   → `assertNoSpecialCategoryInIssuedContent` と `buildCompactJwsSigningInput` の
 *   `JSON.stringify` が同じ確定値を見る。
 * - `identity/normalized-log-input.ts`（`normalizeLogInput`）
 *   → `assertNoSpecialCategoryOnChain` と `webvh/codec.ts` の `canonicalize` が同じ確定値を見る
 *   （`createDidWebVh` / `updateDidWebVh` の 2 経路）。
 * - `credential/chain/build.ts`（`buildDerivedCredential`）
 *   → `assertNoSpecialCategoryInIssuedContent` と派生 VC の直列化が同じ確定値を見る。
 *   こちらはトップレベルのキー範囲だけ **own かつ列挙可能**（スプレッド。戻り値を組み立てる
 *   分割代入と同一範囲）で、畳む深さは他の 2 つと同じである。
 *
 * ## 何を複製し、何を参照のまま残すか
 *
 * 引く線は「**複製できるのはプレーンなコンテナだけ**」である。すなわち複製するのは
 * **素の配列（プロトタイプが `Array.prototype` そのもの）とプレーンオブジェクト**
 * （プロトタイプが `Object.prototype` か `null`）だけで、それ以外（`Date` / `Map` / `Set` /
 * TypedArray / 一般のクラスインスタンス / `Array` サブクラス）は**参照のまま**残す。
 *
 * 理由は共通で、**内部状態（内部スロット・プライベートフィールド）を持つオブジェクトは、
 * コンストラクタを通さずに複製すると必ずどこかが壊れる**からである。`claims` は任意のデータを
 * 取り得るため、壊れ方を呼び出し側に押し付けるわけにはいかない。実例:
 *
 * - `Object.create(Date.prototype)` は `[[DateValue]]` を持たないので `toJSON` が `TypeError`。
 * - `Object.setPrototypeOf([], SubArray.prototype)` はサブクラスのコンストラクタを通らないため
 *   プライベートフィールド（`#x`）がインストールされず、継承した `toJSON` がそれを読む
 *   `Array` サブクラスでは `JSON.stringify` が素の `TypeError` を投げる（Node/V8 で実測。
 *   JavaScriptCore は配列インスタンスの継承 `toJSON` を呼ばないため顕在化しないだけである）。
 * - `JSON.parse(JSON.stringify(...))` 方式は `undefined` の消失・`Date` の文字列化・
 *   `null` プロトタイプの喪失といった挙動変更を招く。
 *
 * したがって保証範囲は正直に狭め、**複製対象であるプレーンなコンテナ（素の配列とプレーン
 * オブジェクト）に限っては、複製後も `JSON.stringify` の出力が元と 1 バイトも変わらない**
 * ことだけを主張する（入れ子に own throwing getter を含まない限り。含む場合は複製自体が例外で
 * 中断するため比較対象が存在しない。下の「既知の限界」参照）。参照のまま残す値は元のオブジェクトそのものなので、当然出力も変わらない。
 *
 * ## 既知の限界
 *
 * **参照のまま残すコンテナの own アクセサは畳まれない。** `Date` / `Map` / `Set` / TypedArray /
 * 一般のクラスインスタンス / `Array` サブクラスは意味論保全のため複製しないので、それらが own
 * アクセサを持つ場合は走査時（1 回目）と署名時（2 回目）で別の値を返し得る二重評価ドリフトが
 * 残る。これは意識的なトレードオフである。これらは JSON 表現を `toJSON` や内部スロットで決める
 * 型か、呼び出し側が自分で構築したクラスインスタンスであり、「発行入力として渡した匿名
 * オブジェクトの getter」で問題になる境界とは別物である。壊れた複製を返すより、
 * 保証範囲を狭く明示するほうが安全という判断による。
 *
 * **`getPrototypeOf` トラップを持たない `Proxy` はこの限界に含まれない。** プレーンなコンテナを
 * 素通しの `Proxy` で包んだ場合、{@link plainContainerPrototype} の判定（`Object.getPrototypeOf` は
 * ターゲットのプロトタイプを返す）で複製対象になるため、`ownKeys` トラップを差し替えて読み取り
 * ごとに違うキー集合を返す `Proxy` でも**トラップは 1 度だけ呼ばれ**、スナップショットは `Proxy` を
 * 参照せず確定値に畳まれる（実測）。
 *
 * **`getPrototypeOf` トラップを持つ `Proxy` はこの限界に入る。** トラップが `Object.prototype` /
 * `null` / `Array.prototype` 以外を返せば判定は「プレーンでない」に倒れ、`Proxy` は参照のまま残る。
 * `Proxy` かどうかを JavaScript から判別する手段は無く、`Date` を包む `Proxy` と区別できないため、
 * ここは**意図的に fail-closed**（壊れた複製を作るより参照のまま残す）である。この場合だけ
 * `ownKeys` / `get` トラップが後段で再評価されうる。
 *
 * なおプロトタイプは**面ごとに 1 度しか読まない**（{@link plainContainerPrototype} が読んだ値を
 * {@link createEmptyCopy} へそのまま渡す）。判定と複製で 2 度読むと、`getPrototypeOf` トラップが
 * 1 回目に `Object.prototype`・2 回目に `Date.prototype` を返すだけで、**判定を通った値の複製先が
 * `Date.prototype` になり** `JSON.stringify` が素の `TypeError` を投げる（本モジュールが塞ぐはずの
 * 二重評価そのもの）。
 *
 * **own の throwing getter は畳み中にそのまま伝播する。** {@link readOnce} が getter を評価するため、
 * 入れ子に `get x() { throw … }` を置くと**攻撃者制御の生の例外が呼び出し元まで抜ける**。
 * 同型の写しである `credential/sdjwt/claims.ts` の `validateCnf` は、写しの生成中に投げた場合も
 * 契約内のエラーコード（`3012` / `3010`）へ正規化している。本モジュールは
 * 呼び出し側ごとに正規化先のコードが違う（発行系と VC チェーンは `10607`、DID Log 経路は
 * `10601` / `2001`）ため共通の正規化先を持てない。**本 SDK は正規化しない**（規範として呼び出し側へ
 * 義務を割り当てるのではなく、**生の例外が公開境界まで抜ける**ことを仕様上の限界として確定させて
 * ある）。同型の写しである `credential/sdjwt/claims.ts` の `validateCnf` が呼び出し側で `3012` /
 * `3010` へ正規化しているのと非対称なのは、あちらが単一の失敗面（KB 検証）に属し正規化先が一意に
 * 決まるのに対し、本モジュールは 3 つの独立した失敗面から共有されるためである。
 *
 * ## プロパティ記述子をそのまま引き継ぐ理由
 *
 * 列挙可能性を落とすと `JSON.stringify` の出力が変わり（非列挙だったキーが**署名済み VC に
 * 載る**）、逆に非列挙プロパティを写さないと Art.9 走査器（`Object.getOwnPropertyNames` で
 * own 全体を見る）の検知範囲が狭まる。どちらも退行なので、記述子は書き換えずに引き継ぎ、
 * **アクセサをデータプロパティへ畳む**ことだけを行う。
 *
 * ## 再帰ではなく明示スタックで辿る
 *
 * 深い入れ子でスタックオーバーフローを起こさないため、走査は明示スタックによる反復で行う
 * （`special-category.ts` の走査器と同じ方針）。循環参照と共有参照は `WeakMap` の
 * 複製メモで畳み、元のオブジェクトグラフの形（循環・同一性）を保つ。
 */

import { defineDataProperty } from './define-data-property.js';

/** {@link plainContainerPrototype} が「複製対象ではない」を表すために返す番兵。 */
const NOT_PLAIN_CONTAINER = Symbol('not-plain-container');

/**
 * 複製対象のプレーンなコンテナ（素の配列 / プレーンオブジェクト）なら**そのプロトタイプ**を、
 * そうでなければ {@link NOT_PLAIN_CONTAINER} を返す。
 *
 * 配列は「`Array.isArray` が真、**かつ**プロトタイプが `Array.prototype` そのもの」だけを真と
 * する。`Array` サブクラスを含めてしまうと、`createEmptyCopy` が作れるのはコンストラクタを
 * 通らない複製だけなので、プライベートフィールドを読む継承 `toJSON` を持つサブクラスで
 * `JSON.stringify` が `TypeError` を投げる（モジュール JSDoc の「何を複製し、何を参照のまま
 * 残すか」を参照）。
 *
 * **プロトタイプは 1 度だけ読み、その値を {@link createEmptyCopy} まで持ち回る（重要）。**
 * `Object.getPrototypeOf` は `Proxy` の `getPrototypeOf` トラップを起動する読み取りであり、
 * 判定と複製で 2 度読むと 1 回目に `Object.prototype`・2 回目に `Date.prototype` を返すトラップに
 * よって**判定を通った値が `Date.prototype` の複製先へ書き込まれる**。この複製は `[[DateValue]]`
 * を持たないため `JSON.stringify` が素の `TypeError` を投げ、本モジュールが塞ぐはずの二重評価が
 * 本モジュール自身の中で成立してしまう。トラップの結果が `Object.prototype` / `null` /
 * `Array.prototype` のいずれでもなければ**複製せず参照のまま残す**（fail-closed）。
 *
 * **本関数と {@link createEmptyCopy} は対で正しさを担保している。** 判定側だけを緩めて複製対象を
 * 広げると `createEmptyCopy` が意味論を保てず `toJSON` 退行が再発し、逆に `createEmptyCopy`
 * だけを素の `[]` に緩めると `Array` サブクラスが素の配列へ成り下がる。片方だけを触らないこと。
 */
function plainContainerPrototype(value: unknown): object | null | typeof NOT_PLAIN_CONTAINER {
  if (typeof value !== 'object' || value === null) {
    return NOT_PLAIN_CONTAINER;
  }
  const prototype = Object.getPrototypeOf(value) as object | null;
  if (Array.isArray(value)) {
    return prototype === Array.prototype ? prototype : NOT_PLAIN_CONTAINER;
  }
  if (prototype === Object.prototype || prototype === null) {
    return prototype;
  }
  return NOT_PLAIN_CONTAINER;
}

/**
 * 中身が空の複製先を作る（素の配列か、元と同じプロトタイプのプレーンオブジェクト）。
 *
 * 配列は配列リテラルで作る。{@link plainContainerPrototype} が素の配列（プロトタイプが
 * `Array.prototype` そのもの）しか複製対象にしないため、これで元とプロトタイプが一致する。
 * `Object.create(Array.prototype)` では配列 exotic object にならず `Array.isArray` が偽に
 * なってしまうので使えない。プレーンオブジェクト側は `Object.prototype` と `null` プロトタイプの
 * 双方を保つため、**判定時に読んだプロトタイプをそのまま**渡す（ここで読み直さない理由は
 * {@link plainContainerPrototype} の JSDoc を参照）。
 */
function createEmptyCopy(source: object, prototype: object | null): object {
  if (Array.isArray(source)) {
    return [];
  }
  return Object.create(prototype);
}

/**
 * 記述子から値を 1 回だけ取り出す（アクセサなら getter を 1 度だけ評価する）。
 *
 * setter だけのプロパティは読み出すと `undefined` になる。これは元のオブジェクトを読んだ場合と
 * 同じ結果であり、`JSON.stringify` の出力も変わらない。
 *
 * **記述子自身も own 限定で読む（重要）。** `Object.getOwnPropertyDescriptor` が返すのは
 * `Object.prototype` を継承する通常のオブジェクトで、**アクセサ記述子の own キーは
 * `get` / `set` / `enumerable` / `configurable` だけで own `value` を持たない**。したがって
 * `'value' in descriptor` / `descriptor.value` はどちらもプロトタイプ鎖を辿り、
 * `Object.prototype.value` が汚染された環境では**畳み中に出会うすべての入れ子 own getter が
 * データ記述子と誤分類され、getter が呼ばれずに攻撃者の値が確定値としてスナップショットへ
 * 書き込まれる**。そのスナップショットは 3 つの呼び出し側すべてで署名・公開されるため
 * （署名済み VC のクレーム / SCID と公開 DID Log / 派生 VC）、本モジュールの目的そのものが
 * 反転する。`Object.hasOwn` で判定し、値の取り出しも own を確認した後だけ行う。
 */
function readOnce(source: object, descriptor: PropertyDescriptor): unknown {
  if (Object.hasOwn(descriptor, 'value')) {
    return descriptor.value;
  }
  // ここはアクセサ記述子（own `get` / `set` を持つ）。own `get` が無い場合に鎖から関数を
  // 拾わないよう、こちらも own 限定で確認する（setter だけのプロパティは `undefined`）。
  const getter = Object.hasOwn(descriptor, 'get') ? descriptor.get : undefined;
  return getter?.call(source);
}

/**
 * 記述子の真偽フラグを **own 限定**で読み、未指定なら `fallback` を返す。
 *
 * `descriptor.writable ?? true` のような鎖読みは、`Object.prototype.writable = false` の汚染下で
 * **アクセサ由来の記述子（own `writable` を持たない）に対して到達する**。畳んだプロパティが
 * 意図せず非 writable になり、以降の書き換えが黙って失敗する。`enumerable` / `configurable` は
 * `Object.getOwnPropertyDescriptor` が常に own で返すため実際には fallback へ落ちないが、
 * 読み方を非対称に残さないため同じヘルパーを通す。
 */
function ownFlag(
  descriptor: PropertyDescriptor,
  key: 'writable' | 'enumerable' | 'configurable',
  fallback: boolean,
): boolean {
  return Object.hasOwn(descriptor, key) ? descriptor[key] === true : fallback;
}

/**
 * 値を深くスナップショットし、入れ子の own アクセサを確定値へ畳む。
 *
 * 複製対象は素の配列とプレーンオブジェクトのみで、各プロパティはちょうど 1 回だけ読む。
 * プロパティ記述子（列挙可能性・書き込み可能性・設定可能性）は引き継ぐため、
 * `JSON.stringify` の出力と Art.9 走査器の検知範囲は元のオブジェクトと一致する。
 *
 * @param value スナップショット対象（1 段の写しが読み終えた値）。
 * @returns アクセサを畳んだ複製。複製対象外の値はそのまま返す。
 */
export function deepSnapshot(value: unknown): unknown {
  const rootPrototype = plainContainerPrototype(value);
  if (rootPrototype === NOT_PLAIN_CONTAINER) {
    return value;
  }
  const rootSource = value as object;
  const copies = new WeakMap<object, object>();
  const root = createEmptyCopy(rootSource, rootPrototype);
  copies.set(rootSource, root);
  const pending: (readonly [object, object])[] = [[rootSource, root]];

  while (pending.length > 0) {
    const entry = pending.pop();
    if (entry === undefined) {
      continue;
    }
    const [source, target] = entry;
    for (const key of Reflect.ownKeys(source)) {
      // 配列の `length` は要素の定義に伴って自動更新されるため写さない（穴のある配列で
      // 末尾が欠けないよう、ループ後に元の長さへ揃える）。
      if (Array.isArray(source) && key === 'length') {
        continue;
      }
      const descriptor = Object.getOwnPropertyDescriptor(source, key);
      if (descriptor === undefined) {
        continue;
      }
      const raw = readOnce(source, descriptor);
      let folded: unknown = raw;
      const rawPrototype = plainContainerPrototype(raw);
      if (rawPrototype !== NOT_PLAIN_CONTAINER) {
        const rawContainer = raw as object;
        const existing = copies.get(rawContainer);
        if (existing === undefined) {
          const copy = createEmptyCopy(rawContainer, rawPrototype);
          copies.set(rawContainer, copy);
          pending.push([rawContainer, copy]);
          folded = copy;
        } else {
          // 循環参照・共有参照は同じ複製を指させる（無限ループを断ち、同一性も保つ）。
          folded = existing;
        }
      }
      // フラグは **own 限定**で読む（{@link ownFlag} 参照）。アクセサ由来の記述子は own
      // `writable` を持たないため、鎖読みだと `Object.prototype.writable` の汚染が畳んだ
      // プロパティに効いてしまう。`enumerable` / `configurable` は常に own で返るので fallback
      // へは落ちないが、読み方を非対称に残さない。定義は `defineDataProperty`（記述子を
      // `null` プロトタイプで組む）経由で行う — 記述子リテラルを直接渡すと
      // `Object.prototype.get` の汚染下で `defineProperty` 自体が TypeError を投げる。
      defineDataProperty(target, key, folded, {
        writable: ownFlag(descriptor, 'writable', true),
        enumerable: ownFlag(descriptor, 'enumerable', true),
        configurable: ownFlag(descriptor, 'configurable', true),
      });
    }
    if (Array.isArray(source) && Array.isArray(target)) {
      target.length = source.length;
    }
  }

  return root;
}
