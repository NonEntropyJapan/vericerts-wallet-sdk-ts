/**
 * 公開する集合定数を「変更不能なビュー」に包むための内部ユーティリティ。
 *
 * 受理集合（受理 `typ` / 対応 format 等）を可変の `Set` のまま公開すると、`ReadonlySet` 型で
 * 隠しても実体は共有レジストリのままである。TypeScript の型はランタイムに残らないため、
 * 利用者側の `(SET as Set<string>).add('kb+jwt')` 一発でプロセス全体の受理集合が恒久的に広がり、
 * 型混同ガード（`assertAcceptedSdJwtVcTypIfPresent` 等）が無力化される。型注釈は防御にならない。
 *
 * 防御は 2 段で構成する。
 *
 * 1. **ガード側は公開ビューを一切参照しない。** 受理判定はモジュール内に閉じた権威集合
 *    （`ACCEPTED_TYPS` / `SUPPORTED_FORMATS` 等）を読む。公開値は非権威なコピーにすぎないため、
 *    仮にビューを汚染できたとしても受理範囲は動かない。
 * 2. **ビュー自体も変更不能にする。** `Object.freeze` は `Set` の内部スロット（`[[SetData]]`）まで
 *    凍結せず `Set.prototype.add.call(view, x)` を素通しするため、`Proxy` で包む。`Proxy` は
 *    `[[SetData]]` を持たないので、プロトタイプ経由で `add` / `delete` / `clear` を呼び出しても
 *    `TypeError` になり、ビューの中身も書き換えられない。
 *
 * ただし 1 段目（権威集合の二重化）を持つのは `ACCEPTED_TYPS`（`sdjwt/typ.ts`）と
 * `SUPPORTED_FORMATS`（`auth/dcql/dcql.ts`）だけである。`SELECTIVE_DISCLOSURE_FORMATS` /
 * `SD_JWT_VC_FORMATS` は本ビューだけで守る（内部ガードがこれらを読んでいないため、権威な双子を
 * 別途持つ必要がない）。この非対称は意図的なものであり、内部ガードが将来これらを読み始める場合は
 * module-private な権威集合を併せて用意すること。
 *
 * どのビューも、素の文字列定数（`SELECTIVE_DISCLOSURE_FORMATS`）か、module-private な権威集合
 * （`ACCEPTED_TYPS` / `SUPPORTED_FORMATS`）か、共有の正準値リスト（`SD_JWT_VC_FORMATS` は
 * `ACCEPTED_SD_JWT_VC_TYP_VALUES`）から組み立てる。別モジュールの公開ビューを派生元にすることは
 * 禁止する。非権威な公開値を権威扱いする層構造の反転であり、派生元のビューが将来可変になれば
 * そのまま伝播するためである。
 *
 * 戻り値の型は `ReadonlySet<T>` のままなので、`has` / `size` / スプレッド / `new Set(view)` /
 * `forEach` / ESNext の集合演算メソッドといった読み取り操作はすべて従来どおり動く
 * （公開シグネチャは不変であり、破壊的変更ではない）。
 *
 * 命名上の注意: `toFrozenSetView` /「変更不能」は変更操作が必ず失敗することを指し、
 * `Object.freeze` を適用したことは意味しない。`Proxy` は対象を凍結しないため
 * `Object.isFrozen(view)` は `false` を返す（`Object.isExtensible(view)` も `true`）。
 * 防御的に `Object.isFrozen()` を見て可否を判断する利用側は誤った結論に至るので、
 * 変更不能性の判定には `Object.isFrozen` ではなく実際の変更操作が `TypeError` になることを使う。
 */

/** 変更不能ビューに対する変更操作。常に `TypeError` を投げる。 */
function rejectMutation(): never {
  throw new TypeError('This Set is a read-only view and cannot be mutated.');
}

/** ビュー越しに拒否する `Set` の変更メソッド名。 */
const MUTATING_METHODS: ReadonlySet<string | symbol> = new Set<string | symbol>([
  'add',
  'delete',
  'clear',
]);

/** `Set.prototype` のメソッド（`this` に `Set` 実体を要求する関数）。 */
type SetMethod = (...args: never[]) => unknown;

/**
 * `Set.prototype` が持つメソッドを鍵ごとに集める（モジュール初期化時に 1 度だけ実行する）。
 *
 * `has` / `keys` / `values` / `entries` / `forEach` / `Symbol.iterator` に加え、ES2025 の集合演算
 * （`union` / `intersection` / `difference` / `symmetricDifference` / `isSubsetOf` / `isSupersetOf` /
 * `isDisjointFrom`）も列挙で自動的に拾うため、ランタイムの拡張に追随できる。
 *
 * `constructor` は除外する（メソッドではなくビューの素性であり、`Set` をそのまま返させる）。
 * 判定に `Reflect.get` を使わないのは、`size` がゲッターであり `Set.prototype` 自身に対して
 * 読むと `TypeError` になるためである。descriptor の `value` が関数のものだけを採る。
 */
function collectSetMethods(): ReadonlyMap<string | symbol, SetMethod> {
  const methods = new Map<string | symbol, SetMethod>();
  for (const key of Reflect.ownKeys(Set.prototype)) {
    if (key === 'constructor') {
      continue;
    }
    const value = Object.getOwnPropertyDescriptor(Set.prototype, key)?.value as unknown;
    if (typeof value === 'function') {
      methods.set(key, value as SetMethod);
    }
  }
  return methods;
}

/** `Set.prototype` のメソッド表。ビュー生成のたびに列挙し直さないよう module-level で持つ。 */
const SET_METHODS = collectSetMethods();

/**
 * 反復可能な値から、変更操作が必ず失敗する読み取り専用の集合ビューを作る。
 *
 * 元の集合とは独立したコピーを内部に保持するため、元の集合を後から変更してもビューには伝播しない。
 *
 * ラッパはビュー 1 個につき生成時に 1 度だけ作って使い回す。プロパティ参照のたびに `bind` すると
 * `view.has !== view.has` となり同一性比較や参照のキャッシュが壊れるうえ、読み取りのたびに関数が
 * 割り当てられる。表に無い鍵（`constructor` / `size` / `Symbol.toStringTag` 等）は素通しするので、
 * `view.constructor === Set` も `size` の追随も `view instanceof Set` も従来どおりである。
 *
 * なお `Object.isFrozen(view)` は `false` を返す（`Proxy` は対象を凍結しない）。詳細は本ファイル
 * 冒頭の注記を参照。
 *
 * @param values ビューに含める値。
 * @returns 変更操作が必ず `TypeError` になる `ReadonlySet`。読み取り操作は `Set` と同一に動く。
 */
export function toFrozenSetView<T>(values: Iterable<T>): ReadonlySet<T> {
  const backing = new Set<T>(values);

  // 変更メソッドは拒否関数へ、それ以外は実体に束縛した関数へ差し替える。`size` ゲッターや
  // `has` は `[[SetData]]` を要求するため、`this` は Proxy ではなく実体でなければならない。
  const wrappers = new Map<string | symbol, unknown>();
  for (const [key, method] of SET_METHODS) {
    wrappers.set(key, MUTATING_METHODS.has(key) ? rejectMutation : method.bind(backing));
  }

  const view = new Proxy(backing, {
    get: (target, property) =>
      wrappers.has(property) ? wrappers.get(property) : Reflect.get(target, property, target),
    set: () => false,
    defineProperty: () => false,
    deleteProperty: () => false,
    setPrototypeOf: () => false,
  }) as ReadonlySet<T>;

  // `forEach` だけは実体に束縛できない。素の `Set.prototype.forEach` はコールバック第 3 引数に
  // `this`＝実体の可変 `Set` を渡してしまい、そこから `add` できてビューが漏れるためである。
  // ビュー（Proxy）を渡す自前の実装に差し替える（`view` 生成後にしか登録できない）。
  wrappers.set(
    'forEach',
    (callback: (value: T, value2: T, set: ReadonlySet<T>) => void, thisArg?: unknown): void => {
      for (const value of backing) {
        callback.call(thisArg, value, value, view);
      }
    },
  );

  return view;
}
