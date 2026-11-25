/**
 * プロトタイプ鎖を辿らずに「自身のプロパティ」だけを読むためのヘルパー。
 *
 * SDK の公開 API は任意プロパティ（`kid` / `allowUnbound` / `verifySignature` 等）を持つ
 * オプションオブジェクトを呼び出し側から受け取る。これを `opts.x !== undefined` /
 * `opts.x ?? 既定値` / `const { x } = opts` / `'x' in opts` で読むと **プロトタイプ鎖を辿る**ため、
 * `Object.prototype` が汚染された環境では **その任意プロパティを省略した正当な呼び出しでも
 * 継承値を拾う**。拾った値はそのまま下流へ流れ、
 *
 * - 署名対象 payload / JWS ヘッダに攻撃者が選んだ値が載る、
 * - 「未指定なら拒否」「既定は厳格」といったガードが素通りする（fail-open）、
 *
 * といった結果になる。下流が `Object.hasOwn` で判定していても、上流が継承値を**自身の
 * プロパティ**として詰め直した後では区別が付かないため、**読み取り時点**で断つ必要がある。
 *
 * ## どちらのヘルパーを使うか（重要）
 *
 * **関数値・DI 依存には `ownProperty`（own 限定）を使ってはならない。** `isRevoked` / `fetchImpl` /
 * `fetchFn` / `verifyLink` のような依存は、`class Deps { isRevoked() {…} }` のように**プロトタイプ
 * メソッドとして実装するのが正当**である。own 限定で読むとこれらが「未指定」と判定され、
 *
 * - 失効検査・署名検査が**無言でスキップ**される（fail-open）、
 * - 注入した証明書ピンニング付き `fetch` が**黙ってグローバル `fetch` に差し替わる**（エラーに
 *   ならないため検知できない）、
 *
 * といった形で壊れる。同じ理由で、`publicKeyJwk` をアクセサで公開する KMS / HSM 鍵ラッパも
 * own 限定では読めない。
 *
 * 使い分け:
 *
 * - **関数値・DI 依存・クラスインスタンスであり得る値** → {@link nonObjectPrototypeProperty}
 *   （`Object.prototype` 由来だけを弾く）。あるいは own 読みしたうえで
 *   `typeof x !== 'function'` を明示的に検査して throw する。
 * - **純データの任意オプション**（時刻・秒数・フラグ・文字列・配列など） → {@link ownProperty}。
 * - **`Object.prototype` 汚染を黙って捨てず拒否したい公開入口**（`Wallet.receiveCredential` の DI キー等）
 *   → 読む前に {@link isObjectPrototypeProperty} で判定して throw する。値の読みは上の 2 つを使う。
 *
 * いずれの場合も、**読み取った値を検証せずに `as` でキャストしない**こと。キャストは
 * `undefined` の混入を型検査から隠し、下流で「取得失敗」や生の `TypeError` に化けて
 * fail-open へ転じる。
 *
 * ## 呼び出し側で無効化しないこと
 *
 * 下流を own 限定にしても、**呼び出し側が継承値を新しいオブジェクトリテラルへ詰め直す**と
 * （`{ nowSeconds: opts.nowSeconds }` のような形）継承値が own プロパティに化け、下流の判定は
 * 汚染値と正当な指定を区別できない。未指定のキーは生やさず、条件付き展開で落とすこと。
 *
 * ## `Object.create(null)` 化に伴う注意
 *
 * 外部由来の鍵で引く対応表はプロトタイプを持たないオブジェクトで構築するが、その結果
 * **既定値が引けず `undefined` になる**経路が生じる。`x > undefined` / `x < undefined` は
 * NaN 比較で常に false になるため、閾値検査がそのまま**黙ってスキップ**される。未知の鍵は
 * 明示的に fail-closed へ倒すこと。
 */

/**
 * `source` が `key` を**自身のプロパティ**として持つときだけ値を返す（継承値は拾わない）。
 *
 * 列挙可能・非列挙は問わない（`Object.hasOwn` と同じ判定）。`source` 自身が `key` を持ち、その値が
 * `undefined` の場合は `undefined` を返す（「明示的な `undefined`」と「未設定」は区別しない）。
 *
 * @param source 読み取り対象のオブジェクト。
 * @param key 読み取るプロパティ名。
 * @returns 自身のプロパティならその値、そうでなければ `undefined`。
 */
export function ownProperty<T>(source: object, key: string): T | undefined {
  return Object.hasOwn(source, key) ? (source as Record<string, T>)[key] : undefined;
}

/**
 * `key` を**最初に保持しているオブジェクトが `Object.prototype` でないとき**だけ値を返す。
 *
 * `ownProperty` は own 限定のため、`class KmsKey { verify() {} }` /
 * `class KmsKey { get publicKeyJwk() {} }` のようにプロトタイプメソッド・アクセサとして
 * メンバを公開する**正当なクラスインスタンス**を一律に「未指定」として弾いてしまう。一方で
 * プロトタイプ鎖をそのまま辿ると `Object.prototype` の汚染値を拾う。そこで
 * `Object.getPrototypeOf` で鎖を辿り、**`key` の記述子を最初に持つオブジェクト**を特定して
 * 「それが `Object.prototype` 自身なら未指定」とだけ判定する。
 *
 * データプロパティ汚染（`{ value }`）とアクセサ汚染（`{ get() {} }`）のどちらでも成立する点が
 * 要点。`candidate !== Object.prototype.verify` のような**同一性比較**は、getter が呼ぶたびに
 * 新しい関数を返す汚染で別インスタンスになり素通りする。
 *
 * 値の読み出しは `source[key]`（鎖経由）で行うため、アクセサは `this === source` で評価される
 * （クラス側の getter がインスタンス状態を参照できる）。
 *
 * @param source 読み取り対象のオブジェクト。
 * @param key 読み取るプロパティ名。
 * @returns `Object.prototype` 由来でないプロパティならその値、そうでなければ `undefined`。
 */
export function nonObjectPrototypeProperty<T>(source: object, key: string): T | undefined {
  for (
    let holder: object | null = source;
    holder !== null;
    holder = Object.getPrototypeOf(holder) as object | null
  ) {
    if (Object.getOwnPropertyDescriptor(holder, key) === undefined) {
      continue;
    }
    // 記述子を最初に持つオブジェクトが `Object.prototype` 自身 = 汚染値。採用しない。
    return holder === Object.prototype ? undefined : (source as Record<string, T>)[key];
  }
  return undefined;
}

/**
 * `key` の記述子を**最初に保持しているオブジェクトが `Object.prototype` 自身**かどうか
 * （= `Object.prototype` 汚染の判定）を返す。{@link nonObjectPrototypeProperty} と同じ走査で、
 * そちらが汚染値を「未指定」として**黙って捨てる**のに対し、本関数は呼び出し側が汚染を
 * **検知して拒否する**ために使う（公開入口で汚染を黙って捨てると利用者が気づけない）。
 *
 * `source` 自身や `Object.prototype` より手前のオブジェクト（クラスのプロトタイプ等）が `key` を
 * 持つなら、`Object.prototype` に同名キーがあっても `false`（own / 継承値が優先される）。
 * データプロパティ汚染・アクセサ汚染のどちらでも `true` になる。値の読み出し（getter の起動）は行わない。
 *
 * @param source 判定対象のオブジェクト。
 * @param key 判定するプロパティ名。
 * @returns 最初の保持者が `Object.prototype` 自身なら `true`。
 */
export function isObjectPrototypeProperty(source: object, key: string): boolean {
  for (
    let holder: object | null = source;
    holder !== null;
    holder = Object.getPrototypeOf(holder) as object | null
  ) {
    if (Object.getOwnPropertyDescriptor(holder, key) !== undefined) {
      return holder === Object.prototype;
    }
  }
  return false;
}

/** 値を読まず、`Object.prototype` より前の最初の記述子だけを返す。 */
function nonObjectPrototypePropertyDescriptor(
  source: object,
  key: string,
): PropertyDescriptor | undefined {
  for (
    let holder: object | null = source;
    holder !== null && holder !== Object.prototype;
    holder = Object.getPrototypeOf(holder) as object | null
  ) {
    const descriptor = Object.getOwnPropertyDescriptor(holder, key);
    if (descriptor !== undefined) return descriptor;
  }
  return undefined;
}

/**
 * 記述子で明示された非関数の data 値 / setter-only だけを検出する。
 *
 * missing と getter は unknown（false）。値を先読み・保存せず、呼出し時点の method 選択を保つ。
 * descriptor と get が異なる Proxy の互換性は保証せず、reflection trap の例外も変換しない。
 * @internal
 */
export function hasExplicitNonCallableProperty(source: object, key: string): boolean {
  const descriptor = nonObjectPrototypePropertyDescriptor(source, key);
  if (descriptor === undefined) return false;
  if (Object.hasOwn(descriptor, 'value')) return typeof descriptor.value !== 'function';
  if (Object.hasOwn(descriptor, 'get')) return typeof descriptor.get !== 'function';
  return Object.hasOwn(descriptor, 'set');
}
