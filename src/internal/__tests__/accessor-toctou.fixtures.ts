/**
 * own アクセサの再評価（TOCTOU）を再現するテスト用フィクスチャ。
 *
 * `ownProperty`（`Object.hasOwn` 判定）は own アクセサを**読むたびに再評価する**。したがって
 * 同じキーを「検査時」と「搭載時」で 2 度読む実装は、検査した値と実際に公開される値がずれる。
 * 本フィクスチャは読み取り回数に応じて別の値を返す own アクセサを対象オブジェクトへ植え付け、
 * その経路をテストから再現する。
 */

/**
 * `target` に、読み取り回数ごとに `values` の要素を順に返す own アクセサを定義する。
 *
 * `values` を使い切った後は最後の要素を返し続ける。3 度目以降の読み取りも「すり替え後」の値に
 * なるため、実装が読み取りを 1 回に畳めているかを厳しく検査できる。
 *
 * アクセサは既定で列挙可能にする。DID Document / DID Log entry は JSON として canonicalize・
 * 公開されるため、非列挙にすると再現したい経路（公開される値のすり替え）から外れるからである。
 *
 * @param target アクセサを植える対象オブジェクト（テスト内で組み立てたもの）。
 * @param key アクセサのプロパティ名。
 * @param values 1 回目・2 回目…の読み取りで返す値。空配列は渡さないこと。
 * @param enumerable アクセサを列挙可能にするか（既定 `true`）。
 * @returns `target` 自身（組み立てた式のまま呼び出し先へ渡せるようにするため）。
 */
export function defineReadCountingAccessor<T extends object>(
  target: T,
  key: string,
  values: readonly unknown[],
  enumerable = true,
): T {
  defineCountedAccessor(target, key, values, enumerable);
  return target;
}

/**
 * {@link defineReadCountingAccessor} と同じアクセサを植え、**読み取り回数を返す関数**を返す。
 *
 * 「実装が読み取りを 1 回に畳めているか」を回数そのもので検査したい呼び出し側のための口である
 * （`internal/__tests__/deep-snapshot*.test.ts` が使う）。`defineReadCountingAccessor` が
 * `target` を返すのは組み立てた式のまま呼び出し先へ渡せるようにするためで、回数を取り出せない。
 * 両者で同じアクセサ実装を共有し、値の選び方（`values` を使い切ったら最後の要素を返し続ける）が
 * 食い違わないようにする。
 *
 * @param target アクセサを植える対象オブジェクト（テスト内で組み立てたもの）。
 * @param key アクセサのプロパティ名。
 * @param values 1 回目・2 回目…の読み取りで返す値。空配列は渡さないこと。
 * @param enumerable アクセサを列挙可能にするか（既定 `true`）。
 * @returns これまでの読み取り回数を返す関数。
 */
export function defineCountedAccessor(
  target: object,
  key: string,
  values: readonly unknown[],
  enumerable = true,
): () => number {
  let reads = 0;
  Object.defineProperty(target, key, {
    configurable: true,
    enumerable,
    get(): unknown {
      const value = values[Math.min(reads, values.length - 1)];
      reads += 1;
      return value;
    },
  });
  return () => reads;
}

/**
 * `target` に own かつ**非列挙**のデータプロパティを定義する。
 *
 * 正規化スナップショットが「own 全域（`Object.getOwnPropertyNames` = Art.9 走査・`ownProperty`）」と
 * 「own かつ列挙可能（`Object.keys` = `canonicalize`・JSON 化）」の両範囲を元の入力と一致させて
 * いることを検査するために使う。非列挙を落とすと Art.9 ガードが素通りし、非列挙を列挙可能へ
 * 格上げすると本来 canonical 形に現れない値が公開 Log に載る。
 *
 * @param target プロパティを植える対象オブジェクト（テスト内で組み立てたもの）。
 * @param key プロパティ名。
 * @param value プロパティ値。
 * @returns `target` 自身。
 */
export function defineNonEnumerableProperty<T extends object>(
  target: T,
  key: string,
  value: unknown,
): T {
  Object.defineProperty(target, key, {
    configurable: true,
    enumerable: false,
    value,
    writable: true,
  });
  return target;
}
