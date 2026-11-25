/**
 * 外部入力の JSON を **`Object.prototype` を継承しない**オブジェクトへパースするヘルパー
 *
 * ## なぜ「読み取り時点」ではなく「パース境界」で断つのか
 *
 * `JSON.parse` の戻り値は `Object.prototype` を継承する。したがって外部入力由来のオブジェクトに
 * 対する `obj.foo` / `const { foo } = obj` / `'foo' in obj` / `obj.foo ?? 既定値` は必ず
 * プロトタイプ鎖を辿り、`Object.prototype.foo` が汚染されていれば**そのメンバを持たない応答でも
 * 汚染値を拾う**（fail-open）。
 *
 * これを各読み取り箇所で `ownProperty` に置き換える対症療法は、応答パーサを 1 つ書くたびに
 * 同じ判断が要るため漏れ続けてきた。典型的な
 * 漏れ方は次の 3 つで、いずれも読み取り箇所の規約では防ぎきれない。
 *
 * - 外側のメンバだけ own 限定にして、入れ子のオブジェクト（`cnf.jwk` など）に穴が残る
 * - own 限定で読んだ値を下流で別オブジェクトへ **repack** し、継承値が own プロパティに化ける
 * - 検査と採用で同じキーを 2 度読み、アクセサ汚染により両者が食い違う（TOCTOU）
 *
 * パース境界で `null` プロトタイプ化すると、これらが**まとめて成立しなくなる**。素の `JSON.parse` の後に
 * 反復走査で入れ子のオブジェクトと配列要素まで処理し（reviver は V8 の高速経路を外れて 5〜40 倍遅いので
 * 使わない）、`JSON.parse` はデータプロパティしか生成しないため結果にアクセサは存在しえない
 * （＝ 2 度読みも安全になる）。
 *
 * ただし走査は**配列自身を差し替えない**ため、配列オブジェクト自身への名前付きプロパティ読み
 * （`arr.foo`）は依然 `Array.prototype` → `Object.prototype` の鎖を辿る。配列を受けて
 * 添字以外のキーを読む箇所は、この手法では守られない。
 *
 * ## 本ヘルパーが**効かない**範囲（重要）
 *
 * **呼び出し側が渡すオプション（`opts.x`）と DI（`fetchImpl` / `now` / `isRevoked` 等）には
 * 一切効かない。** これらは呼び出し側が任意のオブジェクトを渡せるため、`JSON.parse` を通らない。
 * これらの読み取りには**読み取り時点の判定**（純データは `ownProperty`、関数値・DI 依存は
 * `nonObjectPrototypeProperty`）が引き続き必要である。
 *
 * また、既存の `ownProperty` / `nonObjectPrototypeProperty` 呼び出しを本ヘルパーの導入を理由に
 * **削ってはならない**。多層防御であり、パース結果が別経路（呼び出し側が組み立てたオブジェクト）
 * から流入する公開 API では引き続き唯一の防御線になる。
 *
 * @see {@link ./own-property.ts}
 * @module
 */

/** JSON のネスト深さの上限。これを超える入力は下流の再帰処理を枯渇させ得るため、パース境界で `SyntaxError` に倒す。 */
export const MAX_JSON_NESTING_DEPTH = 512;

/**
 * `JSON.parse` の戻り値のオブジェクトを**反復的**に `null` プロトタイプへ切り替える（in place、配列は配列のまま）。
 * reviver 版は V8 の高速経路を外れ素の 5〜40 倍遅かった。1 回の走査なので要素数に線形で、スタックも枯渇しない。
 */
function stripPrototypes(root: unknown): unknown {
  if (root === null || typeof root !== 'object') {
    return root;
  }
  const nodes: object[] = [root];
  const depths: number[] = [1];
  while (nodes.length > 0) {
    const node = nodes.pop() as object;
    const depth = depths.pop() as number;
    if (depth > MAX_JSON_NESTING_DEPTH) {
      throw new SyntaxError('JSON nesting too deep');
    }
    if (Array.isArray(node)) {
      for (const child of node) {
        if (child !== null && typeof child === 'object') {
          nodes.push(child);
          depths.push(depth + 1);
        }
      }
      continue;
    }
    Object.setPrototypeOf(node, null);
    for (const key in node) {
      const child = (node as Record<string, unknown>)[key];
      if (child !== null && typeof child === 'object') {
        nodes.push(child);
        depths.push(depth + 1);
      }
    }
  }
  return root;
}

/**
 * JSON 文字列を、`Object.prototype` を継承しないオブジェクトとしてパースする。
 *
 * 入れ子のオブジェクトと配列要素のオブジェクトも**再帰的に**プロトタイプなしになる。文字列 /
 * 数値 / 真偽値 / `null` / 配列そのもの（プロトタイプを含む）は `JSON.parse` と変わらず、`JSON.stringify` /
 * `Object.hasOwn` / `Object.keys` / スプレッド / 分割代入もそのまま使える。
 *
 * **パース失敗時の例外は正規化しない。** 呼び出し側ごとに異なるエラーコード（2001 / 3002 /
 * 3034 / 8020 等）へ畳み込む責務は各サイトの `try` / `catch` に残す。本関数は
 * `JSON.parse` と同じく `SyntaxError` を送出するだけである（ネスト深さが `MAX_JSON_NESTING_DEPTH` を
 * 超える場合も `SyntaxError`）。
 *
 * @param text パース対象の JSON 文字列。
 * @returns パース結果（型は未知）。**プロトタイプなしになるのはオブジェクト値のみ**で、ルートが
 *   配列の場合その配列自身は `Array.prototype` → `Object.prototype` を保持する（要素側の
 *   オブジェクトは `null` プロトタイプになる）。
 * @throws {SyntaxError} `text` が JSON として解析できない場合、またはネストが深すぎる場合。
 */
export function parseJsonWithoutPrototype(text: string): unknown {
  return stripPrototypes(JSON.parse(text));
}
