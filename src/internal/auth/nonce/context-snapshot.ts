/**
 * replay ガードの入口で `NonceContext` を own プロパティだけのスナップショットへ変換する。
 *
 * 呼び出し側が渡すプロパティの getter は、読み取るたびに違う値を返し得る。
 * 入口で各値を一度だけ読み取り、束縛値の照合・時刻検査と拒否リストへの記録に
 * 同じスナップショットを使う。これにより、検証と消費記録が同じ flow と束縛値に対応する。
 *
 * ## プロトタイプを持たない複製にする理由
 *
 * 複製先は `Object.create(null)` で作る。
 *
 * - `Object.prototype` の継承値が own プロパティに化けない（`own-property.ts` の JSDoc が
 *   警告する「呼び出し側で own 限定読み取りを無効化する」失敗様式を避ける）。
 * - `__proto__` という名のメンバをそのまま own データプロパティとして写せる。プレーンな
 *   `{}` を複製先にすると `Object.prototype.__proto__` のセッタが走り、文字列値は黙って
 *   捨てられて挙動が変わる。
 *
 * 読み取り側（`context.ts` の `ownProperty` = `Object.hasOwn`、DI 用の
 * `nonObjectPrototypeProperty` = プロトタイプ鎖を辿って `Object.prototype` 由来だけを弾く）は
 * どちらもプロトタイプを持たないオブジェクトで正しく動く（鎖は 1 段で終わる）。
 *
 * ## 挙動は変えない
 *
 * 写す範囲は own の全文字列キー（非列挙を含む）で、元の**列挙可能性もそのまま引き継ぐ**
 * （`entry.context` として拒否リストへ載る値の JSON 化・`structuredClone` の範囲を変えない）。
 * 値の型は検証しない。不正なコンテキスト（`flow` 欠落・非文字列の束縛値）は従来どおり
 * `resolveBinding` / `bindingValueFor` の fail-closed 判定で 4012 になる。
 */

import type { NonceContext } from './types.js';

/**
 * `NonceContext` の own プロパティを**一度だけ**読み、データプロパティへ畳んだ複製を返す。
 *
 * 以降このスナップショットを何度読んでも同じ値が返るため、束縛照合・replay-window の窓選択・
 * 拒否リストキーの組み立て・下層 `checkAndUse` への受け渡しはすべて同じ値に基づく。
 *
 * @param ctx 呼び出し側から渡された生の発行コンテキスト。
 * @returns プロトタイプを持たないデータのみの複製。
 */
export function snapshotNonceContext(ctx: NonceContext): NonceContext {
  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const key of Object.getOwnPropertyNames(ctx)) {
    // 列挙可能性は値を読む**前**に控える。値の読み取り（アクセサ呼び出し）が自身のプロパティを
    // 再定義・削除し得るため、後から記述子を引くと値と列挙可能性が別時点の状態から取られる。
    const enumerable = Object.getOwnPropertyDescriptor(ctx, key)?.enumerable ?? true;
    Object.defineProperty(snapshot, key, {
      // アクセサはここで 1 度だけ評価され、以降はデータプロパティになる。
      value: (ctx as unknown as Record<string, unknown>)[key],
      enumerable,
      writable: true,
      configurable: true,
    });
  }
  return snapshot as NonceContext;
}
