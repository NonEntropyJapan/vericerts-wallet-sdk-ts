/**
 * DID 文字列（`did:<method>:<identifier>`）の形式検証・メソッド抽出の共通ヘルパー。
 *
 * `identity/resolver.ts`（メソッドディスパッチ用に `match[1]` でメソッド名を取り出す）と
 * `issuer/module/validate-issue-input.ts`（VC 発行時の holder DID 検証。真偽値のみ必要）が、
 * キャプチャグループの有無だけが異なる同一パターンの正規表現をそれぞれ個別定義していた。
 * どちらも「不正な DID を fail closed で弾く」セキュリティ境界であるため、2 箇所が同時に
 * 更新されないと検証基準がずれる。本モジュールはキャプチャ有無の違いを吸収し、
 * {@link extractDidMethod} 1 つに規則の実体を集約する
 * （{@link isValidDidFormat} はその戻り値の有無で判定するだけ）。
 */

/** DID 文字列の前半（`did:<method>:`）を取り出す正規表現。 */
const DID_METHOD_PATTERN = /^did:([a-z0-9]+):.+$/;

/**
 * DID 文字列からメソッド名を取り出す。
 *
 * @param did DID 文字列（`did:<method>:<identifier>`）。
 * @returns メソッド名。形式に一致しなければ `undefined`。
 */
export function extractDidMethod(did: string): string | undefined {
  return DID_METHOD_PATTERN.exec(did)?.[1];
}

/**
 * DID 文字列が `did:<method>:<identifier>` の形式に一致するか。
 *
 * @param did 判定対象の DID 文字列。
 * @returns 形式に一致すれば `true`。
 */
export function isValidDidFormat(did: string): boolean {
  return extractDidMethod(did) !== undefined;
}

/**
 * DID 文字列の最大長（文字数）。
 *
 * DID は署名検証前に攻撃者制御の `iss` / `kid` から解決されるため、メソッド実装に入る前に
 * 上限で弾く。`did:key` は約 60 文字、`did:web` / `did:webvh` も現実的な長さは
 * 数百文字に収まる。
 */
export const MAX_DID_LENGTH = 2048;

/**
 * did:peer:4 のエンコード済みドキュメント（`z` を含む）の最大文字数。base58 デコードが二次時間のため上限が要る。
 *
 * 16 KiB では 1 回約 0.47 秒の同期 CPU を消費した。正当な長形式ドキュメント（鍵 2〜3 本 +
 * service）は数百バイト〜2 KiB 程度のため 4 KiB（約 30 ms）に絞る。さらに 1 スコープの解決コスト合計は
 * `createBoundedResolver` の `maxTotalDidLength` で抑える。
 */
export const MAX_PEER4_ENCODED_DOCUMENT_LENGTH = 4 * 1024;

/** did:peer:4 長形式 DID 全体の最大長（`did:peer:4` + 短縮ハッシュ + `:` + ドキュメント）。 */
const MAX_PEER4_DID_LENGTH = MAX_PEER4_ENCODED_DOCUMENT_LENGTH + 128;

/**
 * DID 文字列が長さ上限に収まるか。`did:peer:4` 長形式のみドキュメントを抱えるため別上限。
 *
 * @param did 判定対象の DID 文字列。
 * @returns 上限内なら `true`。
 */
export function isDidWithinLengthLimit(did: string): boolean {
  if (did.length <= MAX_DID_LENGTH) {
    return true;
  }
  return did.startsWith('did:peer:4') && did.length <= MAX_PEER4_DID_LENGTH;
}
