/**
 * asset の ABI エンコード/デコード seam（ethers 非依存の境界）。
 *
 * erc20.ts（残高取得）/ erc20-tx.ts（送金 Tx 構築・署名）/ erc721.ts・erc1155.ts
 * （NFT 一覧取得）はこのインターフェース経由でのみ calldata の生成・戻り値の解釈を行い、
 * ethers 実体から切り離される。既定実装は ethers-adapter.ts の `createErc20AbiCodec` /
 * `createErc721AbiCodec` / `createErc1155AbiCodec` が `ethers.Interface` を用いて提供する。
 * テストでは fake codec を注入することで、実 ethers に依存せず構築・デコードロジック・
 * エラー正規化を検証できる。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` にアドレス・金額・残高・引数値・tokenId・uri を含めない。
 */

/**
 * ABI 関数の calldata エンコード/戻り値デコードを提供する seam。
 */
export interface AbiCodec {
  /**
   * 関数名と引数列を calldata（`0x` プレフィックス付き hex）にエンコードする。
   *
   * @param functionName ABI 関数名（例: `balanceOf` / `transfer` / `ownerOf` / `tokenURI` / `uri`）。
   * @param args 引数列（受取人アドレス・金額・tokenId など）。
   * @returns calldata の hex 文字列（セレクタ 4 バイト + ABI エンコード引数）。
   * @throws 引数不正・未知関数の場合（VericertsError、code `4070`。引数値は伝播しない）。
   */
  encode(functionName: string, args: readonly unknown[]): string;

  /**
   * 関数の戻り値（eth_call の生 hex）をデコードして値の配列にする。
   *
   * @param functionName ABI 関数名。
   * @param data eth_call の生戻り値（`0x` プレフィックス付き hex）。
   * @returns デコードした戻り値の配列（順序は ABI 出力定義どおり）。
   * @throws デコード不能・未知関数の場合（VericertsError、code `1021`）。
   */
  decode(functionName: string, data: string): readonly unknown[];
}
