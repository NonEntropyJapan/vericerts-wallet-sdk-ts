/**
 * asset の RPC アクセス用 DI seam（ネットワーク・ethers 非依存の境界）。
 *
 * 残高・NFT の照会に使う `eth_call` / `eth_getBalance`、送金用の gas・nonce 取得、
 * 署名済みトランザクションのブロードキャストを抽象化する。
 * erc20.ts / erc20-tx.ts / erc721.ts / erc1155.ts はこのインターフェース経由でのみ
 * ネットワークに触れ、ethers / RPC 実体から切り離される。
 *
 * 既定実装（ethers）は ethers-adapter.ts の `createEthersCallSource` が提供する。テストは fake な
 * `EvmCallSource` を注入することで、実 RPC・ethers 実体に依存せず取得・正規化を検証できる。
 *
 * セキュリティ上の注意:
 * - RPC URL・アドレス・金額・残高・tokenId・署名済み Tx などの入力や ethers / RPC 由来例外（cause）を
 *   VericertsError の message / context / cause に伝播させない。
 */

/**
 * view（読み取り専用）コントラクト呼び出しのリクエスト（eth_call 相当）。
 *
 * `to` / `data` は ethers 非依存に構築済みであることを前提とする。`data` は ABI エンコード済みの
 * calldata（`0x` プレフィックス付き hex）。
 */
export interface EvmCallRequest {
  /** チェーン ID。未設定チェーンは `CHAIN_NOT_CONFIGURED`（4071）。 */
  readonly chainId: number;
  /** 呼び出し先コントラクトアドレス（`0x` + 40 hex）。 */
  readonly to: string;
  /** ABI エンコード済み calldata（`0x` プレフィックス付き hex）。 */
  readonly data: string;
}

/**
 * 署名済み生トランザクション（`0x` プレフィックス付き hex）の送信リクエスト。
 */
export interface EvmSendRequest {
  /** チェーン ID。 */
  readonly chainId: number;
  /** RLP エンコード・署名済みの生トランザクション（`0x` プレフィックス付き hex）。 */
  readonly rawTransaction: string;
}

/**
 * 送金 Tx 構築に必要なオンチェーン由来パラメータ（nonce / gas / gasPrice）。
 */
export interface EvmTxParams {
  /** 送信元アカウントの次の nonce。 */
  readonly nonce: number;
  /** 見積もりガス上限。 */
  readonly gasLimit: bigint;
  /** legacy gasPrice（wei）。 */
  readonly gasPrice: bigint;
}

/**
 * ガス見積もり対象の最小トランザクション情報。
 */
export interface EvmTxEstimate {
  /** 呼び出し先（トークンコントラクトアドレス）。 */
  readonly to: string;
  /** ABI エンコード済み calldata（`0x` プレフィックス付き hex）。 */
  readonly data: string;
  /** ネイティブ送金額（ERC-20 transfer では常に 0）。 */
  readonly value: bigint;
}

/**
 * EVM RPC アクセスの seam。erc20.ts / erc20-tx.ts / erc721.ts / erc1155.ts はこのインターフェース
 * 経由でのみネットワークに触れる。既定実装は ethers-adapter.ts の `createEthersCallSource`。
 */
export interface EvmCallSource {
  /**
   * view 関数を eth_call で読み取り、生の戻り値（`0x` プレフィックス付き hex）を返す。
   *
   * @param request チェーン ID・呼び出し先・calldata。
   * @returns ABI エンコードされた戻り値の hex 文字列。
   * @throws 未設定チェーンの場合（VericertsError、code `4071`）、
   *         RPC / ethers 失敗の場合（VericertsError、code `1021`）。
   */
  call(request: EvmCallRequest): Promise<string>;

  /**
   * ネイティブ通貨（ETH 等）の残高を取得する（eth_getBalance 相当）。
   *
   * @param chainId チェーン ID。
   * @param address 保有者アドレス（`0x` + 40 hex）。
   * @returns 残高（wei 等の最小単位、`bigint`）。
   * @throws 未設定チェーンの場合（VericertsError、code `4071`）、
   *         RPC / ethers 失敗の場合（VericertsError、code `1021`）。
   */
  nativeBalance(chainId: number, address: string): Promise<bigint>;

  /**
   * 送金 Tx 構築に必要なオンチェーンパラメータ（nonce / gas / gasPrice）を取得する。
   *
   * @param chainId チェーン ID。
   * @param from 送信元アドレス（nonce 取得・ガス見積もりに用いる）。
   * @param tx ガス見積もり対象の Tx（to / data / value）。
   * @returns nonce / gasLimit / gasPrice。
   * @throws RPC / ethers 失敗・未設定チェーンの場合（VericertsError、code `1021`）。
   */
  fetchTxParams(chainId: number, from: string, tx: EvmTxEstimate): Promise<EvmTxParams>;

  /**
   * 署名済み生トランザクションをブロードキャストし、トランザクションハッシュを返す。
   *
   * @param request チェーン ID・署名済み生トランザクション。
   * @returns トランザクションハッシュ（`0x` プレフィックス付き hex）。
   * @throws RPC / ethers 失敗・未設定チェーンの場合（VericertsError、code `1021`）。
   */
  send(request: EvmSendRequest): Promise<string>;
}
