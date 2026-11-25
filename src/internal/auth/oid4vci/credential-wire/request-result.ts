/**
 * `requestCredential` の戻り値の型。
 *
 * `oid4vci.ts` から切り出した（同ファイルの 300 行上限を保つため。`request-body.ts` と同じ理由）。
 * 値を持たない型宣言だけなので、実行時の挙動には関与しない。
 */

/**
 * 受信した VC と OID4VCI の付随情報。永続化・署名検証は呼び出し側の責務。
 */
export interface ReceivedCredential {
  /** 受信した生 VC 文字列（JWT / SD-JWT）。 */
  readonly credential: string;
  /** 更新された c_nonce（存在すれば）。 */
  readonly cNonce?: string;
}

/**
 * 遅延発行（Deferred）応答。即時 VC ではなく `transaction_id` が返ったことを表す。
 */
export interface DeferredCredential {
  /** Deferred Endpoint ポーリング用の取引 ID。 */
  readonly transactionId: string;
  /** 更新された c_nonce（存在すれば）。 */
  readonly cNonce?: string;
}

/** `requestCredential` の戻り値（即時受信 or 遅延発行）。 */
export type RequestCredentialResult =
  | ({ readonly status: 'issued' } & ReceivedCredential)
  | ({ readonly status: 'deferred' } & DeferredCredential);
