/**
 * 9xxx DIDComm v2 のエラーコード定数（schemas/error-codes.json）。
 *
 * `errors.ts` の `ErrorCodes` に結合される部分定数。値は数値文字列。
 */

/** 9xxx（didcomm）のコード（数値文字列）。 */
export const DIDCOMM_ERROR_CODES = {
  /** Authcrypt/Anoncrypt 失敗（相手 DID 解決失敗）。`sendDIDCommMessage`。 */
  DIDCOMM_PACK_FAILED: '9001',
  /** 復号失敗（鍵不一致）。`receiveDIDCommMessage`。 */
  DIDCOMM_UNPACK_FAILED: '9002',
  /** メッセージパッキング失敗（鍵不一致/エンコードエラー）。`sendDIDCommMessage`。 */
  DIDCOMM_PACKING_FAILED: '9003',
  /** メッセージアンパッキング失敗（構造不正等）。`receiveDIDCommMessage`。 */
  DIDCOMM_UNPACKING_FAILED: '9004',
  /** OOB Invitation URI のパース失敗（不正な URI / base64url 形式）。`processOutOfBandInvitation`。 */
  OOB_INVITATION_PARSE_FAILED: '9005',
  /** OOB Invitation 不正（形式エラー）。`processOutOfBandInvitation`。 */
  OOB_INVITATION_INVALID: '9010',
  /** Mediator 到達不能（HTTP エラー）。`sendDIDCommMessage`。 */
  MEDIATOR_UNREACHABLE: '9020',
  /** serviceEndpoint が見つからない（相手 DID Document に DIDComm service なし）。`sendDIDCommMessage`。 */
  SERVICE_ENDPOINT_NOT_FOUND: '9030',
} as const;
