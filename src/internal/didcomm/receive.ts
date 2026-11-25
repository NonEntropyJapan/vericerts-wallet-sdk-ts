/**
 * DIDComm v2 メッセージの受信・復号。
 *
 * 受信した JWE Compact Serialization を復号し（`pack.ts`
 * `unpackMessage`）、Authcrypt の場合は送信者署名と宛先（`to`）を検証する。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { nonObjectPrototypeProperty, ownProperty } from '../prototype-safety/own-property.js';
import type { UnpackedMessage } from './pack.js';
import { unpackMessage } from './pack.js';
import type { DIDCommKeyAgreementKeyPair, DIDCommResolver } from './types.js';

/** `receiveDIDCommMessage` のオプション。 */
export interface ReceiveDidCommMessageOptions {
  /** Authcrypt の送信者署名検証に使う DID 解決 DI。Anoncrypt のみを扱う場合は省略可。 */
  readonly resolver?: DIDCommResolver;
  /**
   * 自分の DID の集合。Authcrypt メッセージは署名済み `to` がこのいずれかを含むことが必須
   * （受信者束縛）。省略時は Authcrypt を拒否する（Anoncrypt のみを扱う場合は不要）。
   */
  readonly recipientDids?: readonly string[];
  /** 現在時刻（UNIX epoch 秒）の供給元。`expires_time` 判定用（既定は `Date.now()`）。 */
  readonly nowSeconds?: () => number;
}

/**
 * 受信した DIDComm v2 メッセージ（JWE Compact Serialization）を復号する。
 *
 * @param packed 受信した JWE Compact Serialization 文字列。
 * @param myKeyAgreement 自分の keyAgreement 鍵ペア。
 * @param options Authcrypt 検証用の `resolver` / `recipientDids`、時刻 DI。
 * @returns 復号済みメッセージと認証済みフラグ。
 * @throws JWE 構造不正（`DIDCOMM_UNPACKING_FAILED`）、鍵不一致による復号・署名検証失敗
 *         （`DIDCOMM_UNPACK_FAILED`。Authcrypt メッセージに `resolver` 未指定の場合も含む）。
 */
export async function receiveDIDCommMessage(
  packed: string,
  myKeyAgreement: DIDCommKeyAgreementKeyPair,
  options?: ReceiveDidCommMessageOptions,
): Promise<UnpackedMessage> {
  // DI 解決器（クラス実装でプロトタイプメソッドを持ち得る）は `Object.prototype` 由来だけ弾き、
  // 純データの recipientDids / nowSeconds は unpackMessage 側で読むため own 限定のまま渡す。
  const resolver = options
    ? nonObjectPrototypeProperty<DIDCommResolver>(options, 'resolver')
    : undefined;
  const recipientDids = options
    ? ownProperty<readonly string[]>(options, 'recipientDids')
    : undefined;
  const nowSeconds = options
    ? nonObjectPrototypeProperty<() => number>(options, 'nowSeconds')
    : undefined;
  return unpackMessage(
    packed,
    myKeyAgreement,
    async (senderDid) => {
      if (resolver === undefined) {
        // Authcrypt メッセージだが検証手段が無い。fail-closed（鍵不一致相当）で拒否する。
        throw new VericertsError(ErrorCodes.DIDCOMM_UNPACK_FAILED);
      }
      return resolver.resolve(senderDid);
    },
    {
      ...(recipientDids === undefined ? {} : { recipientDids }),
      ...(nowSeconds === undefined ? {} : { nowSeconds }),
    },
  );
}
