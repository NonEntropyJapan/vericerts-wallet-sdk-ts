/**
 * DIDComm v2 暗号化メッセージの送信。
 *
 * 1. 送信先 DID を解決し、keyAgreement 鍵と serviceEndpoint を取得する（`resolve.ts`）。
 * 2. Authcrypt / Anoncrypt で JWE パッキングする（`pack.ts`）。
 * 3. serviceEndpoint（直接到達できる場合）へ HTTP POST で送信する。
 * 4. serviceEndpoint が無い場合は Mediator（`options.mediatorDid`）経由の
 *    forward（`https://didcomm.org/routing/2.0/forward`）でルーティングする。
 *
 * エラー面: 相手 DID 解決失敗は `DIDCOMM_PACK_FAILED`、パッキング前段の鍵/エンコード不整合は
 * `DIDCOMM_PACKING_FAILED`、serviceEndpoint 皆無（Mediator も無し）は `SERVICE_ENDPOINT_NOT_FOUND`、
 * HTTP 配送失敗（直接送信・Mediator 経由のいずれも含む）は `MEDIATOR_UNREACHABLE`。
 */

import type { AnyCredentialSigner } from '../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import { resolveInjectedFetch } from '../fetch-di.js';
import { discardBody } from '../http/body-limit.js';
import { isPublicHttpsUrl } from '../http/public-https-url.js';
import type { DIDDocument } from '../identity/did.js';
import { nonObjectPrototypeProperty } from '../prototype-safety/own-property.js';
import { packMessage } from './pack.js';
import { resolveKeyAgreement, resolveServiceEndpoint } from './resolve.js';
import type { DIDCommEncryptionMode, DIDCommPlaintextMessage, DIDCommResolver } from './types.js';

/** `sendDIDCommMessage` のオプション。 */
export interface SendDidCommMessageOptions {
  /** 暗号化モード。省略時は `'anoncrypt'`。 */
  readonly mode?: DIDCommEncryptionMode;
  /** `mode: 'authcrypt'` のときに必須の送信者署名鍵。 */
  readonly senderSigner?: AnyCredentialSigner;
  /** 直接到達可能な serviceEndpoint が無い場合に経由する Mediator の DID。 */
  readonly mediatorDid?: string;
  /** テスト・カスタム transport 用の `fetch` 差し替え。省略時はグローバル `fetch`。 */
  readonly fetchImpl?: typeof fetch;
}

const DIDCOMM_ENCRYPTED_CONTENT_TYPE = 'application/didcomm-encrypted+json';
const FORWARD_MESSAGE_TYPE = 'https://didcomm.org/routing/2.0/forward';
/** serviceEndpoint への POST 全体（応答ヘッダ受信まで）のタイムアウト。無応答サーバーで永久に待たない。 */
const SEND_TIMEOUT_MS = 10_000;

/** DID を解決し、失敗を `DIDCOMM_PACK_FAILED`（相手 DID 解決失敗）へ正規化する。 */
async function resolveDidDocument(resolver: DIDCommResolver, did: string): Promise<DIDDocument> {
  try {
    return await resolver.resolve(did);
  } catch (error) {
    if (error instanceof VericertsError) {
      throw new VericertsError(ErrorCodes.DIDCOMM_PACK_FAILED, { cause: error });
    }
    throw new VericertsError(ErrorCodes.DIDCOMM_PACK_FAILED);
  }
}

/**
 * serviceEndpoint へ POST する。endpoint は相手が制御する DID Document 由来なので、公開ホスト宛の
 * HTTPS に限り（http/file/localhost/プライベート・リンクローカル IP は SSRF になるため拒否）、
 * リダイレクトは追従せず、タイムアウトを付ける。
 */
async function postPackedMessage(
  endpoint: string,
  packed: string,
  fetchSource: object,
): Promise<void> {
  if (!isPublicHttpsUrl(endpoint)) {
    throw new VericertsError(ErrorCodes.MEDIATOR_UNREACHABLE);
  }
  const { doFetch, receiver } = resolveInjectedFetch(fetchSource);
  let response: Response;
  try {
    response = await doFetch.call(receiver, endpoint, {
      method: 'POST',
      headers: { 'content-type': DIDCOMM_ENCRYPTED_CONTENT_TYPE },
      body: packed,
      redirect: 'manual',
      signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
    } as Parameters<typeof doFetch>[1]);
  } catch {
    throw new VericertsError(ErrorCodes.MEDIATOR_UNREACHABLE);
  }
  // 応答本文は使わない（成功・失敗いずれも）。読まずに保持し続けるとソケットを掴んだままになる。
  discardBody(response);
  // `redirect: 'manual'` の 3xx（ブラウザは opaqueredirect / status 0）は `ok` が偽になり配送失敗に倒れる。
  if (!response.ok) {
    throw new VericertsError(ErrorCodes.MEDIATOR_UNREACHABLE);
  }
}

/**
 * DIDComm v2 平文メッセージを暗号化し、相手（または Mediator）の serviceEndpoint へ送信する。
 *
 * @param message 送信する平文メッセージ。
 * @param recipientDid 送信先 DID。
 * @param resolver DID 解決 DI（`identity/resolver.ts` の `Resolver` 等）。
 * @param options 暗号化モード・送信者署名鍵・Mediator DID・`fetch` 差し替え。
 * @throws 相手 DID 解決失敗（`DIDCOMM_PACK_FAILED`）、keyAgreement 鍵不整合・
 *         `mode: 'authcrypt'` に `senderSigner` 未指定（`DIDCOMM_PACKING_FAILED`）、
 *         serviceEndpoint も Mediator も無い（`SERVICE_ENDPOINT_NOT_FOUND`）、
 *         HTTP 配送失敗（`MEDIATOR_UNREACHABLE`）。
 */
export async function sendDIDCommMessage(
  message: DIDCommPlaintextMessage,
  recipientDid: string,
  resolver: DIDCommResolver,
  options?: SendDidCommMessageOptions,
): Promise<void> {
  const recipientDoc = await resolveDidDocument(resolver, recipientDid);

  const recipientKeyAgreement = resolveKeyAgreement(recipientDoc);
  // `options` はプロトタイプ汚染を拾わないよう `Object.prototype` 由来の値を除いて読む。
  const opts: object = options ?? {};
  const mode = nonObjectPrototypeProperty<DIDCommEncryptionMode>(opts, 'mode') ?? 'anoncrypt';
  const senderSigner = nonObjectPrototypeProperty<AnyCredentialSigner>(opts, 'senderSigner');
  if (mode === 'authcrypt' && senderSigner === undefined) {
    throw new VericertsError(ErrorCodes.DIDCOMM_PACKING_FAILED);
  }
  const packed = await packMessage(message, recipientKeyAgreement.publicKeyJwk, {
    recipientKid: recipientKeyAgreement.id,
    senderSigner: mode === 'authcrypt' ? senderSigner : undefined,
  });

  const directEndpoint = resolveServiceEndpoint(recipientDoc);
  if (directEndpoint !== undefined) {
    await postPackedMessage(directEndpoint, packed, opts);
    return;
  }

  const mediatorDid = nonObjectPrototypeProperty<string>(opts, 'mediatorDid');
  if (mediatorDid === undefined) {
    throw new VericertsError(ErrorCodes.SERVICE_ENDPOINT_NOT_FOUND);
  }
  const mediatorDoc = await resolveDidDocument(resolver, mediatorDid);
  const mediatorEndpoint = resolveServiceEndpoint(mediatorDoc);
  if (mediatorEndpoint === undefined) {
    throw new VericertsError(ErrorCodes.SERVICE_ENDPOINT_NOT_FOUND);
  }
  const mediatorKeyAgreement = resolveKeyAgreement(mediatorDoc);
  const forwardMessage: DIDCommPlaintextMessage = {
    id: crypto.randomUUID(),
    type: FORWARD_MESSAGE_TYPE,
    to: [mediatorDid],
    body: { next: recipientDid },
    attachments: [{ media_type: DIDCOMM_ENCRYPTED_CONTENT_TYPE, data: { json: packed } }],
  };
  const forwardPacked = await packMessage(forwardMessage, mediatorKeyAgreement.publicKeyJwk, {
    recipientKid: mediatorKeyAgreement.id,
  });
  await postPackedMessage(mediatorEndpoint, forwardPacked, opts);
}
