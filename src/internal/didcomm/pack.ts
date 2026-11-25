/**
 * DIDComm v2 メッセージのパッキング（Authcrypt / Anoncrypt）とアンパッキング。
 *
 * 設計: Authcrypt は「JWS 署名 → JWE 暗号化」（sign-then-encrypt）として実装する。送信者は
 * 平文メッセージを自身の署名鍵（`AnyCredentialSigner`。DID Document の `authentication` /
 * `assertionMethod` に対応する鍵）で JWS 署名し、その JWS Compact 文字列を JWE でラップする。
 * 受信側は JWE を復号したうえで JWS を検証し、送信者 DID の署名鍵と突き合わせる。
 * Anoncrypt は署名を行わず、平文 JSON をそのまま JWE でラップする。
 * 内側ペイロードの種別は JWE protected header の `cty`（`didcomm-plain+json` /
 * `didcomm-signed+json`）で判別する。
 */

import { isPlainObject } from '../credential/object-guards.js';
import { signCompactJwsAsync } from '../credential/vc/compact-jws.js';
import type { CredentialAlg } from '../credential/vc/jws.js';
import { decodeCompactJwsOrThrow, verifyWithJwkOrFalse } from '../credential/vc/jws.js';
import type { AnyCredentialSigner } from '../credential/vc/signer.js';
import { buildJwsHeader } from '../credential/vc/signer.js';
import { didDocumentToVerifierKey } from '../credential/vc/verifier-key.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import type { DIDDocument, PublicKeyJwk } from '../identity/did.js';
import { nonObjectPrototypeProperty, ownProperty } from '../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../prototype-safety/parse-json.js';
import {
  DIDCOMM_PLAIN_CTY,
  DIDCOMM_SIGNED_CTY,
  decryptDidCommJwe,
  encryptDidCommJwe,
} from './jwe.js';
import type { DIDCommKeyAgreementKeyPair, DIDCommPlaintextMessage } from './types.js';

/** `packMessage` のオプション。 */
export interface PackMessageOptions {
  /** 受信者 keyAgreement の VerificationMethod id（判明している場合、JWE header の `kid` に載せる）。 */
  readonly recipientKid?: string;
  /** Authcrypt に使う送信者署名鍵。指定時は Authcrypt、未指定時は Anoncrypt になる。 */
  readonly senderSigner?: AnyCredentialSigner;
}

/**
 * DIDComm v2 平文メッセージを JWE Compact Serialization へパッキングする。
 *
 * @param message 送信する平文メッセージ。
 * @param recipientKeyAgreementJwk 受信者の keyAgreement 公開鍵 JWK（`crv: P-256`）。
 * @param options `senderSigner` 指定時は Authcrypt、未指定時は Anoncrypt。
 * @returns JWE Compact Serialization 文字列。
 * @throws JSON エンコード失敗・JWS 署名失敗（`DIDCOMM_PACKING_FAILED`）、JWE 暗号化失敗
 *         （`DIDCOMM_PACK_FAILED`。`jwe.ts` から伝播）。
 */
export async function packMessage(
  message: DIDCommPlaintextMessage,
  recipientKeyAgreementJwk: PublicKeyJwk,
  options?: PackMessageOptions,
): Promise<string> {
  // `options` は own 限定で読む。`senderSigner` を省略した Anoncrypt の呼び出しが
  // `Object.prototype.senderSigner` の汚染値を署名者として拾うと、平文全体が汚染された署名関数へ渡り、
  // Authcrypt 経路に切り替わる。署名者は関数値を持つ DI なので `Object.prototype` 由来だけを弾く。
  const senderSigner = options
    ? nonObjectPrototypeProperty<AnyCredentialSigner>(options, 'senderSigner')
    : undefined;
  const kid = options ? ownProperty<string>(options, 'recipientKid') : undefined;
  if (senderSigner === undefined) {
    let plaintext: string;
    try {
      plaintext = JSON.stringify(message);
    } catch {
      throw new VericertsError(ErrorCodes.DIDCOMM_PACKING_FAILED);
    }
    return encryptDidCommJwe(plaintext, recipientKeyAgreementJwk, {
      kid,
      cty: DIDCOMM_PLAIN_CTY,
    });
  }

  const header = buildJwsHeader(senderSigner, DIDCOMM_SIGNED_CTY);
  let jws: string;
  try {
    jws = await signCompactJwsAsync(header, message, senderSigner);
  } catch (error) {
    if (error instanceof VericertsError) {
      throw error;
    }
    throw new VericertsError(ErrorCodes.DIDCOMM_PACKING_FAILED);
  }
  return encryptDidCommJwe(jws, recipientKeyAgreementJwk, {
    kid,
    cty: DIDCOMM_SIGNED_CTY,
  });
}

/** `unpackMessage` の結果。 */
export interface UnpackedMessage {
  /** 復号済みの平文メッセージ。 */
  readonly message: DIDCommPlaintextMessage;
  /** Authcrypt（送信者署名検証済み）なら `true`、Anoncrypt なら `false`。 */
  readonly authenticated: boolean;
}

/** `unpackMessage` のオプション。 */
export interface UnpackMessageOptions {
  /**
   * 自分の DID の集合（受理する宛先）。Authcrypt では署名済みメッセージの `to` がこのいずれかを
   * 含むことを必須にする。送信者の JWS は受信者に束縛されないと、復号した受信者 B が
   * 署名済み JWS を別の C 宛に再暗号化して転送し、A になりすませる。未指定・空は fail-closed
   * （Authcrypt は拒否。Anoncrypt は署名を持たないため影響しない）。
   */
  readonly recipientDids?: readonly string[];
  /** 現在時刻（UNIX epoch 秒）の供給元。`expires_time` 判定用（テスト用 DI。既定は `Date.now()`）。 */
  readonly nowSeconds?: () => number;
}

/**
 * 復号後の JSON を DIDComm 平文メッセージの形状へ検証する。
 *
 * `null` / 配列 / 非オブジェクトや、`from` / `to` / `expires_time` / `attachments` の型不一致は `DIDCOMM_UNPACKING_FAILED`
 * に正規化する（以降の参照で素の `TypeError` を漏らさない）。
 */
function assertPlaintextShape(raw: unknown): DIDCommPlaintextMessage {
  if (!isPlainObject(raw)) {
    throw new VericertsError(ErrorCodes.DIDCOMM_UNPACKING_FAILED);
  }
  // 以降は **null プロトタイプのコピー**で読む。`to` / `from` / `expires_time` / `attachments` は
  // 省略可能で、素のオブジェクトだと `Object.prototype.to` の汚染値が「宛先に自分を含む」「期限なし」として
  // 後段の検査（`assertAddressedToMe` / `assertNotExpired` / 添付抽出）へ流れる。コピーは呼び出し側へ返す
  // メッセージそのものでもあるため、後段の読みもすべて own 限定になる。
  const value = Object.assign(Object.create(null) as Record<string, unknown>, raw);
  const { id, type, from, to, expires_time: expiresTime, attachments } = value;
  if (
    typeof id !== 'string' ||
    typeof type !== 'string' ||
    !isPlainObject(value.body) ||
    // `attachments` は添付抽出（`extractIssuedCredentialJwt` 等）が `entry.data` を読むため、配列・各要素・
    // `data` の形をここで固定して素の TypeError を漏らさない。
    (attachments !== undefined &&
      (!Array.isArray(attachments) ||
        attachments.some((entry) => !isPlainObject(entry) || !isPlainObject(entry.data)))) ||
    (from !== undefined && typeof from !== 'string') ||
    (to !== undefined && (!Array.isArray(to) || to.some((did) => typeof did !== 'string'))) ||
    (expiresTime !== undefined &&
      (typeof expiresTime !== 'number' || !Number.isFinite(expiresTime)))
  ) {
    throw new VericertsError(ErrorCodes.DIDCOMM_UNPACKING_FAILED);
  }
  return value as unknown as DIDCommPlaintextMessage;
}

/** 期限切れ（`expires_time` が現在時刻以前）を拒否する。 */
function assertNotExpired(message: DIDCommPlaintextMessage, options?: UnpackMessageOptions): void {
  const expiresTime = ownProperty<number>(message, 'expires_time');
  if (expiresTime === undefined) {
    return;
  }
  const nowSeconds = options
    ? (nonObjectPrototypeProperty<() => number>(options, 'nowSeconds') ?? systemNowSeconds)
    : systemNowSeconds;
  if (expiresTime <= nowSeconds()) {
    throw new VericertsError(ErrorCodes.DIDCOMM_UNPACK_FAILED);
  }
}

function systemNowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Authcrypt の署名済みメッセージが、自分宛（`to` に自分の DID を含む）であることを要求する。
 *
 * 失敗理由を `context.phase` で区別する。鍵不一致・署名不正と同じ `9003` を理由なしで
 * 返すと、呼び出し側は「復号できなかった」のか「`recipientDids` を渡していない（または宛先が
 * 自分でない）」のかを判別できない。前者は鍵の問題、後者は呼び出し側の設定の問題で、対処が違う。
 */
function assertAddressedToMe(
  message: DIDCommPlaintextMessage,
  options?: UnpackMessageOptions,
): void {
  const recipientDids = options
    ? ownProperty<readonly string[]>(options, 'recipientDids')
    : undefined;
  if (recipientDids === undefined) {
    // 受信者束縛を確かめる材料が無い（Authcrypt には `recipientDids` が必須）。
    throw new VericertsError(ErrorCodes.DIDCOMM_UNPACK_FAILED, {
      context: { phase: 'recipient_dids_missing' },
    });
  }
  const to = ownProperty<readonly string[]>(message, 'to');
  if (to?.some((did) => recipientDids.includes(did)) !== true) {
    throw new VericertsError(ErrorCodes.DIDCOMM_UNPACK_FAILED, {
      context: { phase: 'recipient_not_bound' },
    });
  }
}

/**
 * JWE Compact Serialization を復号し、Authcrypt の場合は送信者署名を検証する。
 *
 * 復号後のメッセージは形状（object / `id` / `type` / `body` / `from` / `to` / `expires_time` の型）を
 * 検証し、`expires_time` 経過済みは拒否する。Authcrypt はさらに `to` が自分の DID を含むことを
 * 必須にする（署名の受信者束縛）。
 *
 * @param packed JWE Compact Serialization 文字列。
 * @param myKeyAgreement 自分の keyAgreement 鍵ペア（復号に使う秘密鍵）。
 * @param resolveSenderDocument Authcrypt の署名検証に使う、送信者 DID Document 解決関数。
 *        Anoncrypt の場合は呼ばれない。
 * @param options 自分の DID 集合（Authcrypt の `to` 検査）・時刻 DI。
 * @returns 復号済みメッセージと認証済みフラグ。
 * @throws JWE 復号失敗（`jwe.ts` から `DIDCOMM_UNPACK_FAILED` / `DIDCOMM_UNPACKING_FAILED` が伝播）、
 *         平文 JSON パース失敗・形状不正・JWS 構造不正・`from` 欠落（`DIDCOMM_UNPACKING_FAILED`）、
 *         送信者署名検証失敗・宛先不一致・期限切れ（`DIDCOMM_UNPACK_FAILED`）。
 */
export async function unpackMessage(
  packed: string,
  myKeyAgreement: DIDCommKeyAgreementKeyPair,
  resolveSenderDocument: (senderDid: string) => Promise<DIDDocument>,
  options?: UnpackMessageOptions,
): Promise<UnpackedMessage> {
  const { plaintext, cty } = await decryptDidCommJwe(packed, myKeyAgreement.privateKey);

  if (cty !== DIDCOMM_SIGNED_CTY) {
    let parsed: unknown;
    try {
      parsed = parseJsonWithoutPrototype(plaintext);
    } catch {
      throw new VericertsError(ErrorCodes.DIDCOMM_UNPACKING_FAILED);
    }
    const message = assertPlaintextShape(parsed);
    assertNotExpired(message, options);
    return { message, authenticated: false };
  }

  const decoded = decodeCompactJwsOrThrow(plaintext, ErrorCodes.DIDCOMM_UNPACKING_FAILED);
  const message = assertPlaintextShape(decoded.payload);
  const sender = ownProperty<unknown>(message, 'from');
  if (typeof sender !== 'string') {
    throw new VericertsError(ErrorCodes.DIDCOMM_UNPACKING_FAILED);
  }
  let verifierPublicKeyJwk: PublicKeyJwk | undefined;
  try {
    const senderDoc = await resolveSenderDocument(sender);
    // 送信者認証は `authentication` 関係の鍵に限る。JWS ヘッダ `kid` があればその鍵を選ぶ。
    const kid = decoded.header.kid;
    verifierPublicKeyJwk = ownProperty<PublicKeyJwk>(
      didDocumentToVerifierKey(senderDoc, {
        relationship: 'authentication',
        ...(typeof kid === 'string' ? { verificationMethodId: kid } : {}),
      }),
      'publicKeyJwk',
    );
  } catch (error) {
    if (error instanceof VericertsError) {
      throw new VericertsError(ErrorCodes.DIDCOMM_UNPACK_FAILED, { cause: error });
    }
    throw new VericertsError(ErrorCodes.DIDCOMM_UNPACK_FAILED);
  }
  const alg =
    typeof decoded.header.alg === 'string' ? (decoded.header.alg as CredentialAlg) : undefined;
  const verified =
    alg !== undefined &&
    verifierPublicKeyJwk !== undefined &&
    verifyWithJwkOrFalse(alg, decoded, verifierPublicKeyJwk);
  if (!verified) {
    // 鍵不一致（ローテーション等）を含む署名検証失敗。
    throw new VericertsError(ErrorCodes.DIDCOMM_UNPACK_FAILED);
  }
  // 署名は検証済みだが、受信者への束縛と期限は署名内容そのもので判定する。
  assertAddressedToMe(message, options);
  assertNotExpired(message, options);
  return { message, authenticated: true };
}
