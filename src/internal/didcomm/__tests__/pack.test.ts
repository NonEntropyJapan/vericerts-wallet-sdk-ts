/**
 * `didcomm/pack.ts`（Authcrypt/Anoncrypt パッキング・アンパッキング）のテスト（
 * 詳細フロー 手順 3-4、「JWE 復号・署名検証」）。
 */

import { describe, expect, it } from 'bun:test';
import { p256 } from '@noble/curves/nist.js';
import { base64urlnopad } from '@scure/base';
import { VericertsError } from '../../errors.js';
import type { DIDDocument } from '../../identity/did.js';
import {
  createDidPeer2,
  encodePublicKeyMultibase,
  resolveDidPeer,
} from '../../identity/peer/method-peer.js';
import { createSecp256k1CredentialSigner } from '../../keymanager/credential-signer.js';
import { getSecp256k1PublicKey } from '../../keymanager/signer.js';
import { decryptDidCommJwe, encryptDidCommJwe } from '../jwe.js';
import { packMessage, unpackMessage } from '../pack.js';
import type { DIDCommKeyAgreementKeyPair, DIDCommPlaintextMessage } from '../types.js';

function buildRecipientKeyAgreement(seed: number): {
  publicKeyJwk: Record<string, string>;
  keyPair: DIDCommKeyAgreementKeyPair;
} {
  const privateKey = new Uint8Array(32).fill(seed);
  const uncompressed = p256.getPublicKey(privateKey, false);
  const publicKeyJwk = {
    kty: 'EC',
    crv: 'P-256',
    x: base64urlnopad.encode(uncompressed.slice(1, 33)),
    y: base64urlnopad.encode(uncompressed.slice(33)),
  };
  return { publicKeyJwk, keyPair: { publicKeyJwk, privateKey } };
}

function buildMessage(): DIDCommPlaintextMessage {
  return {
    id: 'msg-1',
    type: 'https://didcomm.org/basicmessage/2.0/message',
    from: 'did:peer:2.sender',
    to: ['did:peer:2.recipient'],
    body: { content: 'hello' },
  };
}

describe('packMessage / unpackMessage — Anoncrypt', () => {
  it('署名なしでパッキングし、authenticated: false でアンパッキングできる', async () => {
    const recipient = buildRecipientKeyAgreement(10);
    const message = buildMessage();
    const packed = await packMessage(message, recipient.publicKeyJwk);

    const result = await unpackMessage(packed, recipient.keyPair, () => {
      throw new Error('Anoncrypt では呼ばれないはず');
    });
    expect(result.authenticated).toBe(false);
    expect(result.message).toEqual(message);
  });
});

describe('packMessage / unpackMessage — Authcrypt', () => {
  function buildSenderDidDocument(): { doc: DIDDocument; did: string } {
    const senderPrivateKey = new Uint8Array(32).fill(20);
    const signKey = encodePublicKeyMultibase(
      'secp256k1',
      getSecp256k1PublicKey(senderPrivateKey, true),
    );
    const did = createDidPeer2({ verificationKeys: [signKey], keyAgreementKeys: [], services: [] });
    return { doc: resolveDidPeer(did), did };
  }

  it('送信者署名付きでパッキングし、署名検証に成功して authenticated: true を返す', async () => {
    const recipient = buildRecipientKeyAgreement(11);
    const senderPrivateKey = new Uint8Array(32).fill(20);
    const senderSigner = createSecp256k1CredentialSigner(senderPrivateKey);
    const { doc: senderDoc, did: senderDid } = buildSenderDidDocument();
    const message = { ...buildMessage(), from: senderDid };

    const packed = await packMessage(message, recipient.publicKeyJwk, { senderSigner });
    const result = await unpackMessage(
      packed,
      recipient.keyPair,
      async (did) => {
        expect(did).toBe(senderDid);
        return senderDoc;
      },
      { recipientDids: ['did:peer:2.recipient'] },
    );

    expect(result.authenticated).toBe(true);
    expect(result.message).toEqual(message);
  });

  it('送信者 DID の公開鍵が署名鍵と一致しない場合、署名検証に失敗し DIDCOMM_UNPACK_FAILED を送出する', async () => {
    const recipient = buildRecipientKeyAgreement(12);
    const senderPrivateKey = new Uint8Array(32).fill(21);
    const senderSigner = createSecp256k1CredentialSigner(senderPrivateKey);
    const { doc: senderDoc, did: senderDid } = buildSenderDidDocument();
    // buildSenderDidDocument は seed 20 の鍵で DID Document を作るが、ここでは別の秘密鍵（21）で
    // 署名するため、DID Document の検証鍵と署名鍵が一致しない（なりすまし相当）。
    const message = { ...buildMessage(), from: senderDid };

    const packed = await packMessage(message, recipient.publicKeyJwk, { senderSigner });
    await expect(
      unpackMessage(packed, recipient.keyPair, async () => senderDoc, {
        recipientDids: ['did:peer:2.recipient'],
      }),
    ).rejects.toMatchObject({ code: '9002' });
  });

  it('`from` を欠くメッセージの Authcrypt パッキングはアンパッキング時に構造不正として拒否する', async () => {
    const recipient = buildRecipientKeyAgreement(13);
    const senderSigner = createSecp256k1CredentialSigner(new Uint8Array(32).fill(22));
    const message = { ...buildMessage(), from: undefined } as unknown as DIDCommPlaintextMessage;

    const packed = await packMessage(message, recipient.publicKeyJwk, { senderSigner });
    let caught: unknown;
    try {
      await unpackMessage(packed, recipient.keyPair, async () => {
        throw new Error('unreachable');
      });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe('9004');
  });
});

describe('unpackMessage — 復号後メッセージの検証', () => {
  const NOW = 1_700_000_000;
  const senderPrivateKey = new Uint8Array(32).fill(40);
  const senderSigner = createSecp256k1CredentialSigner(senderPrivateKey);
  const senderDid = createDidPeer2({
    verificationKeys: [
      encodePublicKeyMultibase('secp256k1', getSecp256k1PublicKey(senderPrivateKey, true)),
    ],
    keyAgreementKeys: [],
    services: [],
  });
  const senderDoc = resolveDidPeer(senderDid);
  const resolveSender = async () => senderDoc;
  const bob = 'did:peer:2.bob';
  const carol = 'did:peer:2.carol';

  it('B 宛の署名済み JWS を C 宛に再暗号化して転送しても、C は受理しない（受信者束縛）', async () => {
    const b = buildRecipientKeyAgreement(41);
    const c = buildRecipientKeyAgreement(42);
    const message = { ...buildMessage(), from: senderDid, to: [bob] };
    const packedForB = await packMessage(message, b.publicKeyJwk, { senderSigner });

    // B は復号して署名済み JWS を取り出し、C の鍵で再暗号化して転送する。
    const { plaintext, cty } = await decryptDidCommJwe(packedForB, b.keyPair.privateKey);
    const forwarded = await encryptDidCommJwe(plaintext, c.publicKeyJwk, { cty });

    await expect(
      unpackMessage(forwarded, c.keyPair, resolveSender, { recipientDids: [carol] }),
    ).rejects.toMatchObject({ code: '9002' });
    // 正当な宛先 B 自身は受理できる。
    const ok = await unpackMessage(packedForB, b.keyPair, resolveSender, { recipientDids: [bob] });
    expect(ok.authenticated).toBe(true);
  });

  it('recipientDids 未指定の Authcrypt は fail-closed で拒否する', async () => {
    const b = buildRecipientKeyAgreement(43);
    const packed = await packMessage(
      { ...buildMessage(), from: senderDid, to: [bob] },
      b.publicKeyJwk,
      {
        senderSigner,
      },
    );
    // 失敗理由は鍵不一致・署名不正と区別できる。
    await expect(unpackMessage(packed, b.keyPair, resolveSender)).rejects.toMatchObject({
      code: '9002',
      context: { phase: 'recipient_dids_missing' },
    });
  });

  it('宛先が自分でない Authcrypt は recipient_not_bound で拒否する', async () => {
    const b = buildRecipientKeyAgreement(45);
    const packed = await packMessage(
      { ...buildMessage(), from: senderDid, to: ['did:example:someone-else'] },
      b.publicKeyJwk,
      { senderSigner },
    );
    await expect(
      unpackMessage(packed, b.keyPair, resolveSender, { recipientDids: [bob] }),
    ).rejects.toMatchObject({ code: '9002', context: { phase: 'recipient_not_bound' } });
  });

  it('`to` を欠く署名済みメッセージは拒否する', async () => {
    const b = buildRecipientKeyAgreement(44);
    const message = {
      ...buildMessage(),
      from: senderDid,
      to: undefined,
    } as unknown as DIDCommPlaintextMessage;
    const packed = await packMessage(message, b.publicKeyJwk, { senderSigner });
    await expect(
      unpackMessage(packed, b.keyPair, resolveSender, { recipientDids: [bob] }),
    ).rejects.toMatchObject({ code: '9002' });
  });

  it('期限切れ（expires_time <= now）は Authcrypt / Anoncrypt とも拒否し、期限内は受理する', async () => {
    const b = buildRecipientKeyAgreement(45);
    const opts = { recipientDids: [bob], nowSeconds: () => NOW };
    const expired = { ...buildMessage(), from: senderDid, to: [bob], expires_time: NOW };
    const valid = { ...expired, expires_time: NOW + 60 };

    const signedExpired = await packMessage(expired, b.publicKeyJwk, { senderSigner });
    await expect(
      unpackMessage(signedExpired, b.keyPair, resolveSender, opts),
    ).rejects.toMatchObject({ code: '9002' });
    const anonExpired = await packMessage(expired, b.publicKeyJwk);
    await expect(unpackMessage(anonExpired, b.keyPair, resolveSender, opts)).rejects.toMatchObject({
      code: '9002',
    });

    const signedValid = await packMessage(valid, b.publicKeyJwk, { senderSigner });
    expect((await unpackMessage(signedValid, b.keyPair, resolveSender, opts)).authenticated).toBe(
      true,
    );
  });

  it('expires_time が数値でない・to が文字列配列でない・attachments の形が不正・JSON がオブジェクトでない平文は 9004 で拒否する', async () => {
    const b = buildRecipientKeyAgreement(46);
    const base = buildMessage();
    for (const bad of [
      null,
      [],
      'str',
      42,
      { ...base, expires_time: '1' },
      { ...base, to: 'did:peer:2.bob' },
      { ...base, to: [1] },
      { ...base, body: null },
      { ...base, from: 1 },
      // attachments の形不正。
      { ...base, attachments: 'abc' },
      { ...base, attachments: {} },
      { ...base, attachments: [null] },
      { ...base, attachments: [{}] },
      { ...base, attachments: [{ data: null }] },
      { ...base, attachments: [{ data: 'x' }] },
    ]) {
      const packed = await encryptDidCommJwe(JSON.stringify(bad), b.publicKeyJwk, {
        cty: 'application/didcomm-plain+json',
      });
      await expect(unpackMessage(packed, b.keyPair, resolveSender)).rejects.toMatchObject({
        code: '9004',
      });
    }
  });

  it('署名者の鍵が authentication に無い（keyAgreement 専用）送信者は受理しない', async () => {
    const b = buildRecipientKeyAgreement(47);
    const message = { ...buildMessage(), from: senderDid, to: [bob] };
    const packed = await packMessage(message, b.publicKeyJwk, { senderSigner });
    const keyAgreementOnly: DIDDocument = {
      ...senderDoc,
      authentication: [],
      assertionMethod: senderDoc.assertionMethod,
    };
    await expect(
      unpackMessage(packed, b.keyPair, async () => keyAgreementOnly, { recipientDids: [bob] }),
    ).rejects.toMatchObject({ code: '9002' });
  });
});
