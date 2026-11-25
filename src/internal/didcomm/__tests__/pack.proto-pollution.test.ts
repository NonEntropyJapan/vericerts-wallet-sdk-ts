/**
 * `packMessage` の options 汚染耐性。
 *
 * `options.senderSigner` / `options.recipientKid` を素で読むと、Anoncrypt のつもりで省略した呼び出しが
 * `Object.prototype.senderSigner` の汚染値を署名者として拾い、署名対象（= 平文メッセージ全体）が
 * 汚染された関数へ渡ったうえ Authcrypt 経路に切り替わる。結果（cty・署名者呼び出し回数・JWE header の kid）が
 * 汚染前後で変わらないことで検証する。
 */

import { describe, expect, it } from 'bun:test';
import { p256 } from '@noble/curves/nist.js';
import { base64urlnopad } from '@scure/base';
import { withPollutedPrototypeAsync } from '../../__tests__/prototype-pollution.fixtures.js';
import { createSecp256k1CredentialSigner } from '../../keymanager/credential-signer.js';
import { DIDCOMM_PLAIN_CTY, DIDCOMM_SIGNED_CTY } from '../jwe.js';
import { packMessage } from '../pack.js';
import type { DIDCommPlaintextMessage } from '../types.js';

const privateKey = new Uint8Array(32).fill(10);
const uncompressed = p256.getPublicKey(privateKey, false);
const recipientJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: base64urlnopad.encode(uncompressed.slice(1, 33)),
  y: base64urlnopad.encode(uncompressed.slice(33)),
};
const message: DIDCommPlaintextMessage = {
  id: 'm1',
  type: 'https://didcomm.org/basicmessage/2.0/message',
  to: ['did:x'],
  body: { secret: 'PLAINTEXT' },
};

function protectedHeader(packed: string): Record<string, unknown> {
  const [header] = packed.split('.');
  return JSON.parse(Buffer.from(header as string, 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;
}

/** 呼ばれたら記録する汚染署名者（実署名者に委譲する）。 */
function spySigner() {
  const real = createSecp256k1CredentialSigner(new Uint8Array(32).fill(20));
  const seen: Uint8Array[] = [];
  const signer = {
    ...real,
    signAsync: undefined,
    sign: (bytes: Uint8Array) => {
      seen.push(bytes);
      return real.sign(bytes);
    },
  };
  return { signer, seen };
}

describe('packMessage の options 汚染耐性', () => {
  it('senderSigner を省略した呼び出しは汚染署名者へ平文を渡さず Anoncrypt のまま', async () => {
    const clean = protectedHeader(await packMessage(message, recipientJwk));
    expect(clean.cty).toBe(DIDCOMM_PLAIN_CTY);
    const { signer, seen } = spySigner();
    for (const options of [undefined, {}, { recipientKid: undefined }]) {
      const polluted = await withPollutedPrototypeAsync({ senderSigner: signer }, () =>
        packMessage(message, recipientJwk, options),
      );
      expect(protectedHeader(polluted).cty).toBe(clean.cty);
    }
    expect(seen).toHaveLength(0);
  });

  it('recipientKid を省略しても汚染値は JWE header の kid に載らない', async () => {
    const clean = protectedHeader(await packMessage(message, recipientJwk));
    const polluted = await withPollutedPrototypeAsync({ recipientKid: 'did:evil#key-1' }, () =>
      packMessage(message, recipientJwk),
    );
    expect(protectedHeader(polluted).kid).toBe(clean.kid);
    expect(protectedHeader(polluted).kid).toBeUndefined();
  });

  it('own の senderSigner / recipientKid は汚染値より優先される（Authcrypt）', async () => {
    const { signer: polluting, seen: pollutedSeen } = spySigner();
    const { signer: own, seen: ownSeen } = spySigner();
    const packed = await withPollutedPrototypeAsync(
      { senderSigner: polluting, recipientKid: 'did:evil#key-1' },
      () => packMessage(message, recipientJwk, { senderSigner: own, recipientKid: 'did:ok#k1' }),
    );
    expect(protectedHeader(packed)).toMatchObject({ cty: DIDCOMM_SIGNED_CTY, kid: 'did:ok#k1' });
    expect(ownSeen).toHaveLength(1);
    expect(pollutedSeen).toHaveLength(0);
  });
});
