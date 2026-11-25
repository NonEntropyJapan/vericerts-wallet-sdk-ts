/**
 * `createDidPeer2` の任意項目（keyAgreementKeys / services）は自身のプロパティだけを読む。
 *
 * `opts.keyAgreementKeys ?? []` が鎖読みだと、省略した呼び出しが `Object.prototype.keyAgreementKeys` /
 * `services` の汚染値を拾い、生成した DID に攻撃者の暗号鍵・サービスエンドポイントが焼き込まれる。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { createDidPeer2, encodePublicKeyMultibase } from '../../method-peer.js';
import { p256Key } from '../numalgo2-keys.fixtures.js';

const VER_KEY = encodePublicKeyMultibase('Ed25519', new Uint8Array(32).fill(6));
const ATTACKER_KEY = p256Key(9);

describe('createDidPeer2 の任意項目', () => {
  it.each([
    ['keyAgreementKeys', { keyAgreementKeys: [ATTACKER_KEY] }],
    [
      'services',
      { services: [{ type: 'DIDCommMessaging', serviceEndpoint: 'https://attacker.example' }] },
    ],
    [
      '両方',
      { keyAgreementKeys: [ATTACKER_KEY], services: [{ t: 'dm', s: 'https://attacker.example' }] },
    ],
  ])('汚染された %s は DID に反映されない', (_name, polluted) => {
    const clean = createDidPeer2({ verificationKeys: [VER_KEY] });
    const dirty = withPollutedPrototype(polluted, () =>
      createDidPeer2({ verificationKeys: [VER_KEY] }),
    );
    expect(dirty).toBe(clean);
  });

  it('own で渡した keyAgreementKeys は従来どおり反映される（正常系）', () => {
    const did = createDidPeer2({ verificationKeys: [VER_KEY], keyAgreementKeys: [ATTACKER_KEY] });
    expect(did).toContain(`.E${ATTACKER_KEY}`);
  });
});
