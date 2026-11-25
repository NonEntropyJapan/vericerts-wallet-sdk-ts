/**
 * OID4VCI proof JWT 生成の `Object.prototype` 汚染耐性テスト。
 *
 * `generateProofJWT` は `const { nonce, audience, issuer, keyId } = options` でオプションを
 * 読んでいた。分割代入はプロトタイプ鎖を辿るため、必須項目を渡し忘れた JS からの呼び出しでも
 * 汚染値が「指定された値」に化け、`HOLDER_PROOF_INVALID`（3081）のガードを素通りして
 * **署名済み proof JWT** が生成される。
 *
 * とりわけ `keyId` は proof JWT の `kid`（header）になるため、Issuer 側の鍵解決を攻撃者の
 * 指す鍵へ誘導できる。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../__tests__/prototype-pollution.fixtures.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { generateProofJWT } from '../../oid4vci/oid4vci.js';

const SIGNER = createPrivateKeySigner(new Uint8Array(32).fill(21), 'ES256');

const VALID = {
  nonce: 'c_nonce_1',
  audience: 'https://issuer.example',
  issuer: 'did:example:holder',
  keyId: 'did:example:holder#key-1',
} as const;

/** proof JWT の header / payload をデコードする。 */
function decode(jwt: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
} {
  const [h, p] = jwt.split('.');
  const dec = (seg: string): Record<string, unknown> =>
    JSON.parse(Buffer.from(seg, 'base64url').toString('utf8')) as Record<string, unknown>;
  return { header: dec(h ?? ''), payload: dec(p ?? '') };
}

describe('generateProofJWT の Object.prototype 汚染耐性', () => {
  it('継承した keyId では proof を生成せず 3081 で拒否する', () => {
    expect(() =>
      withPollutedPrototype({ keyId: 'did:attacker#key-1' }, () =>
        // `keyId` を渡していない呼び出し。汚染値を拾えば署名済み proof の `kid` が攻撃者の
        // 鍵 ID になる。
        generateProofJWT(
          {
            nonce: VALID.nonce,
            audience: VALID.audience,
            issuer: VALID.issuer,
          } as Parameters<typeof generateProofJWT>[0],
          SIGNER,
        ),
      ),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_PROOF_INVALID));
  });

  it('継承した nonce / audience / issuer でも 3081 で拒否する', () => {
    expect(() =>
      withPollutedPrototype(
        {
          nonce: 'attacker-nonce',
          audience: 'https://attacker.example',
          issuer: 'did:attacker',
        },
        () =>
          generateProofJWT(
            { keyId: VALID.keyId } as Parameters<typeof generateProofJWT>[0],
            SIGNER,
          ),
      ),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_PROOF_INVALID));
  });

  it('継承した now は署名済み proof の iat に載らない', () => {
    const attackerNowMs = 1_000_000_000;
    const jwt = withPollutedPrototype({ now: attackerNowMs }, () =>
      generateProofJWT({ ...VALID }, SIGNER),
    );
    expect(decode(jwt).payload.iat).not.toBe(Math.floor(attackerNowMs / 1000));
  });

  it('明示的に渡したオプションは従来どおり proof に載る（正常系）', () => {
    const jwt = generateProofJWT({ ...VALID, now: 1_767_225_600_000 }, SIGNER);
    const { header, payload } = decode(jwt);
    expect(header.kid).toBe(VALID.keyId);
    expect(payload.iss).toBe(VALID.issuer);
    expect(payload.aud).toBe(VALID.audience);
    expect(payload.nonce).toBe(VALID.nonce);
    expect(payload.iat).toBe(1_767_225_600);
  });
});
