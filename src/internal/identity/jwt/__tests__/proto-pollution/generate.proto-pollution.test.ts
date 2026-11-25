/**
 * did:jwt 生成の `Object.prototype` 汚染耐性テスト。
 *
 * `opts.subjectDid` / `iat` / `nbf` / `expiresInSeconds` をプロトタイプ鎖で読むと、これらを
 * **省略した**正当な生成でも汚染値が **署名済み did:jwt トークンの payload** に載る。
 *
 * `subjectDid` は `iss` / `sub` / `id` の 3 つを同時に設定するため、継承値を拾うと
 * **トークンが指す主体そのものが攻撃者の DID に差し替わる**。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { createDidJwt } from '../../generate.js';

const PRIVATE_KEY = new Uint8Array(32).fill(13);
const ATTACKER_DID = 'did:example:attacker';

/** `did:jwt:<base64url(JWT)>` の payload をデコードする（JWT 自体がもう一段 base64url）。 */
function payloadOf(didJwt: string): Record<string, unknown> {
  const jwt = Buffer.from(didJwt.slice('did:jwt:'.length), 'base64url').toString('utf8');
  const segment = jwt.split('.')[1] ?? '';
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
}

describe('createDidJwt の Object.prototype 汚染耐性', () => {
  it('継承した subjectDid は iss / sub / id を差し替えない', () => {
    const didJwt = withPollutedPrototype({ subjectDid: ATTACKER_DID }, () =>
      createDidJwt({ alg: 'ES256', privateKey: PRIVATE_KEY }),
    );
    const payload = payloadOf(didJwt);
    expect(payload.iss).not.toBe(ATTACKER_DID);
    expect(payload.sub).not.toBe(ATTACKER_DID);
    expect(payload.id).not.toBe(ATTACKER_DID);
    // 既定は `did:jwt:` プレフィックス。
    expect(payload.iss).toBe('did:jwt:');
  });

  it('継承した iat / nbf は署名済み payload に載らない', () => {
    const attackerTime = 1_000_000;
    const didJwt = withPollutedPrototype({ iat: attackerTime, nbf: attackerTime }, () =>
      createDidJwt({ alg: 'ES256', privateKey: PRIVATE_KEY }),
    );
    const payload = payloadOf(didJwt);
    expect(payload.iat).not.toBe(attackerTime);
    expect(payload.nbf).not.toBe(attackerTime);
  });

  it('継承した expiresInSeconds は有効期間を伸ばさない', () => {
    const hundredYears = 100 * 365 * 24 * 3600;
    const didJwt = withPollutedPrototype({ expiresInSeconds: hundredYears }, () =>
      createDidJwt({ alg: 'ES256', privateKey: PRIVATE_KEY }),
    );
    const payload = payloadOf(didJwt);
    const iat = payload.iat as number;
    const exp = payload.exp as number;
    // 既定は 24 時間。
    expect(exp - iat).toBe(24 * 3600);
  });

  it('明示的に渡したオプションは従来どおり payload に載る（正常系）', () => {
    const didJwt = createDidJwt({
      alg: 'ES256',
      privateKey: PRIVATE_KEY,
      subjectDid: 'did:example:me',
      iat: 1_767_225_600,
      expiresInSeconds: 300,
    });
    const payload = payloadOf(didJwt);
    expect(payload.iss).toBe('did:example:me');
    expect(payload.sub).toBe('did:example:me');
    expect(payload.id).toBe('did:example:me');
    expect(payload.iat).toBe(1_767_225_600);
    expect(payload.exp).toBe(1_767_225_900);
  });
});
