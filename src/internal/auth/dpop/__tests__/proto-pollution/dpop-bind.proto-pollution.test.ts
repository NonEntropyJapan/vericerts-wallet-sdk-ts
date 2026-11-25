/**
 * `bindAccessTokenToDpopKey` の `cnf` 読み取りにおける `Object.prototype` 汚染耐性テスト。
 *
 * 修正前は `tokenPayload.cnf` をプロパティアクセス（プロトタイプ鎖読み）で取得していたため、
 * `Object.prototype.cnf` が汚染された環境では **`cnf` を own プロパティとして持たない正当な
 * `tokenPayload`** でも継承値を拾い、`{ ...baseCnf, jkt }` によって余分なメンバが署名対象の
 * `cnf` に紛れ込んでいた。`createDpopProof` の own 限定読みと同じ規約
 * （`src/internal/prototype-safety/own-property.ts`）に揃える。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { createPrivateKeySigner } from '../../../../credential/vc/signer.js';
import { bindAccessTokenToDpopKey } from '../../dpop.js';
import { computeJwkThumbprint } from '../../dpop-common.js';

const KEY = new Uint8Array(32).fill(7);
const SIGNER = createPrivateKeySigner(KEY, 'ES256');
const JKT = computeJwkThumbprint(SIGNER.publicKeyJwk, 'ES256');

describe('bindAccessTokenToDpopKey の cnf 読み取り Object.prototype 汚染耐性', () => {
  it('データ汚染: cnf を持たない payload に継承した cnf メンバを混入しない', () => {
    const payload = { sub: 'user-1' };
    const bound = withPollutedPrototype({ cnf: { role: 'admin' } }, () =>
      bindAccessTokenToDpopKey(payload, SIGNER.publicKeyJwk, 'ES256'),
    );
    expect(bound.cnf).toEqual({ jkt: JKT });
  });

  it('アクセサ汚染: cnf を持たない payload に継承した cnf メンバを混入しない', () => {
    const payload = { sub: 'user-1' };
    const bound = withPollutedPrototypeAccessor({ cnf: () => ({ role: 'admin' }) }, () =>
      bindAccessTokenToDpopKey(payload, SIGNER.publicKeyJwk, 'ES256'),
    );
    expect(bound.cnf).toEqual({ jkt: JKT });
  });

  it('ポジティブコントロール: 汚染下でも own の cnf メンバは保持される', () => {
    const payload = { sub: 'user-1', cnf: { 'x5t#S256': 'cert-thumb' } };
    const bound = withPollutedPrototype({ cnf: { role: 'admin' } }, () =>
      bindAccessTokenToDpopKey(payload, SIGNER.publicKeyJwk, 'ES256'),
    );
    expect(bound.cnf).toEqual({ 'x5t#S256': 'cert-thumb', jkt: JKT });
  });
});
