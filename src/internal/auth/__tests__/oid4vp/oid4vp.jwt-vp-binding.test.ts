/**
 * `buildVPToken` の `jwt_vc_json` 経路が nonce / aud（client_id）の欠落・空・非文字列を
 * 署名前に 3012 で拒否することの回帰テスト。SD-JWT 経路（`addKeyBinding`）と防御を揃える。
 */

import { describe, expect, it } from 'bun:test';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { buildVPToken } from '../../oid4vp/oid4vp.js';
import type { PresentationRequest } from '../../request.js';

const BASE: PresentationRequest = {
  responseType: 'vp_token',
  clientId: 'https://verifier.example.com',
  responseMode: 'direct_post',
  responseUri: 'https://verifier.example.com/callback',
  nonce: 'n-0S6_WzA2Mj',
  state: 'af0ifjsldkj',
};

function buildWith(request: unknown): { result: () => unknown; signCalls: () => number } {
  let calls = 0;
  const inner = createPrivateKeySigner(new Uint8Array(32).fill(11), 'ES256');
  const signer = {
    ...inner,
    sign: (...args: Parameters<typeof inner.sign>) => {
      calls += 1;
      return inner.sign(...args);
    },
  };
  return {
    result: () =>
      buildVPToken(request as PresentationRequest, [
        {
          format: 'jwt_vc_json',
          holder: 'did:example:holder',
          verifiableCredentials: ['eyJhbGciOiJFUzI1NiJ9.vc.sig'],
          signer,
        },
      ]),
    signCalls: () => calls,
  };
}

describe('buildVPToken jwt_vc_json: nonce / aud の検証', () => {
  const bad: [string, unknown][] = [
    ['request = {}', {}],
    ['nonce 空文字', { ...BASE, nonce: '' }],
    ['clientId 空文字', { ...BASE, clientId: '' }],
    ['nonce 非文字列', { ...BASE, nonce: 5 }],
    ['clientId 非文字列', { ...BASE, clientId: 7 }],
    ['nonce 欠落', { ...BASE, nonce: undefined }],
  ];

  it.each(bad)('%s は 3012 で拒否し、署名しない', (_label, request) => {
    const { result, signCalls } = buildWith(request);
    expect(result).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
    expect(signCalls()).toBe(0);
  });

  it('正常な nonce / clientId では署名して JWT-VP を返す（対照）', () => {
    const { result, signCalls } = buildWith(BASE);
    expect(typeof result()).toBe('string');
    expect(signCalls()).toBe(1);
  });
});
