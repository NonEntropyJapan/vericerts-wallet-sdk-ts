/**
 * `submitPresentation` が `presentation_submission` を送ることの回帰テスト。
 *
 * 応答の送信には OpenID4VP 1.0 §8.2 の `direct_post` を使う。旧版の OpenID4VP との互換性のため、
 * SDK は Presentation Exchange の応答パラメータにも対応する。walt.id verifier は
 * `presentation_submission.descriptor_map[0].format` で VP の検証方式を選ぶため、`presentation_definition`
 * 経路の提示でこれが欠落すると HTTP 400（`No presentation submission or presentation format found.`）で
 * 拒否する。DCQL 提示では送らない。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { withPollutedPrototypeAsync } from '../../../__tests__/prototype-pollution.fixtures.js';
import { type SubmitFetchLike, submitPresentation } from '../../oid4vp/oid4vp-submit.js';
import type { PresentationRequest } from '../../request.js';

/** `vp.verifiableCredential` に VC-JWT を `count` 件束ねた JWT-VP（署名は検証されないダミー）。 */
function jwtVp(count: number): string {
  const credentials = Array.from({ length: count }, (_, i) => `vc.jwt.${i}`);
  const [header, payload] = [
    { alg: 'EdDSA', typ: 'JWT' },
    { iss: 'did:key:z6Mk', vp: { verifiableCredential: credentials } },
  ].map((part) => base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(part))));
  return `${header}.${payload}.c2ln`;
}

const DEFINITION = {
  id: 'pd-1',
  input_descriptors: [{ id: 'OpenBadgeCredential' }, { id: 'Other' }],
};

const REQUEST: PresentationRequest = {
  responseType: 'vp_token',
  clientId: 'https://verifier.example.com',
  responseMode: 'direct_post',
  responseUri: 'https://verifier.example.com/response',
  nonce: 'n-0S6_WzA2Mj',
  state: 'state-123',
  presentationDefinition: DEFINITION,
};

/** 送信フォーム本文を捕捉して返す。 */
async function submitAndCapture(
  request: PresentationRequest,
  vpToken: string | string[],
  options: Parameters<typeof submitPresentation>[2] = {},
): Promise<URLSearchParams> {
  let body = '';
  const fetchImpl: SubmitFetchLike = (_url, init) => {
    body = init.body;
    return Promise.resolve(new Response('', { status: 200 }));
  };
  await submitPresentation(request, vpToken, { ...options, fetchImpl });
  return new URLSearchParams(body);
}

describe('submitPresentation / presentation_submission', () => {
  it('presentation_definition 経路の JWT-VP には presentation_submission を載せる', async () => {
    const body = await submitAndCapture(REQUEST, jwtVp(1));
    const submission = JSON.parse(body.get('presentation_submission') ?? 'null');
    expect(submission.definition_id).toBe('pd-1');
    expect(typeof submission.id).toBe('string');
    expect(submission.descriptor_map).toEqual([
      {
        id: 'OpenBadgeCredential',
        format: 'jwt_vp_json',
        path: '$',
        path_nested: {
          id: 'OpenBadgeCredential',
          format: 'jwt_vc_json',
          path: '$.vp.verifiableCredential[0]',
        },
      },
    ]);
  });

  it('VP が束ねる VC の数だけ descriptor を対応付ける', async () => {
    const body = await submitAndCapture(REQUEST, jwtVp(2));
    const submission = JSON.parse(body.get('presentation_submission') ?? 'null');
    expect(submission.descriptor_map.map((d: { id: string }) => d.id)).toEqual([
      'OpenBadgeCredential',
      'Other',
    ]);
    expect(submission.descriptor_map[1].path_nested.path).toBe('$.vp.verifiableCredential[1]');
  });

  it('明示指定の presentationSubmission を既定より優先する', async () => {
    const explicit = { id: 'sub-x', definition_id: 'pd-1', descriptor_map: [] };
    const body = await submitAndCapture(REQUEST, jwtVp(1), { presentationSubmission: explicit });
    expect(JSON.parse(body.get('presentation_submission') ?? 'null')).toEqual(explicit);
  });

  it('DCQL 提示（presentation_definition なし）では送らない', async () => {
    const { presentationDefinition: _omitted, ...dcqlRequest } = REQUEST;
    const body = await submitAndCapture(dcqlRequest, jwtVp(1));
    expect(body.has('presentation_submission')).toBe(false);
  });

  it.each([
    ['SD-JWT VC', 'eyJhbGci.issuer.jwt~WyJzYWx0IiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~'],
    ['複数 VP（配列）', [jwtVp(1), jwtVp(1)]],
    ['VC を束ねない VP', jwtVp(0)],
  ])('既定の対応付けが決められない提示（%s）には送らない', async (_name, vpToken) => {
    const body = await submitAndCapture(REQUEST, vpToken);
    expect(body.has('presentation_submission')).toBe(false);
  });

  it.each([
    ['payload が JSON でない JWT', `${'e30'}.${'bm90LWpzb24'}.c2ln`],
    ['payload が null の JWT', 'e30.bnVsbA.c2ln'],
    ['vp を持たない JWT', 'e30.e30.c2ln'],
    [
      'vp.verifiableCredential が配列でない JWT',
      `e30.${base64urlnopad.encode(new TextEncoder().encode('{"vp":{"verifiableCredential":"x"}}'))}.c2ln`,
    ],
  ])('VC 数を読めない VP（%s）には送らない', async (_name, vpToken) => {
    const body = await submitAndCapture(REQUEST, vpToken);
    expect(body.has('presentation_submission')).toBe(false);
  });

  it.each([
    ['definition の id が無い', { input_descriptors: [{ id: 'a' }] }],
    ['input_descriptors が配列でない', { id: 'pd-1', input_descriptors: 'a' }],
    ['descriptor の id が文字列でない', { id: 'pd-1', input_descriptors: [{ id: 1 }] }],
    ['descriptor がオブジェクトでない', { id: 'pd-1', input_descriptors: ['a'] }],
  ])('定義が不正（%s）なら送らない', async (_name, presentationDefinition) => {
    const body = await submitAndCapture({ ...REQUEST, presentationDefinition }, jwtVp(1));
    expect(body.has('presentation_submission')).toBe(false);
  });

  it('Object.prototype 由来の presentationDefinition / presentationSubmission は採用しない', async () => {
    const { presentationDefinition: _omitted, ...dcqlRequest } = REQUEST;
    await withPollutedPrototypeAsync(
      {
        presentationDefinition: DEFINITION,
        presentationSubmission: { id: 'evil', definition_id: 'pd-1', descriptor_map: [] },
      },
      async () => {
        const body = await submitAndCapture(dcqlRequest, jwtVp(1));
        expect(body.has('presentation_submission')).toBe(false);
      },
    );
  });
});
