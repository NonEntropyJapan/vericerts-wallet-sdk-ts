/**
 * OID4VP `direct_post.jwt` の暗号化パラメータ解決失敗（8036）と response_mode 切替のテスト
 * （実鍵・モック禁止）。
 *
 * direct_post と direct_post.jwt の応答モード切り替えを確認する。
 * ラウンドトリップと JOSE ヘッダは `oid4vp.direct-post-jwt.test.ts` に分離する。
 *
 * 検証内容:
 * - `client_metadata` 欠落 / `alg` 欠落 / 未対応 alg / 未対応 enc / `jwks` 欠落 / `use:"sig"` のみ /
 *   鍵側 alg 不一致 / 非 EC 鍵 / `crv` 不一致 はいずれも 8036 で拒否し **fetch を行わない**
 *   （平文 `direct_post` へフォールバックしない）。
 * - `use` 未指定の EC 鍵は利用できる（`use` は任意）。
 * - `kty` / `crv` / 座標長は正しいが**点が曲線上にない** JWK も 8036 で拒否し、@noble の生の
 *   `Error("bad point: is not on curve")` を呼び出し側へ escape させない。
 * - `direct_post` / `direct_post.jwt` の切替が Authorization Request の `response_mode` で決まる。
 */

import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { RESPONSE_MODE_DIRECT_POST, submitPresentation } from '../../../oid4vp/oid4vp-submit.js';
import type { PresentationRequest } from '../../../request.js';
import {
  capture,
  clientMetadata,
  installFetchCapture,
  RECIPIENT_PUBLIC,
  restoreFetch,
  STATE,
  sampleRequest,
  submitAndCaptureJwe,
  submitAndDecrypt,
  toEcJwk,
} from './direct-post-jwt.fixtures.js';

beforeEach(() => {
  installFetchCapture();
});

afterEach(() => {
  restoreFetch();
});

describe('submitPresentation — direct_post.jwt の暗号化パラメータ解決失敗（8036）', () => {
  /** 8036 で拒否され、fetch が呼ばれないことを確認する。 */
  async function expectUnsupported(request: PresentationRequest): Promise<void> {
    await expect(submitPresentation(request, 'tok')).rejects.toThrow(
      new VericertsError(ErrorCodes.VP_RESPONSE_ENCRYPTION_UNSUPPORTED),
    );
    expect(capture.calls).toBe(0);
  }

  it('client_metadata 欠落', async () => {
    const { clientMetadata: _omitted, ...withoutMetadata } = sampleRequest();
    await expectUnsupported(withoutMetadata as PresentationRequest);
  });

  it('authorization_encrypted_response_alg 欠落', async () => {
    await expectUnsupported(
      sampleRequest({ clientMetadata: { jwks: { keys: [toEcJwk(RECIPIENT_PUBLIC)] } } }),
    );
  });

  it('未対応 alg（RSA-OAEP）', async () => {
    await expectUnsupported(sampleRequest({ clientMetadata: clientMetadata('RSA-OAEP') }));
  });

  it('未対応 enc（A128CBC-HS256）', async () => {
    await expectUnsupported(
      sampleRequest({
        clientMetadata: clientMetadata(
          'ECDH-ES',
          [toEcJwk(RECIPIENT_PUBLIC, { use: 'enc' })],
          'A128CBC-HS256',
        ),
      }),
    );
  });

  it('jwks 欠落', async () => {
    await expectUnsupported(
      sampleRequest({ clientMetadata: { authorization_encrypted_response_alg: 'ECDH-ES' } }),
    );
  });

  it('use:"sig" の鍵しか無い（署名鍵の暗号化転用を拒否する）', async () => {
    await expectUnsupported(
      sampleRequest({
        clientMetadata: clientMetadata('ECDH-ES', [toEcJwk(RECIPIENT_PUBLIC, { use: 'sig' })]),
      }),
    );
  });

  it('鍵側 alg がネゴシエート済み alg と不一致（alg confusion を拒否する）', async () => {
    await expectUnsupported(
      sampleRequest({
        clientMetadata: clientMetadata('ECDH-ES', [
          toEcJwk(RECIPIENT_PUBLIC, { use: 'enc', alg: 'ECDH-ES+A256KW' }),
        ]),
      }),
    );
  });

  it('EC 以外の鍵しか無い（RSA）', async () => {
    await expectUnsupported(
      sampleRequest({
        clientMetadata: clientMetadata('ECDH-ES', [
          { kty: 'RSA', use: 'enc', n: 'AQAB', e: 'AQAB' },
        ]),
      }),
    );
  });

  it('crv が P-256 以外（P-384）は 8036', async () => {
    await expectUnsupported(
      sampleRequest({
        clientMetadata: clientMetadata('ECDH-ES', [
          { ...toEcJwk(RECIPIENT_PUBLIC, { use: 'enc' }), crv: 'P-384' },
        ]),
      }),
    );
  });

  it('use 未指定の EC 鍵は利用できる（use は任意）', async () => {
    const request = sampleRequest({
      clientMetadata: clientMetadata('ECDH-ES', [toEcJwk(RECIPIENT_PUBLIC)]),
    });
    expect((await submitAndDecrypt(request)).vp_token).toBe('vp-token-string');
  });
});

describe('submitPresentation — 曲線外の受信者鍵', () => {
  /** 形式（`kty` / `crv` / 座標長）は正しいが点が曲線上にない EC 公開鍵 JWK。 */
  function offCurveMetadata(alg: string): Record<string, unknown> {
    const coordinate = base64urlnopad.encode(new Uint8Array(32).fill(1));
    return clientMetadata(alg, [
      { kty: 'EC', crv: 'P-256', x: coordinate, y: coordinate, use: 'enc', kid: 'k-bad' },
    ]);
  }

  it('ECDH-ES: 生の Error ではなく VericertsError(8036) を投げ、fetch もしない', async () => {
    const request = sampleRequest({ clientMetadata: offCurveMetadata('ECDH-ES') });
    const error = await submitPresentation(request, 'tok').catch((err: unknown) => err);

    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.VP_RESPONSE_ENCRYPTION_UNSUPPORTED);
    // 曲線外点の鍵は選択段階で不適格として読み飛ばされ、他に鍵が無ければ「鍵なし」になる。
    expect((error as VericertsError).context).toEqual({ reason: 'encryption_key_not_found' });
    expect(capture.calls).toBe(0);
  });

  it('ECDH-ES+A256KW でも 8036 に正規化する', async () => {
    await expect(
      submitPresentation(
        sampleRequest({ clientMetadata: offCurveMetadata('ECDH-ES+A256KW') }),
        'tok',
      ),
    ).rejects.toThrow(new VericertsError(ErrorCodes.VP_RESPONSE_ENCRYPTION_UNSUPPORTED));
  });

  it('例外に鍵素材・@noble のメッセージ・cause を含めない', async () => {
    const request = sampleRequest({ clientMetadata: offCurveMetadata('ECDH-ES') });
    const error = (await submitPresentation(request, 'tok').catch(
      (err: unknown) => err,
    )) as VericertsError;

    expect(error.message).not.toContain('curve');
    expect(error.message).not.toContain('point');
    expect(error.cause).toBeUndefined();
    expect(JSON.stringify(error.context)).not.toContain('AQEB');
  });
});

describe('submitPresentation — response_mode による経路切替', () => {
  it('direct_post は平文 vp_token を送り response を送らない', async () => {
    await submitPresentation(
      sampleRequest({ responseMode: RESPONSE_MODE_DIRECT_POST }),
      'plain-token',
    );
    const params = new URLSearchParams(capture.body);
    expect(params.get('vp_token')).toBe('plain-token');
    expect(params.get('state')).toBe(STATE);
    expect(params.get('response')).toBeNull();
  });

  it('direct_post.jwt は response のみを送り vp_token を送らない', async () => {
    await submitAndCaptureJwe(sampleRequest());
    expect(new URLSearchParams(capture.body).get('vp_token')).toBeNull();
  });

  it('direct_post でも presentation_submission を送れる', async () => {
    const submission = { id: 'sub-1', definition_id: 'def-1', descriptor_map: [] };
    await submitPresentation(sampleRequest({ responseMode: RESPONSE_MODE_DIRECT_POST }), 'tok', {
      presentationSubmission: submission,
    });
    const params = new URLSearchParams(capture.body);
    expect(JSON.parse(params.get('presentation_submission') as string)).toEqual(submission);
  });

  it('direct_post.jwt で HTTP 非 2xx は 8035 に正規化する', async () => {
    installFetchCapture(400);
    await expect(submitPresentation(sampleRequest(), 'tok')).rejects.toThrow(
      new VericertsError(ErrorCodes.PRESENTATION_SUBMIT_FAILED),
    );
  });
});
