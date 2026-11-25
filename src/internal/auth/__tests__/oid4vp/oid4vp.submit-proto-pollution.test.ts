/**
 * `Object.prototype` 汚染下でも vp_token が攻撃者の鍵へ暗号化されないことの回帰テスト。
 *
 * `direct_post.jwt` の要求に `client_metadata` がなければ、SDK は送信前にエラー 8036 を返す。
 *
 * 欠陥時の挙動: `request.clientMetadata` をプロトタイプ鎖越しに読むため、Verifier が
 * `client_metadata` を告知していない要求でも `Object.prototype.clientMetadata` の汚染値が
 * 暗号化パラメータとして解決され、**攻撃者の公開鍵で暗号化した vp_token が送出される**。
 */

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { p256 } from '@noble/curves/nist.js';
import { withPollutedPrototypeAsync } from '../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { submitPresentation } from '../../oid4vp/oid4vp-submit.js';
import {
  capture,
  clientMetadata,
  decryptJwe,
  headerOf,
  installFetchCapture,
  RECIPIENT_PUBLIC,
  RECIPIENT_SECRET,
  restoreFetch,
  sampleRequest,
  submitAndCaptureJwe,
  submitAndDecrypt,
  toEcJwk,
} from './direct-post-jwt/direct-post-jwt.fixtures.js';

/** 攻撃者（汚染値の仕込み手）が保持する受信鍵。 */
const ATTACKER_SECRET = new Uint8Array(32).fill(77);
const ATTACKER_PUBLIC = p256.getPublicKey(ATTACKER_SECRET, false);

/** 攻撃者の公開鍵だけを載せた `client_metadata`。 */
function attackerClientMetadata(): Record<string, unknown> {
  return clientMetadata('ECDH-ES', [toEcJwk(ATTACKER_PUBLIC, { use: 'enc', kid: 'attacker' })]);
}

describe('submitPresentation: Object.prototype 汚染', () => {
  beforeEach(() => {
    installFetchCapture();
  });
  afterEach(() => {
    restoreFetch();
  });

  test('clientMetadata を持たない要求は汚染値を暗号化先に採用せず 8036 で失敗する', async () => {
    // `clientMetadata` プロパティ自体を持たない要求（Verifier が告知していない）。
    const { clientMetadata: _omitted, ...request } = sampleRequest();
    expect(Object.hasOwn(request, 'clientMetadata')).toBe(false);

    await withPollutedPrototypeAsync({ clientMetadata: attackerClientMetadata() }, async () => {
      // 汚染下でも継承値を拾わないため「client_metadata 欠落」として 8036 になる。
      const error = await submitPresentation(request, 'vp-token-string').then(
        () => undefined,
        (e: unknown) => e,
      );
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe(ErrorCodes.VP_RESPONSE_ENCRYPTION_UNSUPPORTED);
    });

    // vp_token は 1 バイトも送出されていない（攻撃者の鍵で暗号化された応答が飛ばない）。
    expect(capture.calls).toBe(0);
    expect(capture.body).toBe('');
  });

  test('jwks / alg 単体の汚染も暗号化パラメータとして採用されない', async () => {
    const request = sampleRequest({ clientMetadata: {} });

    await withPollutedPrototypeAsync(
      {
        authorization_encrypted_response_alg: 'ECDH-ES',
        jwks: { keys: [toEcJwk(ATTACKER_PUBLIC, { use: 'enc', kid: 'attacker' })] },
      },
      async () => {
        const error = await submitPresentation(request, 'vp-token-string').then(
          () => undefined,
          (e: unknown) => e,
        );
        expect(error).toBeInstanceOf(VericertsError);
        expect((error as VericertsError).code).toBe(ErrorCodes.VP_RESPONSE_ENCRYPTION_UNSUPPORTED);
      },
    );
    expect(capture.calls).toBe(0);
  });

  test('presentationSubmission / walletNonce の汚染は送信内容に混入しない', async () => {
    const request = sampleRequest();
    const jwe = await withPollutedPrototypeAsync(
      { presentationSubmission: { id: 'polluted' }, walletNonce: 'polluted-wallet-nonce' },
      async () => submitAndCaptureJwe(request),
    );
    // `walletNonce` は `apu = SHA-256(wallet_nonce)` として JWE protected header に載る。
    // JWE は apu があっても復号できるため、復号結果だけでは汚染の混入を検出できない。
    expect(headerOf(jwe).apu).toBeUndefined();
    const payload = JSON.parse(await decryptJwe(jwe, RECIPIENT_SECRET)) as Record<string, unknown>;
    expect(payload.vp_token).toBe('vp-token-string');
    expect(payload.presentation_submission).toBeUndefined();
  });

  test('正常系: walletNonce を明示した呼び出しでは apu がヘッダに載る', async () => {
    // 直前のテストが「walletNonce 未指定」だけを突いていることを担保する対照ケース。
    const jwe = await submitAndCaptureJwe(sampleRequest(), 'vp-token-string', {
      walletNonce: 'legit-wallet-nonce',
    });
    expect(typeof headerOf(jwe).apu).toBe('string');
  });

  test('正常系: clientMetadata を明示した要求は従来どおり Verifier の鍵で暗号化される', async () => {
    // 受理集合を狭める変更のため、正当な入力が拒否されていないことを確認する。
    const request = sampleRequest();
    const jwe = await withPollutedPrototypeAsync(
      { clientMetadata: attackerClientMetadata() },
      async () => {
        await submitPresentation(request, 'vp-token-string');
        return new URLSearchParams(capture.body).get('response') as string;
      },
    );
    expect(capture.calls).toBe(1);
    // 正規の Verifier 鍵で復号できる = 汚染値の鍵は使われていない。
    const plaintext = JSON.parse(await decryptJwe(jwe, RECIPIENT_SECRET)) as Record<
      string,
      unknown
    >;
    expect(plaintext.vp_token).toBe('vp-token-string');
    // 攻撃者の鍵では復号できない。
    await expect(decryptJwe(jwe, ATTACKER_SECRET)).rejects.toThrow();
  });

  test('kid / apu の汚染は JWE protected header に載らない', async () => {
    // `kid` を持たない Verifier 鍵 + `wallet_nonce` 無し = どちらも「未指定」の正当な要求。
    const request = sampleRequest({
      clientMetadata: clientMetadata('ECDH-ES', [toEcJwk(RECIPIENT_PUBLIC, { use: 'enc' })]),
    });
    const jwe = await withPollutedPrototypeAsync(
      { kid: 'attacker-key-id', apu: new Uint8Array(32).fill(9) },
      async () => submitAndCaptureJwe(request),
    );
    const header = headerOf(jwe);
    expect(header.kid).toBeUndefined();
    expect(header.apu).toBeUndefined();
    // 正規の受信鍵で復号できる（汚染 apu が Concat KDF に入っていない）。
    const plaintext = JSON.parse(await decryptJwe(jwe, RECIPIENT_SECRET)) as Record<
      string,
      unknown
    >;
    expect(plaintext.vp_token).toBe('vp-token-string');
  });

  test('正常系: kid を告知した Verifier 鍵ではその kid がヘッダに載る', async () => {
    const jwe = await submitAndCaptureJwe(sampleRequest());
    expect(headerOf(jwe).kid).toBe('k1');
  });

  test('正常系: presentationSubmission を明示した呼び出しは従来どおり送信される', async () => {
    const submission = { id: 'legit', definition_id: 'd1', descriptor_map: [] };
    const payload = await submitAndDecrypt(sampleRequest(), 'vp-token-string', {
      presentationSubmission: submission,
    });
    expect(payload.presentation_submission).toEqual(submission);
  });
});
