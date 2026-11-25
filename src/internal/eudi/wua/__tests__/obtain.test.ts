/**
 * `obtainWalletUnitAttestation` の 2 段取得フロー正常系。
 *
 * - `POST /wua/challenge` → デバイスバインド Proof 生成 → `POST /wua/issue` の順で通信する
 * - 要求本文は本 SDK が固定した 1 形（`{ devicePubKey }` / `{ assertion, device_posture? }`）
 * - Proof は challenge / nonce を payload に持つコンパクト JWS で、WSCD 鍵で署名されている
 * - `wscdPublicKeyJwk` 指定時は WUA `cnf.jwk` のバインドも検証する（一致で成功、不一致は 10102）
 *
 * 失敗経路は `obtain.failures.test.ts` が受け持つ。ネットワークは `fetchImpl` の注入のみで
 * 再現し、鍵素材は実鍵のみ（`wua-fixtures.ts`）。
 */

import { describe, expect, test } from 'bun:test';
import { decodeCompactJws } from '../../../credential/vc/jws.js';
import { obtainWalletUnitAttestation } from '../obtain.js';
import { WUA_VCT } from '../types.js';
import {
  CHALLENGE,
  CHALLENGE_URL,
  codeOf,
  ENDPOINT,
  ISSUE_URL,
  NONCE,
  obtainOptions,
  PROVIDER_KEY,
  stubTwoStage,
  wscdJwk,
} from './obtain-fixtures.js';
import { makeWuaJwt, OTHER_PRIVATE_KEY, toP256Jwk, WSCD_PRIVATE_KEY } from './wua-fixtures.js';

/** 記録された要求本文を JSON object として読む。 */
function bodyOf(body: string): Record<string, unknown> {
  return JSON.parse(body) as Record<string, unknown>;
}

describe('obtainWalletUnitAttestation の 2 段フロー', () => {
  test('challenge → issue の順に POST し、検証済み WUA を返す', async () => {
    const jwt = makeWuaJwt(PROVIDER_KEY);
    const stub = stubTwoStage(jwt);

    const wua = await obtainWalletUnitAttestation(ENDPOINT, obtainOptions(stub));

    expect(wua.jwt).toBe(jwt);
    expect(wua.vct).toBe(WUA_VCT);
    expect(wua.walletProviderDID).toBe('https://wallet-provider.example.eu');
    expect(wua.cnf.jwk).toEqual(toP256Jwk(WSCD_PRIVATE_KEY));
    expect(stub.requests.map((request) => request.url)).toEqual([CHALLENGE_URL, ISSUE_URL]);
  });

  test('providerEndpoint の末尾スラッシュは除去してからパスを連結する', async () => {
    const stub = stubTwoStage(makeWuaJwt(PROVIDER_KEY));

    await obtainWalletUnitAttestation(`${ENDPOINT}/`, obtainOptions(stub));

    expect(stub.requests.map((request) => request.url)).toEqual([CHALLENGE_URL, ISSUE_URL]);
  });

  test('/wua/challenge には署名鍵の公開鍵を devicePubKey として送る', async () => {
    const stub = stubTwoStage(makeWuaJwt(PROVIDER_KEY));

    await obtainWalletUnitAttestation(ENDPOINT, obtainOptions(stub));

    expect(bodyOf(stub.requests[0]?.body ?? '{}')).toEqual({
      devicePubKey: toP256Jwk(WSCD_PRIVATE_KEY) as unknown as Record<string, unknown>,
    });
  });

  test('/wua/issue の assertion は challenge / nonce を載せた WSCD 鍵署名の JWS', async () => {
    const stub = stubTwoStage(makeWuaJwt(PROVIDER_KEY));

    await obtainWalletUnitAttestation(ENDPOINT, obtainOptions(stub));

    const assertion = bodyOf(stub.requests[1]?.body ?? '{}').assertion;
    expect(typeof assertion).toBe('string');
    const decoded = decodeCompactJws(assertion as string);
    expect(decoded.header).toEqual({ alg: 'ES256', typ: 'wua-device-binding+jwt' });
    expect(decoded.payload).toEqual({ challenge: CHALLENGE, nonce: NONCE });
  });

  test('devicePosture 未指定なら device_posture キー自体を送らない', async () => {
    const stub = stubTwoStage(makeWuaJwt(PROVIDER_KEY));

    await obtainWalletUnitAttestation(ENDPOINT, obtainOptions(stub));

    expect(Object.hasOwn(bodyOf(stub.requests[1]?.body ?? '{}'), 'device_posture')).toBe(false);
  });

  test('devicePosture 指定時は不透明な値のまま device_posture として送る', async () => {
    const stub = stubTwoStage(makeWuaJwt(PROVIDER_KEY));
    const posture = { integrity_verdict: 'MEETS_DEVICE_INTEGRITY', rooted: false };

    await obtainWalletUnitAttestation(ENDPOINT, obtainOptions(stub, { devicePosture: posture }));

    expect(bodyOf(stub.requests[1]?.body ?? '{}').device_posture).toEqual(posture);
  });
});

describe('obtainWalletUnitAttestation の WSCD バインド検証', () => {
  test('wscdPublicKeyJwk が cnf.jwk と一致すれば取得できる', async () => {
    const jwt = makeWuaJwt(PROVIDER_KEY);
    const stub = stubTwoStage(jwt);

    const wua = await obtainWalletUnitAttestation(
      ENDPOINT,
      obtainOptions(stub, { wscdPublicKeyJwk: wscdJwk() }),
    );

    expect(wua.jwt).toBe(jwt);
  });

  test('wscdPublicKeyJwk が cnf.jwk と一致しなければ 10102', async () => {
    const stub = stubTwoStage(makeWuaJwt(PROVIDER_KEY));

    const code = await codeOf(() =>
      obtainWalletUnitAttestation(
        ENDPOINT,
        obtainOptions(stub, { wscdPublicKeyJwk: toP256Jwk(OTHER_PRIVATE_KEY) }),
      ),
    );

    expect(code).toBe('10102');
  });

  test('cnf.jwk が別鍵の WUA は wscdPublicKeyJwk 指定時に 10102（未指定なら通る）', async () => {
    const jwt = makeWuaJwt(PROVIDER_KEY, {}, { cnfJwk: toP256Jwk(OTHER_PRIVATE_KEY) });

    expect(
      await codeOf(() =>
        obtainWalletUnitAttestation(
          ENDPOINT,
          obtainOptions(stubTwoStage(jwt), { wscdPublicKeyJwk: wscdJwk() }),
        ),
      ),
    ).toBe('10102');
    // 基準となる WSCD 鍵を渡さない呼び出しではバインド検証を行わない（従来どおり）。
    expect(
      (await obtainWalletUnitAttestation(ENDPOINT, obtainOptions(stubTwoStage(jwt)))).jwt,
    ).toBe(jwt);
  });

  test('wscdPublicKeyJwk が JWK として読めない値なら検証省略せず 10102', async () => {
    const stub = stubTwoStage(makeWuaJwt(PROVIDER_KEY));
    const options = obtainOptions(stub, {
      wscdPublicKeyJwk: 'not-a-jwk' as unknown as ReturnType<typeof wscdJwk>,
    });

    expect(await codeOf(() => obtainWalletUnitAttestation(ENDPOINT, options))).toBe('10102');
    expect(stub.requests).toEqual([]);
  });

  test.each([
    ['null', null],
    ['配列', []],
  ])('wscdPublicKeyJwk が %s なら検証省略せず 10102（通信しない）', async (_label, value) => {
    const stub = stubTwoStage(makeWuaJwt(PROVIDER_KEY));
    const options = obtainOptions(stub, {
      wscdPublicKeyJwk: value as unknown as ReturnType<typeof wscdJwk>,
    });

    expect(await codeOf(() => obtainWalletUnitAttestation(ENDPOINT, options))).toBe('10102');
    expect(stub.requests).toEqual([]);
  });
});
