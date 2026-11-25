/**
 * `obtainWalletUnitAttestation` のオプション / 応答読み取りの汚染耐性テスト。
 *
 * `options` は**呼び出し側が組み立てて渡す値**でパース境界を
 * 通らないため、鎖読みだと次の fail-open が成立していた。
 *
 * - `providerJwk`: 鍵を**指定していない**正当な呼び出しが `Object.prototype.providerJwk` の
 *   汚染値を検証鍵に採り、**攻撃者が署名した WUA が「検証済み」として返る**。
 * - `nowSeconds`: 時刻を指定していない呼び出しで汚染値が「現在時刻」になり、**期限切れの WUA が
 *   期限内と判定される**。
 * - `wscdPublicKeyJwk`: WSCD 鍵を指定していない呼び出しで汚染値が照合基準になり、**攻撃者が
 *   選んだ鍵にバインドされた WUA が「WSCD バインド済み」として通る**。
 * - `fetchImpl` / `signer`: 指定していない呼び出しが**攻撃者の fetch / 署名器へ委譲**される
 *   （関数値 DI なので own 限定ではなく `Object.prototype` 由来だけを弾く。プロトタイプメソッド
 *   として注入した正当な DI は引き続き `this` 付きで呼ばれなければならない）。
 * - 応答の `challenge` / `nonce` / `wallet_attestation`: 当該フィールドを持たない応答へ
 *   **署名対象の challenge や検証対象の JWT が汚染値から供給される**。
 *
 * **トートロジー回避**: 汚染値には「鎖読みなら通ってしまう正当な値」（攻撃者鍵で署名した WUA・
 * 有効期間内の時刻・実在する challenge / JWT）を仕込み、同じ値を own 側に置いた対照が成功する
 * ことを示す。
 */

import { describe, expect, test } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import type { FetchLike } from '../../../../auth/oid4vci/oid4vci.js';
import { obtainWalletUnitAttestation } from '../../obtain.js';
import {
  CHALLENGE,
  CHALLENGE_URL,
  codeOf,
  ENDPOINT,
  ISSUE_URL,
  jsonResponse,
  NONCE,
  NOW,
  obtainOptions,
  stubFetch,
  stubTwoStage,
} from '../obtain-fixtures.js';
import { makeWuaJwt, OTHER_PRIVATE_KEY, toP256Jwk, wscdSigner } from '../wua-fixtures.js';

/** 攻撃者（= 信頼していない Wallet Provider）の鍵。汚染値として仕込む。 */
const ATTACKER_JWK = toP256Jwk(OTHER_PRIVATE_KEY);

/** 攻撃者鍵で署名した WUA JWT（`cnf.jwk` は既定どおり WSCD 公開鍵）。 */
const ATTACKER_JWT = makeWuaJwt(OTHER_PRIVATE_KEY);

/** 攻撃者鍵で署名し、`cnf.jwk` も攻撃者鍵にした WUA JWT（バインド照合の汚染再現用）。 */
const ATTACKER_BOUND_JWT = makeWuaJwt(OTHER_PRIVATE_KEY, {}, { cnfJwk: ATTACKER_JWK });

/** 汚染値を検証鍵に採らないことを見るための、鍵だけ差し替えた既定オプション。 */
function attackerKeyOptions(
  stub: ReturnType<typeof stubTwoStage>,
): Parameters<typeof obtainWalletUnitAttestation>[1] {
  return obtainOptions(stub, { providerJwk: ATTACKER_JWK });
}

describe('obtainWalletUnitAttestation: options の Object.prototype 汚染耐性', () => {
  test('providerJwk 未指定の呼び出しは汚染値を検証鍵に採らず 10102（通信も起こさない）', async () => {
    const stub = stubTwoStage(ATTACKER_JWT);
    const options = {
      signer: wscdSigner(),
      nowSeconds: NOW,
      fetchImpl: stub.fetchImpl,
    } as unknown as Parameters<typeof obtainWalletUnitAttestation>[1];

    const code = await withPollutedPrototypeAsync({ providerJwk: ATTACKER_JWK }, () =>
      codeOf(() => obtainWalletUnitAttestation(ENDPOINT, options)),
    );

    expect(code).toBe('10102');
    expect(stub.requests).toEqual([]);
  });

  test('対照: own の providerJwk（同じ鍵）を渡せば取得できる', async () => {
    const stub = stubTwoStage(ATTACKER_JWT);

    const wua = await obtainWalletUnitAttestation(ENDPOINT, attackerKeyOptions(stub));

    expect(wua.jwt).toBe(ATTACKER_JWT);
    expect(stub.requests.map((request) => request.url)).toEqual([CHALLENGE_URL, ISSUE_URL]);
  });

  test('nowSeconds 未指定の呼び出しは汚染値を現在時刻に採らず 10102（通信も起こさない）', async () => {
    const stub = stubTwoStage(ATTACKER_JWT);
    const options = {
      providerJwk: ATTACKER_JWK,
      signer: wscdSigner(),
      fetchImpl: stub.fetchImpl,
    } as unknown as Parameters<typeof obtainWalletUnitAttestation>[1];

    const code = await withPollutedPrototypeAsync({ nowSeconds: NOW }, () =>
      codeOf(() => obtainWalletUnitAttestation(ENDPOINT, options)),
    );

    expect(code).toBe('10102');
    expect(stub.requests).toEqual([]);
  });

  test('wscdPublicKeyJwk 未指定の呼び出しは汚染値を照合基準に採らない', async () => {
    const stub = stubTwoStage(ATTACKER_BOUND_JWT);

    // 汚染値が基準に化けるなら「攻撃者鍵にバインドされた WUA」が WSCD バインド済みとして通る。
    // own に無い以上バインド検証自体を行わないため、汚染値との照合は起こらない。
    const wua = await withPollutedPrototypeAsync({ wscdPublicKeyJwk: ATTACKER_JWK }, () =>
      obtainWalletUnitAttestation(ENDPOINT, attackerKeyOptions(stub)),
    );

    expect(wua.cnf.jwk).toEqual(ATTACKER_JWK);
    // 対照: own で別鍵を渡せば同じ WUA が 10102 で拒否される（検証経路自体は生きている）。
    expect(
      await codeOf(() =>
        obtainWalletUnitAttestation(
          ENDPOINT,
          obtainOptions(stubTwoStage(ATTACKER_BOUND_JWT), {
            providerJwk: ATTACKER_JWK,
            wscdPublicKeyJwk: toP256Jwk(new Uint8Array(32).fill(5)),
          }),
        ),
      ),
    ).toBe('10102');
  });
});

describe('obtainWalletUnitAttestation: 関数値 DI（fetchImpl / signer）の扱い', () => {
  test('fetchImpl 未指定の呼び出しは Object.prototype の汚染関数へ委譲しない', async () => {
    const calls: string[] = [];
    const attackerFetch: FetchLike = (url) => {
      calls.push(url);
      return Promise.resolve(jsonResponse({ challenge: CHALLENGE, nonce: NONCE }));
    };
    // グローバル `fetch` は差し替えず、接続できない HTTPS 先を使って「汚染 fetch へ委譲されな
    // かった」ことを（攻撃者 fetch が呼ばれないことと 10101 で）観測する。
    const options = {
      providerJwk: ATTACKER_JWK,
      signer: wscdSigner(),
      nowSeconds: NOW,
    } as unknown as Parameters<typeof obtainWalletUnitAttestation>[1];

    const code = await withPollutedPrototypeAsync({ fetchImpl: attackerFetch }, () =>
      codeOf(() => obtainWalletUnitAttestation('https://127.0.0.1:1/wua', options)),
    );

    expect(code).toBe('10101');
    expect(calls).toEqual([]);
  });

  test('signer 未指定の呼び出しは汚染値を署名器に採らず 10101（通信も起こさない）', async () => {
    const stub = stubTwoStage(ATTACKER_JWT);
    const options = {
      providerJwk: ATTACKER_JWK,
      nowSeconds: NOW,
      fetchImpl: stub.fetchImpl,
    } as unknown as Parameters<typeof obtainWalletUnitAttestation>[1];

    const code = await withPollutedPrototypeAsync({ signer: wscdSigner() }, () =>
      codeOf(() => obtainWalletUnitAttestation(ENDPOINT, options)),
    );

    expect(code).toBe('10101');
    expect(stub.requests).toEqual([]);
  });

  test('プロトタイプメソッドとして注入した fetchImpl は this 付きで呼ばれる（レシーバ束ね直し）', async () => {
    class ObtainOptions {
      readonly providerJwk = ATTACKER_JWK;
      readonly signer = wscdSigner();
      readonly nowSeconds = NOW;
      readonly requestedUrls: string[] = [];
      fetchImpl(url: string): Promise<Response> {
        this.requestedUrls.push(url);
        return Promise.resolve(
          url === CHALLENGE_URL
            ? jsonResponse({ challenge: CHALLENGE, nonce: NONCE })
            : jsonResponse({ wallet_attestation: ATTACKER_JWT }),
        );
      }
    }
    const options = new ObtainOptions();

    const wua = await obtainWalletUnitAttestation(ENDPOINT, options);

    expect(wua.jwt).toBe(ATTACKER_JWT);
    // `this` 経由でインスタンス状態を積めた ＝ レシーバが `options` に束ね直されている。
    expect(options.requestedUrls).toEqual([CHALLENGE_URL, ISSUE_URL]);
  });
});

describe('obtainWalletUnitAttestation: 応答フィールドの汚染耐性', () => {
  test('challenge / nonce を持たない応答へ汚染値が署名対象として供給されない（10101）', async () => {
    const stub = stubFetch((url) =>
      url === CHALLENGE_URL
        ? jsonResponse({ wp_policy: {} })
        : jsonResponse({ wallet_attestation: ATTACKER_JWT }),
    );

    const code = await withPollutedPrototypeAsync({ challenge: CHALLENGE, nonce: NONCE }, () =>
      codeOf(() => obtainWalletUnitAttestation(ENDPOINT, attackerKeyOptions(stub))),
    );

    expect(code).toBe('10101');
    // `/wua/issue` へは進まない（汚染値で Proof を作って発行要求を出さない）。
    expect(stub.requests.map((request) => request.url)).toEqual([CHALLENGE_URL]);
  });

  test('wallet_attestation を持たない応答へ汚染値が JWT として供給されない（10101）', async () => {
    const stub = stubFetch((url) =>
      url === CHALLENGE_URL
        ? jsonResponse({ challenge: CHALLENGE, nonce: NONCE })
        : jsonResponse({ other_field: 'x' }),
    );

    const code = await withPollutedPrototypeAsync({ wallet_attestation: ATTACKER_JWT }, () =>
      codeOf(() => obtainWalletUnitAttestation(ENDPOINT, attackerKeyOptions(stub))),
    );

    expect(code).toBe('10101');
    expect(stub.requests.map((request) => request.url)).toEqual([CHALLENGE_URL, ISSUE_URL]);
  });
});
