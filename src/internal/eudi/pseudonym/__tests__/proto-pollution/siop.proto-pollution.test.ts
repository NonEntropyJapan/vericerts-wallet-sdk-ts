/**
 * SIOPv2 Pseudonym ID Token の署名対象クレームへの汚染混入テスト。
 *
 * `presentPseudonym` は組み立てた claims をそのまま署名するため、必須フィールドを
 * プロトタイプ鎖で読むと、それらを**省略した**入力でも汚染値が **署名済み ID Token** に載る:
 *
 * - `clientId`: `aud` が攻撃者の選んだ RP になり、別 RP 宛の ID Token を署名させられる。
 * - `nonce`: リプレイ防止の nonce が攻撃者の選んだ値に固定される。
 * - `nowSeconds`: `iat` / `exp` が攻撃者の選んだ時刻になる。
 *
 * さらに `clientId` / `nonce` は「検証してから署名するまでに 2 回読む」と、呼ばれるたび別の値を
 * 返すアクセサ汚染で**検証した値と署名した値が食い違う**（TOCTOU）。1 回だけ読むことを確認する。
 * `lifetimeSeconds`は `eudi/__tests__/proto-pollution/eudi-signed-output` が担保する。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { VericertsError } from '../../../../errors.js';
import type { PresentPseudonymOptions } from '../../siop.js';
import { presentPseudonym } from '../../siop.js';
import type { SiopRequest } from '../../types.js';

const MASTER_SEED = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff);
const RP = 'rp-a.example';
const NOW = 1_700_000_000;

/** 攻撃者が仕込む汚染値。 */
const EVIL_CLIENT_ID = 'attacker-rp.example';
const EVIL_NONCE = 'attacker-fixed-nonce';
const EVIL_NOW = 4_100_000_000;

function decodePayload(jwt: string): Record<string, unknown> {
  const [, payloadSeg] = jwt.split('.');
  return JSON.parse(new TextDecoder().decode(base64urlnopad.decode(payloadSeg ?? ''))) as Record<
    string,
    unknown
  >;
}

/** フィールドを**省略した** SiopRequest / オプションを組み立てる（省略キーは生やさない）。 */
function partialRequest(present: Partial<SiopRequest>): SiopRequest {
  return present as SiopRequest;
}
function optsWithout(present: Partial<PresentPseudonymOptions>): PresentPseudonymOptions {
  return present as PresentPseudonymOptions;
}

/** 汚染下で `presentPseudonym` を実行し、payload か送出された例外を返す。 */
function payloadOrError(run: () => { idToken: string }): Record<string, unknown> | unknown {
  try {
    return decodePayload(run().idToken);
  } catch (e) {
    return e;
  }
}

describe('SIOPv2 ID Token の必須クレームの Object.prototype 汚染耐性', () => {
  it('clientId を省略した提示は、継承した clientId を aud に載せず 10201 で拒否する', () => {
    const result = withPollutedPrototype({ clientId: EVIL_CLIENT_ID }, () =>
      payloadOrError(() =>
        presentPseudonym(partialRequest({ nonce: 'nonce_a' }), RP, MASTER_SEED, {
          nowSeconds: NOW,
        }),
      ),
    );
    expect(result).toBeInstanceOf(VericertsError);
    expect((result as VericertsError).code).toBe('10201');
  });

  it('nonce を省略した提示は、継承した nonce を載せず 10201 で拒否する', () => {
    const result = withPollutedPrototype({ nonce: EVIL_NONCE }, () =>
      payloadOrError(() =>
        presentPseudonym(partialRequest({ clientId: RP }), RP, MASTER_SEED, { nowSeconds: NOW }),
      ),
    );
    expect(result).toBeInstanceOf(VericertsError);
    expect((result as VericertsError).code).toBe('10201');
  });

  it('nowSeconds を省略した提示は、継承した nowSeconds を iat / exp に載せず 10201 で拒否する', () => {
    const result = withPollutedPrototype({ nowSeconds: EVIL_NOW }, () =>
      payloadOrError(() =>
        presentPseudonym({ clientId: RP, nonce: 'nonce_a' }, RP, MASTER_SEED, optsWithout({})),
      ),
    );
    expect(result).toBeInstanceOf(VericertsError);
    expect((result as VericertsError).code).toBe('10201');
  });

  it('汚染下でも明示的に渡した clientId / nonce / nowSeconds がそのまま署名される（正常系）', () => {
    const { idToken } = withPollutedPrototype(
      { clientId: EVIL_CLIENT_ID, nonce: EVIL_NONCE, nowSeconds: EVIL_NOW },
      () =>
        presentPseudonym({ clientId: RP, nonce: 'nonce_a' }, RP, MASTER_SEED, { nowSeconds: NOW }),
    );
    const payload = decodePayload(idToken);
    expect(payload.aud).toBe(RP);
    expect(payload.nonce).toBe('nonce_a');
    expect(payload.iat).toBe(NOW);
    expect(payload.exp).toBe(NOW + 5 * 60);
  });
});

describe('SIOPv2 Request の TOCTOU 耐性', () => {
  it('呼ばれるたび別の値を返す継承 getter は採用せず 10201 で拒否する', () => {
    let call = 0;
    const nextValue = (): number => {
      call += 1;
      return call;
    };
    const result = withPollutedPrototypeAccessor(
      {
        clientId: () => `rp-${nextValue()}.example`,
        nonce: () => `nonce_${nextValue()}`,
      },
      () =>
        payloadOrError(() =>
          presentPseudonym(partialRequest({}), RP, MASTER_SEED, { nowSeconds: NOW }),
        ),
    );
    expect(result).toBeInstanceOf(VericertsError);
    expect((result as VericertsError).code).toBe('10201');
  });

  it('自身の getter を持つ Request でも clientId / nonce は 1 回だけ読み、検証した値を署名する', () => {
    // 読み直すと「検証した値」と「署名した値」が食い違う（アクセサは呼ばれるたび別の値を返す）。
    let clientIdReads = 0;
    let nonceReads = 0;
    const request = {} as SiopRequest;
    Object.defineProperty(request, 'clientId', {
      get: () => {
        clientIdReads += 1;
        return `rp-${clientIdReads}.example`;
      },
      configurable: true,
      enumerable: true,
    });
    Object.defineProperty(request, 'nonce', {
      get: () => {
        nonceReads += 1;
        return `nonce_${nonceReads}`;
      },
      configurable: true,
      enumerable: true,
    });

    const payload = decodePayload(
      presentPseudonym(request, RP, MASTER_SEED, { nowSeconds: NOW }).idToken,
    );
    expect(clientIdReads).toBe(1);
    expect(nonceReads).toBe(1);
    // 署名されたのは検証を通った最初の値そのもの。
    expect(payload.aud).toBe('rp-1.example');
    expect(payload.nonce).toBe('nonce_1');
  });
});
