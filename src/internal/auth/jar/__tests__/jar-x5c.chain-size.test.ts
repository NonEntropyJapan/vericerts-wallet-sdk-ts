/**
 * JAR `x5c` の枚数上限。極小エントリを大量に並べた JAR で、base64 デコード・指紋計算・
 * RP Cert 判定キャッシュ保持に資源を使わせない。実時間ではなく**要素への読み取り回数**で pin する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { MAX_INTERMEDIATES } from '../../../trust/etsi-tsl/index.js';
import { requireTrustedSigner } from '../jar-trust-evaluation.js';
import { extractX5cChain } from '../jar-x5c.js';

/** 添字読み取りを数える配列（`length` は実値）。 */
function countingArray(length: number, element: string): { array: string[]; reads: () => number } {
  let reads = 0;
  const array = new Proxy(new Array<string>(length).fill(element), {
    get(target, prop, receiver) {
      if (typeof prop === 'string' && /^\d+$/.test(prop)) {
        reads++;
      }
      return Reflect.get(target, prop, receiver);
    },
  });
  return { array, reads: () => reads };
}

describe('extractX5cChain の枚数上限', () => {
  // 形状: 上限ちょうど超え / 極小エントリ 100 万 / 通常の 3 枚。
  it.each([
    ['上限を 1 枚超える', MAX_INTERMEDIATES + 2],
    ['極小エントリ 100 万枚', 1_000_000],
  ])('%s の x5c は 1 要素も読まずに拒否する', (_label, count) => {
    const { array, reads } = countingArray(count, 'AAAA');
    expect(extractX5cChain({ x5c: array })).toBeUndefined();
    expect(reads()).toBe(0);
  });

  it('リーフ + 上限枚数ちょうどの中間は受理する', () => {
    const chain = extractX5cChain({
      x5c: Array.from({ length: MAX_INTERMEDIATES + 1 }, () => 'AAAA'),
    });
    expect(chain?.intermediatesDer.length).toBe(MAX_INTERMEDIATES);
  });

  it('通常の 3 枚チェーンは受理する', () => {
    const chain = extractX5cChain({ x5c: ['AAAA', 'AAAA', 'AAAA'] });
    expect(chain?.intermediatesDer.length).toBe(2);
  });
});

describe('requireTrustedSigner の中間証明書枚数', () => {
  it('上限超過はキャッシュに触れず 8030 で拒否する', async () => {
    let touched = 0;
    const cache = new Proxy(
      {},
      {
        get() {
          touched++;
          return () => undefined;
        },
      },
    );
    const intermediates = Array.from({ length: MAX_INTERMEDIATES + 1 }, () => new Uint8Array([1]));
    const error = await requireTrustedSigner(new Uint8Array([0x30]), intermediates, [], {
      rpCertJudgmentCache: cache,
      now: 1_700_000_000,
    }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    expect(touched).toBe(0);
  });
});
