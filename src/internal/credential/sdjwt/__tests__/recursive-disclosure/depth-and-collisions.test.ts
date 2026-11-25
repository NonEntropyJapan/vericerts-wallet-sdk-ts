/**
 * 再帰 Disclosure 復元の境界テスト。
 *
 * - 深さは「コンテナ（配列・オブジェクト）へ入る」ときだけ数える。パーサ（`MAX_JSON_NESTING_DEPTH` = 512）が
 *   受理する payload は、末端がプリミティブでも復元で 3010 にならない。
 * - 入れ子の `__proto__` Disclosure は own データプロパティになり、プロトタイプを汚染しない。
 * - 同じ digest の二重参照（`_sd` と入れ子の値、配列の `...` 2 つ、decoy 2 つ）は 3010。
 */

import { describe, expect, it } from 'bun:test';
import { MAX_JSON_NESTING_DEPTH } from '../../../../prototype-safety/parse-json.js';
import { arrayDisclosure, encodeDisclosure, expectRejected, verifyClaims } from './fixtures.js';

/** `containers` 個のオブジェクトを入れ子にし、末端をプリミティブ（`1`）にした値を返す。 */
function nest(containers: number): unknown {
  let value: unknown = 1;
  for (let i = 0; i < containers; i++) {
    value = { k: value };
  }
  return value;
}

/**
 * 親が子の digest を `_sd` で指す Disclosure の連鎖を `length` 個作る。
 * 最後の Disclosure の値は `{ leaf: 1 }`（コンテナ 1 つ + プリミティブの末端）。
 */
function disclosureChain(length: number): { rootDigest: string; encoded: string[] } {
  let value: unknown = { leaf: 1 };
  const encoded: string[] = [];
  let digest = '';
  for (let i = length; i >= 1; i--) {
    const d = encodeDisclosure('a', value, `salt-${i}`);
    encoded.push(d.encoded);
    digest = d.digest;
    value = { _sd: [d.digest] };
  }
  return { rootDigest: digest, encoded };
}

describe('深さ上限（コンテナのみ数える）', () => {
  it('パーサが受理する 512 段の payload（末端がプリミティブ）は 3010 にならない', () => {
    // payload 自身が 1 段目なので、残りの 511 段を入れ子にして合計 512 段にする。
    const claims = verifyClaims({ deep: nest(MAX_JSON_NESTING_DEPTH - 1) }, []);
    let node = claims.deep as Record<string, unknown>;
    for (let i = 1; i < MAX_JSON_NESTING_DEPTH - 1; i++) {
      node = node.k as Record<string, unknown>;
    }
    expect(node.k).toBe(1);
  });

  it('Disclosure の連鎖が 511 段（最後の値が 512 段目のコンテナ）なら受理される', () => {
    const { rootDigest, encoded } = disclosureChain(MAX_JSON_NESTING_DEPTH - 1);
    expect(() => verifyClaims({ _sd: [rootDigest] }, encoded)).not.toThrow();
  });

  it('Disclosure の連鎖が 512 段（最後の値が 513 段目のコンテナ）なら 3010', () => {
    const { rootDigest, encoded } = disclosureChain(MAX_JSON_NESTING_DEPTH);
    expectRejected({ _sd: [rootDigest] }, encoded);
  });
});

describe('入れ子の __proto__ Disclosure', () => {
  it('own データプロパティになり、プロトタイプも Object.prototype も汚染しない', () => {
    const proto = encodeDisclosure('__proto__', { polluted: 'yes' }, 'salt-p');
    const claims = verifyClaims({ address: { _sd: [proto.digest] } }, [proto.encoded]);
    const address = claims.address as Record<string, unknown>;
    expect(Object.hasOwn(address, '__proto__')).toBe(true);
    expect(Object.getOwnPropertyDescriptor(address, '__proto__')?.value).toEqual({
      polluted: 'yes',
    });
    expect(Object.getPrototypeOf(address)).toBeNull();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.hasOwn(Object.prototype, 'polluted')).toBe(false);
  });
});

describe('digest の二重参照', () => {
  it('payload の `_sd` と、別 Disclosure の値の中の `_sd` が同じ digest を指すと 3010', () => {
    const inner = encodeDisclosure('inner', 'x', 'salt-i');
    const outer = encodeDisclosure('outer', { _sd: [inner.digest] }, 'salt-o');
    expectRejected({ _sd: [outer.digest, inner.digest] }, [outer.encoded, inner.encoded]);
  });

  it('配列に同じ digest の `...` が 2 つあると 3010', () => {
    const el = arrayDisclosure('FR', 'salt-fr');
    expectRejected({ list: [el.ref, el.ref] }, [el.encoded]);
  });

  it('`_sd` に同じ decoy digest が 2 つあると 3010', () => {
    expectRejected({ _sd: ['decoy-digest', 'decoy-digest'] }, []);
  });

  it('配列に同じ decoy の `...` が 2 つあると 3010', () => {
    expectRejected({ list: [{ '...': 'decoy-digest' }, { '...': 'decoy-digest' }] }, []);
  });
});
