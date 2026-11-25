/**
 * SD-JWT VC 検証の再帰・配列要素 Disclosure 対応の回帰テスト。
 *
 * RFC 9901 §4.2.1（オブジェクトプロパティ、3 要素）/ §4.2.2（配列要素、2 要素）/ §4.2.6（再帰）と、
 * §7.1 の処理規則（未参照 Disclosure・digest 重複・形状不一致の拒否）を `verifySdJwt` の公開 API で確認する。
 * 修正前は 2 要素 Disclosure が `parseSdJwt` で一律 3010、入れ子の `_sd` は復元されず「未参照」で 3010 だった。
 */

import { describe, expect, it } from 'bun:test';
import {
  arrayDisclosure,
  encodeDisclosure,
  expectRejected,
  rawDisclosure,
  verifyClaims,
} from './fixtures.js';

describe('配列要素 Disclosure（2 要素、§4.2.2）', () => {
  it('配列内の {"...": digest} が値へ置換され、未開示・decoy の要素は取り除かれる', () => {
    const fr = arrayDisclosure('FR', 'salt-fr');
    const hidden = arrayDisclosure('US', 'salt-us');
    const claims = verifyClaims(
      { nationalities: [fr.ref, hidden.ref, { '...': 'decoy-digest' }, 'DE'] },
      [fr.encoded],
    );
    expect(claims.nationalities).toEqual(['FR', 'DE']);
  });

  it('配列要素の値がオブジェクトで、その中の `_sd` も再帰的に復元される', () => {
    const country = encodeDisclosure('country', 'JP', 'salt-c');
    const entry = arrayDisclosure({ _sd: [country.digest], kind: 'passport' }, 'salt-e');
    const claims = verifyClaims({ documents: [entry.ref] }, [entry.encoded, country.encoded]);
    expect(claims.documents).toEqual([{ kind: 'passport', country: 'JP' }]);
  });

  it('`...` の他にキーがある要素や値が文字列でない要素は通常のオブジェクトとして残る', () => {
    const claims = verifyClaims({ list: [{ '...': 'x', other: 1 }, { '...': 7 }] }, []);
    expect(claims.list).toEqual([{ '...': 'x', other: 1 }, { '...': 7 }]);
  });

  it('`_sd` が参照する digest が 2 要素 Disclosure だと 3010（§7.1 3.c.ii.1）', () => {
    const arr = arrayDisclosure('x', 'salt-a');
    expectRejected({ _sd: [arr.digest] }, [arr.encoded]);
  });

  it('配列要素が参照する digest が 3 要素 Disclosure だと 3010（§7.1 3.c.iii.1）', () => {
    const prop = encodeDisclosure('name', 'Alice', 'salt-n');
    expectRejected({ list: [{ '...': prop.digest }] }, [prop.encoded]);
  });

  it('要素数が 1 / 4 の Disclosure は 3010', () => {
    const one = rawDisclosure(['salt-only']);
    const four = rawDisclosure(['salt', 'name', 'v', 'extra']);
    expectRejected({ _sd: [one.digest] }, [one.encoded]);
    expectRejected({ _sd: [four.digest] }, [four.encoded]);
  });

  it('2 要素 Disclosure の salt が文字列でないと 3010', () => {
    const bad = rawDisclosure([1, 'v']);
    expectRejected({ list: [{ '...': bad.digest }] }, [bad.encoded]);
  });
});

describe('入れ子のオブジェクトプロパティ Disclosure（§4.2.1 / §4.2.6）', () => {
  it('入れ子オブジェクトの `_sd` が復元され、`_sd` は結果から除かれる', () => {
    const street = encodeDisclosure('street', '1 Main St', 'salt-s');
    const claims = verifyClaims({ address: { _sd: [street.digest], country: 'JP' } }, [
      street.encoded,
    ]);
    expect(claims.address).toEqual({ country: 'JP', street: '1 Main St' });
  });

  it('Disclosure の値に別の `_sd` を埋め込む再帰（親子とも同梱）が復元される', () => {
    const region = encodeDisclosure('region', 'Tokyo', 'salt-r');
    const address = encodeDisclosure('address', { _sd: [region.digest], zip: '100' }, 'salt-a');
    const claims = verifyClaims({ _sd: [address.digest] }, [address.encoded, region.encoded]);
    expect(claims.address).toEqual({ zip: '100', region: 'Tokyo' });
  });

  it('親の Disclosure を落とすと子の Disclosure は未参照になり 3010（§7.1 5）', () => {
    const region = encodeDisclosure('region', 'Tokyo', 'salt-r');
    const address = encodeDisclosure('address', { _sd: [region.digest] }, 'salt-a');
    expectRejected({ _sd: [address.digest] }, [region.encoded]);
  });

  it('子だけを落とす（親は同梱）提示は受理され、未開示のプロパティは現れない', () => {
    const region = encodeDisclosure('region', 'Tokyo', 'salt-r');
    const address = encodeDisclosure('address', { _sd: [region.digest], zip: '100' }, 'salt-a');
    const claims = verifyClaims({ _sd: [address.digest] }, [address.encoded]);
    expect(claims.address).toEqual({ zip: '100' });
  });

  it('入れ子オブジェクトの `_sd` を配列でないものにしても digest 扱いせず除去する（§7.1 3.b.i）', () => {
    const claims = verifyClaims({ address: { _sd: 'not-an-array', country: 'JP' } }, []);
    expect(claims.address).toEqual({ country: 'JP' });
  });

  it('入れ子では登録済みクレーム名（`exp` 等）の Disclosure も復元できる（非開示対象は最上位のみ）', () => {
    const exp = encodeDisclosure('exp', 123, 'salt-x');
    const claims = verifyClaims({ evidence: { _sd: [exp.digest] } }, [exp.encoded]);
    expect(claims.evidence).toEqual({ exp: 123 });
  });
});

describe('digest 重複・同名衝突・未参照（§7.1 3.c.ii.3 / 4 / 5）', () => {
  it('同一 digest が payload に 2 回現れると 3010', () => {
    const name = encodeDisclosure('name', 'Alice', 'salt-n');
    expectRejected({ _sd: [name.digest], nested: { _sd: [name.digest] } }, [name.encoded]);
  });

  it('同一 Disclosure の重複同梱は 3010', () => {
    const name = encodeDisclosure('name', 'Alice', 'salt-n');
    expectRejected({ _sd: [name.digest] }, [name.encoded, name.encoded]);
  });

  it('同じレベルの平文クレームと同名の Disclosure は 3010', () => {
    const nested = encodeDisclosure('country', 'FR', 'salt-c');
    expectRejected({ address: { country: 'JP', _sd: [nested.digest] } }, [nested.encoded]);
  });

  it('どこからも参照されない Disclosure は 3010', () => {
    const stray = encodeDisclosure('name', 'Alice', 'salt-n');
    expectRejected({}, [stray.encoded]);
  });
});
