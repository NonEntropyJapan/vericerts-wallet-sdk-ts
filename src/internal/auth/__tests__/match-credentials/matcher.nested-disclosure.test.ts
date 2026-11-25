/**
 * `toQueryableFromSdJwt` の入れ子・配列要素 Disclosure 対応の回帰テスト。
 *
 * 修正前は全 Disclosure を `claims[claimName]` へ平坦化していたため、入れ子の Disclosure
 * `country=FR` が最上位の平文 `country=JP` を上書きし、`path: ['address', 'country']` は解決できなかった。
 * 修正後は `verifySdJwt` と同じ再帰復元（署名検証なし）でクレーム木を組む。
 */

import { describe, expect, it } from 'bun:test';
import {
  arrayDisclosure,
  encodeDisclosure,
  NOW,
  reissueWithPayload,
  VCT,
} from '../../../credential/sdjwt/__tests__/recursive-disclosure/fixtures.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { parseDcqlQuery } from '../../dcql/dcql.js';
import {
  FORMAT_SD_JWT_VC,
  selectMatchingCredentials,
  toQueryableFromSdJwt,
} from '../../matcher.js';

function issueNested(): string {
  const nestedCountry = encodeDisclosure('country', 'FR', 'salt-c');
  return reissueWithPayload(
    { vct: VCT, iat: NOW, country: 'JP', address: { _sd: [nestedCountry.digest] } },
    [nestedCountry.encoded],
  );
}

function matchedIndexes(path: readonly string[], values: readonly string[]): number[] {
  const query = parseDcqlQuery({
    credentials: [
      {
        id: 'q',
        format: FORMAT_SD_JWT_VC,
        meta: { vct_values: [VCT] },
        claims: [{ path, values }],
      },
    ],
  });
  return selectMatchingCredentials(query, [toQueryableFromSdJwt(issueNested())]).matchedIndexes;
}

describe('toQueryableFromSdJwt: 入れ子 Disclosure', () => {
  it('入れ子の同名 Disclosure は最上位の平文クレームを上書きせず、入れ子のまま載る', () => {
    const { claims } = toQueryableFromSdJwt(issueNested());
    expect(claims.country).toBe('JP');
    expect(claims.address).toEqual({ country: 'FR' });
  });

  it('path ["address", "country"] は入れ子の値 FR にマッチし、JP にはマッチしない', () => {
    expect(matchedIndexes(['address', 'country'], ['FR'])).toEqual([0]);
    expect(matchedIndexes(['address', 'country'], ['JP'])).toEqual([]);
  });

  it('path ["country"] は最上位の値 JP にマッチし、入れ子の FR にはマッチしない', () => {
    expect(matchedIndexes(['country'], ['JP'])).toEqual([0]);
    expect(matchedIndexes(['country'], ['FR'])).toEqual([]);
  });

  it('配列要素 Disclosure（2 要素）は配列要素として載り、未開示の要素は現れない', () => {
    const fr = arrayDisclosure('FR', 'salt-fr');
    const hidden = arrayDisclosure('US', 'salt-us');
    const sdJwt = reissueWithPayload(
      { vct: VCT, iat: NOW, nationalities: [fr.ref, hidden.ref, 'DE'] },
      [fr.encoded],
    );
    expect(toQueryableFromSdJwt(sdJwt).claims.nationalities).toEqual(['FR', 'DE']);
  });

  it('どこからも参照されない Disclosure は verifySdJwt と同じく 3010 で throw する', () => {
    const stray = encodeDisclosure('name', 'Alice', 'salt-n');
    const sdJwt = reissueWithPayload({ vct: VCT, iat: NOW }, [stray.encoded]);
    let thrown: unknown;
    try {
      toQueryableFromSdJwt(sdJwt);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(VericertsError);
    expect((thrown as VericertsError).code).toBe(ErrorCodes.SIG_INVALID);
  });
});

function codeOf(run: () => unknown): string | undefined {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    return (error as VericertsError).code;
  }
  return undefined;
}

/** `toQueryableFromSdJwt` が `verifySdJwt` と同じ判定で 3010 を投げる、復元できない SD-JWT VC。 */
function unrecoverable(): readonly (readonly [string, () => string])[] {
  return [
    [
      '`_sd_alg` が sha-256 でない',
      () => reissueWithPayload({ vct: VCT, iat: NOW, _sd_alg: 'sha-512' }, []),
    ],
    [
      '同じレベルの平文クレームと同名の Disclosure（衝突）',
      () => {
        const clash = encodeDisclosure('country', 'FR', 'salt-c');
        return reissueWithPayload({ vct: VCT, iat: NOW, country: 'JP', _sd: [clash.digest] }, [
          clash.encoded,
        ]);
      },
    ],
    [
      '同じ digest が payload に 2 回現れる（重複）',
      () => {
        const name = encodeDisclosure('name', 'Alice', 'salt-n');
        return reissueWithPayload(
          { vct: VCT, iat: NOW, _sd: [name.digest], nested: { _sd: [name.digest] } },
          [name.encoded],
        );
      },
    ],
  ];
}

describe('toQueryableFromSdJwt: 復元できない Disclosure は 3010', () => {
  it.each(unrecoverable())('%s', (_label, build) => {
    expect(codeOf(() => toQueryableFromSdJwt(build()))).toBe(ErrorCodes.SIG_INVALID);
  });

  it('1 件ずつ try/catch でスキップすれば、残りの有効なクレデンシャルは selectMatchingCredentials でマッチする', () => {
    const [, buildBroken] = unrecoverable()[0] as readonly [string, () => string];
    const held = [buildBroken(), issueNested()];
    const credentials = held.flatMap((sdJwt) => {
      try {
        return [toQueryableFromSdJwt(sdJwt)];
      } catch {
        return []; // 非準拠の 1 件は候補から外す。
      }
    });
    expect(credentials).toHaveLength(1);
    const query = parseDcqlQuery({
      credentials: [
        {
          id: 'q',
          format: FORMAT_SD_JWT_VC,
          meta: { vct_values: [VCT] },
          claims: [{ path: ['country'], values: ['JP'] }],
        },
      ],
    });
    expect(selectMatchingCredentials(query, credentials).matchedIndexes).toEqual([0]);
  });
});
