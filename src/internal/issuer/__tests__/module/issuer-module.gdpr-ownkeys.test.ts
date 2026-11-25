/**
 * `IssuerModule.issueVC` の Art.9 ガード — 走査範囲と読み取り範囲の一致。
 *
 * 本ファイルが固定するのは「**検査した値がそのまま VC に載る**」という不変条件である。検査範囲と
 * 生成時の読み取り範囲がずれると、ガードを通過した入力から Art.9 属性が署名済み VC に載る。
 * ずれは 2 経路で起きる。
 *
 * 1. **非列挙の own プロパティ**: `build-vc.ts` の `ownProperty` は `Object.hasOwn` 判定なので
 *    非列挙でも読む。走査器が `Object.keys` だけを辿ると検査のほうが狭くなり素通りする。
 * 2. **own アクセサの二重評価**: `get evidence()` が検査時と生成時で別の値を返し得る。
 *
 * どちらも「1 周目 `claims` → 2 周目 `evidence` / `termsOfUse` → 3 周目 `refreshService`」と
 * 同じ**検査対象と実際の対象がずれる**クラスの欠陥なので、回帰として固定する。
 */

import { beforeEach, describe, expect, it } from 'bun:test';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes } from '../../../errors.js';
import { findSpecialCategoryAttributes } from '../../../special-category.js';
import { IssuerModule } from '../../module/issuer-module.js';
import { createStatusList, type StatusListManager } from '../../token-status-list.js';

const ISSUER = 'did:key:z6MkIssuerOwnKeys';
const HOLDER = 'did:key:z6MkHolderOwnKeys';
const REVOCATION_URI = 'https://issuer.example/status/revocation';
const SIGNER_KEY = new Uint8Array(32).fill(61);

/** 非列挙の own プロパティを 1 つ持つ発行オプションを作る。 */
function withNonEnumerable(key: string, value: unknown): Record<string, unknown> {
  const opts: Record<string, unknown> = {};
  Object.defineProperty(opts, key, { value, enumerable: false, configurable: true });
  return opts;
}

describe('issueVC の Art.9 ガード: 走査範囲と読み取り範囲の一致', () => {
  let revocation: StatusListManager;
  let issuer: IssuerModule;

  beforeEach(() => {
    revocation = createStatusList({
      uri: REVOCATION_URI,
      issuer: ISSUER,
      size: 64,
      purpose: 'revocation',
    });
    issuer = new IssuerModule({
      issuer: ISSUER,
      signer: createPrivateKeySigner(SIGNER_KEY, 'ES256'),
      statusLists: { revocation },
    });
  });

  it('非列挙の own プロパティ evidence の Art.9 属性を 10607 で拒否する', async () => {
    const opts = withNonEnumerable('evidence', [{ type: 'DocumentVerification', health: 'HIV+' }]);
    await expect(issuer.issueVC(HOLDER, { degree: 'BSc' }, opts)).rejects.toMatchObject({
      code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE,
    });
  });

  it('非列挙の own プロパティ refreshService の入れ子の Art.9 属性を 10607 で拒否する', async () => {
    const opts = withNonEnumerable('refreshService', {
      id: 'https://issuer.example/refresh',
      type: 'RefreshService2021',
      url: 'https://issuer.example/refresh',
      applicant: { pid: { birth_date: '1990-01-01' } },
    });
    await expect(issuer.issueVC(HOLDER, { degree: 'BSc' }, opts)).rejects.toMatchObject({
      code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE,
    });
  });

  it('非列挙プロパティ経由の拒否も Status List のインデックスを消費しない', async () => {
    const before = revocation.remaining;
    const opts = withNonEnumerable('termsOfUse', [{ type: 'IssuerPolicy', religion: 'X' }]);
    await expect(issuer.issueVC(HOLDER, { degree: 'BSc' }, opts)).rejects.toMatchObject({
      code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE,
    });
    expect(revocation.remaining).toBe(before);
    expect(issuer.exportEntries()).toEqual([]);
  });

  it('own アクセサは 1 度しか評価されず、検査した値がそのまま VC に載る', async () => {
    // 二重評価されると 2 回目に Art.9 属性を返す仕掛け。評価が 1 回なら 1 回目の無害な値が
    // 検査され、同じ値が VC に載る（＝すり替えが成立しない）。
    let reads = 0;
    const opts = {
      get evidence(): readonly Record<string, unknown>[] {
        reads += 1;
        return reads === 1
          ? [{ type: 'DocumentVerification' }]
          : [{ type: 'DocumentVerification', health: 'HIV+' }];
      },
    } as never;
    const vc = await issuer.issueVC(HOLDER, { degree: 'BSc' }, opts);
    expect(reads).toBe(1);
    expect(findSpecialCategoryAttributes(vc)).toEqual([]);
    expect(vc.evidence).toEqual([{ type: 'DocumentVerification' }]);
  });

  it('own アクセサが最初から Art.9 属性を返す場合は 10607 で拒否する', async () => {
    const opts = {
      get termsOfUse(): readonly Record<string, unknown>[] {
        return [{ type: 'IssuerPolicy', geneticData: 'x' }];
      },
    } as never;
    await expect(issuer.issueVC(HOLDER, { degree: 'BSc' }, opts)).rejects.toMatchObject({
      code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE,
    });
  });

  it('claims の非列挙プロパティは検査もされず VC にも載らない（範囲が対称）', async () => {
    // `build-vc.ts` は claims をスプレッド（own かつ列挙可能）で展開するため、非列挙の
    // クレームはそもそも VC に載らない。検査範囲も同じにしてあるので誤検知にならない。
    const claims: Record<string, unknown> = { degree: 'BSc' };
    Object.defineProperty(claims, 'health', { value: 'HIV+', enumerable: false });
    const vc = await issuer.issueVC(HOLDER, claims);
    expect(findSpecialCategoryAttributes(vc)).toEqual([]);
    expect(vc.credentialSubject).toEqual({ degree: 'BSc', id: HOLDER });
  });

  it('非列挙プロパティを持たない正当な発行は従来どおり成功する', async () => {
    const vc = await issuer.issueVC(
      HOLDER,
      { degree: 'BSc' },
      {
        evidence: [{ type: 'DocumentVerification', evidenceDocument: 'Passport' }],
        refreshService: {
          id: 'https://issuer.example/refresh',
          type: 'RefreshService2021',
          url: 'https://issuer.example/refresh',
        },
      },
    );
    expect(vc.status).toEqual({ status_list: { idx: 0, uri: REVOCATION_URI } });
  });
});
