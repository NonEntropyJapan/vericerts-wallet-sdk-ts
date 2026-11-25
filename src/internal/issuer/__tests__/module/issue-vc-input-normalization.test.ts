/**
 * 発行入力の正規化スナップショット。
 *
 * 本ファイルが固定するのは「**検査した値がそのまま署名済み VC に載る**」という不変条件と、
 * それを規約ではなく**型**で強制していることである。`build-vc.ts` は `opts` を `ownProperty`
 * （`Object.hasOwn`）で読むため、生の入力を渡すと
 *
 * 1. 非列挙の own プロパティが `Object.keys` ベースの検査を素通りし、
 * 2. own アクセサが検査時と生成時で 2 回評価されて別の値を返す、
 *
 * という 2 経路で「検査した値」と「VC に載る値」がずれる。`normalized-issue-input.ts` の
 * 正規化関数を通した公称型しか `buildCredential` に渡せないようにすることで、この経路を塞ぐ。
 */

import { beforeEach, describe, expect, it } from 'bun:test';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes } from '../../../errors.js';
import { findSpecialCategoryAttributes } from '../../../special-category.js';
import { buildCredential } from '../../module/build-vc.js';
import type { IssueOptions } from '../../module/issue-options.js';
import { IssuerModule } from '../../module/issuer-module.js';
import { normalizeClaims, normalizeIssueOptions } from '../../module/normalized-issue-input.js';
import { createStatusList, type StatusListManager } from '../../token-status-list.js';

const ISSUER = 'did:key:z6MkIssuerNormalize';
const HOLDER = 'did:key:z6MkHolderNormalize';
const REVOCATION_URI = 'https://issuer.example/status/revocation';
const SIGNER_KEY = new Uint8Array(32).fill(62);

/** 1 回目と 2 回目で別の値を返す own アクセサを持つ発行オプションを作る。 */
function withSwappingAccessor(
  key: string,
  first: unknown,
  second: unknown,
): { opts: IssueOptions; reads: () => number } {
  let reads = 0;
  const opts: Record<string, unknown> = {};
  Object.defineProperty(opts, key, {
    get(): unknown {
      reads += 1;
      return reads === 1 ? first : second;
    },
    enumerable: true,
    configurable: true,
  });
  return { opts: opts as IssueOptions, reads: () => reads };
}

describe('issueVC の入力正規化: 検査した値が署名対象になる', () => {
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

  it('own アクセサは 1 度しか評価されず、1 回目（検査済み）の値が VC に載る', async () => {
    // 正規化を外すと、検査で 1 回・`ownProperty` 読みで 1 回の計 2 回評価され、VC には
    // 2 回目の攻撃者の値が載る（＝このテストが落ちる）。
    const benign = [{ type: 'DocumentVerification', evidenceDocument: 'Passport' }];
    const attacker = [{ type: 'DocumentVerification', evidenceDocument: 'AttackerDocument' }];
    const { opts, reads } = withSwappingAccessor('evidence', benign, attacker);
    const vc = await issuer.issueVC(HOLDER, { degree: 'BSc' }, opts);
    expect(vc.evidence).toEqual(benign);
    expect(vc.evidence).not.toEqual(attacker);
    expect(reads()).toBe(1);
  });

  it('2 回目に Art.9 属性へすり替わる own アクセサでも、VC には無害な値しか載らない', async () => {
    // 観測される正しい挙動は「例外なし・1 回目の無害な値が載る」である（Art.9 値は
    // そもそも読まれないため 10607 にはならない）。
    const benign = [{ type: 'DocumentVerification', evidenceDocument: 'Passport' }];
    const attacker = [{ type: 'DocumentVerification', health: 'HIV+' }];
    const { opts, reads } = withSwappingAccessor('evidence', benign, attacker);
    const vc = await issuer.issueVC(HOLDER, { degree: 'BSc' }, opts);
    expect(findSpecialCategoryAttributes(vc)).toEqual([]);
    expect(vc.evidence).toEqual(benign);
    expect(reads()).toBe(1);
  });

  it('非列挙の own プロパティ evidence の Art.9 属性を 10607 で拒否する', async () => {
    // `ownProperty` は非列挙でも読むため、検査側も同じ範囲を
    // 見ていなければ Art.9 属性が署名済み VC に載る。
    const opts: Record<string, unknown> = {};
    Object.defineProperty(opts, 'evidence', {
      value: [{ type: 'DocumentVerification', health: 'HIV+' }],
      enumerable: false,
      configurable: true,
    });
    const before = revocation.remaining;
    await expect(
      issuer.issueVC(HOLDER, { degree: 'BSc' }, opts as IssueOptions),
    ).rejects.toMatchObject({ code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE });
    // 拒否は確保より前なので Status List のビットは消費されない。
    expect(revocation.remaining).toBe(before);
    expect(issuer.exportEntries()).toEqual([]);
  });
});

describe('normalizeIssueOptions（own の全文字列キー）', () => {
  it('own アクセサをちょうど 1 回だけ評価し、データプロパティへ畳む', () => {
    const { opts, reads } = withSwappingAccessor(
      'derivedFrom',
      'urn:uuid:first',
      'urn:uuid:second',
    );
    const snapshot = normalizeIssueOptions(opts);
    expect(reads()).toBe(1);
    const descriptor = Object.getOwnPropertyDescriptor(snapshot, 'derivedFrom');
    expect(descriptor?.get).toBeUndefined();
    expect(descriptor?.value).toBe('urn:uuid:first');
    // 何度読み直しても評価は増えず、値も動かない。
    expect(snapshot.derivedFrom).toBe('urn:uuid:first');
    expect(snapshot.derivedFrom).toBe('urn:uuid:first');
    expect(reads()).toBe(1);
  });

  it('非列挙の own プロパティも写す（`ownProperty` と同じ範囲）', () => {
    const opts: Record<string, unknown> = { derivedFrom: 'urn:uuid:parent' };
    Object.defineProperty(opts, 'expirationDate', {
      value: '2027-01-01T00:00:00Z',
      enumerable: false,
      configurable: true,
    });
    const snapshot = normalizeIssueOptions(opts as IssueOptions);
    expect(Object.hasOwn(snapshot, 'expirationDate')).toBe(true);
    expect(snapshot.expirationDate).toBe('2027-01-01T00:00:00Z');
    expect(snapshot.derivedFrom).toBe('urn:uuid:parent');
  });

  it('継承したプロパティは写さない（プロトタイプ鎖を辿らない）', () => {
    const base = { expirationDate: '2099-01-01T00:00:00Z' };
    const opts = Object.create(base) as IssueOptions;
    const snapshot = normalizeIssueOptions(opts);
    expect(Object.hasOwn(snapshot, 'expirationDate')).toBe(false);
    expect(Object.getOwnPropertyNames(snapshot)).toEqual([]);
  });
});

describe('normalizeClaims（own かつ列挙可能）', () => {
  it('own アクセサをちょうど 1 回だけ評価し、データプロパティへ畳む', () => {
    let reads = 0;
    const claims: Record<string, unknown> = {};
    Object.defineProperty(claims, 'degree', {
      get(): unknown {
        reads += 1;
        return reads === 1 ? 'BSc' : 'MSc';
      },
      enumerable: true,
      configurable: true,
    });
    const snapshot = normalizeClaims(claims);
    expect(reads).toBe(1);
    expect(Object.getOwnPropertyDescriptor(snapshot, 'degree')?.value).toBe('BSc');
  });

  it('非列挙の own プロパティは写さない（スプレッドと同じ範囲）', () => {
    // `build-vc.ts` は claims をスプレッドで展開するため、非列挙のクレームはそもそも VC に
    // 載らない。ここを広げると今まで載らなかった値が `credentialSubject` に載る。
    const claims: Record<string, unknown> = { degree: 'BSc' };
    Object.defineProperty(claims, 'health', { value: 'HIV+', enumerable: false });
    const snapshot = normalizeClaims(claims);
    expect(Object.hasOwn(snapshot, 'health')).toBe(false);
    expect(Object.getOwnPropertyNames(snapshot)).toEqual(['degree']);
  });

  it('継承したプロパティは写さない（プロトタイプ鎖を辿らない）', () => {
    const claims = Object.create({ health: 'HIV+' }) as Record<string, unknown>;
    claims.degree = 'BSc';
    const snapshot = normalizeClaims(claims);
    expect(Object.hasOwn(snapshot, 'health')).toBe(false);
    expect(Object.getOwnPropertyNames(snapshot)).toEqual(['degree']);
  });
});

describe('buildCredential の型契約（正規化スナップショットの強制）', () => {
  it('生の IssueOptions は buildCredential に渡せない', () => {
    const rawOpts: IssueOptions = { types: ['UniversityDegreeCredential'] };
    const input = {
      issuer: ISSUER,
      holderDID: HOLDER,
      claims: normalizeClaims({ degree: 'BSc' }),
      id: 'urn:uuid:vc-552',
      issuanceDate: '2026-01-01T00:00:00Z',
    };
    // 引数型が素の `IssueOptions` に戻ると**この期待エラーが消えて** `tsc --noEmit` が失敗する。
    // 実行時の挙動は変わらない（ブランドは型だけの存在）ので、下の期待値はそのまま通る。
    // @ts-expect-error 正規化していない生の IssueOptions はブランド型を満たさない
    const vc = buildCredential(input, rawOpts);
    expect(vc.type).toEqual(['VerifiableCredential', 'UniversityDegreeCredential']);
  });

  it('正規化した IssueOptions は渡せる（対比）', () => {
    const vc = buildCredential(
      {
        issuer: ISSUER,
        holderDID: HOLDER,
        claims: normalizeClaims({ degree: 'BSc' }),
        id: 'urn:uuid:vc-552',
        issuanceDate: '2026-01-01T00:00:00Z',
      },
      normalizeIssueOptions({ types: ['UniversityDegreeCredential'] }),
    );
    expect(vc.type).toEqual(['VerifiableCredential', 'UniversityDegreeCredential']);
    expect(vc.credentialSubject).toEqual({ degree: 'BSc', id: HOLDER });
  });
});
