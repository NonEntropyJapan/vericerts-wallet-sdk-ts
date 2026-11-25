/**
 * `IssuerModule.issueVC` の GDPR Art.9 ガード（`10607`）の回帰テスト。
 *
 * SDK は発行時と DID Document 更新時に特別カテゴリ属性を検査する。
 * 従来は DID Document 更新時しか配線されていなかった。本ファイルは発行時の配線を固定する。
 *
 * 検証内容:
 * - Art.9 属性（トップレベル / 入れ子 / 命名揺れ）を含むクレームの発行を `10607` で拒否する。
 * - `opts.evidence` / `opts.termsOfUse` / `opts.refreshService` に混ぜた Art.9 属性も同じく
 *   `10607` で拒否する。いずれも `build-vc.ts` がそのまま VC へ写す。とくに `evidence` は
 *   KYC 記録であり Art.9 の生データが最も現れやすい。ガードは個別フィールドを列挙せず
 *   `opts` 全体を走査するため、あとから増えたフィールドも自動的に覆われる。
 * - オンチェーン用の `10601` は発行経路からは送出されない（発行はチェーンに書き込まない）。
 * - 例外に属性名・クレーム値を載せない（PII 非開示）。
 * - **拒否時に Status List のインデックスを消費しない**（ガードは `allocateStatus` より前に走る）。
 *   ここが崩れると、拒否された発行のたびにビットが 1 つずつ永久に失われる。
 * - 無害な `evidence` / `termsOfUse` / `refreshService` は従来どおり発行でき、VC に載る
 *   （ガードの過剰検知防止）。
 */

import { beforeEach, describe, expect, it } from 'bun:test';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import type { RefreshServiceConfig } from '../../../credential/vc/vc.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { IssueOptions } from '../../module/issue-options.js';
import { IssuerModule } from '../../module/issuer-module.js';
import { createStatusList, type StatusListManager } from '../../token-status-list.js';

const ISSUER = 'did:key:z6MkIssuerGdpr';
const HOLDER = 'did:key:z6MkHolderGdpr';
const REVOCATION_URI = 'https://issuer.example/status/revocation';
const SIGNER_KEY = new Uint8Array(32).fill(59);
const NOW = new Date('2026-08-31T00:00:00.000Z');

/** 属性ガードに対する代表的な違反クレーム（トップレベル / 入れ子 / 命名揺れ）。 */
const VIOLATING_CLAIMS: readonly [string, Record<string, unknown>][] = [
  ['トップレベルの health', { health: 'x' }],
  ['トップレベルの religion', { religion: 'x' }],
  ['入れ子の birth_date', { profile: { pid: { birth_date: '1990-01-01' } } }],
  ['配列要素の national_id', { docs: [{ national_id: 'x' }] }],
  ['camelCase の familyName', { familyName: 'x' }],
];

/**
 * `opts.evidence` / `opts.termsOfUse` 経由の代表的な違反（トップレベル / 入れ子）。
 *
 * どちらも `[key: string]: unknown` を許すため、既知フィールド以外の任意の属性名が入り得る。
 */
const VIOLATING_OPTIONS: readonly [string, IssueOptions][] = [
  ['evidence 直下の health', { evidence: [{ type: 'DocumentVerification', health: 'HIV+' }] }],
  ['evidence 直下の religion', { evidence: [{ type: 'DocumentVerification', religion: 'x' }] }],
  [
    'termsOfUse 直下の birth_date',
    { termsOfUse: [{ type: 'IssuerPolicy', birth_date: '1990-01-01' }] },
  ],
  [
    'evidence エントリの入れ子オブジェクトの national_id',
    { evidence: [{ type: 'DocumentVerification', applicant: { pid: { national_id: 'x' } } }] },
  ],
  [
    'termsOfUse の入れ子オブジェクトの familyName',
    { termsOfUse: [{ type: 'IssuerPolicy', assignee: { profile: { familyName: 'x' } } }] },
  ],
];

/** 正当な `refreshService`（`RefreshServiceConfig` の必須フィールドのみ）。 */
const REFRESH_SERVICE: RefreshServiceConfig = {
  id: 'urn:uuid:refresh-1',
  type: 'ManualRefreshService2018',
  url: 'https://issuer.example/refresh',
};

/**
 * `opts.refreshService` 経由の代表的な違反（トップレベル / 入れ子）。
 *
 * `RefreshServiceConfig` は追加プロパティを宣言していないが、TypeScript の余剰プロパティ検査は
 * **新鮮なオブジェクトリテラル**にしか働かない。ここでのように変数を経由すれば型検査を素通りし、
 * `build-vc.ts` が `refreshService` をオブジェクトごと VC へ写すため Art.9 属性が発行内容に載る。
 * 実際の攻撃面を再現するため、テストでも変数経由で渡す。
 */
const REFRESH_SERVICE_WITH_HEALTH = { ...REFRESH_SERVICE, health: 'HIV+' };
const REFRESH_SERVICE_WITH_NESTED_PID = {
  ...REFRESH_SERVICE,
  applicant: { pid: { birth_date: '1990-01-01' } },
};
const VIOLATING_REFRESH_SERVICES: readonly [string, RefreshServiceConfig][] = [
  ['直下の health', REFRESH_SERVICE_WITH_HEALTH],
  ['入れ子の birth_date', REFRESH_SERVICE_WITH_NESTED_PID],
];

describe('IssuerModule.issueVC の Art.9 ガード', () => {
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
      now: () => NOW,
    });
  });

  for (const [label, claims] of VIOLATING_CLAIMS) {
    it(`${label} を含むクレームの発行を 10607 で拒否する`, async () => {
      const promise = issuer.issueVC(HOLDER, claims);
      await expect(promise).rejects.toThrow(VericertsError);
      await expect(promise).rejects.toMatchObject({
        code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE,
      });
    });
  }

  it('オンチェーン用の 10601 は発行経路から送出しない', async () => {
    // `issueVC` は VC を組み立てて返すだけでチェーンにも IPFS にも書き込まないため、
    // `_ON_CHAIN` を名乗るコードは発生元として不正確。
    await expect(issuer.issueVC(HOLDER, { health: 'x' })).rejects.not.toMatchObject({
      code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ON_CHAIN,
    });
  });

  it('例外に属性名・クレーム値を載せない（PII 非開示）', async () => {
    try {
      await issuer.issueVC(HOLDER, { religion: 'secret-value' });
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      const serialized = JSON.stringify({
        message: (error as VericertsError).message,
        context: (error as VericertsError).context,
      });
      expect(serialized).not.toContain('secret-value');
      expect(serialized).not.toContain('religion');
      expect((error as VericertsError).code).toBe(ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE);
    }
  });

  it('Holder DID 不正の検査は Art.9 ガードより先に走る（3006 が優先）', async () => {
    await expect(issuer.issueVC('not-a-did', { health: 'x' })).rejects.toMatchObject({
      code: ErrorCodes.HOLDER_DID_FORMAT_INVALID,
    });
  });

  // ガードが `allocateStatus` の**あと**に置かれていると、拒否された発行がビットを 1 つ食い潰す。
  // 巻き戻しは不可能（`entries` に載らないインデックスは `setTokenStatus` から永久に辿れない）。
  it('拒否された発行は Status List のインデックスを消費しない', async () => {
    const first = await issuer.issueVC(HOLDER, { degree: 'BSc' }, { id: 'urn:uuid:ok-1' });
    expect(first.status).toEqual({ status_list: { idx: 0, uri: REVOCATION_URI } });
    const remainingBefore = revocation.remaining;

    await expect(
      issuer.issueVC(HOLDER, { health: 'x' }, { id: 'urn:uuid:rejected' }),
    ).rejects.toMatchObject({ code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE });

    // 拒否は残容量も vcId → idx の対応も動かさない。
    expect(revocation.remaining).toBe(remainingBefore);
    expect(issuer.exportEntries().map((entry) => entry.vcId)).toEqual(['urn:uuid:ok-1']);

    // 次の正常な発行が、拒否で焼かれていたはずの idx 1 を受け取る。
    const second = await issuer.issueVC(HOLDER, { degree: 'MSc' }, { id: 'urn:uuid:ok-2' });
    expect(second.status).toEqual({ status_list: { idx: 1, uri: REVOCATION_URI } });
    expect(issuer.exportEntries()).toEqual([
      { vcId: 'urn:uuid:ok-1', indices: { revocation: 0 } },
      { vcId: 'urn:uuid:ok-2', indices: { revocation: 1 } },
    ]);
  });

  // クレームが無害でも、`evidence` / `termsOfUse` はそのまま署名済み VC に載る。
  for (const [label, opts] of VIOLATING_OPTIONS) {
    it(`${label} を含む発行を 10607 で拒否する`, async () => {
      const promise = issuer.issueVC(HOLDER, { degree: 'BSc' }, opts);
      await expect(promise).rejects.toThrow(VericertsError);
      await expect(promise).rejects.toMatchObject({
        code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE,
      });
    });
  }

  // `claims` 経由と同じく、`evidence` / `termsOfUse` 経由の拒否もビットを食い潰してはならない。
  it('evidence / termsOfUse 経由の拒否も Status List のインデックスを消費しない', async () => {
    const first = await issuer.issueVC(HOLDER, { degree: 'BSc' }, { id: 'urn:uuid:opt-ok-1' });
    expect(first.status).toEqual({ status_list: { idx: 0, uri: REVOCATION_URI } });
    const remainingBefore = revocation.remaining;
    const entriesBefore = issuer.exportEntries();

    await expect(
      issuer.issueVC(
        HOLDER,
        { degree: 'BSc' },
        {
          id: 'urn:uuid:opt-rejected',
          evidence: [{ type: 'DocumentVerification', health: 'HIV+' }],
          termsOfUse: [{ type: 'IssuerPolicy', birth_date: '1990-01-01' }],
        },
      ),
    ).rejects.toMatchObject({ code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE });

    expect(revocation.remaining).toBe(remainingBefore);
    expect(issuer.exportEntries()).toEqual(entriesBefore);

    // 次の正常な発行が、拒否で焼かれていたはずの idx 1 を受け取る。
    const second = await issuer.issueVC(HOLDER, { degree: 'MSc' }, { id: 'urn:uuid:opt-ok-2' });
    expect(second.status).toEqual({ status_list: { idx: 1, uri: REVOCATION_URI } });
    expect(issuer.exportEntries()).toEqual([
      { vcId: 'urn:uuid:opt-ok-1', indices: { revocation: 0 } },
      { vcId: 'urn:uuid:opt-ok-2', indices: { revocation: 1 } },
    ]);
  });

  // フィールド列挙型のガードが取りこぼしていた経路。`refreshService` はオブジェクトごと VC へ
  // 写るのに検査対象から漏れており、Art.9 属性が署名対象に載ったうえビットまで消費していた。
  for (const [label, refreshService] of VIOLATING_REFRESH_SERVICES) {
    it(`refreshService ${label} を含む発行を 10607 で拒否する`, async () => {
      const promise = issuer.issueVC(HOLDER, { degree: 'BSc' }, { refreshService });
      await expect(promise).rejects.toThrow(VericertsError);
      await expect(promise).rejects.toMatchObject({
        code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE,
      });
    });
  }

  // `claims` 経由と同じく、`refreshService` 経由の拒否もビットを食い潰してはならない。
  it('refreshService 経由の拒否も Status List のインデックスを消費しない', async () => {
    const first = await issuer.issueVC(HOLDER, { degree: 'BSc' }, { id: 'urn:uuid:rs-ok-1' });
    expect(first.status).toEqual({ status_list: { idx: 0, uri: REVOCATION_URI } });
    const remainingBefore = revocation.remaining;
    const entriesBefore = issuer.exportEntries();

    await expect(
      issuer.issueVC(
        HOLDER,
        { degree: 'BSc' },
        { id: 'urn:uuid:rs-rejected', refreshService: REFRESH_SERVICE_WITH_HEALTH },
      ),
    ).rejects.toMatchObject({ code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE });

    expect(revocation.remaining).toBe(remainingBefore);
    expect(issuer.exportEntries()).toEqual(entriesBefore);

    // 次の正常な発行が、拒否で焼かれていたはずの idx 1 を受け取る。
    const second = await issuer.issueVC(HOLDER, { degree: 'MSc' }, { id: 'urn:uuid:rs-ok-2' });
    expect(second.status).toEqual({ status_list: { idx: 1, uri: REVOCATION_URI } });
  });

  // 陽性対照: ガードが過剰検知していないこと（正当な KYC 記録・利用条件・更新参照は通す）。
  it('無害な evidence / termsOfUse は発行でき、VC にそのまま載る', async () => {
    const evidence = [{ type: 'DocumentVerification', evidenceDocument: 'DriversLicense' }];
    const termsOfUse = [{ type: 'IssuerPolicy' }];

    const vc = await issuer.issueVC(HOLDER, { degree: 'BSc' }, { evidence, termsOfUse });

    expect(vc.evidence).toEqual(evidence);
    expect(vc.termsOfUse).toEqual(termsOfUse);
  });

  // `opts` 全体を走査する設計が、正当な `IssueOptions` のキー名（`refreshService` / `format` 等）を
  // Art.9 語彙と誤認しないことの確認。誤認すると正当な発行が丸ごと止まる。
  it('無害な refreshService は発行でき、VC にそのまま載る', async () => {
    const vc = await issuer.issueVC(
      HOLDER,
      { degree: 'BSc' },
      {
        refreshService: REFRESH_SERVICE,
        format: 'jwt',
        expirationDate: '2027-01-01T00:00:00.000Z',
      },
    );

    expect(vc.refreshService).toEqual(REFRESH_SERVICE);
    expect(vc.status).toEqual({ status_list: { idx: 0, uri: REVOCATION_URI } });
  });
});
