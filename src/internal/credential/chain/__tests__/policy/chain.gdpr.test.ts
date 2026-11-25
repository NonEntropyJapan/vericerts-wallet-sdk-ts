/**
 * `buildDerivedCredential` の GDPR Art.9 ガード回帰テスト（エラー `10607`）。
 *
 * 本関数は署名しない純関数なので、`IssueChainedCredential` 経由で発行すれば
 * `vc/issue.ts`（`issueCredential`）のガードに覆われる。それでも構築時点で拒否するのは、
 * `IssuerModule.issueVC` が「署名せず VC を返す時点で」拒否するのと対称にし、**戻り値を署名せず
 * そのまま保存・転送する使い方**（公開エクスポートされた純関数として単体で呼べる）も覆うためである。
 *
 * 検証内容:
 * - 子 VC / 失効伝搬ポリシーのいずれに由来する Art.9 属性でも `10607` で拒否する。
 * - **親 VC は走査対象外**である。本関数が戻り値に載せる親由来のデータは `derivedFrom` に入る
 *   `parent.id` 文字列だけで、親の属性は一切発行されないため。親まで走査すると、外部発行 EUDI PID
 *   を親にしたデータ最小化派生が子の内容によらず拒否される機能退行になる。
 * - 入れ子・配列要素・命名揺れ（`birthDate` / `birth_date` / 圧縮 IRI / 展開済み IRI）を覆う。
 * - `10601`（オンチェーン）ではなく `10607`（発行）を送出する。
 * - 例外に属性名・クレーム値を載せない（PII 非開示）。
 * - **親 VC に `id` が無い場合の既存の `3002` がガード追加後も先に投げられる**（非退行）。
 *   ここが逆転すると、構造不正の診断が Art.9 拒否に化けて呼び出し側の分岐が壊れる。
 * - 無害な親子は従来どおり構築でき、親エッジの正規化（`derivedFrom` 以外を落とす）も維持される。
 * - **入力の own アクセサを二重評価しない**（検査した値と戻り値に載る値がずれない）。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../../errors.js';
import type { VerifiableCredential } from '../../../vc/vc.js';
import { buildDerivedCredential } from '../../build.js';
import type { ChainPolicy, DerivedCredentialInput } from '../../types.js';

const V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
const PARENT_ID = 'urn:uuid:parent-1';
const CHILD_ID = 'urn:uuid:child-1';
/** 外部発行 EUDI PID の ID（本 SDK が受領のみ行う他者発行 VC を親に据えるケース）。 */
const EUDI_PID_ID = 'urn:uuid:eudi-pid-1';
const ISSUER_DID = 'did:example:issuer';
const SUBJECT_DID = 'did:example:subject';

/** 指定したクレームと ID を持つ最小 VC を作る。 */
function makeVc(
  id: string | undefined,
  claims: Record<string, unknown> = {},
): VerifiableCredential {
  return {
    '@context': [V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer: ISSUER_DID,
    credentialSubject: { id: SUBJECT_DID, ...claims },
    issuanceDate: '2026-01-01T00:00:00Z',
    ...(id !== undefined ? { id } : {}),
  };
}

/** 構築が指定コードで拒否されることを表明する（`toThrow` だけではコードを固定できない）。 */
function expectBuildRejectedWith(code: ErrorCode, build: () => VerifiableCredential): void {
  try {
    build();
    throw new Error('should have thrown');
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(code);
  }
}

/** 構築が Art.9 ガード（`10607`）で拒否されることを表明する。 */
function expectBuildRejected(build: () => VerifiableCredential): void {
  expectBuildRejectedWith(ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE, build);
}

/** 発行時に拒否する代表的なクレーム（トップレベル / 入れ子 / 配列 / 命名揺れ）。 */
const VIOLATING_CLAIMS: readonly [string, Record<string, unknown>][] = [
  ['トップレベルの health', { health: 'HIV+' }],
  ['トップレベルの religion', { religion: 'x' }],
  ['入れ子の profile.diagnosis', { profile: { diagnosis: 'x' } }],
  ['配列要素の documents[0].national_id', { documents: [{ national_id: 'x' }] }],
  ['camelCase の birthDate', { birthDate: '1990-01-01' }],
  ['snake_case の birth_date', { birth_date: '1990-01-01' }],
  ['圧縮 IRI の pid:birth_date', { 'pid:birth_date': '1990-01-01' }],
  [
    '展開済み IRI の https://schema.org/birthDate',
    { 'https://schema.org/birthDate': '1990-01-01' },
  ],
];

describe('buildDerivedCredential の Art.9 ガード', () => {
  for (const [label, claims] of VIOLATING_CLAIMS) {
    it(`子 VC の ${label} を 10607 で拒否する`, () => {
      const child: DerivedCredentialInput = makeVc(CHILD_ID, claims);
      expectBuildRejected(() => buildDerivedCredential(makeVc(PARENT_ID), child));
    });
  }

  // 親の属性は戻り値に載らない（載るのは `derivedFrom` に入る `parent.id` 文字列だけ）ため、
  // 親は走査対象外である。子がクリーンなら親の内容にかかわらず構築できる。
  it('親 VC に Art.9 属性があっても子がクリーンなら拒否しない', () => {
    const parent = makeVc(PARENT_ID, { health: 'HIV+' });

    const derived = buildDerivedCredential(parent, makeVc(CHILD_ID, { degree: 'BSc' }));

    expect(derived.derivedFrom).toBe(PARENT_ID);
    expect(derived.credentialSubject).toEqual({ id: SUBJECT_DID, degree: 'BSc' });
  });

  it('親 VC の入れ子の Art.9 属性も拒否しない', () => {
    const parent = makeVc(PARENT_ID, { profile: { pid: { birth_date: '1990-01-01' } } });

    const derived = buildDerivedCredential(parent, makeVc(CHILD_ID, { degree: 'BSc' }));

    expect(derived.derivedFrom).toBe(PARENT_ID);
    expect(derived.credentialSubject).toEqual({ id: SUBJECT_DID, degree: 'BSc' });
  });

  // 機能退行の回帰。親まで走査していた頃は、SDK が受領を正式サポートする外部発行 EUDI PID
  // （`given_name` / `family_name` / `birth_date` を必須で持つ）を親にすると、子が完全に
  // クリーンでも 10607 で拒否され、チェーン機能が実質使用不能だった。
  it('外部発行 PID を親に age_over_18 だけを子にした派生が成功する', () => {
    const pid = makeVc(EUDI_PID_ID, {
      given_name: 'Alice',
      family_name: 'Example',
      birth_date: '1990-01-01',
    });

    const derived = buildDerivedCredential(pid, makeVc(CHILD_ID, { age_over_18: true }));

    // 親エッジは PID の ID を指すが、PID 生データは子に一切載らない。
    expect(derived.derivedFrom).toBe(EUDI_PID_ID);
    expect(derived.credentialSubject).toEqual({ id: SUBJECT_DID, age_over_18: true });
    const serialized = JSON.stringify(derived);
    for (const rawPidClaim of ['given_name', 'family_name', 'birth_date', '1990-01-01']) {
      expect(serialized).not.toContain(rawPidClaim);
    }
  });

  it('revocationPropagation 由来の Art.9 属性も 10607 で拒否する', () => {
    // `ChainPolicy` は文字列 union だが、型のない JS 呼び出しではオブジェクトが渡り得る。
    // ガードが第 3 引数を走査対象から外していると、そのまま子 VC の `revocationPropagation`
    // へ埋め込まれて Art.9 属性が VC に載る。
    const policy = { mode: 'strict', applicant: { familyName: 'x' } } as unknown as ChainPolicy;
    expectBuildRejected(() =>
      buildDerivedCredential(makeVc(PARENT_ID), makeVc(CHILD_ID, { degree: 'BSc' }), policy),
    );
  });

  it('例外に属性名・クレーム値を載せない（PII 非開示）', () => {
    try {
      buildDerivedCredential(makeVc(PARENT_ID), makeVc(CHILD_ID, { religion: 'secret-value' }));
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      const serialized = JSON.stringify({
        message: (error as VericertsError).message,
        context: (error as VericertsError).context,
      });
      expect(serialized).not.toContain('secret-value');
      expect(serialized).not.toContain('religion');
      // 構築はチェーンに書き込まないため `_ON_CHAIN`（10601）ではなく発行用の 10607。
      expect((error as VericertsError).code).toBe(ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE);
      expect((error as VericertsError).code).not.toBe(ErrorCodes.GDPR_SPECIAL_CATEGORY_ON_CHAIN);
    }
  });
});

describe('buildDerivedCredential の既存挙動の非退行', () => {
  // ガードを親 ID 検査より前に置くと、構造不正（3002）が Art.9 拒否（10607）に化ける。
  // Art.9 属性は走査対象である子に置く（親は走査対象外なので順序の検証材料にならない）。
  it('親 VC に id が無い場合は子に Art.9 属性があっても先に 3002 を投げる', () => {
    expectBuildRejectedWith(ErrorCodes.VC_SCHEMA_INVALID, () =>
      buildDerivedCredential(makeVc(undefined), makeVc(CHILD_ID, { religion: 'x' })),
    );
  });

  it('親 VC の id が空文字列の場合も子の Art.9 属性より先に 3002 を投げる', () => {
    expectBuildRejectedWith(ErrorCodes.VC_SCHEMA_INVALID, () =>
      buildDerivedCredential(makeVc(''), makeVc(CHILD_ID, { health: 'HIV+' })),
    );
  });

  // 陽性対照。これが無いとガードを厳しくしすぎる変更（正当な派生発行まで止める）を検知できない。
  it('無害な親子は従来どおり構築でき、derivedFrom と失効伝搬ポリシーが載る', () => {
    const derived = buildDerivedCredential(
      makeVc(PARENT_ID, { degree: 'BSc' }),
      makeVc(CHILD_ID, { degree: 'MSc' }),
      'strict',
    );

    expect(derived.derivedFrom).toBe(PARENT_ID);
    expect(derived.revocationPropagation).toBe('strict');
    expect(derived.credentialSubject).toEqual({ id: SUBJECT_DID, degree: 'MSc' });
  });

  it('入力に残った親エッジは従来どおり落とされる（ガード追加で変わらない）', () => {
    const child = {
      ...makeVc(CHILD_ID, { degree: 'MSc' }),
      derivedFrom: 'urn:uuid:other',
      basedOn: 'urn:uuid:other-2',
      supersedes: 'urn:uuid:other-3',
      amends: 'urn:uuid:other-4',
    } as DerivedCredentialInput;

    const derived = buildDerivedCredential(makeVc(PARENT_ID), child);

    expect(derived.derivedFrom).toBe(PARENT_ID);
    expect(derived.basedOn).toBeUndefined();
    expect(derived.supersedes).toBeUndefined();
    expect(derived.amends).toBeUndefined();
  });

  // 入力を検査時と生成時で 2 回読むと、own アクセサが 1 回目に無害な値・2 回目に Art.9 属性を
  // 返すことでガードを素通りできる。入力を一度だけ読んでスナップショットする実装を固定する。
  it('子 VC の own アクセサを二重評価せず、2 回目に返す Art.9 属性が戻り値に載らない', () => {
    let reads = 0;
    const child = makeVc(CHILD_ID);
    Object.defineProperty(child, 'credentialSubject', {
      enumerable: true,
      configurable: true,
      get: () => {
        reads += 1;
        return reads === 1
          ? { id: SUBJECT_DID, nickname: 'ali' }
          : { id: SUBJECT_DID, religion: 'x' };
      },
    });

    const derived = buildDerivedCredential(makeVc(PARENT_ID), child);

    // 走査範囲（スナップショット）と戻り値に載る範囲が一致するので評価は 1 回だけ。
    expect(reads).toBe(1);
    // 1 回目のクリーンな値が検査され、そのまま載る。禁止属性が混入する余地がない。
    expect(Object.keys(derived.credentialSubject as object)).toEqual(['id', 'nickname']);
    expect(JSON.stringify(derived)).not.toContain('religion');
  });

  // `parent.id` を検証時と `derivedFrom` 格納時で 2 回読むと、検証を通った値と実際に親エッジへ
  // 載る値がずれる（空文字列や別 VC の ID を指すエッジができる）。
  it('親 VC の id own アクセサを二重評価せず、derivedFrom は検証した 1 回目の値になる', () => {
    let reads = 0;
    const parent = makeVc(undefined);
    Object.defineProperty(parent, 'id', {
      enumerable: true,
      configurable: true,
      get: () => {
        reads += 1;
        return reads === 1 ? PARENT_ID : '';
      },
    });

    const derived = buildDerivedCredential(parent, makeVc(CHILD_ID, { degree: 'MSc' }));

    expect(reads).toBe(1);
    expect(derived.derivedFrom).toBe(PARENT_ID);
  });

  it('Art.9 語彙に似た無害な属性名（serviceEndpoint / raceTrack）は拒否しない', () => {
    // 判定は正規化名の**完全一致**であり部分一致ではない（`special-category.ts`）。
    const child = makeVc(CHILD_ID, {
      serviceEndpoint: 'https://example.org/svc',
      raceTrack: 'Suzuka',
      healthy: true,
    });

    const derived = buildDerivedCredential(makeVc(PARENT_ID), child);
    expect(derived.credentialSubject).toEqual(child.credentialSubject);
  });
});
