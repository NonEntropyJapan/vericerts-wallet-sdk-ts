/**
 * 低レベル JWT-VC 発行プリミティブ（`issueCredential` / `issueCredentialAsync`）の
 * GDPR Art.9 ガード回帰テスト（エラー `10607`）。
 *
 * SDK は VC 発行時と DID Document 更新時にクレームを検査する。
 * 従来のガードは `IssuerModule.issueVC` の 1 経路にしか配線されておらず、公開エクスポート済みの
 * 低レベル発行入口（`issueCredential` / `issueCredentialAsync`、およびそれへ委譲する
 * `Wallet.issueCredential`）は無ガードだった。本ファイルは署名プリミティブ側の配線を固定する。
 *
 * 固定する不変条件は 1 つ、**「署名済み JWT-VC に Art.9 属性は載らない」**である。以下のケースは
 * この不変条件の破れ方を列挙している:
 * - トップレベル / 入れ子 / 配列要素 / 命名揺れ（`birthDate` / `birth_date` / 圧縮 IRI /
 *   展開済み IRI）の禁止属性を `10607` で拒否する（同期版・非同期版の両方）。
 * - `credentialSubject` 以外の VC 直下フィールド（`evidence` / `termsOfUse`）も覆う。
 * - 拒否時に `signer.sign` が **1 度も呼ばれない**（署名鍵を使う前に fail-closed）。`10601`
 *   （オンチェーン）ではなく `10607`（発行）を送出し、例外に属性名・クレーム値を載せない。
 * - own アクセサの二重評価では不変条件が破れない（検査値と署名バイト列が定義上一致するため）。
 * - 非列挙 own プロパティは `JSON.stringify` が出力しないため、**拒否ではなく非搭載**で守られる。
 * - 無害な VC は従来どおり発行でき、payload にそのまま載る（過剰検知の回帰防止）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { findSpecialCategoryAttributes } from '../../../../special-category.js';
import { issueCredential, issueCredentialAsync } from '../../issue.js';
import { type CredentialSigner, createPrivateKeySigner } from '../../signer.js';
import type { VerifiableCredential } from '../../vc.js';

const ISSUER_KEY = new Uint8Array(32).fill(11);
const ISSUER_DID = 'did:example:issuer';
const SUBJECT_DID = 'did:example:subject';
const ISSUANCE_DATE = '2026-01-01T00:00:00Z';
const NOW_SECONDS = 1_767_225_600;

/** `sign` の呼び出し回数を数える signer（fail-closed の確認用）。 */
interface CountingSigner {
  /** 委譲先の実 signer と同一の署名を返す signer。 */
  readonly signer: CredentialSigner;
  /** `sign` が呼ばれた回数。 */
  readonly calls: () => number;
}

/**
 * 署名回数を数える signer を作る。「ガードが `signer.sign` より前に走る」ことは戻り値からは
 * 観測できない（どちらでも例外は同じ `10607`）ため、呼び出し回数で直接固定する。
 */
function countingSigner(): CountingSigner {
  const inner = createPrivateKeySigner(ISSUER_KEY, 'ES256');
  let calls = 0;
  return {
    signer: {
      alg: inner.alg,
      publicKeyJwk: inner.publicKeyJwk,
      sign(signingInput: Uint8Array): Uint8Array {
        calls += 1;
        return inner.sign(signingInput);
      },
    },
    calls: () => calls,
  };
}

/** 指定したクレームを持つ最小 VC を作る。 */
function vcWithClaims(claims: Record<string, unknown>): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: ISSUER_DID,
    credentialSubject: { id: SUBJECT_DID, ...claims },
    issuanceDate: ISSUANCE_DATE,
  };
}

/** 署名済み JWT の payload をデコードする。 */
function decodePayload(jwt: string): Record<string, unknown> {
  const [, payload = ''] = jwt.split('.');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<string, unknown>;
}

/** 同期発行が `10607` で拒否されることを表明する（`toThrow` だけではコードを固定できない）。 */
function expectIssuanceRejected(issue: () => string): void {
  try {
    issue();
    throw new Error('should have thrown');
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE);
  }
}

/** 発行時に拒否する代表的なクレーム（トップレベル / 入れ子 / 配列 / 命名揺れ）。 */
const VIOLATING_CLAIMS: readonly [string, Record<string, unknown>][] = [
  ['トップレベルの health', { health: 'HIV+' }],
  ['トップレベルの religion', { religion: 'x' }],
  ['入れ子の credentialSubject.profile.diagnosis', { profile: { diagnosis: 'x' } }],
  ['配列要素の documents[0].national_id', { documents: [{ national_id: 'x' }] }],
  // 命名揺れ: `normalizeAttributeName` が末尾の `:` `/` `#` 以降を取り出して畳むこと。
  ['camelCase の birthDate', { birthDate: '1990-01-01' }],
  ['snake_case の birth_date', { birth_date: '1990-01-01' }],
  ['圧縮 IRI の pid:birth_date', { 'pid:birth_date': '1990-01-01' }],
  [
    '展開済み IRI の https://schema.org/birthDate',
    { 'https://schema.org/birthDate': '1990-01-01' },
  ],
];

/** `credentialSubject` の外（VC 直下）に置いた違反。`vc` クレームごと署名対象に載る。 */
const VIOLATING_VC_FIELDS: readonly [string, Partial<VerifiableCredential>][] = [
  ['evidence 直下の health', { evidence: [{ type: 'DocumentVerification', health: 'HIV+' }] }],
  ['termsOfUse 直下の religion', { termsOfUse: [{ type: 'IssuerPolicy', religion: 'x' }] }],
  [
    'evidence の入れ子の familyName',
    { evidence: [{ type: 'DocumentVerification', applicant: { familyName: 'x' } }] },
  ],
];

describe('issueCredential / issueCredentialAsync の Art.9 ガード', () => {
  for (const [label, claims] of VIOLATING_CLAIMS) {
    it(`${label} を含む VC の同期発行を 10607 で拒否する`, () => {
      const { signer, calls } = countingSigner();
      expectIssuanceRejected(() => issueCredential(vcWithClaims(claims), signer));
      // 署名鍵を使う前に倒れていること（fail-closed）。
      expect(calls()).toBe(0);
    });

    // 非同期版は独立した関数であり、`buildSigningInput` の共有が外れると片方だけ無ガードになる。
    it(`${label} を含む VC の非同期発行を 10607 で拒否する`, async () => {
      const { signer, calls } = countingSigner();
      const promise = issueCredentialAsync(vcWithClaims(claims), signer);
      await expect(promise).rejects.toMatchObject({
        code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE,
      });
      expect(calls()).toBe(0);
    });
  }

  it('同期発行の拒否コードは 10607（3002 でも 10601 でもない）', () => {
    try {
      issueCredential(vcWithClaims({ health: 'x' }), createPrivateKeySigner(ISSUER_KEY, 'ES256'));
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      // 発行はチェーンにも IPFS にも書き込まないため `_ON_CHAIN` を名乗る 10601 は不正確。
      expect((error as VericertsError).code).toBe(ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE);
      expect((error as VericertsError).code).not.toBe(ErrorCodes.GDPR_SPECIAL_CATEGORY_ON_CHAIN);
    }
  });

  it('例外に属性名・クレーム値を載せない（PII 非開示）', () => {
    try {
      issueCredential(
        vcWithClaims({ religion: 'secret-value' }),
        createPrivateKeySigner(ISSUER_KEY, 'ES256'),
      );
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      const serialized = JSON.stringify({
        message: (error as VericertsError).message,
        context: (error as VericertsError).context,
      });
      expect(serialized).not.toContain('secret-value');
      expect(serialized).not.toContain('religion');
    }
  });

  // クレームが無害でも、VC 直下のフィールドはそのまま `vc` クレームとして署名対象に載る。
  // ガードを `credentialSubject` だけに掛けると、ここが丸ごと素通りする。
  for (const [label, fields] of VIOLATING_VC_FIELDS) {
    it(`VC 直下 ${label} を含む発行を 10607 で拒否する`, () => {
      const { signer, calls } = countingSigner();
      const vc: VerifiableCredential = { ...vcWithClaims({ degree: 'BSc' }), ...fields };
      expectIssuanceRejected(() => issueCredential(vc, signer));
      expect(calls()).toBe(0);
    });
  }
});

describe('issueCredential の Art.9 不変条件: 検査値と署名バイト列の一致', () => {
  /**
   * 「署名済み JWT に Art.9 属性が載らない」ことだけを固定する。own アクセサを仕込んだ入力では
   * 発行成功か `10607` 拒否かは実装の読み取り回数に依存するため、結果で分岐して両方を許し、
   * 「ガードを通過したうえで禁止属性が署名済み JWT に載る」ケースだけを落とす。
   */
  function expectIssuedJwtFreeOfSpecialCategory(issue: () => string): void {
    let jwt: string;
    try {
      jwt = issue();
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe(ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE);
      return;
    }
    expect(findSpecialCategoryAttributes(decodePayload(jwt))).toEqual([]);
  }

  it('own アクセサが 2 回目に禁止属性を返しても、署名済み JWT に禁止属性は載らない', () => {
    // 「検査時は無害・署名時は有害」という二重評価が成立すると、ガードを
    // 通過した発行から Art.9 属性が署名済み JWT へ載る。payload を 1 度だけ直列化し、その
    // 文字列を解析した値を検査してから**同じ文字列**を署名対象にする実装では原理的に起きない。
    let reads = 0;
    const vc = vcWithClaims({});
    Object.defineProperty(vc.credentialSubject, 'x', {
      get(): unknown {
        reads += 1;
        return reads === 1 ? { degree: 'BSc' } : { health: 'HIV+' };
      },
      enumerable: true,
      configurable: true,
    });

    expectIssuedJwtFreeOfSpecialCategory(() =>
      issueCredential(vc, createPrivateKeySigner(ISSUER_KEY, 'ES256')),
    );
  });

  it('own アクセサが 1 回目から禁止属性を返す場合は 10607 で拒否する', () => {
    const vc = vcWithClaims({});
    Object.defineProperty(vc.credentialSubject, 'x', {
      get: (): unknown => ({ geneticData: 'x' }),
      enumerable: true,
      configurable: true,
    });

    const { signer, calls } = countingSigner();
    expectIssuanceRejected(() => issueCredential(vc, signer));
    expect(calls()).toBe(0);
  });

  it('非列挙 own プロパティの禁止属性は拒否ではなく「JWT に載らない」形で守られる', () => {
    // `JSON.stringify` は非列挙 own プロパティを出力しないため、署名対象にそもそも入らない。
    // したがって走査対象（直列化後の文字列）にも現れず、発行は **成功する**。
    // 「拒否される」と書いてしまうと実装の実挙動と食い違うため、不変条件の側を固定する。
    const vc = vcWithClaims({ degree: 'BSc' });
    Object.defineProperty(vc.credentialSubject, 'health', {
      value: 'HIV+',
      enumerable: false,
      configurable: true,
    });

    const jwt = issueCredential(vc, createPrivateKeySigner(ISSUER_KEY, 'ES256'), {
      nowSeconds: NOW_SECONDS,
    });
    const payload = decodePayload(jwt);
    expect(findSpecialCategoryAttributes(payload)).toEqual([]);
    const subject = (payload.vc as VerifiableCredential).credentialSubject;
    expect(Object.hasOwn(subject, 'health')).toBe(false);
    expect(subject).toEqual({ id: SUBJECT_DID, degree: 'BSc' });
  });
});

describe('issueCredential の Art.9 ガードの過剰検知防止', () => {
  // 陽性対照。これが無いと「疑わしきは拒否」方向へガードを厳しくしすぎる変更を検知できない。
  it('無害な VC は同期発行でき、payload にそのまま載る', () => {
    const vc: VerifiableCredential = {
      ...vcWithClaims({ degree: 'BSc', name: 'Alice' }),
      id: 'urn:uuid:ok-1',
      evidence: [{ type: 'DocumentVerification', evidenceDocument: 'DriversLicense' }],
      termsOfUse: [{ type: 'IssuerPolicy' }],
    };

    const jwt = issueCredential(vc, createPrivateKeySigner(ISSUER_KEY, 'ES256'), {
      nowSeconds: NOW_SECONDS,
    });

    const payload = decodePayload(jwt);
    expect(jwt.split('.')).toHaveLength(3);
    expect(payload.iss).toBe(ISSUER_DID);
    expect(payload.sub).toBe(SUBJECT_DID);
    expect(payload.jti).toBe('urn:uuid:ok-1');
    expect(payload.vc).toEqual(vc);
  });

  it('無害な VC は非同期発行でき、同期発行とバイト単位で一致する', async () => {
    const vc = vcWithClaims({ degree: 'BSc' });
    const signer = createPrivateKeySigner(ISSUER_KEY, 'ES256');
    const sync = issueCredential(vc, signer, { nowSeconds: NOW_SECONDS });
    expect(await issueCredentialAsync(vc, signer, { nowSeconds: NOW_SECONDS })).toBe(sync);
  });

  it('Art.9 語彙に似た無害な属性名（serviceEndpoint / raceTrack）は拒否しない', () => {
    // 判定は正規化名の**完全一致**であり部分一致ではない（`special-category.ts`）。部分一致に
    // 倒すと `serviceEndpoint` や `raceTrack` のような正当な属性名で発行が丸ごと止まる。
    const vc = vcWithClaims({
      serviceEndpoint: 'https://example.org/svc',
      raceTrack: 'Suzuka',
      healthy: true,
    });

    const jwt = issueCredential(vc, createPrivateKeySigner(ISSUER_KEY, 'ES256'), {
      nowSeconds: NOW_SECONDS,
    });
    expect((decodePayload(jwt).vc as VerifiableCredential).credentialSubject).toEqual(
      vc.credentialSubject,
    );
  });
});
