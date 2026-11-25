/**
 * `verifyPresentation` の仕事量予算の回帰テスト。
 *
 * 個別の入力サイズ上限は同種の別経路に迂回されてきた。そこで VP 1 通ぶんの
 * 署名検証回数・信頼リスト走査量を共有の `PresentationWorkBudget` で数え、超過を fail-closed で拒否する。実時間ではなく
 * 決定的なカウンタ（`credentialKey` の呼び出し回数・予算の残り・例外コード）で pin する。
 * 形状を変えて検証する: 件数だけ多い（極小要素）/ 少数で重い（巨大な `type`）/ 重複 / 発行者エントリが多い。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { HEAVY_INPUT_TIMEOUT_MS } from '../../../../__tests__/heavy-input-timeout.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import {
  MAX_CREDENTIAL_TYPES,
  MAX_PRESENTATION_CREDENTIALS,
  newPresentationWorkBudget,
  PRESENTATION_WORK_LIMITS,
} from '../../../../primitives/presentation-work-budget.js';
import type { TrustedIssuerList } from '../../../../trusted-issuer/types.js';
import { signCompactJws } from '../../../vc/compact-jws.js';
import { issueCredential } from '../../../vc/issue.js';
import type { VerifiableCredential } from '../../../vc/vc.js';
import type { EmbeddedCredentialKeyResolver } from '../../credential-results.js';
import { issuePresentation } from '../../issue.js';
import { verifyPresentation } from '../../presentation.js';
import { VC_V2_CONTEXT } from '../../vp.js';
import { FIXTURES, sampleVp, signerFor } from '../presentation.fixtures.js';

setDefaultTimeout(HEAVY_INPUT_TIMEOUT_MS);

const NOW = Math.floor(Date.parse('2026-01-01T00:00:00Z') / 1000);
const HOLDER_ALG = 'ES256' as const;
const ISSUER_ALG = 'ES256K' as const;
const ISSUER_DID = 'did:example:issuer';
const ISSUER_KEY = { publicKeyJwk: FIXTURES[ISSUER_ALG].jwk } as const;
const holderKey = { key: { publicKeyJwk: FIXTURES[HOLDER_ALG].jwk }, allowUnbound: true } as const;

/** 呼び出し回数を数える発行者鍵 DI。 */
function countingResolver() {
  const counter = { calls: 0 };
  const credentialKey: EmbeddedCredentialKeyResolver = () => {
    counter.calls += 1;
    return ISSUER_KEY;
  };
  return { counter, credentialKey };
}

/** 発行者鍵で署名した JWT-VC（`seq` で内容を変えて別要素にする）。 */
function embeddedVc(seq: number, types: readonly string[] = ['VerifiableCredential']): string {
  const vc = {
    '@context': [VC_V2_CONTEXT],
    type: types,
    issuer: ISSUER_DID,
    credentialSubject: { id: 'did:example:holder' },
    issuanceDate: '2025-01-01T00:00:00Z',
    expirationDate: '2030-01-01T00:00:00Z',
    id: `urn:uuid:vc-${seq}`,
  } as unknown as VerifiableCredential;
  return issueCredential(vc, signerFor(ISSUER_ALG), { nowSeconds: NOW });
}

/** 件数に上限が無い前提で VP を署名する（`issuePresentation` の構造検証を迂回して要素を差し替える）。 */
function vpWith(entries: readonly string[]): string {
  const seed = issuePresentation(sampleVp(), signerFor(HOLDER_ALG), { nowSeconds: NOW });
  const [header, payload] = seed.split('.') as [string, string];
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
  claims.vp.verifiableCredential = entries;
  return signCompactJws(
    JSON.parse(Buffer.from(header, 'base64url').toString()),
    claims,
    signerFor(HOLDER_ALG),
  );
}

function thrown(run: () => unknown): VericertsError {
  try {
    run();
  } catch (err) {
    if (err instanceof VericertsError) {
      return err;
    }
    throw err;
  }
  throw new Error('should have thrown');
}

function tilOf(trustedIssuers: TrustedIssuerList['trustedIssuers']): TrustedIssuerList {
  return {
    id: 'til',
    type: 'TrustedIssuerList',
    version: 'TSLv1',
    listOperator: 'did:example:operator',
    listName: 'TIL',
    issuedAt: '2025-01-01T00:00:00Z',
    trustedIssuers,
  };
}

const opts = (credentialKey: EmbeddedCredentialKeyResolver) => ({
  ...holderKey,
  nowSeconds: NOW,
  credentialKey,
});

describe('VP の内包 VC 数の上限', () => {
  it('MAX_PRESENTATION_CREDENTIALS を超える VP は、署名検証にも鍵解決にも入る前に 3002 で拒否する', () => {
    const { counter, credentialKey } = countingResolver();
    const vp = vpWith(
      Array.from({ length: MAX_PRESENTATION_CREDENTIALS + 1 }, (_, i) => embeddedVc(i)),
    );
    const err = thrown(() => verifyPresentation(vp, opts(credentialKey)));
    expect(err.code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
    expect(counter.calls).toBe(0);
  });

  it('極小要素を大量に並べた VP（20 万件・約 4 バイト/件）も、要素数だけで即座に拒否する', () => {
    const { counter, credentialKey } = countingResolver();
    const vp = vpWith(Array.from({ length: 200_000 }, () => 'a.b'));
    expect(thrown(() => verifyPresentation(vp, opts(credentialKey))).code).toBe(
      ErrorCodes.VC_SCHEMA_INVALID,
    );
    expect(counter.calls).toBe(0);
  });

  it('上限ちょうど（異なる 64 件）の通常の VP は従来どおり検証される', () => {
    const { counter, credentialKey } = countingResolver();
    const vp = vpWith(
      Array.from({ length: MAX_PRESENTATION_CREDENTIALS }, (_, i) => embeddedVc(i)),
    );
    const result = verifyPresentation(vp, opts(credentialKey));
    expect(result.valid).toBe(true);
    expect(result.credentialResults).toHaveLength(MAX_PRESENTATION_CREDENTIALS);
    expect(counter.calls).toBe(MAX_PRESENTATION_CREDENTIALS);
  });

  it('完全一致する要素は 1 度だけ検証し、結果は要素数ぶん返る', () => {
    const { counter, credentialKey } = countingResolver();
    const same = embeddedVc(1);
    const vp = vpWith(Array.from({ length: MAX_PRESENTATION_CREDENTIALS }, () => same));
    const result = verifyPresentation(vp, opts(credentialKey));
    expect(counter.calls).toBe(1);
    expect(result.credentialResults).toHaveLength(MAX_PRESENTATION_CREDENTIALS);
    expect(result.valid).toBe(true);
  });
});

describe('署名検証回数の共有予算', () => {
  it('渡した予算の signatures を使い切ったら、それ以降の署名検証に入らず 3002 で拒否する', () => {
    const { counter, credentialKey } = countingResolver();
    const budget = newPresentationWorkBudget();
    budget.signatures = 3;
    const vp = vpWith(Array.from({ length: 5 }, (_, i) => embeddedVc(i)));
    const err = thrown(() =>
      verifyPresentation(vp, { ...opts(credentialKey), workBudget: budget }),
    );
    expect(err.code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
    expect(err.context).toMatchObject({ reason: 'work_budget_exceeded' });
    expect(counter.calls).toBe(3);
    expect(budget.signatures).toBe(0);
  });

  it('予算は VP をまたいで共有できる: 2 通目以降の消費は残りに積み上がる', () => {
    const { credentialKey } = countingResolver();
    const budget = newPresentationWorkBudget();
    const vp = vpWith([embeddedVc(1), embeddedVc(2)]);
    verifyPresentation(vp, { ...opts(credentialKey), workBudget: budget });
    verifyPresentation(vp, { ...opts(credentialKey), workBudget: budget });
    expect(PRESENTATION_WORK_LIMITS.signatures - budget.signatures).toBe(4);
    expect(PRESENTATION_WORK_LIMITS.total - budget.total).toBe(4);
  });
});

describe('Trusted Issuer List 照合の走査量', () => {
  const scansFor = (types: readonly string[], list: TrustedIssuerList) => {
    const { credentialKey } = countingResolver();
    const budget = newPresentationWorkBudget();
    const result = verifyPresentation(vpWith([embeddedVc(1, types)]), {
      ...opts(credentialKey),
      trustedIssuerList: list,
      workBudget: budget,
    });
    return { result, spent: PRESENTATION_WORK_LIMITS.trustScans - budget.trustScans };
  };

  // 発行者以外のエントリ 5000 件 + 発行者エントリ 1 件（`Victim` 型のみ信頼）。
  const bigList = tilOf([
    ...Array.from({ length: 5000 }, (_, i) => ({ id: `did:web:tsp-${i}.example.eu`, name: 'n' })),
    { id: ISSUER_DID, name: 'v', credentialTypes: ['Victim'] },
  ]);

  it('走査量は VC の type 件数にもリストの総エントリ数にも比例しない（type 10 件でも 60 万件でも同じ）', () => {
    const few = scansFor(['VerifiableCredential', 'Victim'], bigList);
    const many = scansFor(['VerifiableCredential', ...Array(600_000).fill('a'), 'Victim'], bigList);
    // 発行者エントリ 1 件 + 宣言種別 1 件 = 2 単位。
    expect(few.spent).toBe(2);
    expect(few.result.credentialResults[0]?.isTrustedIssuer).toBe(true);
    // 相異なる種別は 'VerifiableCredential' / 'a' / 'Victim' の 3 件だが、重複は畳まれ走査量は変わらない。
    expect(many.spent).toBe(2);
    expect(many.result.credentialResults[0]?.isTrustedIssuer).toBe(true);
  });

  it(`相異なる種別が ${MAX_CREDENTIAL_TYPES} 件を超える VC は種別を取り出せない扱い（制限付きエントリを信頼しない）`, () => {
    const distinct = Array.from({ length: MAX_CREDENTIAL_TYPES + 1 }, (_, i) => `T${i}`);
    const restricted = scansFor([...distinct, 'Victim'], bigList);
    expect(restricted.result.credentialResults[0]?.isTrustedIssuer).toBe(false);
    const unrestricted = scansFor(distinct, tilOf([{ id: ISSUER_DID, name: 'u' }]));
    expect(unrestricted.result.credentialResults[0]?.isTrustedIssuer).toBe(true);
  });

  it('署名検証に失敗する VC でも走査量は予算に計上される（失敗経路が無料の迂回口にならない）', () => {
    const budget = newPresentationWorkBudget();
    const result = verifyPresentation(vpWith([embeddedVc(1)]), {
      ...holderKey,
      nowSeconds: NOW,
      // 鍵を解決しない = 署名検証に入らず fail-closed（3010）。
      trustedIssuerList: bigList,
      workBudget: budget,
    });
    expect(result.credentialResults[0]?.valid).toBe(false);
    expect(PRESENTATION_WORK_LIMITS.trustScans - budget.trustScans).toBe(2);
  });

  it('同じ発行者のエントリが多数あっても、VP 全体の走査量は trustScans で縛られ 3002 で拒否する', () => {
    // 同一 DID のエントリ 200 件（どれも別種別のみ信頼 = 一致せず全件を走査する）。
    const crowded = tilOf(
      Array.from({ length: 200 }, (_, i) => ({
        id: ISSUER_DID,
        name: `e${i}`,
        credentialTypes: [`Other${i}`],
      })),
    );
    const { counter, credentialKey } = countingResolver();
    const budget = newPresentationWorkBudget();
    const vp = vpWith(
      Array.from({ length: MAX_PRESENTATION_CREDENTIALS }, (_, i) => embeddedVc(i)),
    );
    const err = thrown(() =>
      verifyPresentation(vp, {
        ...opts(credentialKey),
        trustedIssuerList: crowded,
        workBudget: budget,
      }),
    );
    expect(err.code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
    expect(err.context).toMatchObject({ reason: 'work_budget_exceeded' });
    // 1 VC あたり 200 件 × 2 単位 = 400。8192 / 400 = 20 件目まで通り、21 件目で超過する。
    expect(counter.calls).toBe(Math.floor(PRESENTATION_WORK_LIMITS.trustScans / 400) + 1);
  });
});
