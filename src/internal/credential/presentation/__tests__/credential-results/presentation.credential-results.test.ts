/**
 * `verifyPresentation` の内包 VC 検証と `credentialResults` の回帰テスト。
 *
 * `verifyPresentation` は VP の署名と内包する各 VC を検証し、VC ごとの結果を `credentialResults` に返す。
 *
 * 本ファイルはその欠陥を突く。修正前は「内包 VC が偽物でも成功」だったため、`valid === false`
 * を期待するケースはすべて失敗する（`valid` プロパティ自体が存在しなかった）。
 *
 * 実鍵のみを使う（モック禁止）。VP holder は ES256、VC issuer は ES256K で別鍵にし、
 * 「VP 署名が通っても内包 VC の署名は別途検証される」ことを鍵の分離で示す。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { issueCredential } from '../../../vc/issue.js';
import type { VerifiableCredential } from '../../../vc/vc.js';
import type { EmbeddedCredentialKeyResolver } from '../../credential-results.js';
import { issuePresentation } from '../../issue.js';
import { verifyPresentation } from '../../presentation.js';
import { FIXTURES, sampleVp, signerFor } from '../presentation.fixtures.js';

const NOW = Math.floor(Date.parse('2026-01-01T00:00:00Z') / 1000);
const HOLDER_ALG = 'ES256' as const;
const ISSUER_ALG = 'ES256K' as const;
/** 内包 VC の正しい発行者鍵（ES256K）。 */
const ISSUER_KEY = { publicKeyJwk: FIXTURES[ISSUER_ALG].jwk } as const;

function sampleVc(overrides: Partial<VerifiableCredential> = {}): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: '2025-01-01T00:00:00Z',
    expirationDate: '2027-01-01T00:00:00Z',
    id: 'urn:uuid:vc-1',
    ...overrides,
  };
}

/** 内包用の JWT-VC を発行する（既定は正しい発行者鍵 ES256K で署名）。 */
function embeddedVc(alg: typeof ISSUER_ALG | typeof HOLDER_ALG = ISSUER_ALG, vc = sampleVc()) {
  return issueCredential(vc, signerFor(alg), { nowSeconds: NOW });
}

/**
 * 内包用の COSE_Sign1 VC（`vc+cose`）を模した base64url 文字列を作る。
 *
 * 署名検証には一切到達しないため、必要なのは COSE_Sign1 の外形（タグ 18 + 4 要素の CBOR 配列）
 * だけで、中身は何でもよい。
 */
function coseSign1Vc(): string {
  // d2 = tag(18) COSE_Sign1 / 84 = array(4) / 43 a10126 = protected（bstr）/ a0 = unprotected（map(0)）
  // / 44 01020304 = payload（bstr）/ 43 050607 = signature（bstr）。
  const cose = [
    0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x44, 0x01, 0x02, 0x03, 0x04, 0x43, 0x05, 0x06, 0x07,
  ];
  return base64urlnopad.encode(Uint8Array.from(cose));
}

/**
 * 内包用の Data Integrity BBS VC（`bbs+`）を模したオブジェクトを作る。
 *
 * `ldp_vc` との違いは `proof.cryptosuite` だけで、どちらも未実装のため拒否コードは同じ 3002。
 * ここで固定するのは「同じ経路で落ちること」と「診断上の `format` が実態に合うこと」の 2 点。
 */
function bbsVc(): Record<string, unknown> {
  return {
    ...sampleVc(),
    id: 'urn:uuid:vc-bbs',
    proof: {
      type: 'DataIntegrityProof',
      cryptosuite: 'bbs-2023',
      created: '2025-01-01T00:00:00Z',
      verificationMethod: 'did:example:issuer#bbs-key-1',
      proofPurpose: 'assertionMethod',
      proofValue: 'u-not-verified',
    },
  };
}

/** 指定の VC 群を内包した JWT-VP を holder 鍵で署名する。 */
function vpWith(entries: ReadonlyArray<string | Readonly<Record<string, unknown>>>): string {
  return issuePresentation(sampleVp({ verifiableCredential: entries }), signerFor(HOLDER_ALG), {
    nowSeconds: NOW,
  });
}

/** 常に正しい発行者鍵を返す DI。 */
const issuerKeyResolver: EmbeddedCredentialKeyResolver = () => ISSUER_KEY;

/** VP 署名の検証に必要な最小オプション。 */
const holderKey = { key: { publicKeyJwk: FIXTURES[HOLDER_ALG].jwk }, allowUnbound: true } as const;

describe('verifyPresentation の内包 VC 検証', () => {
  it('holder が他人の発行でない VC を詰めた VP は valid: false になる', () => {
    // holder 自身の鍵（ES256）で「発行」した VC を詰める = 発行者 did:example:issuer の署名ではない。
    const jwt = vpWith([embeddedVc(HOLDER_ALG)]);
    const result = verifyPresentation(jwt, {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    // VP 署名は holder のものなので通る。しかし内包 VC は発行者鍵で検証されて落ちる。
    expect(result.presentation.holder).toBe('did:example:holder');
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3010']);
    expect(result.errors).toEqual(['3010']);
  });

  it('正しい発行者鍵で署名された内包 VC は valid: true になる', () => {
    const jwt = vpWith([embeddedVc()]);
    const result = verifyPresentation(jwt, {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.valid).toBe(true);
    expect(result.holderDID).toBe('did:example:holder');
    expect(result.errors).toBeUndefined();
    expect(result.credentialResults).toHaveLength(1);
    expect(result.credentialResults[0]).toMatchObject({
      valid: true,
      issuerDID: 'did:example:issuer',
      isExpired: false,
      isRevoked: null,
      isSuspended: null,
      isTrustedIssuer: null,
      schemaValid: null,
      format: 'jwt_vc_json',
    });
  });

  it('credentialKey 未指定は fail-closed（検証不能な VC を成功にしない）', () => {
    const jwt = vpWith([embeddedVc()]);
    const result = verifyPresentation(jwt, { ...holderKey, nowSeconds: NOW });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3010']);
  });

  it('credentialResults は verifiableCredential と同じ長さ・同じ順序で返る', () => {
    const good = embeddedVc();
    const bad = embeddedVc(HOLDER_ALG);
    const jwt = vpWith([good, bad, good]);
    const result = verifyPresentation(jwt, {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.credentialResults.map((r) => r.valid)).toEqual([true, false, true]);
    expect(result.valid).toBe(false);
  });

  it('期限切れの内包 VC は isExpired: true と 3024 を返す', () => {
    const expired = embeddedVc(
      ISSUER_ALG,
      sampleVc({ expirationDate: '2025-06-01T00:00:00Z', id: 'urn:uuid:vc-expired' }),
    );
    const result = verifyPresentation(vpWith([expired]), {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]).toMatchObject({ valid: false, isExpired: true });
    expect(result.credentialResults[0]?.errors).toEqual(['3024']);
  });

  it('JSON-LD VC（object）は検証手段が無いため valid: false・3002（ldp_vc）', () => {
    const result = verifyPresentation(vpWith([sampleVc() as unknown as Record<string, unknown>]), {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.credentialResults[0]).toMatchObject({ valid: false, format: 'ldp_vc' });
    // 署名検証は一度も行っていないので、署名不正と読める 3010 ではなく未対応構造の 3002 を返す。
    expect(result.credentialResults[0]?.errors).toEqual(['3002']);
  });

  it('bbs-2023 の Data Integrity VC は valid: false・3002 で format: bbs+', () => {
    const result = verifyPresentation(vpWith([bbsVc()]), {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    // BBS+ 署名・BLS12-381 とも未実装。ldp_vc と同じ経路で落ちるが、診断上の format は実態に合わせる。
    expect(result.credentialResults[0]).toMatchObject({ valid: false, format: 'bbs+' });
    expect(result.credentialResults[0]?.errors).toEqual(['3002']);
    expect(result.valid).toBe(false);
  });

  it('COSE_Sign1 VC（文字列）は検証手段が無いため valid: false・3002（vc+cose）', () => {
    const result = verifyPresentation(vpWith([coseSign1Vc()]), {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.credentialResults[0]).toMatchObject({ valid: false, format: 'vc+cose' });
    // JWT-VC 経路へ落ちると「デコード不能」で 3010 になる。署名検証は行っていないので 3002。
    expect(result.credentialResults[0]?.errors).toEqual(['3002']);
  });

  // 旧契約（「検証すべき VC が無いので valid: true」）は 撤回した。`every([])` の
  // 空真により、何も証明しない提示が認可されていた。詳細は presentation.empty-credentials.test.ts。
  it('内包 VC が 0 件の VP は valid: false / 3002', () => {
    const result = verifyPresentation(vpWith([]), { ...holderKey, nowSeconds: NOW });
    expect(result.valid).toBe(false);
    expect(result.credentialResults).toEqual([]);
    expect(result.errors).toEqual(['3002']);
  });

  it('デコードできない内包 VC は 3010 で valid: false（例外にはしない）', () => {
    const result = verifyPresentation(vpWith(['not-a-jws']), {
      ...holderKey,
      nowSeconds: NOW,
      credentialKey: issuerKeyResolver,
    });
    expect(result.credentialResults[0]).toMatchObject({ valid: false, issuerDID: '' });
    expect(result.credentialResults[0]?.errors).toEqual(['3010']);
  });
});

describe('credentialKey DI の読み取り', () => {
  it('プロトタイプメソッドで実装したクラスベース DI を受理する（own 限定にしない）', () => {
    class VerifierDeps {
      credentialKey(): { readonly publicKeyJwk: (typeof ISSUER_KEY)['publicKeyJwk'] } {
        return ISSUER_KEY;
      }
    }
    const opts = Object.assign(new VerifierDeps(), {
      key: { publicKeyJwk: FIXTURES[HOLDER_ALG].jwk },
      allowUnbound: true,
      nowSeconds: NOW,
    });
    const result = verifyPresentation(vpWith([embeddedVc()]), opts);
    expect(result.valid).toBe(true);
  });

  it('Object.prototype.credentialKey の汚染は採用しない（fail-closed のまま）', () => {
    const jwt = vpWith([embeddedVc()]);
    // 汚染された「常に正しい鍵を返す」コールバックを拾うと、渡していない検証が成功に化ける。
    const result = withPollutedPrototype({ credentialKey: () => ISSUER_KEY }, () =>
      verifyPresentation(jwt, { ...holderKey, nowSeconds: NOW }),
    );
    expect(result.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3010']);
  });

  it('Object.prototype.issuerTrust の汚染は FC-11 の突合材料として採用しない', () => {
    const jwt = vpWith([embeddedVc()]);
    // 不成立チェーンを汚染値で注入されると、正当な VP が一律 5010 に落とされる（可用性攻撃）。
    const result = withPollutedPrototype(
      { issuerTrust: { trustChain: { valid: false, leaf: 'did:example:issuer' } } },
      () =>
        verifyPresentation(jwt, {
          ...holderKey,
          nowSeconds: NOW,
          credentialKey: issuerKeyResolver,
        }),
    );
    expect(result.valid).toBe(true);
  });

  it('Object.prototype.exp の汚染は内包 VC の isExpired を反転させない', () => {
    // `isExpired` は**失敗パスでのみ** payload から算出される。成功パスは常に false のリテラルなので、
    // 正しい鍵で成功させると汚染の有無に関わらず false になりトートロジーになる。そこで
    // 「`exp` を持たない VC」を「誤った鍵」で失敗させ、算出経路を必ず通す。
    const noExp = sampleVc();
    delete (noExp as { expirationDate?: string }).expirationDate;
    // holder 鍵（ES256）で署名した = 発行者 ES256K 鍵では検証できない → 3010 の失敗パスへ入る。
    const jwt = vpWith([embeddedVc(HOLDER_ALG, noExp)]);
    const result = withPollutedPrototype({ exp: NOW - 1 }, () =>
      verifyPresentation(jwt, {
        ...holderKey,
        nowSeconds: NOW,
        credentialKey: issuerKeyResolver,
      }),
    );
    expect(result.credentialResults[0]?.valid).toBe(false);
    expect(result.credentialResults[0]?.errors).toEqual(['3010']);
    // 鎖読みだと汚染値 `NOW - 1` を「VC の exp」として拾い isExpired が true に反転する。
    expect(result.credentialResults[0]?.isExpired).toBe(false);
  });

  it('Object.prototype.proof / cryptosuite の汚染は ldp_vc を bbs+ と表示させない', () => {
    // 診断ラベルの決定は外部入力 JSON を読むため、鎖読みすると `proof` を持たない VC・
    // `cryptosuite` を持たない proof が汚染値を拾い、`ldp_vc` が `bbs+` として報告される。
    const withoutProof = sampleVc() as unknown as Record<string, unknown>;
    const withoutCryptosuite = { ...sampleVc(), proof: { type: 'DataIntegrityProof' } };
    const jwt = vpWith([withoutProof, withoutCryptosuite]);
    const polluted = { proof: { cryptosuite: 'bbs-2023' }, cryptosuite: 'bbs-2023' };
    const result = withPollutedPrototype(polluted, () =>
      verifyPresentation(jwt, { ...holderKey, nowSeconds: NOW, credentialKey: issuerKeyResolver }),
    );
    expect(result.credentialResults.map((r) => r.format)).toEqual(['ldp_vc', 'ldp_vc']);
    // 拒否そのものはラベルに依存しない（どちらの経路でも未対応構造の 3002）。
    expect(result.credentialResults.map((r) => r.errors)).toEqual([['3002'], ['3002']]);
  });
});
