/**
 * `verifyJarSignature` が OpenID Federation Trust Chain / ARF Trust Anchor Catalogue を x5c チェーンの
 * 信頼起点として受け付けることの回帰テスト。
 *
 * `evaluateTrust`（trust/arf）への統合により、TSL 単独の既存経路（jar-signature.trust.test.ts）に
 * 加えて OIDF / ARF のいずれか 1 つでも起点が確認できれば受理されること、いずれにも到達しなければ
 * 拒否されること、上位層（TSL）が REVOKED の場合は fail-closed で拒否されること（
 * 明示拒否ポリシーが JAR 経路にも効くこと）を確かめる。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import { spkiToBase64 } from '../../../trust/arf/__tests__/arf-fixtures.js';
import { parseCertificate } from '../../../trust/etsi-tsl/index.js';
import {
  makeFetchMock,
  nowFn,
  signStatement,
  toJwk,
  validPeriod,
} from '../../../trust/federation/__tests__/federation-fixtures.js';
import { verifyJarSignature } from '../jar-signature.js';
import { buildArfTrustAnchor } from './arf-trust-anchor-fixtures.js';
import { CLIENT_ID, makeJarSigner, signJar, toX5cEntry } from './jar-fixtures.js';

const VERIFIER = makeJarSigner();

async function expectReason(promise: Promise<unknown>, reason: string): Promise<void> {
  try {
    await promise;
    throw new Error('should have thrown');
  } catch (err) {
    const error = err as VericertsError;
    expect(error.code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    expect(error.context).toMatchObject({ reason });
  }
}

/**
 * Leaf（`CLIENT_ID`）が自身の Trust Anchor である退化ケースの Federation トポロジを組み立てる
 * （`buildTrustChain(entityId, trustAnchor)` の `entityId === trustAnchor` 分岐。1 段チェーンで
 * 済むため中間 / Trust Anchor エンティティを別途用意する必要が無い）。
 *
 * @param embedX5c leaf の JWK に JAR 署名者証明書の `x5c`（RFC 7517 §4.7）を埋め込むか。
 */
function buildSelfAnchoredFederation(embedX5c: boolean): Map<string, string> {
  const leafKey = new Uint8Array(32).fill(31);
  const jwk = toJwk(leafKey, 'leaf-1');
  const key = embedX5c ? { ...jwk, x5c: [toX5cEntry(VERIFIER.rp.der)] } : jwk;
  const ec = signStatement(
    leafKey,
    { iss: CLIENT_ID, sub: CLIENT_ID, ...validPeriod(), jwks: { keys: [key] } },
    { kid: 'leaf-1' },
  );
  const responses = new Map<string, string>();
  responses.set(`${CLIENT_ID}/.well-known/openid-federation`, ec);
  return responses;
}

describe('verifyJarSignature: ARF Trust Anchor Catalogue 経由', () => {
  it('ARF Catalogue に leaf の SPKI が登録されていれば受理する', async () => {
    const spki = parseCertificate(VERIFIER.rp.der).spki;
    const arfTrustAnchor = await buildArfTrustAnchor([
      { id: CLIENT_ID, role: 'relying-party', spki: spkiToBase64(spki) },
    ]);
    await expect(
      verifyJarSignature(signJar(VERIFIER), { trustAnchors: [], arfTrustAnchor }),
    ).resolves.toBeUndefined();
  });

  it('ARF Catalogue に一致するエントリが無ければ拒否する', async () => {
    const arfTrustAnchor = await buildArfTrustAnchor([]);
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), { trustAnchors: [], arfTrustAnchor }),
      'rp_cert_untrusted',
    );
  });
});

describe('verifyJarSignature: OpenID Federation Trust Chain 経由', () => {
  it('Trust Chain が成立し、leaf の jwks に x5c を埋め込む鍵があれば受理する', async () => {
    const responses = buildSelfAnchoredFederation(true);
    await expect(
      verifyJarSignature(signJar(VERIFIER), {
        trustAnchors: [],
        expectedClientId: CLIENT_ID,
        federationTrustAnchor: {
          trustAnchorEntityId: CLIENT_ID,
          deps: { fetchFn: makeFetchMock(responses), now: nowFn },
        },
      }),
    ).resolves.toBeUndefined();
  });

  it('Trust Chain が成立しても x5c を埋め込む鍵が無ければ拒否する', async () => {
    const responses = buildSelfAnchoredFederation(false);
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), {
        trustAnchors: [],
        expectedClientId: CLIENT_ID,
        federationTrustAnchor: {
          trustAnchorEntityId: CLIENT_ID,
          deps: { fetchFn: makeFetchMock(responses), now: nowFn },
        },
      }),
      'rp_cert_untrusted',
    );
  });

  it('expectedClientId が無ければ OIDF 層を評価せず拒否する（SSRF 回避。federationTrustAnchor を渡しても素通りしない）', async () => {
    const responses = buildSelfAnchoredFederation(true);
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), {
        trustAnchors: [],
        federationTrustAnchor: {
          trustAnchorEntityId: CLIENT_ID,
          deps: { fetchFn: makeFetchMock(responses), now: nowFn },
        },
      }),
      'rp_cert_untrusted',
    );
  });
});

describe('verifyJarSignature: いずれの層にも到達しない場合は拒否する', () => {
  it('TSL / OIDF / ARF をすべて設定してもいずれにも到達しなければ拒否する', async () => {
    const foreign = makeJarSigner();
    const arfTrustAnchor = await buildArfTrustAnchor([]);
    const responses = buildSelfAnchoredFederation(false);
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), {
        trustAnchors: foreign.anchors,
        arfTrustAnchor,
        expectedClientId: CLIENT_ID,
        federationTrustAnchor: {
          trustAnchorEntityId: CLIENT_ID,
          deps: { fetchFn: makeFetchMock(responses), now: nowFn },
        },
      }),
      'rp_cert_untrusted',
    );
  });
});

describe('verifyJarSignature: ARF 層の identity binding', () => {
  it('SPKI が一致しても entry.id が証明書の origin と異なれば拒否する（なりすまし防止）', async () => {
    const spki = parseCertificate(VERIFIER.rp.der).spki;
    // `id` は Catalogue に登録された別エンティティの識別子。SPKI（署名鍵）だけ一致させても、
    // SAN の origin（`CLIENT_ID`）とは異なるため受理してはならない。
    const arfTrustAnchor = await buildArfTrustAnchor([
      { id: 'https://unrelated-entity.example', role: 'relying-party', spki: spkiToBase64(spki) },
    ]);
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), { trustAnchors: [], arfTrustAnchor }),
      'rp_cert_untrusted',
    );
  });

  it('entry.id が origin と一致しても expectedClientId と食い違えば拒否する', async () => {
    const spki = parseCertificate(VERIFIER.rp.der).spki;
    const arfTrustAnchor = await buildArfTrustAnchor([
      { id: CLIENT_ID, role: 'relying-party', spki: spkiToBase64(spki) },
    ]);
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), {
        trustAnchors: [],
        arfTrustAnchor,
        expectedClientId: 'https://different-deep-link.example',
      }),
      'rp_cert_untrusted',
    );
  });

  it('entry.id が origin にも expectedClientId にも一致すれば受理する', async () => {
    const spki = parseCertificate(VERIFIER.rp.der).spki;
    const arfTrustAnchor = await buildArfTrustAnchor([
      { id: CLIENT_ID, role: 'relying-party', spki: spkiToBase64(spki) },
    ]);
    await expect(
      verifyJarSignature(signJar(VERIFIER), {
        trustAnchors: [],
        arfTrustAnchor,
        expectedClientId: CLIENT_ID,
      }),
    ).resolves.toBeUndefined();
  });
});

describe('verifyJarSignature: ARF 層の role 絞り込み', () => {
  it.each([
    'wallet-provider',
    'issuer',
    'attestation-provider',
  ] as const)('SPKI・origin が一致しても role が %s なら ARF 層は受理しない', async (role) => {
    const spki = parseCertificate(VERIFIER.rp.der).spki;
    // SPKI・id↔origin の一致条件はすべて満たすが、role が `relying-party` ではない
    // （Wallet Provider / Issuer / Attestation Provider として登録されたエンティティが
    // Verifier になりすませないことを確かめる）。
    const arfTrustAnchor = await buildArfTrustAnchor([
      { id: CLIENT_ID, role, spki: spkiToBase64(spki) },
    ]);
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), { trustAnchors: [], arfTrustAnchor }),
      'rp_cert_untrusted',
    );
  });

  it('role が relying-party のエントリのみが登録されていれば受理する', async () => {
    const spki = parseCertificate(VERIFIER.rp.der).spki;
    const arfTrustAnchor = await buildArfTrustAnchor([
      { id: 'https://unrelated-issuer.example', role: 'issuer', spki: spkiToBase64(spki) },
      { id: CLIENT_ID, role: 'relying-party', spki: spkiToBase64(spki) },
    ]);
    await expect(
      verifyJarSignature(signJar(VERIFIER), { trustAnchors: [], arfTrustAnchor }),
    ).resolves.toBeUndefined();
  });
});

describe('verifyJarSignature: OIDF/ARF 層の有効期間・失効検査', () => {
  it('ARF Catalogue に登録済みでも証明書が有効期間外なら拒否する', async () => {
    const expired = makeJarSigner({ notAfter: new Date(Date.now() - 86_400_000) });
    const spki = parseCertificate(expired.rp.der).spki;
    const arfTrustAnchor = await buildArfTrustAnchor([
      { id: CLIENT_ID, role: 'relying-party', spki: spkiToBase64(spki) },
    ]);
    await expectReason(
      verifyJarSignature(signJar(expired), { trustAnchors: [], arfTrustAnchor }),
      'rp_cert_untrusted',
    );
  });

  it('ARF Catalogue に登録済みでも証明書のシリアルが失効集合にあれば拒否する', async () => {
    const spki = parseCertificate(VERIFIER.rp.der).spki;
    const arfTrustAnchor = await buildArfTrustAnchor([
      { id: CLIENT_ID, role: 'relying-party', spki: spkiToBase64(spki) },
    ]);
    // フィクスチャの RP 証明書はシリアル 101 = 16 進 `65`（jar-signature.trust.test.ts と同じ）。
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), {
        trustAnchors: [],
        arfTrustAnchor,
        revokedSerials: new Set(['65']),
      }),
      'rp_cert_untrusted',
    );
  });

  it('Federation Trust Chain が成立しても証明書が有効期間外なら拒否する', async () => {
    const expired = makeJarSigner({ notAfter: new Date(Date.now() - 86_400_000) });
    const leafKey = new Uint8Array(32).fill(31);
    const jwk = { ...toJwk(leafKey, 'leaf-1'), x5c: [toX5cEntry(expired.rp.der)] };
    const ec = signStatement(
      leafKey,
      { iss: CLIENT_ID, sub: CLIENT_ID, ...validPeriod(), jwks: { keys: [jwk] } },
      { kid: 'leaf-1' },
    );
    const responses = new Map<string, string>();
    responses.set(`${CLIENT_ID}/.well-known/openid-federation`, ec);
    await expectReason(
      verifyJarSignature(signJar(expired), {
        trustAnchors: [],
        expectedClientId: CLIENT_ID,
        federationTrustAnchor: {
          trustAnchorEntityId: CLIENT_ID,
          deps: { fetchFn: makeFetchMock(responses), now: nowFn },
        },
      }),
      'rp_cert_untrusted',
    );
  });

  it('Federation Trust Chain が成立しても証明書のシリアルが失効集合にあれば拒否する', async () => {
    const responses = buildSelfAnchoredFederation(true);
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), {
        trustAnchors: [],
        expectedClientId: CLIENT_ID,
        revokedSerials: new Set(['65']),
        federationTrustAnchor: {
          trustAnchorEntityId: CLIENT_ID,
          deps: { fetchFn: makeFetchMock(responses), now: nowFn },
        },
      }),
      'rp_cert_untrusted',
    );
  });
});

describe('verifyJarSignature: 上位層 REVOKED による fail-closed 拒否', () => {
  it('TSL が失効していれば、OIDF が PASS でも下位を採用せず明示的に拒否する', async () => {
    const responses = buildSelfAnchoredFederation(true);
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), {
        // フィクスチャの RP 証明書はシリアル 101 = 16 進 `65`（jar-signature.trust.test.ts と同じ）。
        trustAnchors: VERIFIER.anchors,
        revokedSerials: new Set(['65']),
        expectedClientId: CLIENT_ID,
        federationTrustAnchor: {
          trustAnchorEntityId: CLIENT_ID,
          deps: { fetchFn: makeFetchMock(responses), now: nowFn },
        },
      }),
      'rp_cert_untrusted',
    );
  });
});
