import { describe, expect, test } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import type { QtspServiceCertificate } from '../../etsi-tsl/tsl.js';
import type { RequestedClaim } from '../types.js';
import { verifyRpAccessCertificate } from '../verify.js';
import { makeRpCertificate, type RpCertFixture } from './fixtures.js';

/** TSL の granted QTSP CA と、その CA が発行した RP Access Certificate を組み立てる。 */
function buildRpChain(overrides?: {
  scope?: { attributes?: string[]; purposes?: string[]; categories?: string[] };
  country?: string;
  notBefore?: Date;
  notAfter?: Date;
}): { ca: RpCertFixture; rp: RpCertFixture; anchors: QtspServiceCertificate[] } {
  const ca = makeRpCertificate({
    kind: 'rsa',
    subject: { organizationName: 'EU Trusted RP CA', country: 'DE' },
  });
  const rp = makeRpCertificate({
    kind: 'ec',
    subject: {
      organizationName: 'Example Retailer',
      organizationIdentifier: 'VATDE-123456789',
      country: overrides?.country ?? 'DE',
    },
    origin: 'https://rp.example.de',
    scope: overrides?.scope ?? {
      attributes: ['family_name', 'age_over_18'],
      purposes: ['identification', 'age_verification'],
      categories: ['identification', 'authorization'],
    },
    notBefore: overrides?.notBefore,
    notAfter: overrides?.notAfter,
    issuer: { name: ca.subjectName, privateKey: ca.privateKey, kind: 'rsa' },
  });
  const anchors: QtspServiceCertificate[] = [{ certDer: ca.der, granted: true }];
  return { ca, rp, anchors };
}

const okClaims: RequestedClaim[] = [
  { claimPath: 'family_name', purpose: 'identification', category: 'identification' },
  { claimPath: 'age_over_18', purpose: 'age_verification', category: 'authorization' },
];

describe('verifyRpAccessCertificate (TSL 連携)', () => {
  test('granted な TSL Trust Anchor へ連鎖し要求属性が認可されれば valid', async () => {
    const { rp, anchors } = buildRpChain();
    const result = await verifyRpAccessCertificate({
      certDer: rp.der,
      requestedClaims: okClaims,
      trustAnchors: anchors,
    });
    expect(result.valid).toBe(true);
    expect(result.rp.legalName).toBe('Example Retailer');
    expect(result.rp.country).toBe('DE');
    expect(result.rp.origin).toBe('https://rp.example.de');
    expect(result.claimAuthorization.every((c) => c.authorized)).toBe(true);
    expect(result.trustChain).toHaveLength(1);
    expect(result.trustChain[0]?.source).toBe('etsi-tsl');
    expect(result.trustChain[0]?.subject).toBe('Example Retailer');
    // issuer は発行 Anchor(CA) の legalName であり、RP の属性ではない。
    expect(result.trustChain[0]?.issuer).toBe('EU Trusted RP CA');
    // revokedSerials 未指定 = 失効情報源が無いので「未確認」。確認していない失効状態を
    // checked:true / trusted-list として主張しない。
    expect(result.revocation.checked).toBe(false);
    expect(result.revocation.method).toBe('none');
    expect(result.revocation.revoked).toBe(false);
    expect(result.crossBorderWarning).toBe(false);
  });

  test('Trust Anchor 集合に無い場合は署名検証失敗で invalid', async () => {
    const { rp } = buildRpChain();
    const other = makeRpCertificate({
      kind: 'rsa',
      subject: { organizationName: 'Unrelated CA', country: 'FR' },
    });
    const result = await verifyRpAccessCertificate({
      certDer: rp.der,
      requestedClaims: okClaims,
      trustAnchors: [{ certDer: other.der, granted: true }],
    });
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(ErrorCodes.RP_ACCESS_CERT_SIG_INVALID);
    expect(result.trustChain).toHaveLength(0);
  });

  test('Anchor が granted でない場合はチェーン不成立で invalid', async () => {
    const { rp, ca } = buildRpChain();
    const result = await verifyRpAccessCertificate({
      certDer: rp.der,
      requestedClaims: okClaims,
      // granted=false の Anchor は grantedTrustAnchors で除外されチェーンが成立しない。
      trustAnchors: [{ certDer: ca.der, granted: false }],
    });
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(ErrorCodes.RP_ACCESS_CERT_SIG_INVALID);
  });

  test('シリアルが失効集合にあれば revoked で invalid', async () => {
    const { rp, anchors } = buildRpChain();
    // rp フィクスチャの serial は既定 1 → serialHex '01'。
    const result = await verifyRpAccessCertificate({
      certDer: rp.der,
      requestedClaims: okClaims,
      trustAnchors: anchors,
      revokedSerials: new Set(['01']),
    });
    expect(result.valid).toBe(false);
    expect(result.revocation.checked).toBe(true);
    expect(result.revocation.revoked).toBe(true);
    expect(result.revocation.method).toBe('trusted-list');
    expect(result.errors).toContain(ErrorCodes.RP_ACCESS_CERT_REVOKED);
  });

  test('失効集合を渡し該当しなければ checked:true / revoked:false で確認済みを主張できる', async () => {
    const { rp, anchors } = buildRpChain();
    const result = await verifyRpAccessCertificate({
      certDer: rp.der,
      requestedClaims: okClaims,
      trustAnchors: anchors,
      // 失効集合は渡されているが当該シリアル（'01'）は含まれない = 確認した上で失効なし。
      revokedSerials: new Set(['ff']),
    });
    expect(result.valid).toBe(true);
    expect(result.revocation.checked).toBe(true);
    expect(result.revocation.revoked).toBe(false);
    expect(result.revocation.method).toBe('trusted-list');
  });

  test('revokedSerials 未指定では失効を確認済みと主張しない（checked:false / none）', async () => {
    const { rp, anchors } = buildRpChain();
    const result = await verifyRpAccessCertificate({
      certDer: rp.der,
      requestedClaims: okClaims,
      trustAnchors: anchors,
    });
    // 何も確認していないのに checked:true / 'trusted-list' を返すのは安全性の誤主張。
    expect(result.revocation.checked).toBe(false);
    expect(result.revocation.method).toBe('none');
    expect(result.revocation.revoked).toBe(false);
  });

  test('要求属性がスコープ外なら scope violation で invalid', async () => {
    const { rp, anchors } = buildRpChain();
    const result = await verifyRpAccessCertificate({
      certDer: rp.der,
      requestedClaims: [
        { claimPath: 'given_name', purpose: 'identification', category: 'identification' },
      ],
      trustAnchors: anchors,
    });
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(ErrorCodes.RP_ACCESS_SCOPE_VIOLATION);
    expect(result.claimAuthorization[0]?.authorized).toBe(false);
  });

  test('有効期間外の証明書は out-of-validity で invalid', async () => {
    const past = new Date(Date.now() - 2 * 86_400_000);
    const { rp, anchors } = buildRpChain({
      notBefore: new Date(Date.now() - 3 * 86_400_000),
      notAfter: past,
    });
    const result = await verifyRpAccessCertificate({
      certDer: rp.der,
      requestedClaims: okClaims,
      trustAnchors: anchors,
    });
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(ErrorCodes.RP_ACCESS_CERT_OUT_OF_VALIDITY);
    // 早期 return する経路でも失効は未確認のまま。checked:true と主張しない。
    expect(result.revocation.checked).toBe(false);
    expect(result.revocation.method).toBe('none');
  });

  test('第三国 RP には Cross-border 警告が付く', async () => {
    const { rp, anchors } = buildRpChain({ country: 'US' });
    const result = await verifyRpAccessCertificate({
      certDer: rp.der,
      requestedClaims: okClaims,
      trustAnchors: anchors,
    });
    expect(result.crossBorderWarning).toBe(true);
    expect(result.errors).toContain(ErrorCodes.RP_CROSS_BORDER_WARNING);
  });

  test('パース不能な DER は invalid（署名検証失敗コード）', async () => {
    const result = await verifyRpAccessCertificate({
      certDer: new Uint8Array([0x00, 0x01, 0x02]),
      requestedClaims: okClaims,
      trustAnchors: [],
    });
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(ErrorCodes.RP_ACCESS_CERT_SIG_INVALID);
    expect(result.claimAuthorization.every((c) => !c.authorized)).toBe(true);
  });

  test.each([
    Number.NaN,
    Number.POSITIVE_INFINITY,
  ])('非有限の now（%p）は RangeError でなく RP_ACCESS_CERT_OUT_OF_VALIDITY の invalid', async (now) => {
    const { rp, anchors } = buildRpChain();
    const result = await verifyRpAccessCertificate({
      certDer: rp.der,
      requestedClaims: okClaims,
      trustAnchors: anchors,
      now,
    });
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(ErrorCodes.RP_ACCESS_CERT_OUT_OF_VALIDITY);
    expect(result.claimAuthorization.every((c) => !c.authorized)).toBe(true);
  });
});
