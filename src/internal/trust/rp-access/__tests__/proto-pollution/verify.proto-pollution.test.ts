/**
 * RP Access Certificate 検証オプションの `Object.prototype` 汚染耐性テスト。
 *
 * `options.now` をプロトタイプ鎖で読むと、`now` を**省略した**正当な検証でも汚染値が
 * 基準時刻として使われ、**有効期間を過ぎた RP Access Certificate が `valid` と判定される**
 * （＝失効した RP が属性を要求できてしまう）。`revokedSerials` / `intermediatesDer` も同様に
 * 「渡していないのに渡されたことになる」fail-open 読みであり、同一関数内で読み方を揃える。
 */

import { describe, expect, test } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes } from '../../../../errors.js';
import type { QtspServiceCertificate } from '../../../etsi-tsl/tsl.js';
import type { RequestedClaim } from '../../types.js';
import { verifyRpAccessCertificate } from '../../verify.js';
import { makeRpCertificate } from '../fixtures.js';

const okClaims: RequestedClaim[] = [
  { claimPath: 'family_name', purpose: 'identification', category: 'identification' },
];

/** 有効期間が既に過ぎた RP Access Certificate と、その発行 CA を組み立てる。 */
function expiredRpChain(): {
  certDer: Uint8Array;
  anchors: QtspServiceCertificate[];
  whenValid: number;
} {
  const notBefore = new Date(Date.now() - 30 * 86_400_000);
  const notAfter = new Date(Date.now() - 10 * 86_400_000);
  const ca = makeRpCertificate({
    kind: 'rsa',
    subject: { organizationName: 'EU Trusted RP CA', country: 'DE' },
  });
  const rp = makeRpCertificate({
    kind: 'ec',
    subject: {
      organizationName: 'Example Retailer',
      organizationIdentifier: 'VATDE-123456789',
      country: 'DE',
    },
    origin: 'https://rp.example.de',
    scope: {
      attributes: ['family_name'],
      purposes: ['identification'],
      categories: ['identification'],
    },
    notBefore,
    notAfter,
    issuer: { name: ca.subjectName, privateKey: ca.privateKey, kind: 'rsa' },
  });
  return {
    certDer: rp.der,
    anchors: [{ certDer: ca.der, granted: true }],
    whenValid: Math.floor((notBefore.getTime() + notAfter.getTime()) / 2000),
  };
}

describe('verifyRpAccessCertificate の時刻オプション汚染耐性', () => {
  test('継承した now では有効期間外の証明書を valid にしない', async () => {
    const { certDer, anchors, whenValid } = expiredRpChain();
    const result = await withPollutedPrototypeAsync({ now: whenValid }, () =>
      // now は渡していない。汚染値を拾えば「まだ有効」と判定されてしまう。
      verifyRpAccessCertificate({ certDer, requestedClaims: okClaims, trustAnchors: anchors }),
    );
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(ErrorCodes.RP_ACCESS_CERT_OUT_OF_VALIDITY);
  });

  test('継承した revokedSerials で「確認済み・失効なし」と報告しない', async () => {
    const { certDer, anchors } = expiredRpChain();
    const result = await withPollutedPrototypeAsync({ revokedSerials: new Set<string>() }, () =>
      // `revokedSerials` を渡していない ＝ 失効情報源が無く「未確認」が正。汚染値を拾うと
      // `checked: true` / `revoked: false` になり、**確認していないのに失効なしと報告**する。
      verifyRpAccessCertificate({ certDer, requestedClaims: okClaims, trustAnchors: anchors }),
    );
    expect(result.revocation.checked).toBe(false);
    expect(result.revocation.method).toBe('none');
  });

  test('明示的に渡した now は従来どおり基準時刻になる（正常系）', async () => {
    const { certDer, anchors, whenValid } = expiredRpChain();
    const result = await verifyRpAccessCertificate({
      certDer,
      requestedClaims: okClaims,
      trustAnchors: anchors,
      now: whenValid,
    });
    expect(result.errors).not.toContain(ErrorCodes.RP_ACCESS_CERT_OUT_OF_VALIDITY);
  });
});

/**
 * Root CA → 中間 CA → RP のチェーンを組み立てる（中間 CA を渡さないと Anchor へ到達しない形）。
 */
function chainedRpCertificates(): {
  certDer: Uint8Array;
  intermediateDer: Uint8Array;
  anchors: QtspServiceCertificate[];
} {
  const root = makeRpCertificate({
    kind: 'rsa',
    subject: { organizationName: 'EU Trusted Root CA', country: 'DE' },
  });
  const intermediate = makeRpCertificate({
    kind: 'rsa',
    subject: { organizationName: 'EU Trusted Issuing CA', country: 'DE' },
    // 中間 CA は basicConstraints で CA を名乗る必要がある（`etsi-tsl/chain.ts`）。
    ca: true,
    issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'rsa' },
  });
  const rp = makeRpCertificate({
    kind: 'ec',
    subject: {
      organizationName: 'Example Retailer',
      organizationIdentifier: 'VATDE-123456789',
      country: 'DE',
    },
    origin: 'https://rp.example.de',
    scope: {
      attributes: ['family_name'],
      purposes: ['identification'],
      categories: ['identification'],
    },
    issuer: { name: intermediate.subjectName, privateKey: intermediate.privateKey, kind: 'rsa' },
  });
  return {
    certDer: rp.der,
    intermediateDer: intermediate.der,
    anchors: [{ certDer: root.der, granted: true }],
  };
}

describe('verifyRpAccessCertificate の intermediatesDer 汚染耐性', () => {
  test('継承した intermediatesDer では中間 CA を渡していない検証を trusted にしない', async () => {
    const { certDer, intermediateDer, anchors } = chainedRpCertificates();
    const result = await withPollutedPrototypeAsync({ intermediatesDer: [intermediateDer] }, () =>
      // `intermediatesDer` を渡していない ＝ 中間 CA 抜きでは Anchor へ到達しないのが正。
      // 汚染値を拾うと攻撃者が選んだ中間 CA 集合が注入され、チェーンが成立してしまう。
      verifyRpAccessCertificate({ certDer, requestedClaims: okClaims, trustAnchors: anchors }),
    );
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(ErrorCodes.RP_ACCESS_CERT_SIG_INVALID);
    expect(result.trustChain).toEqual([]);
  });

  test('明示的に渡した intermediatesDer は従来どおりチェーン構築に使われる（正常系）', async () => {
    const { certDer, intermediateDer, anchors } = chainedRpCertificates();
    const result = await verifyRpAccessCertificate({
      certDer,
      requestedClaims: okClaims,
      trustAnchors: anchors,
      intermediatesDer: [intermediateDer],
    });
    expect(result.valid).toBe(true);
    expect(result.trustChain).toHaveLength(1);
  });
});
