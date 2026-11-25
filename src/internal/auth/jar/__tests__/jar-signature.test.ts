/**
 * `verifyJarSignature` の回帰テスト
 * ―― 正常系と JWS 署名検証。
 *
 * 従来、`fetchJAR` / `parsePresentationRequest` は取得した Request Object の署名を
 * 検証せずに解析していた。`request_uri` は deep link / QR 由来 = 攻撃者が値を選べる URL なので、
 * 攻撃者は自分のホストに `request_uri` を向け、Request Object 内の `client_id` と `response_uri`
 * を自分のドメインで揃えるだけで**任意の提示要求を注入できた**。本ファイルはその穴が塞がった
 * ことを固定する。`x5c` / Trust Anchor / alg 許可リストは `jar-signature.trust.test.ts`、
 * 発行者同一性は `jar-signature.identity.test.ts` が担う（Linterly の 1 ファイル上限）。
 */

import { describe, expect, it } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import { makeCertificate } from '../../../trust/etsi-tsl/__tests__/fixtures.js';
import { makeRpCertificate } from '../../../trust/rp-access/__tests__/fixtures.js';
import { verifyJarSignature } from '../jar-signature.js';
import { CLIENT_ID, jarClaims, makeJarSigner, signJar, toX5cEntry } from './jar-fixtures.js';

const VERIFIER = makeJarSigner();
const TRUST = { trustAnchors: VERIFIER.anchors } as const;

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

describe('verifyJarSignature: 正常系', () => {
  it('RP Access Certificate 鍵で署名された JAR を受理する（ES256）', async () => {
    await expect(verifyJarSignature(signJar(VERIFIER), TRUST)).resolves.toBeUndefined();
  });

  it('RS256（sha256WithRSAEncryption の RP 証明書）も受理する', async () => {
    const rsa = makeJarSigner({ kind: 'rsa' });
    await expect(
      verifyJarSignature(signJar(rsa), { trustAnchors: rsa.anchors }),
    ).resolves.toBeUndefined();
  });

  it('中間 CA 経由のチェーンも Trust Anchor へ到達すれば受理する', async () => {
    const root = makeRpCertificate({
      subject: { organizationName: 'Root CA', country: 'DE' },
      kind: 'ec',
      serial: 1,
    });
    const intermediate = makeRpCertificate({
      subject: { organizationName: 'Intermediate CA', country: 'DE' },
      kind: 'ec',
      serial: 2,
      // 中間 CA は basicConstraints で CA を名乗る必要がある（`etsi-tsl/chain.ts`）。
      ca: true,
      issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'ec' },
    });
    const leaf = makeRpCertificate({
      subject: { organizationName: 'Example Verifier', country: 'DE' },
      kind: 'ec',
      origin: CLIENT_ID,
      serial: 3,
      issuer: { name: intermediate.subjectName, privateKey: intermediate.privateKey, kind: 'ec' },
    });
    const chained = {
      ca: root,
      rp: leaf,
      anchors: [{ certDer: root.der, granted: true }],
      kind: 'ec' as const,
    };
    const jar = signJar(chained, {
      header: { x5c: [toX5cEntry(leaf.der), toX5cEntry(intermediate.der)] },
    });
    await expect(
      verifyJarSignature(jar, { trustAnchors: chained.anchors }),
    ).resolves.toBeUndefined();
  });

  it('expectedClientId が deep link と Request Object で一致すれば受理する', async () => {
    await expect(
      verifyJarSignature(signJar(VERIFIER), { ...TRUST, expectedClientId: CLIENT_ID }),
    ).resolves.toBeUndefined();
  });
});

describe('verifyJarSignature: 署名検証', () => {
  it('署名を保ったままペイロードを差し替えた JAR を拒否する', async () => {
    // 攻撃者が正当な Request Object の `response_uri` / `dcql_query` だけを書き換える形。
    const tampered = signJar(VERIFIER, {
      tamperedClaims: jarClaims({ nonce: 'attacker-nonce' }),
    });
    await expectReason(verifyJarSignature(tampered, TRUST), 'jar_signature_invalid');
  });

  it('別鍵で署名された JAR を拒否する（証明書は正当・署名だけ他人）', async () => {
    const other = makeJarSigner();
    // `x5c` は VERIFIER の証明書（Trust Anchor へ到達する）だが、署名は別鍵。
    const jar = signJar(
      { ...other, rp: { ...other.rp } },
      { header: { x5c: [toX5cEntry(VERIFIER.rp.der)] } },
    );
    await expectReason(verifyJarSignature(jar, TRUST), 'jar_signature_invalid');
  });

  it('署名部分が空の JWS を拒否する（無署名の Request Object）', async () => {
    // 3 セグメントに見えても署名が空なら JWS として不正であり、`decodeCompactJwsOrThrow` が
    // 8030 へ正規化する（`reason` は付かない = 形式不正であって検証結果ではない）。
    const signed = signJar(VERIFIER);
    const [header, payload] = signed.split('.') as [string, string, string];
    await expect(verifyJarSignature(`${header}.${payload}.`, TRUST)).rejects.toMatchObject({
      code: ErrorCodes.OID4VP_REQUEST_PARSE_FAILED,
    });
  });

  it('JWS として不正な本文は 8030 へ正規化される', async () => {
    await expect(verifyJarSignature('not-a-jws', TRUST)).rejects.toMatchObject({
      code: ErrorCodes.OID4VP_REQUEST_PARSE_FAILED,
    });
  });
});

describe('verifyJarSignature: RS256 の署名鍵長', () => {
  /** 指定ビット長の RSA 鍵を持つ RP 証明書（正当な CA が発行）で RS256 署名した JAR を組む。 */
  function rsaSignerWithKeyBits(modulusLength: number): ReturnType<typeof makeJarSigner> {
    const base = makeJarSigner({ kind: 'rsa' });
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength });
    const rp = makeCertificate({
      cn: 'Example Verifier',
      kind: 'rsa',
      subjectKey: privateKey,
      sanUris: [CLIENT_ID],
      issuer: { name: base.ca.subjectName, privateKey: base.ca.privateKey, kind: 'rsa' },
    });
    return { ...base, rp };
  }

  it('2048bit の RP 鍵で署名した RS256 JAR は受理する（対照）', async () => {
    const signer = rsaSignerWithKeyBits(2048);
    await expect(
      verifyJarSignature(signJar(signer), { trustAnchors: signer.anchors }),
    ).resolves.toBeUndefined();
  });

  it('1024bit の RP 鍵で署名した RS256 JAR は、署名が正しくても 8030 で拒否する', async () => {
    const signer = rsaSignerWithKeyBits(1024);
    await expectReason(
      verifyJarSignature(signJar(signer), { trustAnchors: signer.anchors }),
      'jar_signature_invalid',
    );
  });
});

describe('verifyJarSignature: 秘密の非漏洩', () => {
  it('例外に証明書・JWT・cause を含めない', async () => {
    const tampered = signJar(VERIFIER, {
      tamperedClaims: jarClaims({ state: 'secret-state-value' }),
    });
    try {
      await verifyJarSignature(tampered, TRUST);
      throw new Error('should have thrown');
    } catch (err) {
      const error = err as VericertsError;
      const dump = JSON.stringify({ message: error.message, context: error.context });
      expect(dump).not.toContain('secret-state-value');
      expect(dump).not.toContain('MII');
      expect(error.cause).toBeUndefined();
    }
  });
});
