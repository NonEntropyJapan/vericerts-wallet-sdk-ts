/**
 * `verifyJarSignature` の回帰テスト ―― `x5c` 抽出・Trust Anchor 到達・alg 許可リスト。
 *
 * 検証の入口（どの証明書を信頼の起点とし、どの署名方式を受け入れるか）を固定する。署名そのものの
 * 検証は `jar-signature.test.ts`、発行者同一性は `jar-signature.identity.test.ts` が担う。
 */

import { describe, expect, it } from 'bun:test';
import { base64 } from '@scure/base';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import { verifyJarSignature } from '../jar-signature.js';
import { makeJarSigner, signJar } from './jar-fixtures.js';

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

describe('verifyJarSignature: x5c と Trust Anchor', () => {
  it('x5c を持たない JAR を拒否する', async () => {
    await expectReason(
      verifyJarSignature(signJar(VERIFIER, { omitX5c: true }), TRUST),
      'missing_x5c',
    );
  });

  it('x5c が空配列の JAR を拒否する', async () => {
    await expectReason(
      verifyJarSignature(signJar(VERIFIER, { header: { x5c: [] } }), TRUST),
      'missing_x5c',
    );
  });

  it('x5c の要素が base64 でなければ拒否する', async () => {
    await expectReason(
      verifyJarSignature(signJar(VERIFIER, { header: { x5c: ['*** not base64 ***'] } }), TRUST),
      'missing_x5c',
    );
  });

  it('x5c が base64url（`-` / `_`）で符号化されていれば拒否する（RFC 7515 §4.1.6 は標準 base64）', async () => {
    const urlish = base64.encode(VERIFIER.rp.der).replace(/\+/g, '-').replace(/\//g, '_');
    // `+` / `/` を含まない DER では差が出ないため、差が出る場合のみ意味のある検査になる。
    if (urlish !== base64.encode(VERIFIER.rp.der)) {
      await expectReason(
        verifyJarSignature(signJar(VERIFIER, { header: { x5c: [urlish] } }), TRUST),
        'missing_x5c',
      );
    }
  });

  it('Trust Anchor が渡されなければ拒否する（fail-closed / 検証していないものを通さない）', async () => {
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), {} as Parameters<typeof verifyJarSignature>[1]),
      'jar_trust_anchors_unconfigured',
    );
  });

  it('Trust Anchor が空配列なら拒否する', async () => {
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), { trustAnchors: [] }),
      'jar_trust_anchors_unconfigured',
    );
  });

  it('Trust Anchor へ到達しない x5c を拒否する（無関係な CA を渡す）', async () => {
    const foreign = makeJarSigner();
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), { trustAnchors: foreign.anchors }),
      'rp_cert_untrusted',
    );
  });

  it('granted でない Trust Anchor は信頼の起点にしない（TSL の Trusted List Status）', async () => {
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), {
        trustAnchors: [{ certDer: VERIFIER.ca.der, granted: false }],
      }),
      'rp_cert_untrusted',
    );
  });

  it('有効期間外の RP 証明書を拒否する', async () => {
    const expired = makeJarSigner({ notAfter: new Date(Date.now() - 86_400_000) });
    await expectReason(
      verifyJarSignature(signJar(expired), { trustAnchors: expired.anchors }),
      'rp_cert_untrusted',
    );
  });

  it('失効した RP 証明書を拒否する（Trusted List Status の失効集合）', async () => {
    // フィクスチャの RP 証明書はシリアル 101 = 16 進 `65`。
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), { ...TRUST, revokedSerials: new Set(['65']) }),
      'rp_cert_untrusted',
    );
  });
});

describe('verifyJarSignature: alg 許可リスト', () => {
  it('alg=none を拒否する', async () => {
    await expectReason(
      verifyJarSignature(signJar(VERIFIER, { header: { alg: 'none' } }), TRUST),
      'unsupported_jar_alg',
    );
  });

  it('MAC（HS256）を拒否する', async () => {
    await expectReason(
      verifyJarSignature(signJar(VERIFIER, { header: { alg: 'HS256' } }), TRUST),
      'unsupported_jar_alg',
    );
  });

  it('alg を持たないヘッダを拒否する', async () => {
    const jar = signJar(VERIFIER, { header: { alg: undefined } });
    await expectReason(verifyJarSignature(jar, TRUST), 'unsupported_jar_alg');
  });

  it('Verifier metadata の request_object_signing_alg_values_supported に無い alg を拒否する', async () => {
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), {
        ...TRUST,
        requestObjectSigningAlgValuesSupported: ['RS256'],
      }),
      'jar_alg_not_advertised',
    );
  });

  it('告知リストが配列でなければ拒否する（照合できないものを素通りさせない）', async () => {
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), {
        ...TRUST,
        requestObjectSigningAlgValuesSupported: 'ES256' as unknown as readonly string[],
      }),
      'jar_alg_not_advertised',
    );
  });

  it('告知リストに非文字列が混ざっていれば拒否する', async () => {
    await expectReason(
      verifyJarSignature(signJar(VERIFIER), {
        ...TRUST,
        requestObjectSigningAlgValuesSupported: ['ES256', 42] as unknown as readonly string[],
      }),
      'jar_alg_not_advertised',
    );
  });

  it('告知された alg と一致すれば受理する', async () => {
    await expect(
      verifyJarSignature(signJar(VERIFIER), {
        ...TRUST,
        requestObjectSigningAlgValuesSupported: ['ES256', 'RS256'],
      }),
    ).resolves.toBeUndefined();
  });
});
