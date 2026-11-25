/**
 * `verifyCertificateChain` が leaf の keyUsage を検査すること（RFC 5280 §4.2.1.3）。
 *
 * leaf の公開鍵は必ず JWS 署名の検証鍵として使われる（`wallet/issuer-trust/x5c.ts` の Issuer 鍵解決・
 * `trust/rp-access/verify.ts`・`auth/jar/jar-trust-evaluation.ts`）。CA が「この鍵で任意のデータに
 * 署名してはならない」と keyUsage に書いた証明書を通すと、その用途違反をチェーン検証が追認する。
 * ここでは「データ署名を許さない leaf が落ちること」と、真正な証明書を巻き添えにしないこと
 * （`nonRepudiation` だけの eIDAS 署名用 Qualified 証明書・keyUsage 拡張を持たない証明書）を固定する。
 *
 * ビット位置そのものの解釈は `trust/x509/__tests__/ca-constraints.test.ts` が直接確かめる。
 * `chain.test.ts` と分けてあるのは 1 ファイル 300 行の上限に収めるためで、対象関数は同じである。
 */

import { describe, expect, test } from 'bun:test';
import { verifyCertificateChain } from '../../chain.js';
import { type CertExtensionOptions, type CertFixture, makeCertificate } from '../fixtures.js';

/** keyUsage に立てるビットの指定（省略すると keyUsage 拡張そのものを付けない）。 */
type KeyUsage = CertExtensionOptions['keyUsage'];

/** ec 鍵で署名する発行者情報。 */
function issuerOf(cert: CertFixture): {
  name: number[];
  privateKey: CertFixture['privateKey'];
  kind: 'ec';
} {
  return { name: cert.subjectName, privateKey: cert.privateKey, kind: 'ec' };
}

/** root(anchor) ← interCA ← leaf のチェーンを組んで `verifyCertificateChain` に通す。 */
async function trusts(opts: {
  readonly leafKeyUsage?: KeyUsage;
  readonly interKeyUsage?: KeyUsage;
}): Promise<boolean> {
  const root = makeCertificate({ cn: 'Root CA', kind: 'ec', ca: true });
  const inter = makeCertificate({
    cn: 'Intermediate CA',
    kind: 'ec',
    ca: true,
    keyUsage: opts.interKeyUsage ?? ['keyCertSign'],
    issuer: issuerOf(root),
  });
  const leaf = makeCertificate({
    cn: 'QTSP Issuer',
    kind: 'ec',
    ...(opts.leafKeyUsage === undefined ? {} : { keyUsage: opts.leafKeyUsage }),
    issuer: issuerOf(inter),
  });
  const result = await verifyCertificateChain(leaf.der, [inter.der], {
    trustAnchorsDer: [root.der],
  });
  return result.trusted;
}

describe('verifyCertificateChain（leaf の keyUsage）', () => {
  test('keyUsage が keyEncipherment だけの leaf のチェーンは信頼しない', async () => {
    // 鍵交換専用と宣言された鍵。署名検証鍵として使うのは CA の意図に反する。
    expect(await trusts({ leafKeyUsage: ['keyEncipherment'] })).toBe(false);
  });

  test('keyUsage が keyCertSign だけの leaf のチェーンは信頼しない', async () => {
    // 証明書への署名だけを許された鍵。JWS のような任意データへの署名は許されていない。
    expect(await trusts({ leafKeyUsage: ['keyCertSign'] })).toBe(false);
  });

  test('keyUsage が digitalSignature の leaf は信頼する（正常系）', async () => {
    expect(await trusts({ leafKeyUsage: ['digitalSignature'] })).toBe(true);
  });

  test('keyUsage が nonRepudiation だけの leaf は信頼する（正常系）', async () => {
    // eIDAS の署名用 Qualified 証明書は nonRepudiation だけを立てるものが普通にある。
    expect(await trusts({ leafKeyUsage: ['nonRepudiation'] })).toBe(true);
  });

  test('keyUsage 拡張を持たない leaf は信頼する（正常系）', async () => {
    // keyUsage は任意拡張。無ければ用途の制限は無い（RFC 5280 §4.2.1.3）。
    expect(await trusts({})).toBe(true);
  });

  test('中間証明書に digitalSignature が無くてもチェーンは信頼する（leaf だけの検査）', async () => {
    // 中間の用途は keyCertSign で既に見ている。データ署名の可否を中間にも課すと、
    // 証明書発行専用に keyUsage を絞った真正な CA が落ちる。
    expect(
      await trusts({ leafKeyUsage: ['digitalSignature'], interKeyUsage: ['keyCertSign'] }),
    ).toBe(true);
  });
});
