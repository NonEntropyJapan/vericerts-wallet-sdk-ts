/**
 * `verifyCertificateChain` の nameConstraints 検証（RFC 5280 §4.2.1.10 / §6.1.4 (g)）。
 *
 * 発行できる名前空間を限定した中間 CA でも、制約を読まなければ範囲外の leaf を発行できてしまう。
 * ここでは「制約の外に出たチェーンが落ちること」と「評価できない制約・名前は拒否側に倒れること」を
 * 固定する。値の解釈そのもの（文字列型の違いを吸収する正規化・URI base の一致規則）は
 * `trust/x509/__tests__/name-constraints.test.ts` が直接確かめる。
 *
 * `chain.test.ts` と分けてあるのは 1 ファイル 300 行の上限に収めるためで、対象関数は同じである。
 */

import { describe, expect, test } from 'bun:test';
import { MAX_NAME_CONSTRAINT_ENTRIES } from '../../../x509/name-constraints.js';
import { verifyCertificateChain } from '../../chain.js';
import { type CertFixture, makeCertificate, type NameConstraintsFixture } from '../fixtures.js';

/** root(anchor) ← interCA(nameConstraints) ← [subCA] ← leaf のチェーンを組む条件。 */
interface ChainOptions {
  /** 中間 CA が配下へ課す名前制約（省略すると拡張そのものを付けない）。 */
  readonly nameConstraints?: NameConstraintsFixture;
  /** leaf の subject CN。 */
  readonly leafCn?: string;
  /** leaf の URI SAN。 */
  readonly leafSanUris?: readonly string[];
  /** leaf の dNSName SAN（評価規約を持たない種別）。 */
  readonly leafSanDnsNames?: readonly string[];
  /** 指定すると中間 CA の下にさらに sub-CA を 1 段挟む（その CN）。 */
  readonly subCaCn?: string;
}

/** ec 鍵で署名する発行者情報。 */
function issuerOf(cert: CertFixture): {
  name: number[];
  privateKey: CertFixture['privateKey'];
  kind: 'ec';
} {
  return { name: cert.subjectName, privateKey: cert.privateKey, kind: 'ec' };
}

/** チェーンを組んで `verifyCertificateChain` に通す。 */
async function trusts(opts: ChainOptions): Promise<boolean> {
  const root = makeCertificate({ cn: 'Root CA', kind: 'ec' });
  const inter = makeCertificate({
    cn: 'Intermediate CA',
    kind: 'ec',
    ca: true,
    keyUsage: ['keyCertSign'],
    nameConstraints: opts.nameConstraints,
    issuer: issuerOf(root),
  });
  const intermediates: CertFixture[] = [inter];
  let issuer = inter;
  if (opts.subCaCn !== undefined) {
    const sub = makeCertificate({
      cn: opts.subCaCn,
      kind: 'ec',
      ca: true,
      keyUsage: ['keyCertSign'],
      issuer: issuerOf(inter),
    });
    intermediates.push(sub);
    issuer = sub;
  }
  const leaf = makeCertificate({
    cn: opts.leafCn ?? 'Leaf',
    kind: 'ec',
    sanUris: opts.leafSanUris,
    sanDnsNames: opts.leafSanDnsNames,
    issuer: issuerOf(issuer),
  });
  const result = await verifyCertificateChain(
    leaf.der,
    intermediates.map((c) => c.der),
    { trustAnchorsDer: [root.der], maxDepth: 6 },
  );
  return result.trusted;
}

describe('verifyCertificateChain（nameConstraints）', () => {
  test('nameConstraints を持たない中間 CA のチェーンは信頼する（正常系）', async () => {
    expect(await trusts({ leafSanUris: ['https://anything.example.org/'] })).toBe(true);
  });

  test('permittedSubtrees の URI 範囲内の leaf は信頼する（正常系）', async () => {
    const trusted = await trusts({
      nameConstraints: { permittedUris: ['issuer.example.com'] },
      leafSanUris: ['https://issuer.example.com/vc'],
    });
    expect(trusted).toBe(true);
  });

  test('permittedSubtrees の URI 範囲外の SAN を持つ leaf は信頼しない', async () => {
    const trusted = await trusts({
      nameConstraints: { permittedUris: ['issuer.example.com'] },
      leafSanUris: ['https://attacker.example.net/vc'],
    });
    expect(trusted).toBe(false);
  });

  test('permittedSubtrees の base `.example.com` は host.example.com を信頼する（正常系）', async () => {
    const trusted = await trusts({
      nameConstraints: { permittedUris: ['.example.com'] },
      leafSanUris: ['https://host.example.com/vc'],
    });
    expect(trusted).toBe(true);
  });

  test('permittedSubtrees の base `.example.com` は example.com 自身を信頼しない', async () => {
    const trusted = await trusts({
      nameConstraints: { permittedUris: ['.example.com'] },
      leafSanUris: ['https://example.com/vc'],
    });
    expect(trusted).toBe(false);
  });

  test('excludedSubtrees の URI に一致する SAN を持つ leaf は信頼しない', async () => {
    const trusted = await trusts({
      nameConstraints: { excludedUris: ['.example.com'] },
      leafSanUris: ['https://blocked.example.com/vc'],
    });
    expect(trusted).toBe(false);
  });

  test('excludedSubtrees は末尾ドット付きホスト名（root label 付き）の SAN にも一致する', async () => {
    // 末尾ドットを落とさないと除外したはずの名前が素通りする（照合規則そのものは
    // `trust/x509/__tests__/name-constraints.test.ts`）。
    const trusted = await trusts({
      nameConstraints: { excludedUris: ['.example.com'] },
      leafSanUris: ['https://blocked.example.com./vc'],
    });
    expect(trusted).toBe(false);
  });

  test('permittedSubtrees の directoryName 範囲外の subject DN を持つ leaf は信頼しない', async () => {
    const trusted = await trusts({
      nameConstraints: { permittedCns: ['Permitted Org'] },
      leafCn: 'Other Org',
    });
    expect(trusted).toBe(false);
  });

  test('permittedSubtrees の directoryName に一致する subject DN の leaf は信頼する（正常系）', async () => {
    const trusted = await trusts({
      nameConstraints: { permittedCns: ['Permitted Org'] },
      leafCn: 'Permitted Org',
    });
    expect(trusted).toBe(true);
  });

  test('excludedSubtrees の directoryName に一致する subject DN の leaf は信頼しない', async () => {
    const trusted = await trusts({
      nameConstraints: { excludedCns: ['Blocked Org'] },
      leafCn: 'Blocked Org',
    });
    expect(trusted).toBe(false);
  });

  test('制約は配下の中間 CA にも課される（範囲外の sub-CA は信頼しない）', async () => {
    const trusted = await trusts({
      nameConstraints: { permittedCns: ['Permitted Org'] },
      subCaCn: 'Rogue Sub CA',
      leafCn: 'Permitted Org',
    });
    expect(trusted).toBe(false);
  });

  test('未対応の GeneralName 種別（dNSName）を base に持つ制約は信頼しない', async () => {
    const trusted = await trusts({
      nameConstraints: { permittedDnsNames: ['example.com'] },
      leafSanUris: ['https://example.com/vc'],
    });
    expect(trusted).toBe(false);
  });

  test('nameConstraints 下で dNSName SAN を持つ leaf は信頼しない', async () => {
    const trusted = await trusts({
      nameConstraints: { permittedUris: ['issuer.example.com'] },
      leafSanUris: ['https://issuer.example.com/vc'],
      leafSanDnsNames: ['issuer.example.com'],
    });
    expect(trusted).toBe(false);
  });

  test('GeneralSubtree.minimum を持つ制約は信頼しない', async () => {
    const trusted = await trusts({
      nameConstraints: { permittedUris: ['issuer.example.com'], minimum: 1 },
      leafSanUris: ['https://issuer.example.com/vc'],
    });
    expect(trusted).toBe(false);
  });

  test('空の permittedSubtrees を持つ制約は信頼しない', async () => {
    const trusted = await trusts({
      nameConstraints: { emptyPermitted: true },
      leafSanUris: ['https://issuer.example.com/vc'],
    });
    expect(trusted).toBe(false);
  });

  // 照合は名前数 × base 数の全対全比較で、件数は x5c 由来（攻撃者が決める）。上限を超える
  // 件数は評価不能として落とす。上限ちょうどは従来どおり評価される（境界を両側から固定する）。
  test('permittedSubtrees が上限ちょうどなら評価され、末尾の base に一致する leaf は信頼する', async () => {
    const decoys = Array.from({ length: MAX_NAME_CONSTRAINT_ENTRIES - 1 }, (_, i) => `d${i}.test`);
    const trusted = await trusts({
      nameConstraints: { permittedUris: [...decoys, 'issuer.example.com'] },
      leafSanUris: ['https://issuer.example.com/vc'],
    });
    expect(trusted).toBe(true);
  });

  test('permittedSubtrees が上限 + 1 件の制約は評価不能として信頼しない', async () => {
    const decoys = Array.from({ length: MAX_NAME_CONSTRAINT_ENTRIES }, (_, i) => `d${i}.test`);
    const trusted = await trusts({
      nameConstraints: { permittedUris: [...decoys, 'issuer.example.com'] },
      leafSanUris: ['https://issuer.example.com/vc'],
    });
    expect(trusted).toBe(false);
  });

  test('URI SAN が上限 + 1 件の leaf は nameConstraints 下で信頼しない', async () => {
    const sans = Array.from(
      { length: MAX_NAME_CONSTRAINT_ENTRIES + 1 },
      () => 'https://issuer.example.com/vc',
    );
    const trusted = await trusts({
      nameConstraints: { permittedUris: ['issuer.example.com'] },
      leafSanUris: sans,
    });
    expect(trusted).toBe(false);
  });

  test('URI SAN が上限ちょうどの leaf は nameConstraints 下でも信頼する', async () => {
    const sans = Array.from(
      { length: MAX_NAME_CONSTRAINT_ENTRIES },
      () => 'https://issuer.example.com/vc',
    );
    const trusted = await trusts({
      nameConstraints: { permittedUris: ['issuer.example.com'] },
      leafSanUris: sans,
    });
    expect(trusted).toBe(true);
  });
});
