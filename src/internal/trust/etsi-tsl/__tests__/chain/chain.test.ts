import { describe, expect, test } from 'bun:test';
import { verifyCertificateChain } from '../../chain.js';
import { makeCertificate } from '../fixtures.js';

describe('verifyCertificateChain', () => {
  test('リーフ → 中間 → Anchor の RSA チェーンを信頼する', async () => {
    const root = makeCertificate({ cn: 'Root CA', kind: 'rsa' });
    const inter = makeCertificate({
      cn: 'Intermediate CA',
      kind: 'rsa',
      ca: true,
      keyUsage: ['keyCertSign'],
      issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'rsa' },
    });
    const leaf = makeCertificate({
      cn: 'QTSP Issuer',
      kind: 'ec',
      issuer: { name: inter.subjectName, privateKey: inter.privateKey, kind: 'rsa' },
    });
    const result = await verifyCertificateChain(leaf.der, [inter.der], {
      trustAnchorsDer: [root.der],
    });
    expect(result.trusted).toBe(true);
    expect(result.anchorSubjectDer).toBeDefined();
  });

  test('Anchor が直接発行者ならリーフ 1 段で信頼する', async () => {
    const root = makeCertificate({ cn: 'Root CA', kind: 'ec' });
    const leaf = makeCertificate({
      cn: 'Issuer',
      kind: 'ec',
      issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'ec' },
    });
    const result = await verifyCertificateChain(leaf.der, [], { trustAnchorsDer: [root.der] });
    expect(result.trusted).toBe(true);
  });

  test('Trust Anchor 集合に無い発行者は信頼しない', async () => {
    const root = makeCertificate({ cn: 'Root CA', kind: 'rsa' });
    const other = makeCertificate({ cn: 'Unrelated CA', kind: 'rsa' });
    const leaf = makeCertificate({
      cn: 'Issuer',
      kind: 'ec',
      issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'rsa' },
    });
    const result = await verifyCertificateChain(leaf.der, [], { trustAnchorsDer: [other.der] });
    expect(result.trusted).toBe(false);
  });

  test('別鍵で署名された偽造リーフは署名検証で落ちる', async () => {
    const root = makeCertificate({ cn: 'Root CA', kind: 'rsa' });
    const attacker = makeCertificate({ cn: 'Attacker', kind: 'rsa' });
    // issuer 名は Root だが実際は attacker 鍵で署名 → 署名検証失敗。
    const forged = makeCertificate({
      cn: 'Forged',
      kind: 'ec',
      issuer: { name: root.subjectName, privateKey: attacker.privateKey, kind: 'rsa' },
    });
    const result = await verifyCertificateChain(forged.der, [], { trustAnchorsDer: [root.der] });
    expect(result.trusted).toBe(false);
  });

  test('期限切れ証明書は信頼しない', async () => {
    const past = new Date(Date.now() - 172_800_000);
    const root = makeCertificate({ cn: 'Root CA', kind: 'rsa' });
    const leaf = makeCertificate({
      cn: 'Expired',
      kind: 'ec',
      notBefore: new Date(Date.now() - 200_000_000),
      notAfter: past,
      issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'rsa' },
    });
    const result = await verifyCertificateChain(leaf.der, [], { trustAnchorsDer: [root.der] });
    expect(result.trusted).toBe(false);
  });

  // 同一チェーンを追跡する深さの既定値は 5 段。
  // `makeChain(n)` はリーフ + 中間 n 段 + Root を作り、走査される非 Anchor 証明書は n+1 段になる。
  function makeChain(intermediateCount: number): {
    root: ReturnType<typeof makeCertificate>;
    intermediates: ReturnType<typeof makeCertificate>[];
    leaf: ReturnType<typeof makeCertificate>;
  } {
    const root = makeCertificate({ cn: 'Root CA', kind: 'ec' });
    const intermediates: ReturnType<typeof makeCertificate>[] = [];
    let issuer = root;
    for (let i = 0; i < intermediateCount; i++) {
      const inter = makeCertificate({
        cn: `Intermediate CA ${i}`,
        kind: 'ec',
        ca: true,
        issuer: { name: issuer.subjectName, privateKey: issuer.privateKey, kind: 'ec' },
      });
      intermediates.push(inter);
      issuer = inter;
    }
    const leaf = makeCertificate({
      cn: 'QTSP Issuer',
      kind: 'ec',
      issuer: { name: issuer.subjectName, privateKey: issuer.privateKey, kind: 'ec' },
    });
    return { root, intermediates, leaf };
  }

  test('既定の深さ上限ちょうど（5 段）のチェーンは信頼する', async () => {
    const { root, intermediates, leaf } = makeChain(4);
    const result = await verifyCertificateChain(
      leaf.der,
      intermediates.map((c) => c.der),
      { trustAnchorsDer: [root.der] },
    );
    expect(result.trusted).toBe(true);
  });

  test('既定の深さ上限を超える（6 段）チェーンは信頼しない', async () => {
    const { root, intermediates, leaf } = makeChain(5);
    const result = await verifyCertificateChain(
      leaf.der,
      intermediates.map((c) => c.der),
      { trustAnchorsDer: [root.der] },
    );
    expect(result.trusted).toBe(false);
  });

  test('maxDepth を明示すれば既定を超える深さも辿れる', async () => {
    const { root, intermediates, leaf } = makeChain(5);
    const result = await verifyCertificateChain(
      leaf.der,
      intermediates.map((c) => c.der),
      { trustAnchorsDer: [root.der], maxDepth: 6 },
    );
    expect(result.trusted).toBe(true);
  });

  // 中間証明書の CA 制約（RFC 5280 §4.2.1.9 / §4.2.1.3）。DN 一致だけで中間を選ぶと、信頼済み
  // QTSP が発行したエンドエンティティ証明書をそのまま中間に差し込める。
  //
  // 攻撃者の手順:
  //   1. 信頼済み QTSP から**正当な**エンドエンティティ証明書（CA:FALSE）と秘密鍵を得る
  //   2. その鍵で任意の leaf（例: 別 Issuer を名乗る証明書）に署名する
  //   3. leaf + 手順 1 の証明書を `x5c` として提示する
  // DN の連結も各段の署名検証も成立するため、CA 制約が無ければチェーンは trusted になる。
  function attackerChain(caFlag: {
    ca?: boolean;
    keyUsage?: readonly ('digitalSignature' | 'keyCertSign')[];
  }): {
    rootDer: Uint8Array;
    eeDer: Uint8Array;
    forgedLeafDer: Uint8Array;
  } {
    const root = makeCertificate({ cn: 'Root CA', kind: 'ec', ca: true });
    // QTSP が正当に発行したエンドエンティティ証明書（攻撃者が秘密鍵を持つ）。
    const endEntity = makeCertificate({
      cn: 'Attacker End Entity',
      kind: 'ec',
      ...caFlag,
      issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'ec' },
    });
    // そのエンドエンティティ鍵で署名した偽の leaf。
    const forged = makeCertificate({
      cn: 'Impersonated Issuer',
      kind: 'ec',
      issuer: { name: endEntity.subjectName, privateKey: endEntity.privateKey, kind: 'ec' },
    });
    return { rootDer: root.der, eeDer: endEntity.der, forgedLeafDer: forged.der };
  }

  test('CA:FALSE のエンドエンティティ証明書を中間に使ったチェーンは信頼しない', async () => {
    const { rootDer, eeDer, forgedLeafDer } = attackerChain({ ca: false });
    const result = await verifyCertificateChain(forgedLeafDer, [eeDer], {
      trustAnchorsDer: [rootDer],
    });
    expect(result.trusted).toBe(false);
  });

  test('basicConstraints 拡張を持たない証明書を中間に使ったチェーンは信頼しない', async () => {
    // 拡張そのものが無い = CA を名乗っていない。fail-closed で落とす。
    const { rootDer, eeDer, forgedLeafDer } = attackerChain({});
    const result = await verifyCertificateChain(forgedLeafDer, [eeDer], {
      trustAnchorsDer: [rootDer],
    });
    expect(result.trusted).toBe(false);
  });

  test('CA:TRUE でも keyUsage に keyCertSign が無い中間は信頼しない', async () => {
    const { rootDer, eeDer, forgedLeafDer } = attackerChain({
      ca: true,
      keyUsage: ['digitalSignature'],
    });
    const result = await verifyCertificateChain(forgedLeafDer, [eeDer], {
      trustAnchorsDer: [rootDer],
    });
    expect(result.trusted).toBe(false);
  });

  test('CA:TRUE + keyUsage keyCertSign の中間は従来どおり信頼する（正常系）', async () => {
    const { rootDer, eeDer, forgedLeafDer } = attackerChain({
      ca: true,
      keyUsage: ['keyCertSign'],
    });
    const result = await verifyCertificateChain(forgedLeafDer, [eeDer], {
      trustAnchorsDer: [rootDer],
    });
    expect(result.trusted).toBe(true);
  });

  // basicConstraints の pathLenConstraint（RFC 5280 §4.2.1.9 / §6.1.4 (m)）。`cA:TRUE` だけを見て
  // pathLenConstraint を読まないと、QTSP が「この CA の下にさらに CA を作らせない」と明示した
  // 制約が無視され、pathLen:0 の中間 CA の配下に攻撃者の sub-CA を挟んだチェーンが通る。
  //
  // `makePathLenChain(pathLen, subCaCount)` は
  // root(anchor) ← interCA(pathLen 付き) ← subCA 0..n ← leaf を作る。
  function makePathLenChain(
    pathLen: number,
    subCaCount: number,
  ): { rootDer: Uint8Array; intermediatesDer: Uint8Array[]; leafDer: Uint8Array } {
    const root = makeCertificate({ cn: 'Root CA', kind: 'ec', ca: true });
    const inter = makeCertificate({
      cn: 'Intermediate CA',
      kind: 'ec',
      ca: true,
      pathLen,
      keyUsage: ['keyCertSign'],
      issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'ec' },
    });
    const intermediates = [inter];
    let issuer = inter;
    for (let i = 0; i < subCaCount; i++) {
      const subCa = makeCertificate({
        cn: `Sub CA ${i}`,
        kind: 'ec',
        ca: true,
        keyUsage: ['keyCertSign'],
        issuer: { name: issuer.subjectName, privateKey: issuer.privateKey, kind: 'ec' },
      });
      intermediates.push(subCa);
      issuer = subCa;
    }
    const leaf = makeCertificate({
      cn: 'QTSP Issuer',
      kind: 'ec',
      issuer: { name: issuer.subjectName, privateKey: issuer.privateKey, kind: 'ec' },
    });
    return {
      rootDer: root.der,
      intermediatesDer: intermediates.map((c) => c.der),
      leafDer: leaf.der,
    };
  }

  test('pathLenConstraint: 0 の中間 CA の下に sub-CA を挟んだチェーンは信頼しない', async () => {
    const { rootDer, intermediatesDer, leafDer } = makePathLenChain(0, 1);
    const result = await verifyCertificateChain(leafDer, intermediatesDer, {
      trustAnchorsDer: [rootDer],
    });
    expect(result.trusted).toBe(false);
  });

  test('pathLenConstraint: 0 の中間 CA が直接発行した leaf は信頼する（正常系）', async () => {
    const { rootDer, intermediatesDer, leafDer } = makePathLenChain(0, 0);
    const result = await verifyCertificateChain(leafDer, intermediatesDer, {
      trustAnchorsDer: [rootDer],
    });
    expect(result.trusted).toBe(true);
  });

  test('pathLenConstraint: 1 なら sub-CA を 1 段挟んだチェーンを信頼する（正常系）', async () => {
    const { rootDer, intermediatesDer, leafDer } = makePathLenChain(1, 1);
    const result = await verifyCertificateChain(leafDer, intermediatesDer, {
      trustAnchorsDer: [rootDer],
    });
    expect(result.trusted).toBe(true);
  });

  test('pathLenConstraint: 1 でも sub-CA を 2 段挟んだチェーンは信頼しない', async () => {
    // leaf → subCA1 → subCA0 → interCA → root の 4 段で、既定 maxDepth(5) には掛からない。
    // pathLenConstraint を読まない実装ではここが trusted になる。
    const { rootDer, intermediatesDer, leafDer } = makePathLenChain(1, 2);
    const result = await verifyCertificateChain(leafDer, intermediatesDer, {
      trustAnchorsDer: [rootDer],
    });
    expect(result.trusted).toBe(false);
  });

  test('パース不能な入力は信頼しない（例外を投げない）', async () => {
    const result = await verifyCertificateChain(Uint8Array.from([0x00, 0x01]), [], {
      trustAnchorsDer: [],
    });
    expect(result.trusted).toBe(false);
  });
});
