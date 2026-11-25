import { describe, expect, test } from 'bun:test';
import type { TrustChain, TrustChainNode } from '../../federation/federation-types.js';
import type { ArfCatalogueEntry } from '../arf-types.js';
import { mapFederationToArf } from '../federation-mapping.js';

/** テスト用の最小 Trust Chain を作る。 */
function chain(
  leaf: string,
  valid = true,
  revokedKeys: TrustChain['revokedKeys'] = [],
  trustAnchor = 'https://anchor.example',
): TrustChain {
  const node: TrustChainNode = {
    iss: leaf,
    sub: leaf,
    kind: 'entity-configuration',
    statement: {
      iss: leaf,
      sub: leaf,
      iat: 0,
      exp: 1,
      jwks: { keys: [] },
    },
  };
  return {
    valid,
    leaf,
    trustAnchor,
    nodes: [node],
    length: 1,
    revokedKeys,
  };
}

/** ARF エントリを作る。 */
function entry(id: string): ArfCatalogueEntry {
  return { id, role: 'issuer' };
}

describe('mapFederationToArf', () => {
  test('Entity Identifier 一致で Federation ⇔ ARF を突き合わせる', () => {
    const chains = [chain('https://issuer-a.example'), chain('https://issuer-b.example')];
    const arf = [entry('https://issuer-a.example'), entry('https://issuer-b.example')];

    const result = mapFederationToArf(chains, arf);

    expect(result.matched.map((m) => m.entityId).sort()).toEqual([
      'https://issuer-a.example',
      'https://issuer-b.example',
    ]);
    expect(result.federationOnly.length).toBe(0);
    expect(result.arfOnly.length).toBe(0);
    expect(result.matched[0]?.entry.id).toBe('https://issuer-a.example');
  });

  test('Federation のみ・ARF のみを分類する', () => {
    const chains = [chain('https://shared.example'), chain('https://fed-only.example')];
    const arf = [entry('https://shared.example'), entry('https://arf-only.example')];

    const result = mapFederationToArf(chains, arf);

    expect(result.matched.map((m) => m.entityId)).toEqual(['https://shared.example']);
    expect(result.federationOnly).toEqual(['https://fed-only.example']);
    expect(result.arfOnly.map((e) => e.id)).toEqual(['https://arf-only.example']);
  });

  test('valid でない Trust Chain はマッチにも federationOnly にも含めない（fail-closed）', () => {
    const chains = [chain('https://invalid.example', false), chain('https://valid.example')];
    const arf = [entry('https://invalid.example'), entry('https://valid.example')];

    const result = mapFederationToArf(chains, arf);

    expect(result.matched.map((m) => m.entityId)).toEqual(['https://valid.example']);
    expect(result.federationOnly.length).toBe(0);
    // invalid.example は Federation 側から除外されるので ARF 側では arfOnly に残る。
    expect(result.arfOnly.map((e) => e.id)).toEqual(['https://invalid.example']);
  });

  test('leaf 識別子が空の Trust Chain は無視する', () => {
    const chains = [chain(''), chain('https://real.example')];
    const arf = [entry('https://real.example')];

    const result = mapFederationToArf(chains, arf);

    expect(result.matched.map((m) => m.entityId)).toEqual(['https://real.example']);
    expect(result.federationOnly.length).toBe(0);
  });

  test('重複する leaf 識別子は 1 つにまとめる', () => {
    const chains = [chain('https://dup.example'), chain('https://dup.example')];
    const arf: ArfCatalogueEntry[] = [];

    const result = mapFederationToArf(chains, arf);

    expect(result.federationOnly).toEqual(['https://dup.example']);
    expect(result.matched.length).toBe(0);
  });

  test('ARF Catalogue の重複識別子は最初のエントリを採用する', () => {
    const chains = [chain('https://dup.example')];
    const arf = [
      { id: 'https://dup.example', role: 'issuer', country: 'DE' } as ArfCatalogueEntry,
      { id: 'https://dup.example', role: 'wallet-provider', country: 'FR' } as ArfCatalogueEntry,
    ];

    const result = mapFederationToArf(chains, arf);

    expect(result.matched.length).toBe(1);
    expect(result.matched[0]?.entry.country).toBe('DE');
    expect(result.arfOnly.length).toBe(0);
  });

  test('Entity Identifier は完全一致のみ（サブドメイン・部分一致は突き合わせない）', () => {
    const chains = [chain('https://issuer.example')];
    const arf = [entry('https://sub.issuer.example'), entry('https://issuer.example.org')];

    const result = mapFederationToArf(chains, arf);

    expect(result.matched.length).toBe(0);
    expect(result.federationOnly).toEqual(['https://issuer.example']);
    expect(result.arfOnly.length).toBe(2);
  });

  test('空入力は空マッピングを返す', () => {
    const result = mapFederationToArf([], []);
    expect(result.matched.length).toBe(0);
    expect(result.federationOnly.length).toBe(0);
    expect(result.arfOnly.length).toBe(0);
  });
});

/**
 * FC-11 の鍵無効化宣言を突き合わせ結果に持ち越すことの回帰。
 *
 * 以前は識別子だけを返しており、突き合わせを通過した時点で
 * `chain.revokedKeys` が失われ、この Leaf が発行した VC を検証する下流が FC-11 を適用できなかった。
 * VC 側の突合は VC の `iat` 基準であり、VC を手にした下流でしか行えないため、宣言はここで
 * 落としてはならない。
 */
describe('mapFederationToArf - FC-11 鍵無効化宣言の持ち越し', () => {
  const REVOKED = [
    { sub: 'https://issuer-a.example', kid: 'issuer-2026-01', revoked_at: 1767222000 },
  ] as const;

  test('突き合わせ結果が根拠の Trust Chain を保持する', () => {
    const source = chain('https://issuer-a.example', true, REVOKED);

    const result = mapFederationToArf([source], [entry('https://issuer-a.example')]);

    expect(result.matched).toHaveLength(1);
    // 同一の chain オブジェクトがそのまま持ち越される（射影で情報を落とさない）。
    expect(result.matched[0]?.chain).toBe(source);
    expect(result.matched[0]?.entityId).toBe(source.leaf);
  });

  test('持ち越した chain から鍵無効化宣言を読み出せる', () => {
    const source = chain('https://issuer-a.example', true, REVOKED);

    const result = mapFederationToArf([source], [entry('https://issuer-a.example')]);

    // これが空になると、この Leaf の VC に対して FC-11 を適用する術が下流に無くなる。
    expect(result.matched[0]?.chain.revokedKeys).toEqual([...REVOKED]);
  });

  test('宣言があっても突き合わせ自体は妨げない（正当な鍵ローテーションを弾かない）', () => {
    // 宣言の存在は「この Leaf を信頼しない」ことを意味しない。チェーン自体の検証は
    // buildTrustChain が nowSeconds 基準で済ませており、ここで再度弾くと巻き添えになる。
    const source = chain('https://issuer-a.example', true, REVOKED);

    const result = mapFederationToArf([source], [entry('https://issuer-a.example')]);

    expect(result.federationOnly).toEqual([]);
    expect(result.arfOnly).toEqual([]);
  });
});

/**
 * 同一 Leaf が複数の Trust Anchor から到達可能な場合の宣言の和集合。
 *
 * `dedupeValidChains` が Leaf ごとに最初の 1 本だけを残して
 * いた頃は、2 本目のチェーンにしか載っていない `revoked_keys` が黙って捨てられ、その失効鍵で
 * 署名された VC が受理される fail-open になっていた。宣言はどの Trust Anchor 由来であっても
 * 失ってはならない（FC-11 は fail-closed）。
 */
describe('mapFederationToArf - 同一 Leaf の宣言の和集合（fail-open 回帰）', () => {
  const LEAF = 'https://issuer-a.example';
  const ANCHOR_A = 'https://anchor-a.example';
  const ANCHOR_B = 'https://anchor-b.example';
  const FROM_A = { sub: LEAF, kid: 'issuer-2026-01', revoked_at: 1767222000 } as const;
  const FROM_B = { sub: LEAF, kid: 'issuer-2026-02', revoked_at: 1767225600 } as const;

  // 中核の回帰: 宣言が 2 本目の Trust Anchor 側にしか無くても取りこぼしてはならない。
  test('2 本目のチェーンにしか無い宣言も match.chain.revokedKeys に含まれる', () => {
    const chains = [chain(LEAF, true, [], ANCHOR_A), chain(LEAF, true, [FROM_B], ANCHOR_B)];

    const result = mapFederationToArf(chains, [entry(LEAF)]);

    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]?.chain.revokedKeys).toEqual([FROM_B]);
  });

  test('両方のチェーンの宣言を入力順で和集合にする', () => {
    const chains = [chain(LEAF, true, [FROM_A], ANCHOR_A), chain(LEAF, true, [FROM_B], ANCHOR_B)];

    const result = mapFederationToArf(chains, [entry(LEAF)]);

    expect(result.matched[0]?.chain.revokedKeys).toEqual([FROM_A, FROM_B]);
  });

  test('(sub, kid, revoked_at) が同一の宣言は重複排除する', () => {
    const chains = [chain(LEAF, true, [FROM_A], ANCHOR_A), chain(LEAF, true, [FROM_A], ANCHOR_B)];

    const result = mapFederationToArf(chains, [entry(LEAF)]);

    expect(result.matched[0]?.chain.revokedKeys).toEqual([FROM_A]);
  });

  // `trustAnchor` は最初の 1 本のまま。`nodes` は全チェーンを連結する（各宣言の出自の JWKS を
  // 残さないと `kid` を解決できず fail-open になるため / `federation-mapping.kid-resolution.test.ts`）。
  // 重複排除はしない（`jwks` を含まないキーで畳むと別内容の Statement を取りこぼすため）。
  test('trustAnchor は最初のチェーンのものを保ち、nodes は全チェーンの連結・length と整合する', () => {
    const first = chain(LEAF, true, [FROM_A], ANCHOR_A);
    const second = chain(LEAF, true, [FROM_B], ANCHOR_B);

    const matched = mapFederationToArf([first, second], [entry(LEAF)]).matched[0];

    expect(matched?.chain.trustAnchor).toBe(ANCHOR_A);
    expect(matched?.chain.nodes).toEqual([...first.nodes, ...second.nodes]);
    expect(matched?.chain.length).toBe(matched?.chain.nodes.length);
    expect(matched?.chain.valid).toBe(true);
    expect(matched?.chain.leaf).toBe(LEAF);
  });

  // 不成立チェーンは信頼判定に使えないため、その宣言も採用しない（fail-closed の一貫性）。
  test('valid でないチェーンの宣言は和集合に含めない', () => {
    const chains = [chain(LEAF, true, [FROM_A], ANCHOR_A), chain(LEAF, false, [FROM_B], ANCHOR_B)];

    const result = mapFederationToArf(chains, [entry(LEAF)]);

    expect(result.matched[0]?.chain.revokedKeys).toEqual([FROM_A]);
  });

  // 別 Leaf の宣言が混ざらないこと（宣言は Leaf ごとに閉じる）。
  test('別 Leaf のチェーンの宣言は混ざらない', () => {
    const other = 'https://issuer-b.example';
    const chains = [
      chain(LEAF, true, [FROM_A], ANCHOR_A),
      chain(other, true, [{ sub: other, kid: 'other-1', revoked_at: 1 }], ANCHOR_B),
    ];

    const result = mapFederationToArf(chains, [entry(LEAF), entry(other)]);

    const forLeaf = result.matched.find((m) => m.entityId === LEAF);
    expect(forLeaf?.chain.revokedKeys).toEqual([FROM_A]);
  });
});
