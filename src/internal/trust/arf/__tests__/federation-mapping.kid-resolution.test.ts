/**
 * 同一 Leaf のチェーンを畳む際に、宣言とその出自の JWKS を切り離さないことの回帰。
 *
 * 鍵無効化宣言と照合する `kid` の解決を確認する。
 *
 * 回帰対象の fail-open: `dedupeValidChains` が `revokedKeys` だけをチェーン横断で和集合にし、
 * `nodes` を先頭チェーンのままにしていた頃、**宣言とその出自の JWKS が切り離されていた**。`kid` は
 * 1 つの JWKS の中でしか一意でないため、これは失効鍵の受理につながる。
 *
 * 具体的には、Leaf `L` が Anchor `A` / `B` の双方から到達可能で、`B` が鍵 `K` を `"b-1"` として
 * attest しつつ `{sub: L, kid: "b-1"}` を宣言し、`A` が同じ `K` を `"a-1"` として attest している
 * 場合、畳んだチェーンの `nodes` が `A` 側だけだと、VC 検証経路が鍵素材から解決する `kid` は
 * `"a-1"` のみになる。`B` の宣言は永久に一致せず、失効鍵 `K` で署名された VC が受理されてしまう。
 *
 * ここでは畳んだチェーンを実際に `assertSigningKeyNotRevoked`（VC 検証経路が使う判定）へ渡し、
 * `B` 側の宣言が効くことを end-to-end で固定する。
 */

import { describe, expect, test } from 'bun:test';
import { assertSigningKeyNotRevoked } from '../../../credential/issuer-key-revocation.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import type { TrustChain, TrustChainNode } from '../../federation/federation-types.js';
import type { ArfCatalogueEntry } from '../arf-types.js';
import { mapFederationToArf } from '../federation-mapping.js';

const LEAF = 'https://issuer-a.example';
const ANCHOR_A = 'https://anchor-a.example';
const ANCHOR_B = 'https://anchor-b.example';

/** 無効化時刻 T。この時刻**以降**に発行された VC を拒否する（境界を含む）。 */
const REVOKED_AT = 1_767_225_600;

/** 両 Anchor が attest する同一の鍵素材（`kid` ラベルだけが Anchor ごとに異なる）。 */
const KEY_MATERIAL: PublicKeyJwk = { kty: 'EC', crv: 'P-256', x: 'x-value', y: 'y-value' };

/** 上位が `LEAF` について発行した Subordinate Statement ノード。 */
function subordinate(iss: string, kid: string, iat: number): TrustChainNode {
  return {
    iss,
    sub: LEAF,
    kind: 'subordinate-statement',
    statement: {
      iss,
      sub: LEAF,
      iat,
      exp: iat + 1000,
      jwks: { keys: [{ ...KEY_MATERIAL, kid }] },
    },
  };
}

/** 1 本の Trust Chain（Anchor ごとに `kid` ラベルが異なる）。 */
function chainVia(
  trustAnchor: string,
  kid: string,
  iat: number,
  revokedKeys: TrustChain['revokedKeys'] = [],
): TrustChain {
  const nodes = [subordinate(trustAnchor, kid, iat)];
  return { valid: true, leaf: LEAF, trustAnchor, nodes, length: nodes.length, revokedKeys };
}

function entry(id: string): ArfCatalogueEntry {
  return { id, role: 'issuer' };
}

/** 畳んだチェーンを FC-11 判定へ渡す（SD-JWT VC 相当の `iat` 基準）。 */
function assertVc(chain: TrustChain, iat: number): void {
  assertSigningKeyNotRevoked({ iat }, { trustChain: chain }, 'iat', KEY_MATERIAL);
}

describe('mapFederationToArf - 畳み込み後の kid 解決（fail-open 回帰）', () => {
  /** A は `a-1` として attest（宣言なし）、B は同じ鍵を `b-1` として attest し失効を宣言。 */
  function foldedChain(): TrustChain {
    const chains = [
      chainVia(ANCHOR_A, 'a-1', 10),
      chainVia(ANCHOR_B, 'b-1', 20, [{ sub: LEAF, kid: 'b-1', revoked_at: REVOKED_AT }]),
    ];
    const matched = mapFederationToArf(chains, [entry(LEAF)]).matched[0];
    if (matched === undefined) {
      throw new Error('leaf did not match');
    }
    return matched.chain;
  }

  // 中核の回帰: `nodes` が先頭チェーン（A）のままだと `b-1` を解決できず、失効鍵で署名された
  // VC が受理されてしまう。畳んだチェーンには B の Subordinate Statement も残っていること。
  test('2 本目の Anchor が attest した kid の宣言が効く（失効後の VC を拒否）', () => {
    let caught: unknown;
    try {
      assertVc(foldedChain(), REVOKED_AT + 1);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.FEDERATION_KEY_REVOKED);
  });

  // 巻き添え防止の対照。宣言が効くのは `revoked_at` 以降に発行された VC だけである。
  test('同じ鍵でも漏洩前に発行された VC は受理する', () => {
    expect(() => assertVc(foldedChain(), REVOKED_AT - 1)).not.toThrow();
  });

  // 機構の直接確認: 両 Anchor の Subordinate Statement が畳み込み後も残っている。
  test('畳んだチェーンは両 Anchor の Subordinate Statement を保持する', () => {
    const kids = foldedChain()
      .nodes.filter((node) => node.kind === 'subordinate-statement' && node.sub === LEAF)
      .flatMap((node) => node.statement.jwks.keys.map((key) => key.kid));

    expect(kids).toEqual(['a-1', 'b-1']);
  });
});
