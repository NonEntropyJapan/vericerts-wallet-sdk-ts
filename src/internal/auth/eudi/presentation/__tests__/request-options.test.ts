/**
 * `presentationRequestOptions`（`request-options.ts`）の単体テスト。
 *
 * `federationTrustAnchor` / `arfTrustAnchor`（OIDF / ARF 層）は他の `jarTrust`
 * メンバと同じ `trustMember` 経路で `parsePresentationRequest` へ転送される実装になっているが、
 * 転送し忘れると `PresentDeps.jarTrust` に OIDF / ARF 層を設定していても
 * `parsePresentationRequest` 側は黙って TSL 単独へ縮退する（呼び出し側は設定したつもりのまま、
 * 実際には ARF/OIDF Trust Anchor が一切効かない状態になる）。ここでは `presentationRequestOptions`
 * の戻り値に両キーがそのまま載ることを固定し、この縮退を回帰させない。
 */

import { describe, expect, it } from 'bun:test';
import type { ArfTrustAnchorSet } from '../../../../trust/arf/index.js';
import type { JarTrustOptions } from '../../../jar/index.js';
import { presentationRequestOptions } from '../request-options.js';
import type { PresentDeps } from '../types.js';

const ARF_TRUST_ANCHOR: ArfTrustAnchorSet = { signatureValid: true, entries: [] };
const FEDERATION_TRUST_ANCHOR: NonNullable<JarTrustOptions['federationTrustAnchor']> = {
  trustAnchorEntityId: 'https://federation.example.eu',
};

function deps(jarTrust: PresentDeps['jarTrust']): PresentDeps {
  return {
    signer: { publicKeyJwk: {} } as unknown as PresentDeps['signer'],
    jarTrust,
  };
}

/**
 * `presentationRequestOptions` の戻り値型（`Parameters<typeof parsePresentationRequest>[1]`）は
 * `parsePresentationRequest` の第 2 引数が省略可能なため `| undefined` を含む。実装は常にオブジェクト
 * を返すので、テスト側で非 `undefined` を確認してから絞り込む。
 */
function expectDefined<T>(value: T | undefined): T {
  expect(value).not.toBeUndefined();
  return value as T;
}

describe('presentationRequestOptions: OIDF / ARF Trust Anchor の転送', () => {
  it('federationTrustAnchor / arfTrustAnchor の両方が戻り値に載る', () => {
    const options = expectDefined(
      presentationRequestOptions(
        deps({
          trustAnchors: [],
          federationTrustAnchor: FEDERATION_TRUST_ANCHOR,
          arfTrustAnchor: ARF_TRUST_ANCHOR,
        }),
      ),
    );

    expect(options.federationTrustAnchor).toBe(FEDERATION_TRUST_ANCHOR);
    expect(options.arfTrustAnchor).toBe(ARF_TRUST_ANCHOR);
  });

  it('arfTrustAnchor だけを設定した場合も federationTrustAnchor は undefined のまま黙って失われない', () => {
    const options = expectDefined(
      presentationRequestOptions(deps({ trustAnchors: [], arfTrustAnchor: ARF_TRUST_ANCHOR })),
    );

    expect(options.arfTrustAnchor).toBe(ARF_TRUST_ANCHOR);
    expect(options.federationTrustAnchor).toBeUndefined();
  });

  it('jarTrust 未指定でも federationTrustAnchor / arfTrustAnchor キー自体は存在する（own プロパティとして載る）', () => {
    const options = expectDefined(presentationRequestOptions(deps(undefined)));

    expect(Object.hasOwn(options, 'federationTrustAnchor')).toBe(true);
    expect(Object.hasOwn(options, 'arfTrustAnchor')).toBe(true);
    expect(options.federationTrustAnchor).toBeUndefined();
    expect(options.arfTrustAnchor).toBeUndefined();
  });
});
