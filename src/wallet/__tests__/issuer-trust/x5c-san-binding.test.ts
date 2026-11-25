/**
 * `x5c` 経路の `iss` ↔ SubjectAltName 突き合わせ（draft-ietf-oauth-sd-jwt-vc）。
 *
 * `x5c.ts` は冒頭で「Trust Anchor へ連鎖しただけの証明書を受理すると、同じ Trust Anchor 配下の
 * 任意の証明書保持者が任意の `iss` を騙れる」と宣言している。突き合わせを origin 一致まで緩めると、
 * その縮小版（**同一 origin の別テナントへのなりすまし**）が同じ理屈で成立してしまうため、
 * 「正規化した上での完全一致」であることをここで固定する。
 *
 * 受領経路まで通す回帰は `__tests__/eudi/wallet.eudi.receive-x5c.test.ts` にあり、本ファイルは
 * 突き合わせ規則そのものを最小の入力で押さえる（証明書・チェーンは実 DER のまま）。
 */

import { describe, expect, it } from 'bun:test';
import { resolveX5cIssuerKey } from '../../issuer-trust/index.js';
import { makeIssuerChain } from '../eudi/x5c-fixtures.js';

const TENANT_A = 'https://pid-provider.example.eu/tenant-a';
const TENANT_B = 'https://pid-provider.example.eu/tenant-b';

/** SAN を指定したチェーンで `iss` の鍵解決を試み、成否を返す。 */
async function resolve(san: string, iss: string): Promise<'resolved' | 'rejected'> {
  const chain = makeIssuerChain({ san });
  try {
    await resolveX5cIssuerKey({ x5c: chain.x5c }, iss, chain.anchors);
    return 'resolved';
  } catch {
    return 'rejected';
  }
}

describe('x5c: iss と SubjectAltName の突き合わせ', () => {
  it('SAN と iss が一致すれば leaf の公開鍵を返す', async () => {
    const chain = makeIssuerChain({ san: TENANT_A });

    const key = await resolveX5cIssuerKey({ x5c: chain.x5c }, TENANT_A, chain.anchors);

    expect(key.kty).toBe('EC');
    expect(key.crv).toBe('P-256');
  });

  // 同一 origin の別テナントを騙れると、テナント A の正当な証明書でテナント B の PID を偽造できる。
  it('origin だけ同じでパスが違う iss は拒否する（同一 origin の別テナントなりすまし）', async () => {
    expect(await resolve(TENANT_A, TENANT_B)).toBe('rejected');
  });

  // 揺れの吸収はパスを捨てずに行う（捨てると上のなりすましが通る）。
  it('末尾スラッシュ・既定ポートの表記揺れは一致として扱う', async () => {
    expect(await resolve(TENANT_A, `${TENANT_A}/`)).toBe('resolved');
    expect(await resolve(TENANT_A, 'https://pid-provider.example.eu:443/tenant-a')).toBe(
      'resolved',
    );
  });

  it('ホストが違えば拒否する', async () => {
    expect(await resolve(TENANT_A, 'https://other-provider.example.eu/tenant-a')).toBe('rejected');
  });

  // `did:` も `new URL` はパースできる（scheme `did:`、host 無し、pathname `web:…`）ので、DID も
  // 正規化経路を通る。同じ規則を SAN URI 側にも掛けるため突き合わせは対称で、結果として
  // 「同じ DID なら通り、違う DID なら通らない」= 完全一致と同じ振る舞いになる。
  it('HTTPS でない iss（DID）も、同じ DID のときだけ通る', async () => {
    expect(
      await resolve('did:web:pid-provider.example.eu', 'did:web:pid-provider.example.eu'),
    ).toBe('resolved');
    expect(await resolve('did:web:pid-provider.example.eu', 'did:web:other.example.eu')).toBe(
      'rejected',
    );
  });

  // `URL.host` は userinfo を含まないため、正規化で組み戻さないと `https://a@ex/t` /
  // `https://b@ex/t` / `https://ex/t` が同じ文字列に畳まれ、異なる `iss` が同じ SAN へ束縛される。
  // パスを捨てないと決めたのと同じ理由で、userinfo も落とさない。
  it('userinfo が違う iss は拒否する（正規化で userinfo を落とさない）', async () => {
    expect(await resolve(`https://a@pid-provider.example.eu/tenant-a`, TENANT_A)).toBe('rejected');
    expect(await resolve(TENANT_A, `https://a@pid-provider.example.eu/tenant-a`)).toBe('rejected');
    expect(
      await resolve(
        `https://a@pid-provider.example.eu/tenant-a`,
        `https://b@pid-provider.example.eu/tenant-a`,
      ),
    ).toBe('rejected');
  });

  it('userinfo が一致していれば表記揺れは吸収する', async () => {
    expect(
      await resolve(
        `https://a@pid-provider.example.eu/tenant-a`,
        `https://a@pid-provider.example.eu/tenant-a/`,
      ),
    ).toBe('resolved');
  });
});
