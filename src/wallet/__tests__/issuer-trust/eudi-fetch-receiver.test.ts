/**
 * `createWallet` が渡す fetch のレシーバ束縛（`internal/fetch-di.ts`）の回帰テスト。
 *
 * `eudiFetchImpl` は `nonObjectPrototypeProperty` で読む —— つまり
 * `class Deps { eudiFetchImpl(url, init) { return this.agent.fetch(url, init) } }` のように
 * **prototype メソッドとして実装するのは正当な DI** である（接続プールや証明書ピンニングを
 * インスタンスに持つ fetch はこの形になる）。ところがシームは**関数値のまま**下流へ配られ、
 * 受け取る `fetchJsonWithinLimits` が束ね直せるのは合成リテラル `{ fetchImpl }` であって
 * 呼び出し側の DI オブジェクトではない（`http/fetch-json.ts` の docblock）。したがって
 * **配る側（`wallet/factory.ts`）が束ねない限り `this` は失われる**。
 *
 * 失敗は無言である点が厄介で、`this.…` の参照が TypeError になっても各経路の catch が
 * 「取得に失敗した」へ正規化するため、注入した fetch が壊れていることは通信障害と区別が付かない
 * （metadata 経路なら `3010` `issuer_key_unresolved` の幻の障害になる）。そこで
 * **インスタンス状態を実際に使う DI で受領が最後まで通ること**を固定する。
 *
 * 本ファイルが覆うのは、同じ 1 つのシームが分かれて流れる 2 経路である。
 *
 * 1. EUDI の発行者通信（`EudiFacade` → OID4VCI の Metadata / Nonce / Token / Credential）
 * 2. JWT VC Issuer Metadata による Issuer 鍵解決（`issuer-trust/resolve.ts` →
 *    `jwt-vc-issuer.ts` → `fetchWellKnownJson`）
 */

import { describe, expect, it } from 'bun:test';
import type { FetchLike } from '../../../internal/auth/oid4vci/oid4vci.js';
import { PID_VCT } from '../../../internal/eudi/pid/index.js';
import type { Storage } from '../../../storage/storage.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import type { Wallet } from '../../types.js';
import {
  buildSdJwtVcWith,
  createStub,
  ISSUER,
  ISSUER_PUBLIC_JWK,
  jsonResponse,
  offerURI,
  TEST_MNEMONIC,
  VALID_PID_CLAIMS,
} from '../eudi/eudi-fixtures.js';
import { WELL_KNOWN_URL } from '../eudi/jwt-vc-issuer/jwt-vc-issuer-fixtures.js';

/**
 * `eudiFetchImpl` を **prototype メソッド**として実装した `createWallet` オプション。
 *
 * 転送先の `route` をインスタンスに持つので、裸で呼ばれると `this` が `undefined` になり
 * `this.route` の参照が TypeError になる。`storage` / `jwtVcIssuerMetadataResolution` は
 * 純データなので own プロパティに置く（読み取り側が `ownProperty` で読むため）。
 */
class PinnedWalletDeps {
  readonly storage: Storage;
  readonly jwtVcIssuerMetadataResolution = true;
  /** 束縛が効いていれば呼ばれた回数（`this` が失われると 0 のまま）。 */
  calls = 0;

  constructor(
    storage: Storage,
    private readonly route: FetchLike,
  ) {
    this.storage = storage;
  }

  eudiFetchImpl(url: string, init: Parameters<FetchLike>[1]): Promise<Response> {
    this.calls += 1;
    return this.route(url, init);
  }
}

/** `PinnedWalletDeps` を注入した Wallet を、アクティブペルソナまで設定して返す。 */
async function pinnedWallet(): Promise<{
  wallet: Wallet;
  deps: PinnedWalletDeps;
  urls: () => readonly string[];
}> {
  const sdJwt = buildSdJwtVcWith({ vct: PID_VCT, claims: VALID_PID_CLAIMS, iss: ISSUER });
  const stub = createStub(sdJwt, {
    [WELL_KNOWN_URL]: () => jsonResponse({ issuer: ISSUER, jwks: { keys: [ISSUER_PUBLIC_JWK] } }),
  });
  const deps = new PinnedWalletDeps(new MemoryStorage(), stub.fetchImpl);
  const wallet = await createWallet(deps);
  await wallet.importMnemonic(TEST_MNEMONIC);
  const persona = await wallet.createPersona();
  await wallet.setActivePersona(persona.id);
  return { wallet, deps, urls: () => stub.calls.map((call) => call.url) };
}

describe('createWallet の eudiFetchImpl レシーバ束縛', () => {
  it('this 参照つきクラス DI でも PID を受領できる（発行者通信と鍵解決の両経路）', async () => {
    const { wallet, deps, urls } = await pinnedWallet();

    const pid = await wallet.receivePID(offerURI());

    expect(pid.claims.family_name).toBe('Bianchi');
    // 経路 2（JWT VC Issuer Metadata）も同じ束ね済みシームで到達していること。
    expect(urls()).toContain(WELL_KNOWN_URL);
    // 経路 1（OID4VCI）と合わせて、すべての取得がインスタンス経由で行われたこと。
    expect(deps.calls).toBe(urls().length);
  });
});
