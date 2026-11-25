// test/interop/adapters/veramo/agent.mjs
//
// Veramo（実ライブラリ・npm 公式パッケージ、モックなし）の agent を組み立てる。`server.mjs`（相互運用ピア）と
// 実 Veramo の発行 JWT を検査する回帰テスト（`__tests__/adapter-issue-jwt.veramo.test.mjs`）が同じ構成を共有する。

import { createAgent } from '@veramo/core';
import { CredentialProviderJWT } from '@veramo/credential-jwt';
import { CredentialPlugin } from '@veramo/credential-w3c';
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager';
import { getDidJwkResolver } from '@veramo/did-provider-jwk';
import { KeyDIDProvider } from '@veramo/did-provider-key';
import { DIDResolverPlugin } from '@veramo/did-resolver';
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager';
import { KeyManagementSystem } from '@veramo/kms-local';
import { Resolver } from 'did-resolver';
import { getResolver as getKeyResolver } from 'key-did-resolver';

/**
 * この agent が解決できる DID メソッド。`server.mjs` の `GET /identifiers/{did}` が使う
 * （このマトリクスで駆動するのは did:key と did:jwk）。
 *
 * did:web / did:ethr は解決器（`web-did-resolver` / `ethr-did-resolver`）自体は入手できるが、
 * 解決先の HTTPS ホスト・EIP-1056 registry を載せたチェーン fixture が harness に無く、
 * 登録しても一度も駆動できない。fixture が入る Issue で解決器ごと追加する。
 */
function createResolver() {
  return new Resolver({ ...getKeyResolver(), ...getDidJwkResolver() });
}

/** `did:key` + JWT-VC（メモリストア）の Veramo agent を返す。 */
export function createVeramoAgent() {
  return createAgent({
    plugins: [
      new KeyManager({
        store: new MemoryKeyStore(),
        kms: { local: new KeyManagementSystem(new MemoryPrivateKeyStore()) },
      }),
      new DIDManager({
        store: new MemoryDIDStore(),
        defaultProvider: 'did:key',
        providers: { 'did:key': new KeyDIDProvider({ defaultKms: 'local' }) },
      }),
      new DIDResolverPlugin({ resolver: createResolver() }),
      new CredentialPlugin([new CredentialProviderJWT()]),
    ],
  });
}
