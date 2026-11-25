/**
 * did-signing テストの共有フィクスチャ（実鍵・実 Resolver・実 PersonaManager。外部ネットワークは使わない）。
 *
 * - `newWorld()`: 固定ニーモニックの `KeyManager` + `PersonaManager`（メモリ storage）+ DID Resolver。
 * - 取り込み用の外部鍵（P-256 / secp256k1 / Ed25519）は固定バイトから作る秘密鍵 JWK。
 * - did:web は `fetchFn` の DI で `did.json` を返す。DID を解決できない外部メソッド（ethr / cheqd）は、
 *   実際の DID Document 生成関数（`buildDidEthrDocument`）または各メソッドの Document 形のスタブを返す
 *   `DIDMethod` を Resolver に登録する。
 */

import { base58, base64urlnopad } from '@scure/base';
import { MemoryStorage } from '../../../../storage/storage.js';
import type { DIDDocument, DIDMethod } from '../../../identity/did.js';
import { buildDidEthrDocument } from '../../../identity/ethr/events.js';
import { MethodJwk } from '../../../identity/jwk/method-jwk.js';
import { MethodJwt } from '../../../identity/jwt/method-jwt.js';
import { createDidKey, MethodKey } from '../../../identity/method-key.js';
import { MethodPeer } from '../../../identity/peer/method-peer.js';
import { Resolver } from '../../../identity/resolver.js';
import { MethodWeb } from '../../../identity/web/method-web.js';
import { getEd25519PublicKey } from '../../../keymanager/ed25519.js';
import { KeyManager } from '../../../keymanager/keymanager.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import { PersonaManager } from '../../../persona/persona.js';
import type { PrivateKeyJwk } from '../external-key.js';

export const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** 検証側の現在時刻（エポック秒）。 */
export const NOW = 1_767_225_600;

const b64u = (bytes: Uint8Array): string => base64urlnopad.encode(bytes);

/** 取り込む外部鍵（固定バイト）。公開鍵 JWK と秘密鍵 JWK を持つ。 */
export interface ExternalKey {
  readonly privateKeyJwk: PrivateKeyJwk;
  readonly publicKeyJwk: Readonly<Record<string, unknown>>;
  /** 圧縮公開鍵（Ed25519 は 32 バイト）。 */
  readonly publicKey: Uint8Array;
}

export function externalKey(kind: 'P-256' | 'secp256k1' | 'Ed25519', fill: number): ExternalKey {
  const d = new Uint8Array(32).fill(fill);
  if (kind === 'Ed25519') {
    const publicKey = getEd25519PublicKey(d);
    const publicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: b64u(publicKey) };
    return { privateKeyJwk: { ...publicKeyJwk, d: b64u(d) }, publicKeyJwk, publicKey };
  }
  const getPublic = kind === 'P-256' ? getP256PublicKey : getSecp256k1PublicKey;
  const uncompressed = getPublic(d, false);
  const publicKeyJwk = {
    kty: 'EC',
    crv: kind,
    x: b64u(uncompressed.subarray(1, 33)),
    y: b64u(uncompressed.subarray(33, 65)),
  };
  return {
    privateKeyJwk: { ...publicKeyJwk, d: b64u(d) },
    publicKeyJwk,
    publicKey: getPublic(d, true),
  };
}

/** `Resolver` に登録する、固定 DID Document を返すだけのスタブメソッド。 */
export function stubMethod(name: string, documents: Record<string, DIDDocument>): DIDMethod {
  return {
    method: () => name,
    create: async () => {
      throw new Error('unused');
    },
    resolve: async (did) => {
      const document = documents[did];
      if (document === undefined) {
        throw new Error(`stub: ${did} not registered`);
      }
      return document;
    },
    update: async () => {
      throw new Error('unused');
    },
    deactivate: async () => {
      throw new Error('unused');
    },
  };
}

/** `https:` の最終 URL を持つ `Response`（did:web の取得シームが最終 URL の HTTPS を検査する）。 */
function jsonResponse(url: string, body: unknown): Response {
  const response = new Response(JSON.stringify(body), {
    status: 200,
    // 鍵ローテーション直後の再解決を検証できるよう、resolver 側の TTL キャッシュを無効にする。
    headers: { 'content-type': 'application/did+json', 'cache-control': 'max-age=0' },
  });
  Object.defineProperty(response, 'url', { value: url });
  return response;
}

/** `did.json` の配信を模した `fetch`（URL → 文書）。未登録の URL は 404 相当で失敗する。 */
export function webFetch(files: Record<string, unknown>): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = String(input);
    const body = files[url];
    if (body === undefined) {
      return new Response('not found', { status: 404 });
    }
    return jsonResponse(url, body);
  }) as typeof fetch;
}

export interface World {
  readonly km: KeyManager;
  readonly personas: PersonaManager;
  readonly resolver: Resolver;
}

/** 固定ニーモニックの KeyManager・PersonaManager・Resolver を組み立てる。 */
export async function newWorld(
  opts: {
    readonly files?: Record<string, unknown>;
    readonly methods?: readonly DIDMethod[];
    readonly mnemonic?: string;
  } = {},
): Promise<World> {
  const km = new KeyManager();
  await km.importMnemonic(opts.mnemonic ?? TEST_MNEMONIC);
  let tick = 1_000;
  const personas = new PersonaManager(km, new MemoryStorage(), createDidKey, () => tick++);
  const resolver = new Resolver();
  resolver.register(new MethodKey());
  resolver.register(new MethodJwk());
  resolver.register(new MethodPeer());
  resolver.register(new MethodJwt());
  resolver.register(new MethodWeb({ fetchFn: webFetch(opts.files ?? {}) }));
  for (const method of opts.methods ?? []) {
    resolver.register(method);
  }
  return { km, personas, resolver };
}

/** did:ethr（chain 1）の DID Document。`attrs` は実 builder へ渡す属性変更イベント。 */
export function ethrDocument(
  address: string,
  attrs: readonly { name: string; value: string }[],
): { did: string; document: DIDDocument } {
  const did = `did:ethr:1:${address}`;
  const document = buildDidEthrDocument(
    did,
    address,
    1,
    {
      ownerChanges: [],
      attributeChanges: attrs.map((attr, i) => ({
        ...attr,
        validTo: NOW + 100_000,
        blockNumber: 5,
        logIndex: i,
      })),
    },
    NOW,
  );
  return { did, document };
}

/** did:cheqd 形の DID Document（Ed25519VerificationKey2018 + publicKeyBase58）。 */
export function cheqdDocument(publicKey: Uint8Array): { did: string; document: DIDDocument } {
  const did = 'did:cheqd:testnet:a86f9cae-0902-4a7c-a144-96b60ced2fc9';
  const vm = `${did}#key-1`;
  return {
    did,
    document: {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      controller: [did],
      verificationMethod: [
        {
          id: vm,
          type: 'Ed25519VerificationKey2018',
          controller: did,
          publicKeyBase58: base58.encode(publicKey),
        },
      ],
      authentication: [vm],
      assertionMethod: [vm],
    },
  };
}
