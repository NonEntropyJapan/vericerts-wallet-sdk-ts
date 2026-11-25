/**
 * ネットワーク取得を伴う DID メソッド（did:ion / did:ebsi / did:webvh / did:ipid）の署名ラウンドトリップ。
 *
 * 各メソッドの**実際の** `Method*`（`MethodIon` / `MethodEbsi` / `MethodWebVh` / `MethodIpid`）を Resolver に登録し、
 * ノード・Gateway・配信サーバーの応答だけを `fetch` のスタブで返す。DID Document はスタブが返した応答を各メソッドの
 * 解決器が組み立てた形（did:ion の相対 DID URL の絶対化、did:ipid の `id` 補完、did:webvh の DID Log 検証など）で、
 * 署名・検証の本体は `roundtrip-suite.ts`（VP / VC / SIOPv2 id_token / signMessage）。
 */

import { afterAll, beforeAll } from 'bun:test';
import { jsonReply, recordingFetch } from '../../../identity/__tests__/network-method.fixtures.js';
import { ebsiDocument } from '../../../identity/ebsi/__tests__/ebsi.fixtures.js';
import { MethodEbsi } from '../../../identity/ebsi/method-ebsi.js';
import { ionResponse, makeIonCreate } from '../../../identity/ion/__tests__/ion.fixtures.js';
import { MethodIon } from '../../../identity/ion/method-ion.js';
import { rawCidOf } from '../../../identity/ipid/__tests__/cid-fixture.js';
import { MethodIpid } from '../../../identity/ipid/method-ipid.js';
import { encodePublicKeyMultibase } from '../../../identity/peer/method-peer.js';
import {
  generateKey,
  signEntry,
  toJsonl,
} from '../../../identity/webvh/__tests__/webvh-fixtures.js';
import { createDidWebVh, MethodWebVh } from '../../../identity/webvh/method-webvh.js';
import { externalKey, newWorld } from './fixtures.js';
import { type Case, defineRoundtripSuite, imported } from './roundtrip-suite.js';

const SECP_KEY = externalKey('secp256k1', 41);
const P256_KEY = externalKey('P-256', 42);
const ED_KEY = externalKey('Ed25519', 43);

/** did:webvh / did:ipid が使うグローバル `fetch` の差し替え（URL → 本文）。 */
const served = new Map<string, { body: string; contentType: string }>();
const originalFetch = globalThis.fetch;

beforeAll(() => {
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url =
      typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const hit = served.get(url);
    if (hit === undefined) {
      return new Response('not found', { status: 404 });
    }
    const response = new Response(hit.body, {
      status: 200,
      headers: { 'content-type': hit.contentType },
    });
    Object.defineProperty(response, 'url', { value: url, configurable: true });
    return response;
  }) as unknown as typeof fetch;
});

afterAll(() => {
  globalThis.fetch = originalFetch;
});

const NODE_URL = 'https://ion.example.org';
const API_URL = 'https://api-pilot.ebsi.example.org';
const EBSI_DID = 'did:ebsi:zvHWX359A3CvfJnCYaAiAde';

const CASES: readonly Case[] = [
  {
    name: 'did:ion（Sidetree ノードの応答。相対 DID URL は解決器が絶対化、secp256k1）',
    alg: 'ES256K',
    setup: async () => {
      const create = makeIonCreate();
      const did = create.shortForm;
      const vm = {
        id: '#signing',
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: SECP_KEY.publicKeyJwk,
      };
      const { fetchFn } = recordingFetch(() =>
        jsonReply(
          ionResponse(did, create, {
            document: {
              verificationMethod: [vm],
              authentication: ['#signing'],
              assertionMethod: ['#signing'],
            },
          }),
          'application/did+ld+json',
        ),
      );
      const world = await newWorld({ methods: [new MethodIon({ nodeUrl: NODE_URL, fetchFn })] });
      return imported(world, did, SECP_KEY.privateKeyJwk);
    },
  },
  {
    name: 'did:ebsi（DID Registry の応答、P-256 の authentication / assertionMethod）',
    alg: 'ES256',
    setup: async () => {
      const vm = {
        id: `${EBSI_DID}#es256`,
        type: 'JsonWebKey2020',
        controller: EBSI_DID,
        publicKeyJwk: P256_KEY.publicKeyJwk,
      };
      const document = ebsiDocument(EBSI_DID, {
        verificationMethod: [vm],
        authentication: [vm.id],
        assertionMethod: [vm.id],
        capabilityInvocation: [],
      });
      const { fetchFn } = recordingFetch(() => jsonReply(document, 'application/did+ld+json'));
      const world = await newWorld({ methods: [new MethodEbsi({ apiUrl: API_URL, fetchFn })] });
      return imported(world, EBSI_DID, P256_KEY.privateKeyJwk);
    },
  },
  {
    name: 'did:webvh（検証済み DID Log の state、Ed25519 Multikey）',
    alg: 'EdDSA',
    setup: async () => {
      const updateKey = generateKey();
      const vmId = 'did:webvh:{SCID}:vericerts.io#key-1';
      const { did, logEntry } = createDidWebVh({
        domain: 'vericerts.io',
        updateKeys: [updateKey.multikey],
        document: {
          '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
          verificationMethod: [
            {
              id: vmId,
              type: 'Multikey',
              controller: 'did:webvh:{SCID}:vericerts.io',
              publicKeyMultibase: encodePublicKeyMultibase('Ed25519', ED_KEY.publicKey),
            },
          ],
          authentication: [vmId],
          assertionMethod: [vmId],
        },
      });
      served.set('https://vericerts.io/.well-known/did.jsonl', {
        body: toJsonl([signEntry(logEntry, updateKey)]),
        contentType: 'application/jsonl',
      });
      const world = await newWorld({ methods: [new MethodWebVh()] });
      return imported(world, did, ED_KEY.privateKeyJwk);
    },
  },
  {
    name: 'did:ipid（Gateway の CID 本文。id は解決器が補完、相対参照 #key-1、Ed25519）',
    alg: 'EdDSA',
    setup: async () => {
      // `MethodIpid.create` が IPFS へ保存する正規形（id なし・相対参照）。
      const canonical = {
        '@context': ['https://www.w3.org/ns/did/v1'],
        verificationMethod: [
          {
            id: '#key-1',
            type: 'Ed25519VerificationKey2020',
            controller: '',
            publicKeyMultibase: encodePublicKeyMultibase('Ed25519', ED_KEY.publicKey),
          },
        ],
        authentication: ['#key-1'],
        assertionMethod: ['#key-1'],
      };
      const body = JSON.stringify(canonical);
      const cid = rawCidOf(body);
      served.set(`https://ipfs.io/ipfs/${cid}`, { body, contentType: 'application/did+json' });
      const world = await newWorld({ methods: [new MethodIpid()] });
      return imported(world, `did:ipid:${cid}`, ED_KEY.privateKeyJwk);
    },
  },
];

defineRoundtripSuite(CASES);
