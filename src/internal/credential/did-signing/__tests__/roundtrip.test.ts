/**
 * 各 DID メソッドの署名ラウンドトリップ。
 *
 * ペルソナの署名鍵（`resolvePersonaSigner`）で VP / VC / SIOPv2 id_token / signMessage を署名し、SDK の
 * 検証経路（`verifyPresentation` / `verifyCredential` / DID Document から引いた検証鍵 / `verifyMessageJws`）で
 * 検証する。署名した JWS の `kid` が DID Document 上の検証メソッドで、`alg` が鍵の種類に合うことも確かめる。
 *
 * 検証の本体は `roundtrip-suite.ts`。ネットワーク取得を伴うメソッド（ion / ebsi / webvh / ipid）は `roundtrip.network.test.ts`。
 *
 * 対象（実鍵・実 Resolver。did:web は `fetch` の DI、did:ethr は実 DID Document builder）:
 * key P-256 / key secp256k1（レガシー既定）/ key Ed25519（取り込み）/ jwk P-256 / peer P-256・secp256k1・Ed25519 /
 * web（シード由来 P-256・外部 secp256k1）/ ethr（delegate の publicKeyHex）/ jwt / cheqd（Ed25519）。
 */

import { expect } from 'bun:test';
import { createDidJwt } from '../../../identity/jwt/generate.js';
import { createDidKey } from '../../../identity/method-key.js';
import { createDidPeer2, encodePublicKeyMultibase } from '../../../identity/peer/method-peer.js';
import { buildDidWebDocument } from '../did-document-export.js';
import { importPersonaFromDid } from '../import-persona.js';
import { cheqdDocument, ethrDocument, externalKey, NOW, newWorld, stubMethod } from './fixtures.js';
import { type Case, defineRoundtripSuite, imported, type Setup } from './roundtrip-suite.js';

const SECP_KEY = externalKey('secp256k1', 21);
const ED_KEY = externalKey('Ed25519', 22);
const P256_KEY = externalKey('P-256', 23);

async function created(method: 'key' | 'jwk' | 'peer'): Promise<Setup> {
  const world = await newWorld();
  return { world, persona: await world.personas.createPersona({ method }) };
}

const CASES: readonly Case[] = [
  { name: 'did:key P-256（新規作成）', alg: 'ES256', setup: () => created('key') },
  {
    name: 'did:key secp256k1（既存レコードの復元。新規作成はできない）',
    alg: 'ES256K',
    setup: async () => {
      const world = await newWorld();
      return { world, persona: await world.personas.restoreLegacyPersona({ index: 0 }) };
    },
  },
  {
    name: 'did:key Ed25519（取り込み）',
    alg: 'EdDSA',
    setup: async () =>
      imported(
        await newWorld(),
        createDidKey('Ed25519', ED_KEY.publicKey).id,
        ED_KEY.privateKeyJwk,
      ),
  },
  { name: 'did:jwk P-256（新規作成）', alg: 'ES256', setup: () => created('jwk') },
  { name: 'did:peer P-256（新規作成）', alg: 'ES256', setup: () => created('peer') },
  {
    name: 'did:peer Ed25519（取り込み）',
    alg: 'EdDSA',
    setup: async () =>
      imported(
        await newWorld(),
        createDidPeer2({
          verificationKeys: [encodePublicKeyMultibase('Ed25519', ED_KEY.publicKey)],
        }),
        ED_KEY.privateKeyJwk,
      ),
  },
  {
    name: 'did:web（シード由来 P-256 を取り込み、did.json は書き出し結果を配信）',
    alg: 'ES256',
    setup: async () => {
      const probe = await newWorld();
      const did = 'did:web:example.com:users:alice';
      const seedKey = await probe.km.deriveP256Key("m/9256'/0'/7'/0'");
      const exported = buildDidWebDocument({
        did,
        publicKeyJwk: probe.km.getCredentialSigner(seedKey.id).publicKeyJwk,
      });
      expect(exported.url).toBe('https://example.com/users/alice/did.json');
      const world = await newWorld({ files: { [exported.url]: exported.document } });
      const persona = await importPersonaFromDid(
        { personas: world.personas, keymanager: world.km, resolver: world.resolver },
        { did, key: { seed: { keyType: 'P-256', index: 7 } } },
      );
      return { world, persona };
    },
  },
  {
    name: 'did:web（外部 secp256k1）',
    alg: 'ES256K',
    setup: async () => {
      const did = 'did:web:example.org';
      const exported = buildDidWebDocument({ did, publicKeyJwk: SECP_KEY.publicKeyJwk });
      expect(exported.path).toBe('.well-known/did.json');
      const world = await newWorld({ files: { [exported.url]: exported.document } });
      return imported(world, did, SECP_KEY.privateKeyJwk);
    },
  },
  {
    name: 'did:ethr（delegate の publicKeyHex、secp256k1 の veriKey / sigAuth）',
    alg: 'ES256K',
    setup: async () => {
      const value = `0x${Buffer.from(SECP_KEY.publicKey).toString('hex')}`;
      // sigAuth は authentication のみ、veriKey は assertionMethod のみに載る（did:ethr 仕様）。VP / SIOP / signMessage と
      // VC 発行の両方を通すため、同じ鍵を両方の属性で登録する。
      const { did, document } = ethrDocument('0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb', [
        { name: 'did/pub/Secp256k1/sigAuth/hex', value },
        { name: 'did/pub/Secp256k1/veriKey/hex', value },
      ]);
      const world = await newWorld({ methods: [stubMethod('ethr', { [did]: document })] });
      return imported(world, did, SECP_KEY.privateKeyJwk);
    },
  },
  {
    name: 'did:jwt（P-256）',
    alg: 'ES256',
    setup: async () => {
      const did = createDidJwt({
        alg: 'ES256',
        privateKey: new Uint8Array(32).fill(23),
        iat: NOW - 10,
        // did:jwt の解決は実時刻で exp を評価するため、テストの実行日に依存しない長い有効期間にする。
        expiresInSeconds: 20 * 365 * 24 * 3600,
      });
      return imported(await newWorld(), did, P256_KEY.privateKeyJwk);
    },
  },
  {
    name: 'did:cheqd（Ed25519、publicKeyBase58）',
    alg: 'EdDSA',
    setup: async () => {
      const { did, document } = cheqdDocument(ED_KEY.publicKey);
      const world = await newWorld({ methods: [stubMethod('cheqd', { [did]: document })] });
      return imported(world, did, ED_KEY.privateKeyJwk);
    },
  },
];

defineRoundtripSuite(CASES);
