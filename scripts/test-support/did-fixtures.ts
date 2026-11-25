/** SDK所有のbuilderを再利用する、公開可能なテスト専用素材生成器。 */

import { base64urlnopad } from '@scure/base';
import { createPrivateKeySigner } from '../../src/internal/credential/vc/signer.js';
import { rawCidOf } from '../../src/internal/identity/ipid/__tests__/cid-fixture.js';
import { createDidJwt } from '../../src/internal/identity/jwt/generate.js';
import { multibaseBase58Encode } from '../../src/internal/identity/multibase.js';
import {
  createDidPeer0,
  encodePublicKeyMultibase,
} from '../../src/internal/identity/peer/method-peer.js';
import {
  keyFromSeed,
  signEntry,
  toJsonl,
} from '../../src/internal/identity/webvh/__tests__/webvh-fixtures.js';
import type { WebVhCreateDocument } from '../../src/internal/identity/webvh/lifecycle/lifecycle.js';
import { createDidWebVh, updateDidWebVh } from '../../src/internal/identity/webvh/method-webvh.js';
import { eddsaJcs2022HashData } from '../../src/internal/identity/webvh/proof.js';
import { witnessDocumentHash } from '../../src/internal/identity/webvh/witness/verify.js';
import { signEd25519 } from '../../src/internal/keymanager/ed25519.js';

export const FIXTURE_TIME = '2026-01-01T00:00:00Z';
export interface HostedDidOptions {
  readonly host: string;
  readonly versions?: number;
  /** 公開テスト鍵。実運用では使用しない。 */
  readonly seed?: number;
  readonly time?: string;
  readonly witness?: boolean;
  readonly document?: WebVhCreateDocument;
}

/** 任意host/版数の署名済みログ。内部builder自体を拡張へコピーしない。 */
export async function hostedWebVh(options: HostedDidOptions) {
  const { host, versions = 1, seed = 53, time = FIXTURE_TIME, witness = false } = options;
  if (
    !Number.isInteger(seed) ||
    seed < 0 ||
    seed > 254 ||
    !Number.isInteger(versions) ||
    versions < 1 ||
    versions > 100
  ) {
    throw new Error('Invalid synthetic fixture options');
  }
  const key = keyFromSeed(new Uint8Array(32).fill(seed));
  const witnessKey = keyFromSeed(new Uint8Array(32).fill(seed + 1));
  const witnessId = `did:key:${witnessKey.multikey}`;
  const { did, logEntry } = createDidWebVh({
    domain: host,
    updateKeys: [key.multikey],
    versionTime: time,
    ...(options.document ? { document: options.document } : {}),
    ...(witness ? { witness: { threshold: 1, witnesses: [{ id: witnessId }] } } : {}),
  });
  const log = [signEntry(logEntry, key)];
  while (log.length < versions) {
    const last = log[log.length - 1];
    if (!last) throw new Error('Missing synthetic genesis');
    log.push(
      signEntry(
        updateDidWebVh({
          previousLog: log,
          state: last.state,
          versionTime: new Date(Date.parse(time) + log.length * 1000).toISOString(),
        }),
        key,
      ),
    );
  }
  const bodies: Record<string, { text: string; contentType: string }> = {
    '/.well-known/did.jsonl': { text: toJsonl(log), contentType: 'application/jsonl' },
  };
  if (witness) {
    const last = log[log.length - 1];
    if (!last) throw new Error('Missing synthetic final version');
    // 公開witness生成APIは実時計を使うため、テスト素材では既存hash/signを固定時刻で合成する。
    const config = {
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      verificationMethod: `${witnessId}#${witnessKey.multikey}`,
      created: time,
      proofPurpose: 'assertionMethod',
    };
    const signature = signEd25519(
      eddsaJcs2022HashData(config, witnessDocumentHash(last.versionId)),
      witnessKey.secretKey,
    );
    const proof = { ...config, proofValue: multibaseBase58Encode(signature) };
    bodies['/.well-known/did-witness.json'] = {
      text: JSON.stringify([{ versionId: last.versionId, proof: [proof] }]),
      contentType: 'application/json',
    };
  }
  return { did, host, versions, bodies };
}

/** ネットワーク不要なDIDとCIDに束縛された合成本文。 */
export function localDids(seed = 53) {
  const privateKey = new Uint8Array(32).fill(seed);
  const signer = createPrivateKeySigner(privateKey, 'EdDSA');
  const publicKey = base64urlnopad.decode(String(signer.publicKeyJwk.x));
  const body = JSON.stringify({
    '@context': ['https://www.w3.org/ns/did/v1'],
    verificationMethod: [
      { id: '#key-1', type: 'JsonWebKey2020', controller: '', publicKeyJwk: signer.publicKeyJwk },
    ],
    authentication: ['#key-1'],
    assertionMethod: ['#key-1'],
  });
  return {
    publicKeyJwk: signer.publicKeyJwk,
    peer: createDidPeer0(encodePublicKeyMultibase('Ed25519', publicKey)),
    jwt: createDidJwt({ alg: 'EdDSA', privateKey, iat: Date.parse(FIXTURE_TIME) / 1000 }),
    ipid: { did: `did:ipid:${rawCidOf(body)}`, body },
  };
}
