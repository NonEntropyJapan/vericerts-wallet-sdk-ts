/**
 * did:ion の単体テスト共通フィクスチャ。
 *
 * 実装（`did-ion.ts`）とは独立に、`node:crypto` と素朴な再帰 JCS で Sidetree の did-suffix・deltaHash・
 * long-form を組み立てる。
 */

import { createHash } from 'node:crypto';
import { secp256k1Jwk } from '../../__tests__/network-method.fixtures.js';

export const NODE_URL = 'https://ion.example.org';

/** RFC 8785 相当（テストが使う文字列・配列・オブジェクトだけを扱う）。 */
function jcs(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(jcs).join(',')}]`;
  }
  if (typeof value === 'object' && value !== null) {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a < b ? -1 : 1,
    );
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${jcs(v)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

/** Sidetree の `canonicalizeThenHashThenEncode`（sha2-256 multihash の base64url）。 */
export function multihash(value: unknown): string {
  const digest = createHash('sha256').update(jcs(value)).digest();
  return Buffer.concat([Buffer.from([0x12, 0x20]), digest]).toString('base64url');
}

/** 初期状態 1 件ぶんの Create 材料。 */
export interface IonCreate {
  readonly suffix: string;
  readonly shortForm: string;
  readonly longForm: string;
  readonly suffixData: Record<string, unknown>;
  readonly delta: Record<string, unknown>;
}

/** 検証可能な long-form を作る。`seed` で別の DID になる。 */
export function makeIonCreate(seed = 1): IonCreate {
  const delta = {
    patches: [
      {
        action: 'replace',
        document: {
          publicKeys: [
            {
              id: 'signing',
              type: 'JsonWebKey2020',
              publicKeyJwk: secp256k1Jwk(seed),
              purposes: ['assertionMethod'],
            },
          ],
        },
      },
    ],
    updateCommitment: multihash(`update-${seed}`),
  };
  const suffixData = {
    deltaHash: multihash(delta),
    recoveryCommitment: multihash(`recovery-${seed}`),
  };
  const suffix = multihash(suffixData);
  const initialState = Buffer.from(jcs({ suffixData, delta })).toString('base64url');
  return {
    suffix,
    shortForm: `did:ion:${suffix}`,
    longForm: `did:ion:${suffix}:${initialState}`,
    suffixData,
    delta,
  };
}

/** `longForm` の初期状態セグメントを別の JSON に差し替えた DID（suffix はそのまま）。 */
export function withInitialState(create: IonCreate, state: unknown): string {
  return `did:ion:${create.suffix}:${Buffer.from(JSON.stringify(state)).toString('base64url')}`;
}

/** Sidetree ノードの解決応答（相対 DID URL つき）。 */
export function ionResponse(
  did: string,
  create: IonCreate,
  overrides: {
    metadata?: Record<string, unknown>;
    document?: Record<string, unknown>;
    published?: boolean;
  } = {},
): Record<string, unknown> {
  return {
    '@context': 'https://w3id.org/did-resolution/v1',
    didDocument: {
      id: did,
      '@context': ['https://www.w3.org/ns/did/v1'],
      service: [{ id: '#hub', type: 'IdentityHub', serviceEndpoint: 'https://hub.example.org' }],
      verificationMethod: [
        {
          id: '#signing',
          controller: did,
          type: 'JsonWebKey2020',
          publicKeyJwk: secp256k1Jwk(),
        },
      ],
      assertionMethod: ['#signing'],
      ...overrides.document,
    },
    didDocumentMetadata: {
      canonicalId: create.shortForm,
      equivalentId: [create.shortForm, create.longForm],
      method: {
        published: overrides.published ?? true,
        updateCommitment: create.delta.updateCommitment,
        recoveryCommitment: create.suffixData.recoveryCommitment,
      },
      ...overrides.metadata,
    },
  };
}
