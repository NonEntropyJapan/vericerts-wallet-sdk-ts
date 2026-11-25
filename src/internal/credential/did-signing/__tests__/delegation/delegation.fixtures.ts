/**
 * 委任 DIDのテスト用フィクスチャ。委任先 `D`（did:web）の `did.json` を可変にしておき、登録後の失効・鍵の
 * 差し替えを実 Resolver（キャッシュ無効の did:web）で再現する。
 */

import type { DIDDocument } from '../../../../identity/did.js';
import type { PersonaMetadata } from '../../../../persona/types.js';
import { type PersonaSigner, resolvePersonaSigner } from '../../persona-signer.js';
import { newWorld, type World } from '../fixtures.js';

/** 委任先 DID `D`。 */
export const DELEGATED_DID = 'did:web:corp.example';
const DELEGATED_URL = 'https://corp.example/.well-known/did.json';
/** `D` の検証メソッド id（埋め込み）。 */
export const EMBEDDED_KID = `${DELEGATED_DID}#agent-1`;

export type DidJson = Record<string, unknown>;

export interface Delegation {
  readonly world: World;
  readonly persona: PersonaMetadata;
  /** ペルソナ自身の署名鍵（自分の DID 用の `kid` 付き）。 */
  readonly own: PersonaSigner;
  /** `D` の `did.json`（配信内容）。書き換えると次の解決に反映される。 */
  readonly files: Record<string, unknown>;
  /** `D` の文書を作り直して配信する。 */
  publish(overrides: DidJson): void;
}

/** `D` の既定文書（controller にペルソナ、`authentication` に `K` の検証メソッドを埋め込みで載せる）。 */
export function delegatedDocument(
  persona: PersonaMetadata,
  own: PersonaSigner,
  overrides: DidJson = {},
): DIDDocument {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: DELEGATED_DID,
    controller: [persona.did],
    verificationMethod: [
      {
        id: EMBEDDED_KID,
        type: 'JsonWebKey2020',
        controller: DELEGATED_DID,
        publicKeyJwk: own.signer.publicKeyJwk,
      },
    ],
    authentication: [EMBEDDED_KID],
    assertionMethod: [],
    ...overrides,
  } as DIDDocument;
}

/** ペルソナを 1 件作り、`D` を既定文書で配信する世界を組み立てる。 */
export async function newDelegation(
  keyType: 'P-256' | 'secp256k1',
  overrides: DidJson = {},
): Promise<Delegation> {
  const files: Record<string, unknown> = {};
  const world = await newWorld({ files });
  // 新規作成は P-256 のみ。secp256k1 は既存の旧レコード（did:key + secp256k1）の復元経路で用意する。
  const persona =
    keyType === 'P-256'
      ? await world.personas.createPersona({ method: 'key', keyType })
      : await world.personas.restoreLegacyPersona({ index: 0 });
  const own = await resolvePersonaSigner(world.km, persona);
  const publish = (next: DidJson): void => {
    files[DELEGATED_URL] = delegatedDocument(persona, own, next);
  };
  publish(overrides);
  return { world, persona, own, files, publish };
}

/** 失敗した Promise の `VericertsError.code` と `context.reason`。 */
export interface Failure {
  readonly code?: string;
  readonly reason?: string;
}

interface ErrorShape {
  readonly code?: string;
  readonly context?: { readonly reason?: string };
}

/** 失敗した Promise の失敗内容。成功したら `undefined`。 */
export async function failureOf(promise: Promise<unknown>): Promise<Failure | undefined> {
  try {
    await promise;
  } catch (error) {
    // `VericertsError`（`code` / `context.reason` を持つ）以外が来ても読むだけで失敗しない形に揃える。
    const shape = error as ErrorShape;
    return { code: shape.code, reason: shape.context?.reason };
  }
  return undefined;
}
