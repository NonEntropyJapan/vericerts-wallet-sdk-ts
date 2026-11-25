/**
 * did:plc の DID Document の組み立てと、ディレクトリ応答との一致確認。
 *
 * 組み立ては参照実装 `formatDidDoc` に従う。PLC は `authentication` / `assertionMethod` を出さないため、
 * 既定ではどちらも空配列（VC / VP の署名検証は鍵を見つけられず fail-closed）。`relationshipsForKeys` で
 * 明示された鍵名だけに検証関係を付ける。
 *
 * 一致確認は、検証済みの操作列から組み立てた文書と、ディレクトリが返した文書の比較である。順序に意味を持たない
 * 配列（`@context` / `verificationMethod` / `service`）は順不同で比べ、未知のキーを持つ応答は拒否する。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { DIDDocument, Service, VerificationMethod } from '../did.js';
import { parseKey } from './keys.js';
import type { PlcOperationData } from './operation.js';

/** `relationshipsForKeys` が付与できる検証関係。 */
export type PlcRelationship = 'authentication' | 'assertionMethod';

const BASE_CONTEXT = ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'];
const KEY_CONTEXTS = {
  'P-256': 'https://w3id.org/security/suites/ecdsa-2019/v1',
  secp256k1: 'https://w3id.org/security/suites/secp256k1-2019/v1',
} as const;
const DID_KEY_PREFIX = 'did:key:';
const DIRECTORY_DOCUMENT_KEYS = ['@context', 'id', 'alsoKnownAs', 'verificationMethod', 'service'];

/** 検証済みの状態データから DID Document を組み立てる。 */
export function buildPlcDocument(
  did: string,
  data: PlcOperationData,
  relationshipsForKeys: Readonly<Record<string, readonly PlcRelationship[]>>,
): DIDDocument {
  const context = [...BASE_CONTEXT];
  const verificationMethod: VerificationMethod[] = [];
  const authentication: string[] = [];
  const assertionMethod: string[] = [];
  for (const [name, didKey] of Object.entries(data.verificationMethods)) {
    const { keyType } = parseKey(didKey);
    const keyContext = keyType === 'Ed25519' ? undefined : KEY_CONTEXTS[keyType];
    if (keyContext !== undefined && !context.includes(keyContext)) {
      context.push(keyContext);
    }
    const id = `${did}#${name}`;
    verificationMethod.push({
      id,
      type: 'Multikey',
      controller: did,
      publicKeyMultibase: didKey.slice(DID_KEY_PREFIX.length),
    });
    const relationships = Object.hasOwn(relationshipsForKeys, name)
      ? (relationshipsForKeys[name] as readonly PlcRelationship[])
      : [];
    if (relationships.includes('authentication')) {
      authentication.push(id);
    }
    if (relationships.includes('assertionMethod')) {
      assertionMethod.push(id);
    }
  }
  const service: Service[] = Object.entries(data.services).map(([name, entry]) => ({
    id: `#${name}`,
    type: entry.type,
    serviceEndpoint: entry.endpoint,
  }));
  return {
    '@context': context,
    id: did,
    alsoKnownAs: [...data.alsoKnownAs],
    verificationMethod,
    authentication,
    assertionMethod,
    service,
  };
}

/** キー順に依存しない JSON（比較用）。 */
function canonical(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(',')}]`;
  }
  if (typeof value === 'object' && value !== null) {
    const entries = Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`);
    return `{${entries.join(',')}}`;
  }
  return JSON.stringify(value);
}

/** 欠落は空配列、配列以外は `undefined`（= 不一致）。 */
function asArray(value: unknown): unknown[] | undefined {
  if (value === undefined) {
    return [];
  }
  return Array.isArray(value) ? value : undefined;
}

function sameUnordered(a: readonly unknown[], b: readonly unknown[]): boolean {
  const left = new Set(a.map(canonical));
  const right = new Set(b.map(canonical));
  return left.size === right.size && [...left].every((item) => right.has(item));
}

/**
 * ディレクトリが返した DID Document が、検証済みの操作列から組み立てた文書と一致することを確認する。
 *
 * @throws 不一致（VericertsError、code `2010`、`context.reason: 'plc_document_mismatch'`）。
 */
export function assertMatchesDirectoryDocument(
  built: DIDDocument,
  response: Record<string, unknown>,
): void {
  // `built` はこのモジュールが組み立てた自前の値（外部入力ではない）。
  const expected: Record<string, unknown> = { ...built };
  const context = asArray(response['@context']);
  const alsoKnownAs = asArray(response.alsoKnownAs);
  const verificationMethod = asArray(response.verificationMethod);
  const service = asArray(response.service);
  if (
    !Object.keys(response).every((key) => DIRECTORY_DOCUMENT_KEYS.includes(key)) ||
    response.id !== expected.id ||
    context === undefined ||
    alsoKnownAs === undefined ||
    verificationMethod === undefined ||
    service === undefined ||
    !sameUnordered(context, asArray(expected['@context']) ?? []) ||
    canonical(alsoKnownAs) !== canonical(expected.alsoKnownAs ?? []) ||
    !sameUnordered(verificationMethod, asArray(expected.verificationMethod) ?? []) ||
    !sameUnordered(service, asArray(expected.service) ?? [])
  ) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID, {
      context: { reason: 'plc_document_mismatch' },
    });
  }
}
