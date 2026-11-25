/**
 * did:plc テストの共有フィクスチャ。実際の鍵で署名した操作列と、`fetchFn` 注入のモックディレクトリを組み立てる。
 * 実ネットワークには接続しない。
 */

import { expect } from 'bun:test';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { type ErrorCode, VericertsError } from '../../../errors.js';
import { createDidKey } from '../../method-key.js';
import { buildPlcDocument } from '../document.js';
import { createDidPlc, deactivateDidPlc, updateDidPlc } from '../lifecycle.js';
import {
  cidOfSignedBytes,
  type PlcOperationData,
  type PlcSignedOperation,
  parseOperation,
} from '../operation.js';

export const DIRECTORY = 'https://plc.directory';

export interface TestKey {
  readonly didKey: string;
  readonly keyType: 'secp256k1' | 'P-256' | 'Ed25519';
  /** 通常の署名器（low-S の 64 バイト）。 */
  readonly sign: (unsigned: Uint8Array) => Promise<Uint8Array>;
  /** High-S の署名を返す署名器（正規化されることの確認用）。 */
  readonly signHighS: (unsigned: Uint8Array) => Promise<Uint8Array>;
  /** 同じ鍵で署名し、署名器の戻り値をそのまま返す（SDK を通さない生の署名）。 */
  readonly signRaw: (unsigned: Uint8Array, lowS: boolean) => Uint8Array;
}

export function makeKey(keyType: 'secp256k1' | 'P-256' = 'secp256k1'): TestKey {
  const curve = keyType === 'secp256k1' ? secp256k1 : p256;
  const secret = curve.utils.randomSecretKey();
  const publicKey = curve.getPublicKey(secret);
  const didKey = createDidKey(keyType, publicKey).id;
  const signRaw = (unsigned: Uint8Array, lowS: boolean): Uint8Array => {
    for (let attempt = 0; attempt < 64; attempt += 1) {
      const sig = curve.sign(unsigned, secret, { lowS: false, extraEntropy: true });
      const signature = curve.Signature.fromBytes(sig, 'compact');
      if (signature.hasHighS() !== lowS) {
        return sig;
      }
    }
    throw new Error('署名を得られなかった');
  };
  return {
    didKey,
    keyType,
    sign: async (unsigned) => signRaw(unsigned, true),
    signHighS: async (unsigned) => signRaw(unsigned, false),
    signRaw,
  };
}

export function dataOf(rotationKeys: TestKey[], signingKey = makeKey('P-256')): PlcOperationData {
  return {
    rotationKeys: rotationKeys.map((key) => key.didKey),
    verificationMethods: { atproto: signingKey.didKey },
    alsoKnownAs: ['at://alice.example.com'],
    services: {
      atproto_pds: { type: 'AtprotoPersonalDataServer', endpoint: 'https://pds.example.com' },
    },
  };
}

export interface LogEntry {
  did: string;
  operation: PlcSignedOperation | Record<string, unknown>;
  cid: string;
  nullified: boolean;
  createdAt: string;
}

export function cidOf(operation: PlcSignedOperation | Record<string, unknown>): string {
  return cidOfSignedBytes(parseOperation(operation).signed);
}

export function entry(
  did: string,
  operation: PlcSignedOperation | Record<string, unknown>,
  createdAt: string,
  nullified = false,
): LogEntry {
  return { did, operation, cid: cidOf(operation), nullified, createdAt };
}

/** ジェネシスだけの DID と監査ログ。 */
export async function genesis(
  rotation: TestKey,
  data: PlcOperationData = dataOf([rotation]),
  createdAt = '2026-10-01T00:00:00.000Z',
) {
  const created = await createDidPlc({ data, signer: rotation.sign, signerKey: rotation.didKey });
  return { ...created, entries: [entry(created.did, created.operation, createdAt)], data };
}

export async function nextOperation(
  did: string,
  prev: LogEntry,
  data: PlcOperationData,
  key: TestKey,
): Promise<PlcSignedOperation> {
  return updateDidPlc({ did, prev: prev.cid, data, signer: key.sign, signerKey: key.didKey });
}

export async function tombstone(
  did: string,
  prev: LogEntry,
  key: TestKey,
): Promise<PlcSignedOperation> {
  return deactivateDidPlc({ did, prev: prev.cid, signer: key.sign, signerKey: key.didKey });
}

/** PLC ディレクトリが返す文書の形（`authentication` / `assertionMethod` を出さない）。 */
export function documentOf(did: string, data: PlcOperationData): Record<string, unknown> {
  const { authentication: _a, assertionMethod: _m, ...served } = buildPlcDocument(did, data, {});
  return served;
}

export interface Directory {
  readonly fetchFn: typeof fetch;
  readonly requests: { url: string; method: string }[];
}

type Reply = Response | Error | undefined;

/** `<DIRECTORY>/<did>` と `/log/audit` を返すモックディレクトリ。`audit` / `doc` は応答の上書き。 */
export function directoryFor(
  did: string,
  entries: unknown,
  doc: unknown,
  overrides: { audit?: Reply; doc?: Reply } = {},
): Directory {
  const requests: Directory['requests'] = [];
  const json = (body: unknown, contentType: string): Response =>
    new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': contentType } });
  const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
    const url =
      typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    requests.push({ url, method: init?.method ?? 'GET' });
    const isAudit = url === `${DIRECTORY}/${did}/log/audit`;
    if (!isAudit && url !== `${DIRECTORY}/${did}`) {
      return new Response('not found', { status: 404 });
    }
    const override = isAudit ? overrides.audit : overrides.doc;
    if (override instanceof Error) {
      throw override;
    }
    return (
      override ??
      (isAudit ? json(entries, 'application/json') : json(doc, 'application/did+ld+json'))
    );
  }) as unknown as typeof fetch;
  return { fetchFn, requests };
}

export async function expectVericertsError(
  action: () => Promise<unknown>,
  code: ErrorCode,
  reason?: string,
): Promise<void> {
  const error = await action().then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(VericertsError);
  expect((error as VericertsError).code).toBe(code);
  if (reason !== undefined) {
    expect((error as VericertsError).context?.reason).toBe(reason);
  }
}
