import {
  appendSigned,
  signedGenesis,
  witnessKey,
  witnessProofFor,
} from '../../../internal/identity/webvh/__tests__/v1/log-builders.js';
import { toJsonl } from '../../../internal/identity/webvh/__tests__/webvh-fixtures.js';

export const MIB = 1024 * 1024;
export const originalFetch = globalThis.fetch;

export function deferred() {
  let release: () => void = () => {
    throw new Error('deferred not initialized');
  };
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

export async function transition(predicate: () => boolean): Promise<void> {
  for (let i = 0; i < 100; i += 1) {
    if (predicate()) return;
    await Bun.sleep(0);
  }
  throw new Error('Expected HTTP transition was not observed');
}

export function response(body: string | ReadableStream<Uint8Array>, url: string): Response {
  const result = new Response(body, {
    headers: { 'content-type': url.endsWith('.jsonl') ? 'application/jsonl' : 'application/json' },
  });
  Object.defineProperty(result, 'url', { value: url });
  return result;
}

export function webResponse(url: string, marker = 'initial'): Response {
  const host = new URL(url).host;
  return response(
    JSON.stringify({ '@context': ['https://www.w3.org/ns/did/v1'], id: `did:web:${host}`, marker }),
    url,
  );
}

export function serve(handler: (url: string, init?: RequestInit) => Promise<Response>): string[] {
  const requested: string[] = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    requested.push(url);
    return handler(url, init);
  }) as typeof fetch;
  return requested;
}

export async function signedLog(domain: string, witnessed = false, versions = 1) {
  const witness = witnessKey();
  const { key, did, genesis } = signedGenesis({
    domain,
    ...(witnessed ? { witness: { threshold: 1, witnesses: [{ id: witness.id }] } } : {}),
  });
  const log = [genesis];
  while (log.length < versions) log.push(appendSigned(log, key));
  const last = log[log.length - 1];
  if (last === undefined) throw new Error('Missing signed log');
  const file = JSON.stringify([
    { versionId: last.versionId, proof: [await witnessProofFor(last.versionId, witness)] },
  ]);
  return { did, log, text: toJsonl(log), file };
}
