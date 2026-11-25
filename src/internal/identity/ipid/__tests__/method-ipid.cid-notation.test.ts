/**
 * did:ipid の CID 照合は識別子の**表記**（base32 / base36 / CIDv0）に依存しない。
 *
 * 以前は先頭文字（`k` / `Qm` / `1`）で IPNS 名（無検証）と CID（本文ハッシュ照合）を振り分けていたため、
 * CIDv1 base36（`k...`）と CIDv0（`Qm...`）の CID は IPNS 扱いになり、Gateway が返した偽造文書が
 * 無検証で受理された。識別子を復号して multicodec で分類する。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import { MethodIpid } from '../method-ipid.js';
import { cidV0Of, ipnsNameOf, rawCidBase36Of, rawCidOf } from './cid-fixture.js';
import { ipnsGateway } from './ipns-fixture.js';

const docWith = (key: string): string =>
  JSON.stringify({
    '@context': ['https://www.w3.org/ns/did/v1'],
    verificationMethod: [
      { id: '#key-1', type: 'Multikey', controller: '', publicKeyMultibase: key },
    ],
    authentication: ['#key-1'],
    assertionMethod: ['#key-1'],
  });
const GENUINE = docWith('zGENUINE');
const FORGED = docWith('zFORGEDBYGATEWAY');

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});

/** Gateway が常に `body` を返し、要求 URL を記録するモック。 */
function gatewayReturns(body: string): string[] {
  const urls: string[] = [];
  globalThis.fetch = (async (input: string | URL | Request) => {
    urls.push(typeof input === 'string' ? input : input.toString());
    return new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
  }) as unknown as typeof fetch;
  return urls;
}

async function reasonOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    expect((error as VericertsError).code).toBe(ErrorCodes.DID_DOC_INVALID);
    return (error as VericertsError).context?.reason;
  }
  throw new Error('should have thrown');
}

describe('did:ipid の CID 表記と本文照合', () => {
  const notations = [
    ['base32 CIDv1 (b...)', rawCidOf(GENUINE)],
    ['base36 CIDv1 (k...)', rawCidBase36Of(GENUINE)],
  ] as const;

  it.each(notations)('%s: Gateway が偽造文書を返したら cid_mismatch で拒否', async (_name, cid) => {
    gatewayReturns(FORGED);
    expect(await reasonOf(new MethodIpid().resolve(`did:ipid:${cid}`))).toBe('cid_mismatch');
  });

  it.each(notations)('%s: 本文が CID と一致すれば /ipfs/ から解決できる', async (_name, cid) => {
    const urls = gatewayReturns(GENUINE);
    const doc = await new MethodIpid().resolve(`did:ipid:${cid}`);
    expect(doc.id).toBe(`did:ipid:${cid}`);
    expect(urls[0]).toBe(`https://ipfs.io/ipfs/${cid}`);
  });

  it('CIDv0 (Qm...) は中身だけでは照合できないため偽造文書でも真正文書でも cid_unverifiable', async () => {
    const did = `did:ipid:${cidV0Of(GENUINE)}`;
    gatewayReturns(FORGED);
    expect(await reasonOf(new MethodIpid().resolve(did))).toBe('cid_unverifiable');
    gatewayReturns(GENUINE);
    expect(await reasonOf(new MethodIpid().resolve(did))).toBe('cid_unverifiable');
  });

  it('libp2p-key の IPNS 名 (k51...) は /ipns/ のレコード検証を経て /ipfs/ から解決する', async () => {
    const name = ipnsNameOf(8);
    const gateway = ipnsGateway(8, GENUINE);
    globalThis.fetch = gateway.fetch;
    const doc = await new MethodIpid().resolve(`did:ipid:${name}`);
    expect(doc.id).toBe(`did:ipid:${name}`);
    expect(gateway.urls[0]).toBe(`https://ipfs.io/ipns/${name}`);
  });
});
