/**
 * did:web 解決結果の配列形状。
 *
 * `verificationMethod` / relationship / `service` が配列でない文書は解決出口で
 * `DID_DOC_INVALID`（2010）にする。欠落は DID Core の省略として解決自体は成功し、
 * 検証鍵の選択側が候補なしを 2010 に倒す。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { didDocumentToVerifierKey } from '../../../credential/vc/verifier-key.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { resolveDidWeb } from '../method-web.js';

const DID = 'did:web:example.com';
const URL = 'https://example.com/.well-known/did.json';
const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function serve(body: string): void {
  globalThis.fetch = (async () => {
    const response = new Response(body, {
      status: 200,
      headers: { 'content-type': 'application/did+json' },
    });
    Object.defineProperty(response, 'url', { value: URL });
    return response;
  }) as unknown as typeof fetch;
}

describe('resolveDidWeb の DID Document 形状', () => {
  it('verificationMethod が文字列の文書は 2010', async () => {
    serve(JSON.stringify({ id: DID, verificationMethod: 'oops', assertionMethod: 7 }));
    await expect(resolveDidWeb(DID)).rejects.toThrow(
      new VericertsError(ErrorCodes.DID_DOC_INVALID),
    );
  });

  it('verificationMethod / assertionMethod を欠く文書は解決でき、検証鍵選択は 2010', async () => {
    serve(JSON.stringify({ id: DID }));
    const doc = await resolveDidWeb(DID);
    expect(doc.id).toBe(DID);
    expect(() => didDocumentToVerifierKey(doc)).toThrow(
      new VericertsError(ErrorCodes.DID_DOC_INVALID),
    );
  });
});
