/**
 * DID Document の配列**要素**が null / 非オブジェクトのときの 2010 正規化。
 *
 * 以前は `verificationMethod` / `service` / relationship が配列かどうかだけを検査していたため、
 * `verificationMethod: [null]` や `service: [null]` が shape 検査を通り、後続の読み手
 * （`didDocumentToVerifierKey` / `sendDIDCommMessage` の送信先解決 / `wallet.updateDID`）が
 * 生の `TypeError` を漏らしていた。全読み手が共有する `*Of` で要素まで検査する。
 */

import { describe, expect, it } from 'bun:test';
import { didDocumentToVerifierKey } from '../../credential/vc/verifier-key.js';
import { resolveKeyAgreement, resolveServiceEndpoint } from '../../didcomm/resolve.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { DIDDocument, Service, VerificationMethod } from '../did.js';
import { applyDidDocumentUpdate } from '../did-document-patch.js';
import { assertNetworkDidDocumentShape } from '../did-document-read.js';

const DID = 'did:web:issuer.example';

const METHOD: VerificationMethod = {
  id: `${DID}#key-0`,
  type: 'Multikey',
  controller: DID,
  publicKeyMultibase: 'zOld',
};

const SERVICE: Service = {
  id: `${DID}#svc`,
  type: 'LinkedDomains',
  serviceEndpoint: 'https://issuer.example',
};

function doc(partial: Record<string, unknown>): DIDDocument {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: DID,
    ...partial,
  } as unknown as DIDDocument;
}

/** 要素が不正な Document（キー → 不正な配列）。 */
const BAD_DOCS: ReadonlyArray<readonly [string, DIDDocument]> = [
  ['verificationMethod: [null]', doc({ verificationMethod: [null] })],
  ['verificationMethod: [5]', doc({ verificationMethod: [5] })],
  ['verificationMethod: [{ id なし }]', doc({ verificationMethod: [{ type: 'x' }] })],
  ['verificationMethod: [[]]', doc({ verificationMethod: [[]] })],
  ['service: [null]', doc({ service: [null] })],
  ['service: ["x"]', doc({ service: ['x'] })],
  ['authentication: [null]', doc({ authentication: [null] })],
  ['authentication: [7]', doc({ authentication: [7] })],
  ['keyAgreement: [null]', doc({ keyAgreement: [null] })],
  ['assertionMethod: [{ id なし }]', doc({ assertionMethod: [{}] })],
];

/** 投げられた例外を返す（投げなければ undefined）。 */
function thrownBy(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    return error;
  }
  return undefined;
}

function expectDocInvalid(run: () => unknown): void {
  const error = thrownBy(run);
  expect(error).toBeInstanceOf(VericertsError);
  expect((error as VericertsError).code).toBe(ErrorCodes.DID_DOC_INVALID);
}

describe('DID Document の配列要素の形状検査', () => {
  it.each(BAD_DOCS)('assertNetworkDidDocumentShape: %s は 2010', (_name, bad) => {
    expectDocInvalid(() => assertNetworkDidDocumentShape(bad));
  });

  it('didDocumentToVerifierKey: 要素が null の authentication / verificationMethod は 2010', () => {
    expectDocInvalid(() =>
      didDocumentToVerifierKey(doc({ authentication: [null], verificationMethod: [METHOD] }), {
        relationship: 'authentication',
      }),
    );
    expectDocInvalid(() =>
      didDocumentToVerifierKey(doc({ assertionMethod: ['x'], verificationMethod: [null] })),
    );
  });

  it('resolveServiceEndpoint: service: [null] は生 TypeError ではなく 2010', () => {
    expectDocInvalid(() => resolveServiceEndpoint(doc({ service: [null] })));
  });

  it('resolveKeyAgreement: verificationMethod / keyAgreement の null 要素は 2010', () => {
    expectDocInvalid(() =>
      resolveKeyAgreement(doc({ keyAgreement: [`${DID}#k`], verificationMethod: [null] })),
    );
    expectDocInvalid(() => resolveKeyAgreement(doc({ keyAgreement: [null] })));
  });

  it('applyDidDocumentUpdate: null 要素を含む文書への add / remove は 2010', () => {
    const updates = [
      [doc({ verificationMethod: [null] }), { removeVerificationMethod: `${DID}#key-0` }],
      [doc({ verificationMethod: [null] }), { addVerificationMethod: METHOD }],
      [doc({ service: [null] }), { removeService: `${DID}#svc` }],
      [doc({ service: [null] }), { addService: SERVICE }],
    ] as const;
    for (const [document, update] of updates) {
      expectDocInvalid(() => applyDidDocumentUpdate(document, update as never));
    }
  });

  it('正常な要素（文字列参照・埋め込み VM・id 付き service）は従来どおり通る', () => {
    const good = doc({
      verificationMethod: [METHOD],
      authentication: [METHOD.id, METHOD],
      service: [SERVICE],
    });
    expect(() => assertNetworkDidDocumentShape(good)).not.toThrow();
  });
});
