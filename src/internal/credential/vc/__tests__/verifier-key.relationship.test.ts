/**
 * `didDocumentToVerifierKey` の検証関係（relationship）限定の鍵選択。
 *
 * 候補は指定 relationship（既定 `assertionMethod`、DIDComm 送信者認証は `authentication`）に列挙された
 * VerificationMethod だけ。`verificationMethod[0]` へのフォールバックは無く、`keyAgreement` 専用鍵や
 * 未宣言の鍵は署名鍵にならない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { DIDDocument } from '../../../identity/did.js';
import { MAX_DID_DOCUMENT_ARRAY_ENTRIES } from '../../../identity/did-document-read.js';
import { didDocumentToVerifierKey } from '../verifier-key.js';

const DID = 'did:example:issuer';
const invalid = new VericertsError(ErrorCodes.DID_DOC_INVALID);

function jwk(x: string) {
  return { kty: 'OKP', crv: 'Ed25519', x };
}

function vm(fragment: string, x: string) {
  return {
    id: `${DID}#${fragment}`,
    type: 'JsonWebKey2020',
    controller: DID,
    publicKeyJwk: jwk(x),
  };
}

function doc(partial: Record<string, unknown>): DIDDocument {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: DID,
    ...partial,
  } as unknown as DIDDocument;
}

describe('didDocumentToVerifierKey: relationship 限定', () => {
  it('assertionMethod が空で keyAgreement 専用鍵しか無い文書は 2010（フォールバックしない）', () => {
    const d = doc({
      verificationMethod: [vm('enc', 'ENC')],
      keyAgreement: [`${DID}#enc`],
      assertionMethod: [],
    });
    expect(() => didDocumentToVerifierKey(d)).toThrow(invalid);
  });

  it('assertionMethod 未宣言（キー欠落）の文書も 2010', () => {
    expect(() => didDocumentToVerifierKey(doc({ verificationMethod: [vm('k', 'K')] }))).toThrow(
      invalid,
    );
  });

  it('assertionMethod[0] が解決できない参照なら 2010（verificationMethod[0] へ落ちない）', () => {
    const d = doc({
      verificationMethod: [vm('enc', 'ENC'), vm('sig', 'SIG')],
      assertionMethod: [`${DID}#typo`, `${DID}#sig`],
    });
    expect(() => didDocumentToVerifierKey(d)).toThrow(invalid);
  });

  it('verificationMethod[0] が assertion 用でなくても、assertionMethod に列挙された鍵を選ぶ', () => {
    const d = doc({
      verificationMethod: [vm('enc', 'ENC'), vm('sig', 'SIG')],
      keyAgreement: [`${DID}#enc`],
      assertionMethod: [`${DID}#sig`],
    });
    expect(didDocumentToVerifierKey(d).publicKeyJwk).toEqual(jwk('SIG'));
  });

  it('verificationMethodId（JWS kid）は assertionMethod の候補内から選ぶ。相対 id も解決する', () => {
    const d = doc({
      verificationMethod: [vm('k1', 'K1'), vm('k2', 'K2'), vm('enc', 'ENC')],
      assertionMethod: [`${DID}#k1`, `${DID}#k2`],
    });
    expect(didDocumentToVerifierKey(d, { verificationMethodId: `${DID}#k2` }).publicKeyJwk).toEqual(
      jwk('K2'),
    );
    expect(didDocumentToVerifierKey(d, { verificationMethodId: '#k2' }).publicKeyJwk).toEqual(
      jwk('K2'),
    );
    // verificationMethod には在るが assertionMethod に無い鍵は、id 指定でも選ばない。
    expect(() => didDocumentToVerifierKey(d, { verificationMethodId: `${DID}#enc` })).toThrow(
      invalid,
    );
  });

  it('埋め込み VerificationMethod も候補になる', () => {
    const d = doc({ verificationMethod: [], assertionMethod: [vm('inline', 'INL')] });
    expect(didDocumentToVerifierKey(d).publicKeyJwk).toEqual(jwk('INL'));
  });

  it('relationship: authentication は authentication の鍵だけを候補にする', () => {
    const d = doc({
      verificationMethod: [vm('auth', 'AUTH'), vm('assert', 'ASSERT')],
      authentication: [`${DID}#auth`],
      assertionMethod: [`${DID}#assert`],
    });
    expect(didDocumentToVerifierKey(d, { relationship: 'authentication' }).publicKeyJwk).toEqual(
      jwk('AUTH'),
    );
    expect(didDocumentToVerifierKey(d).publicKeyJwk).toEqual(jwk('ASSERT'));
    expect(() =>
      didDocumentToVerifierKey(
        doc({ verificationMethod: [vm('a', 'A')], assertionMethod: [`${DID}#a`] }),
        {
          relationship: 'authentication',
        },
      ),
    ).toThrow(invalid);
  });
});

describe('didDocumentToVerifierKey: 件数の上限', () => {
  it('verificationMethod が配列件数の上限を超える文書は 2010（選択走査に入らない）', () => {
    const methods = Array.from({ length: MAX_DID_DOCUMENT_ARRAY_ENTRIES + 1 }, (_, index) =>
      vm(`k${index}`, `X${index}`),
    );
    const d = doc({ verificationMethod: methods, assertionMethod: [`${DID}#k0`] });
    expect(() => didDocumentToVerifierKey(d)).toThrow(invalid);
  });

  it('assertionMethod が配列件数の上限を超える文書は 2010', () => {
    const refs = Array.from(
      { length: MAX_DID_DOCUMENT_ARRAY_ENTRIES + 1 },
      (_, index) => `${DID}#k${index}`,
    );
    const d = doc({ verificationMethod: [vm('k0', 'X0')], assertionMethod: refs });
    expect(() => didDocumentToVerifierKey(d)).toThrow(invalid);
  });

  it('上限ちょうどの件数で、末尾の参照を重複 id の先頭 VM へ解決する', () => {
    const methods = Array.from({ length: MAX_DID_DOCUMENT_ARRAY_ENTRIES }, (_, index) =>
      vm(`k${index}`, `X${index}`),
    );
    methods[MAX_DID_DOCUMENT_ARRAY_ENTRIES - 1] = vm('k0', 'DUPLICATE');
    const refs = [`${DID}#k0`];
    const key = didDocumentToVerifierKey(
      doc({ verificationMethod: methods, assertionMethod: refs }),
    );
    expect(key.publicKeyJwk).toEqual(jwk('X0'));
  });
});
