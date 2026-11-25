/**
 * 委任 DID: 他 DID の検証メソッドへの参照の解決（`inlineExternalMethods`）と、委任先の文書 id の照合
 * （`documentIdMatches`）。controller 検証と署名鍵の解決の本体は `delegation.test.ts`。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import type { DIDDocument } from '../../../../identity/did.js';
import {
  resolveDelegatedSigner,
  verifyDelegatedKey,
  verifyDelegationControl,
} from '../../delegation.js';
import {
  createDereferenceBudget,
  documentIdMatches,
  inlineExternalMethods,
  MAX_EXTERNAL_DEREFERENCES,
} from '../../external-methods.js';
import { DELEGATED_DID, type Delegation, failureOf, newDelegation } from './delegation.fixtures.js';

describe('inlineExternalMethods', () => {
  const DOC_ID = 'did:web:corp.example';
  // 部分的な文書（検証関係の要素に型の緩い値を入れる）を DIDDocument として渡す。
  const document = (authentication: unknown[]): DIDDocument =>
    ({
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: DOC_ID,
      verificationMethod: [],
      authentication,
      assertionMethod: [],
    }) as unknown as DIDDocument;

  it('他 DID への参照が無ければ同じ文書をそのまま返し、解決しない', async () => {
    let calls = 0;
    const resolver = {
      resolve: async (): Promise<DIDDocument> => {
        calls += 1;
        throw new Error('unused');
      },
    };
    const input = document([`${DOC_ID}#a`, { id: `${DOC_ID}#b`, type: 'JsonWebKey2020' }]);
    expect(await inlineExternalMethods(resolver, input, 'authentication')).toBe(input);
    expect(calls).toBe(0);
  });

  it('kid の指す参照 1 件だけを解決し、他の外部参照は外す（解決しない）', async () => {
    const d = await newDelegation('P-256');
    const resolved: string[] = [];
    const resolver = {
      resolve: async (did: string) => {
        resolved.push(did);
        return d.world.resolver.resolve(did);
      },
    };
    const otherDid = 'did:key:zDoesNotMatter';
    const result = await inlineExternalMethods(
      resolver,
      document([`${otherDid}#x`, d.own.kid]),
      'authentication',
      { kid: d.own.kid },
    );
    expect(resolved).toEqual([d.persona.did]);
    expect(result.authentication).toHaveLength(1);
  });

  it(`外部参照が ${MAX_EXTERNAL_DEREFERENCES} 件を超える all 指定は 2010`, async () => {
    const d = await newDelegation('P-256');
    const refs = Array.from({ length: MAX_EXTERNAL_DEREFERENCES + 1 }, () => d.own.kid);
    expect(
      await failureOf(
        inlineExternalMethods(d.world.resolver, document(refs), 'authentication', { all: true }),
      ),
    ).toEqual({ code: ErrorCodes.DID_DOC_INVALID, reason: 'external_references_too_many' });
  });
});

describe('委任 DID の検証で辿る他 DID への参照', () => {
  /** 解決した DID を記録する Resolver。 */
  function recording(d: Delegation) {
    const resolved: string[] = [];
    const resolver = {
      resolve: async (did: string) => {
        resolved.push(did);
        return d.world.resolver.resolve(did);
      },
    };
    return { resolved, resolver };
  }

  it('署名者の kid が既知なら、その DID を指す参照だけを解決する（無関係な外部参照は解決しない）', async () => {
    const d = await newDelegation('P-256');
    d.publish({
      verificationMethod: [],
      authentication: ['did:web:unrelated.example#k', d.own.kid],
    });
    const { resolved, resolver } = recording(d);
    const delegated = await resolveDelegatedSigner(d.world.km, d.persona, {
      delegatedDid: DELEGATED_DID,
      resolver,
    });
    expect(delegated.kid).toBe(d.own.kid);
    expect(resolved).toEqual([DELEGATED_DID, d.persona.did]);
  });

  it('kid を渡さない verifyDelegatedKey は外部参照をすべて辿る（予算の範囲で）', async () => {
    const d = await newDelegation('P-256');
    d.publish({ verificationMethod: [], authentication: [d.own.kid, d.own.kid] });
    const { resolved, resolver } = recording(d);
    await verifyDelegatedKey(
      resolver,
      { delegatedDid: DELEGATED_DID, controllerDid: d.persona.did },
      d.own.signer.publicKeyJwk,
    );
    expect(resolved).toEqual([DELEGATED_DID, d.persona.did, d.persona.did]);
  });

  it(`controller 関係と署名鍵の選択で予算（${MAX_EXTERNAL_DEREFERENCES} 件）を共有する: 合計が超えると 2010`, async () => {
    const d = await newDelegation('P-256');
    const refs = Array.from({ length: MAX_EXTERNAL_DEREFERENCES - 3 }, () => d.own.kid);
    // capabilityDelegation（controller 関係）で 5 件、authentication（署名鍵）で 5 件 = 10 件。各 5 件は単独なら上限内。
    d.publish({
      controller: [],
      verificationMethod: [],
      capabilityDelegation: refs,
      authentication: refs,
    });
    const input = { delegatedDid: DELEGATED_DID, controllerDid: d.persona.did };
    expect(
      await failureOf(verifyDelegatedKey(d.world.resolver, input, d.own.signer.publicKeyJwk)),
    ).toEqual({ code: ErrorCodes.DID_DOC_INVALID, reason: 'external_references_too_many' });
    // 同じ文書でも、authentication だけなら（予算を使い切らないので）通る。
    d.publish({ verificationMethod: [], authentication: refs });
    expect((await verifyDelegatedKey(d.world.resolver, input, d.own.signer.publicKeyJwk)).kid).toBe(
      d.own.kid,
    );
  });

  it('同じ予算オブジェクトを渡した inlineExternalMethods の呼び出し間で残りが減る', async () => {
    const d = await newDelegation('P-256');
    const budget = createDereferenceBudget();
    const doc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: DELEGATED_DID,
      verificationMethod: [],
      authentication: [d.own.kid, d.own.kid, d.own.kid],
    } as unknown as DIDDocument;
    await inlineExternalMethods(d.world.resolver, doc, 'authentication', { all: true, budget });
    expect(budget.remaining).toBe(MAX_EXTERNAL_DEREFERENCES - 3);
  });
});

describe('documentIdMatches', () => {
  it('did:ion の long-form だけが短縮形 id の接頭辞一致を許す', () => {
    expect(documentIdMatches('did:ion:EiA', 'did:ion:EiA:eyJ4')).toBe(true);
    expect(documentIdMatches('did:web:a.example', 'did:web:a.example:path')).toBe(false);
    expect(documentIdMatches('did:web:a.example', 'did:web:a.example')).toBe(true);
    expect(documentIdMatches(undefined, 'did:web:a.example')).toBe(false);
  });

  it('D の文書の id が D の下位パスの DID（did:web）だと 2010 document_id_mismatch', async () => {
    const d = await newDelegation('P-256');
    const resolver = {
      resolve: async (): Promise<DIDDocument> =>
        ({
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: DELEGATED_DID,
          controller: [d.persona.did],
        }) as unknown as DIDDocument,
    };
    expect(
      await failureOf(verifyDelegationControl(resolver, `${DELEGATED_DID}:sub`, d.persona.did)),
    ).toEqual({ code: ErrorCodes.DID_DOC_INVALID, reason: 'document_id_mismatch' });
  });
});
