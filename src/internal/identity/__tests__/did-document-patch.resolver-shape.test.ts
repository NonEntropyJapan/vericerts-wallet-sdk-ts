/**
 * ネットワーク由来の DID Document が型どおりの形をしていない場合の差分適用（`2010` 正規化）。
 *
 * `applyDidDocumentUpdate` の `document` は `resolver.resolve(did)` の戻り値であり、ネットワーク
 * resolver（`did-web-fetch.ts` / `ipid/gateway.ts`）が検査するのは `id` の一致だけである。
 * `DIDDocument` 型は `verificationMethod` を必須と書いているが、**実体はリモートが返した JSON**
 * なので、持たない文書・配列でない文書が普通に到達する。素で `.filter` / `.some` を呼ぶと
 * 公開 API `wallet.updateDID` から生の `TypeError` が漏れる（仕様上は `2010`）。
 *
 * 同じ根拠は `verificationMethod` の兄弟にも当てはまる —— relationship 配列（`authentication` 等）・
 * `service`・`controller`。いずれも読み手は `.filter` / `.some` / `.includes` なので、配列でない値が
 * 到達した時点で生の `TypeError` になる。本ファイルは 4 系統すべてを固定する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { DIDDocument, Service, VerificationMethod } from '../did.js';
import { applyDidDocumentUpdate } from '../did-document-patch.js';

const DID = 'did:web:issuer.example';

const NEW_METHOD: VerificationMethod = {
  id: `${DID}#key-1`,
  type: 'Multikey',
  controller: DID,
  publicKeyMultibase: 'zNew',
};

const EXISTING_METHOD: VerificationMethod = {
  id: `${DID}#key-0`,
  type: 'Multikey',
  controller: DID,
  publicKeyMultibase: 'zOld',
};

const NEW_SERVICE: Service = {
  id: `${DID}#svc`,
  type: 'LinkedDomains',
  serviceEndpoint: 'https://issuer.example',
};

/** `verificationMethod` を持たない（DID Core では省略可能な）解決済み Document。 */
function documentWithoutMethods(): DIDDocument {
  return { '@context': ['https://www.w3.org/ns/did/v1'], id: DID } as unknown as DIDDocument;
}

/** 投げられたエラーの `code` / `context.reason` を取り出す（TypeError ならそのまま返す）。 */
function thrownBy(run: () => unknown): unknown {
  try {
    run();
  } catch (e) {
    return e;
  }
  throw new Error('should throw');
}

describe('applyDidDocumentUpdate: verificationMethod を持たない解決結果', () => {
  it('削除は 2010（verification_method_not_found）にする — 生の TypeError を漏らさない', () => {
    const error = thrownBy(() =>
      applyDidDocumentUpdate(documentWithoutMethods(), {
        removeVerificationMethod: `${DID}#key-1`,
      }),
    );
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.DID_DOC_INVALID);
    expect((error as VericertsError).context?.reason).toBe('verification_method_not_found');
  });

  it('追加は空配列からの追加として成功する（service 側の `?? []` と揃える）', () => {
    const next = applyDidDocumentUpdate(documentWithoutMethods(), {
      addVerificationMethod: NEW_METHOD,
    });
    expect(next.verificationMethod).toEqual([NEW_METHOD]);
  });

  it('配列でない verificationMethod は `[]` に倒さず 2010 で拒否する', () => {
    // `[]` に倒すと「既存の鍵を 1 つも持たない Document」として追加が成功し、鍵の総入れ替えが
    // 追加の顔で通る。読めない現行 Document は拒否側に倒す（fail-closed）。
    const polluted = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: DID,
      verificationMethod: 'not-an-array',
    } as unknown as DIDDocument;
    const error = thrownBy(() =>
      applyDidDocumentUpdate(polluted, { addVerificationMethod: NEW_METHOD }),
    );
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).context?.reason).toBe('verification_method_unreadable');
  });
});

describe('applyDidDocumentUpdate: relationship 配列が配列でない解決結果', () => {
  // `authentication: 'did:web:issuer.example#key-1'` のように文字列 1 個を直に置いた文書は
  // DID Core としては不正だが、resolver は `id` の一致しか検査しないので到達する。
  function documentWithStringRelationship(): DIDDocument {
    return {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: DID,
      verificationMethod: [EXISTING_METHOD],
      authentication: `${DID}#key-0`,
    } as unknown as DIDDocument;
  }

  it('VerificationMethod 削除は 2010（relationship_unreadable）にする', () => {
    const error = thrownBy(() =>
      applyDidDocumentUpdate(documentWithStringRelationship(), {
        removeVerificationMethod: EXISTING_METHOD.id,
      }),
    );
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.DID_DOC_INVALID);
    expect((error as VericertsError).context?.reason).toBe('relationship_unreadable');
  });
});

describe('applyDidDocumentUpdate: service が配列でない解決結果', () => {
  function documentWithStringService(): DIDDocument {
    return {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: DID,
      verificationMethod: [EXISTING_METHOD],
      service: 'not-an-array',
    } as unknown as DIDDocument;
  }

  it('削除は 2010（service_unreadable）にする', () => {
    const error = thrownBy(() =>
      applyDidDocumentUpdate(documentWithStringService(), { removeService: `${DID}#svc` }),
    );
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).context?.reason).toBe('service_unreadable');
  });

  it('追加も `[]` に倒さず 2010 で拒否する（差し替えを追加の顔で通させない）', () => {
    const error = thrownBy(() =>
      applyDidDocumentUpdate(documentWithStringService(), { addService: NEW_SERVICE }),
    );
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).context?.reason).toBe('service_unreadable');
  });
});

describe('applyDidDocumentUpdate: controller が文字列でも配列でもない解決結果', () => {
  function documentWithObjectController(): DIDDocument {
    return {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: DID,
      verificationMethod: [EXISTING_METHOD],
      controller: { 0: DID },
    } as unknown as DIDDocument;
  }

  it('削除は 2010（controller_unreadable）にする', () => {
    const error = thrownBy(() =>
      applyDidDocumentUpdate(documentWithObjectController(), { removeController: DID }),
    );
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).context?.reason).toBe('controller_unreadable');
  });

  it('追加も 2010（controller_unreadable）にする', () => {
    const error = thrownBy(() =>
      applyDidDocumentUpdate(documentWithObjectController(), {
        addController: 'did:web:other.example',
      }),
    );
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).context?.reason).toBe('controller_unreadable');
  });
});
