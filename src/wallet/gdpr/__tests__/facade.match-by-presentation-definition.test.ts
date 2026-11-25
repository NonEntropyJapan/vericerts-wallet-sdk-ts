/**
 * `GdprFacade.matchCredentialsByPresentationDefinition`の
 * 結合テスト（実鍵・モック禁止）。
 *
 * `matchCredentialsByPresentationDefinitionWith`（純粋な PEx マッチング、
 * `match-by-presentation-definition.test.ts` で単体検証済み）単体では、
 * `CredentialStore.listActiveCredentials()` による GDPR 処理制限 VC の除外（Art.18）は
 * 検証できない。本ファイルは `GdprFacade` がこの 2 つを結合する唯一の箇所であることを踏まえ、
 * 「処理制限中の VC は PEx マッチ結果から実際に除外される」ことを通しで検証する
 * （`src/wallet/credential/__tests__/match.test.ts`、共通で使う
 * `matchCredentialsWith` の結合テストと同種のパターン）。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../../internal/credential/index.js';
import { CredentialStore } from '../../../internal/gdpr/credential-store/index.js';
import { DashboardLog } from '../../../internal/gdpr/dashboard-log/dashboard-log.js';
import { createDidKey } from '../../../internal/identity/method-key.js';
import { KeyManager } from '../../../internal/keymanager/keymanager.js';
import { PersonaManager } from '../../../internal/persona/persona.js';
import { parsePresentationDefinition } from '../../../internal/presentation-exchange/index.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { GdprFacade } from '../facade.js';

const VC_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

function makeVc(id: string, name: string): VerifiableCredential {
  return {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name },
    issuanceDate: '2026-01-01T00:00:00Z',
    id,
  };
}

/** storage を共有する GdprFacade 一式を用意する。personas / keymanager は本テストの対象操作では未使用。 */
function setup(): { credentials: CredentialStore; gdpr: GdprFacade } {
  const storage = new MemoryStorage();
  const dashboardLog = new DashboardLog(storage);
  const credentials = new CredentialStore(storage, dashboardLog);
  const keymanager = new KeyManager();
  const personas = new PersonaManager(keymanager, storage, createDidKey, () => Date.now());
  const gdpr = new GdprFacade(credentials, personas, keymanager);
  return { credentials, gdpr };
}

describe('GdprFacade.matchCredentialsByPresentationDefinition', () => {
  it('constraints を満たす保持 VC を返す', async () => {
    const { credentials, gdpr } = setup();
    await credentials.store(makeVc('vc-bob', 'Bob'));
    await credentials.store(makeVc('vc-alice', 'Alice'));
    const pd = parsePresentationDefinition({
      id: 'pd-1',
      input_descriptors: [
        {
          id: 'd1',
          constraints: {
            fields: [
              { path: ['$.credentialSubject.name'], filter: { type: 'string', const: 'Bob' } },
            ],
          },
        },
      ],
    });

    const result = await gdpr.matchCredentialsByPresentationDefinition(pd);

    expect(result).toHaveLength(1);
    expect(result[0]?.id).toBe('vc-bob');
  });

  it('処理制限中（Art.18）の VC は constraints を満たしていても除外する', async () => {
    const { credentials, gdpr } = setup();
    await credentials.store(makeVc('vc-bob', 'Bob'));
    await credentials.setProcessingRestriction('vc-bob', true);
    const pd = parsePresentationDefinition({
      id: 'pd-1',
      input_descriptors: [
        { id: 'd1', constraints: { fields: [{ path: ['$.credentialSubject.name'] }] } },
      ],
    });

    const result = await gdpr.matchCredentialsByPresentationDefinition(pd);

    expect(result).toEqual([]);
  });

  it('処理制限中の VC と非制限の VC が混在する場合、非制限の VC だけを返す', async () => {
    const { credentials, gdpr } = setup();
    await credentials.store(makeVc('vc-bob', 'Bob'));
    await credentials.store(makeVc('vc-alice', 'Alice'));
    await credentials.setProcessingRestriction('vc-bob', true);
    const pd = parsePresentationDefinition({
      id: 'pd-1',
      input_descriptors: [
        { id: 'd1', constraints: { fields: [{ path: ['$.credentialSubject.name'] }] } },
      ],
    });

    const result = await gdpr.matchCredentialsByPresentationDefinition(pd);

    expect(result).toHaveLength(1);
    expect(result[0]?.id).toBe('vc-alice');
  });
});
