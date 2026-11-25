/**
 * DIF Credential Application 構築・提出と Credential Response 処理のユニット / 統合テスト
 *
 * 検証内容:
 * - buildCredentialApplication: presentation_definition なし / あり、submission の descriptor_map、要件未充足で 3080。
 * - processCredentialResponse: fulfillment（VC 検証 → accepted）、denial、遅延発行、検証失敗（3022）、構造不正（3031）。
 * - submitCredentialApplication: 申請 POST → 受領 VC 検証（統合）、非 HTTPS / 通信失敗で 3004。
 *
 * ネットワークは FetchLike スタブで注入し、実 HTTP は行わない（ロジックの実挙動を検証する）。
 */

import { describe, expect, it } from 'bun:test';
import type { FetchLike } from '../../../auth/oid4vci/oid4vci.js';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import type { VerifiableCredential } from '../../vc/vc.js';
import { buildCredentialApplication } from '../application-build.js';
import { processCredentialResponse, submitCredentialApplication } from '../application-response.js';
import { parseCredentialManifest } from '../parse.js';
import type { CredentialManifest } from '../types.js';

const SUPPORTED_SPEC_VERSION = 'https://identity.foundation/credential-manifest/spec/v1.0.0/';

/** 最小の有効な Manifest（生 JSON 形）。 */
function rawManifest(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'manifest-1',
    spec_version: SUPPORTED_SPEC_VERSION,
    issuer: { id: 'https://issuer.example', name: 'Example Issuer' },
    output_descriptors: [{ id: 'od-1', schema: 'https://schema.example/IdCard' }],
    ...overrides,
  };
}

/** パース済みの有効な Manifest。 */
function makeManifest(): CredentialManifest {
  return parseCredentialManifest(rawManifest());
}

/** 固定 ID を返す generateId（テストの決定論化）。 */
let idCounter = 0;
function seqId(): string {
  idCounter += 1;
  return `id-${idCounter}`;
}

/** JSON 応答を返す FetchLike スタブ。 */
function jsonFetch(status: number, body: unknown): FetchLike {
  return async () =>
    new Response(typeof body === 'string' ? body : JSON.stringify(body), { status });
}

const VERIFIED_VC: VerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'IdentityCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { id: 'did:example:holder' },
  issuanceDate: '2026-01-01T00:00:00Z',
  id: 'urn:vc:issued',
};

describe('buildCredentialApplication', () => {
  it('presentation_definition なしでは submission を含まない', () => {
    const app = buildCredentialApplication(makeManifest(), {}, { generateId: seqId });
    expect(app.manifest_id).toBe('manifest-1');
    expect(app.presentation_submission).toBeUndefined();
  });

  it('presentation_definition ありで submission の descriptor_map を構築する', () => {
    const manifest = parseCredentialManifest(
      rawManifest({ presentation_definition: { id: 'pd-9' } }),
    );
    const app = buildCredentialApplication(
      manifest,
      { 'in-1': 'answer-a', 'in-2': 'answer-b' },
      { generateId: seqId, presentationFormat: 'vc+sd-jwt' },
    );
    expect(app.presentation_submission?.definition_id).toBe('pd-9');
    expect(app.presentation_submission?.descriptor_map).toEqual([
      { id: 'in-1', format: 'vc+sd-jwt', path: '$.verifiableCredential[0]' },
      { id: 'in-2', format: 'vc+sd-jwt', path: '$.verifiableCredential[1]' },
    ]);
  });

  it('presentation_definition を要求するが answers 空で VC_REQUIREMENT_MISMATCH（3080）', () => {
    const manifest = parseCredentialManifest(
      rawManifest({ presentation_definition: { id: 'pd-9' } }),
    );
    try {
      buildCredentialApplication(manifest, {}, { generateId: seqId });
      throw new Error('should throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.VC_REQUIREMENT_MISMATCH);
    }
  });

  it('Manifest の format を Application にエコーバックする', () => {
    const manifest = parseCredentialManifest(rawManifest({ format: { jwt_vc_json: {} } }));
    const app = buildCredentialApplication(manifest, {}, { generateId: seqId });
    expect(app.format).toEqual({ jwt_vc_json: {} });
  });
});

describe('processCredentialResponse', () => {
  const verifyOk = async (): Promise<VerifiableCredential> => VERIFIED_VC;
  const verifyFail = async (): Promise<VerifiableCredential> => {
    throw new Error('sig invalid');
  };

  it('fulfillment（verifiableCredential）で VC を検証して accepted', async () => {
    const result = await processCredentialResponse(
      { verifiableCredential: 'eyJ...jwt-vc' },
      verifyOk,
    );
    expect(result.accepted).toBe(true);
    expect(result.credential?.id).toBe('urn:vc:issued');
  });

  it('fulfillment（credential エイリアス）でも受理する', async () => {
    const result = await processCredentialResponse({ credential: 'eyJ...jwt-vc' }, verifyOk);
    expect(result.accepted).toBe(true);
    expect(result.credential).toBeDefined();
  });

  it('受領 VC 検証失敗で REFRESHED_VC_VERIFICATION_FAILED（3022）', async () => {
    await expect(
      processCredentialResponse({ verifiableCredential: 'bad' }, verifyFail),
    ).rejects.toMatchObject({ code: ErrorCodes.REFRESHED_VC_VERIFICATION_FAILED });
  });

  it('denial.reason で却下結果を返す', async () => {
    const result = await processCredentialResponse(
      { denial: { reason: 'insufficient evidence' } },
      verifyOk,
    );
    expect(result.accepted).toBe(false);
    expect(result.rejectionReason).toBe('insufficient evidence');
  });

  it('rejectionReason（フラット）でも却下結果を返す', async () => {
    const result = await processCredentialResponse({ rejectionReason: 'denied' }, verifyOk);
    expect(result.accepted).toBe(false);
    expect(result.rejectionReason).toBe('denied');
  });

  it('transaction_id で遅延発行を返す', async () => {
    const result = await processCredentialResponse({ transaction_id: 'tx-123' }, verifyOk);
    expect(result.accepted).toBe(true);
    expect(result.transactionId).toBe('tx-123');
    expect(result.credential).toBeUndefined();
  });

  it('判別不能な応答で MANIFEST_SCHEMA_INVALID（3031）', async () => {
    await expect(processCredentialResponse({ unknown: true }, verifyOk)).rejects.toMatchObject({
      code: ErrorCodes.MANIFEST_SCHEMA_INVALID,
    });
  });

  it('object でない応答で 3031', async () => {
    await expect(processCredentialResponse(null, verifyOk)).rejects.toMatchObject({
      code: ErrorCodes.MANIFEST_SCHEMA_INVALID,
    });
  });
});

describe('submitCredentialApplication', () => {
  it('申請を POST し受領 VC を検証して受理する（統合）', async () => {
    let sentBody: string | undefined;
    const capturing: FetchLike = async (_url, init) => {
      sentBody = init.body;
      return new Response(JSON.stringify({ verifiableCredential: 'eyJ...jwt-vc' }), {
        status: 200,
      });
    };
    const result = await submitCredentialApplication(
      makeManifest(),
      {},
      { fetchImpl: capturing, verifyReceived: async () => VERIFIED_VC },
      { generateId: seqId },
    );
    expect(result.accepted).toBe(true);
    expect(result.credential?.id).toBe('urn:vc:issued');
    // 送信ボディに DIF credential_application が含まれる。
    expect(JSON.parse(sentBody ?? '{}')).toHaveProperty(
      'credential_application.manifest_id',
      'manifest-1',
    );
  });

  it('送信先が非 HTTPS（issuer.id が DID）で ISSUER_COMMUNICATION_FAILED（3004）', async () => {
    const manifest = parseCredentialManifest(rawManifest({ issuer: { id: 'did:example:issuer' } }));
    await expect(
      submitCredentialApplication(
        manifest,
        {},
        { fetchImpl: jsonFetch(200, {}), verifyReceived: async () => VERIFIED_VC },
        { generateId: seqId },
      ),
    ).rejects.toMatchObject({ code: ErrorCodes.ISSUER_COMMUNICATION_FAILED });
  });

  it('submitEndpoint を明示すると DID issuer でも送信する', async () => {
    const manifest = parseCredentialManifest(rawManifest({ issuer: { id: 'did:example:issuer' } }));
    const result = await submitCredentialApplication(
      manifest,
      {},
      {
        fetchImpl: jsonFetch(200, { transaction_id: 'tx-1' }),
        verifyReceived: async () => VERIFIED_VC,
      },
      { generateId: seqId, submitEndpoint: 'https://issuer.example/apply' },
    );
    expect(result.transactionId).toBe('tx-1');
  });

  it('HTTP エラーで 3004', async () => {
    await expect(
      submitCredentialApplication(
        makeManifest(),
        {},
        { fetchImpl: jsonFetch(500, {}), verifyReceived: async () => VERIFIED_VC },
        { generateId: seqId },
      ),
    ).rejects.toMatchObject({ code: ErrorCodes.ISSUER_COMMUNICATION_FAILED });
  });

  it('ネットワーク失敗で 3004', async () => {
    const failing: FetchLike = async () => {
      throw new Error('down');
    };
    await expect(
      submitCredentialApplication(
        makeManifest(),
        {},
        { fetchImpl: failing, verifyReceived: async () => VERIFIED_VC },
        { generateId: seqId },
      ),
    ).rejects.toMatchObject({ code: ErrorCodes.ISSUER_COMMUNICATION_FAILED });
  });

  it('denial 応答を却下結果として返す', async () => {
    const result = await submitCredentialApplication(
      makeManifest(),
      {},
      {
        fetchImpl: jsonFetch(200, { denial: { reason: 'kyc failed' } }),
        verifyReceived: async () => VERIFIED_VC,
      },
      { generateId: seqId },
    );
    expect(result.accepted).toBe(false);
    expect(result.rejectionReason).toBe('kyc failed');
  });
});
