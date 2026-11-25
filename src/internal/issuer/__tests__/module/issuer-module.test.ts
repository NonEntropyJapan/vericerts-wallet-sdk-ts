/**
 * `IssuerModule` facadeの回帰テスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - `generateTokenStatusList(purpose)` が Status List Token（JWT）を返し、検証できる。
 * - `setTokenStatus(vcId, purpose, value)` で対象 VC のビットが更新され、再署名した Token に載る。
 * - `IssueOptions.statusListType` の既定値解決（`resolveStatusListType`）は `issue-options.test.ts`。
 * - `statusListType === 'token-status-list'` で発行した VC に `status.status_list.{idx,uri}` が
 *   自動で入る。
 * - エラー: Holder DID 不正 3006 / 未登録 vcId 3070 / 未設定 purpose 3018 / 容量枯渇 3007。
 * - `claims.id` は検証済み `holderDID` で上書きされる（subject 詐称の防止）。
 * - 容量枯渇時の確保はアトミック（他リストのカーソルを進めない）。
 */

import { beforeEach, describe, expect, it } from 'bun:test';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import { IssuerModule } from '../../module/issuer-module.js';
import { readStatusBit, verifyStatusListToken } from '../../status-list-token-verify.js';
import { createStatusList, type StatusListManager } from '../../token-status-list.js';

const ISSUER = 'did:key:z6MkIssuerFacade';
const HOLDER = 'did:key:z6MkHolderFacade';
const REVOCATION_URI = 'https://issuer.example/status/revocation';
const SUSPENSION_URI = 'https://issuer.example/status/suspension';
const SIGNER_KEY = new Uint8Array(32).fill(59);
const IAT = 1_767_225_600;
const NOW = new Date('2026-08-28T00:00:00.000Z');

/** Issuer 署名鍵に対応する P-256 公開鍵 JWK。 */
function issuerJwk(): PublicKeyJwk {
  const pub = getP256PublicKey(SIGNER_KEY, false);
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

describe('IssuerModule facade', () => {
  let revocation: StatusListManager;
  let suspension: StatusListManager;
  let issuer: IssuerModule;

  beforeEach(() => {
    revocation = createStatusList({
      uri: REVOCATION_URI,
      issuer: ISSUER,
      size: 64,
      purpose: 'revocation',
    });
    suspension = createStatusList({
      uri: SUSPENSION_URI,
      issuer: ISSUER,
      size: 64,
      purpose: 'suspension',
    });
    issuer = new IssuerModule({
      issuer: ISSUER,
      signer: createPrivateKeySigner(SIGNER_KEY, 'ES256'),
      statusLists: { revocation, suspension },
      now: () => NOW,
    });
  });

  it('issueVC が status.status_list.{idx,uri} を自動付与する（受入条件 4）', async () => {
    const vc = await issuer.issueVC(HOLDER, { degree: 'BSc' });
    expect(vc.issuer).toBe(ISSUER);
    expect(vc.credentialSubject.id).toBe(HOLDER);
    expect(vc.credentialSubject.degree).toBe('BSc');
    expect(vc.issuanceDate).toBe(NOW.toISOString());
    // 既定 format は 'jwt' のため statusListType は 'token-status-list'。
    expect(vc.status).toEqual({ status_list: { idx: 0, uri: REVOCATION_URI } });
  });

  it('generateTokenStatusList が検証可能な Status List Token を返す（受入条件 1）', async () => {
    await issuer.issueVC(HOLDER, {});
    const token = await issuer.generateTokenStatusList('revocation', { iatSeconds: IAT });
    const verified = verifyStatusListToken(token, REVOCATION_URI, issuerJwk());
    expect(verified.payload.iss).toBe(ISSUER);
    expect(verified.payload.iat).toBe(IAT);
    expect(await readStatusBit(verified, 0)).toBe(0);
  });

  it('setTokenStatus で対象 VC のビットが更新され再署名した Token に載る（受入条件 2）', async () => {
    const first = await issuer.issueVC(HOLDER, {});
    const second = await issuer.issueVC(HOLDER, {});

    await issuer.setTokenStatus(second.id ?? '', 'revocation', 1);

    const token = await issuer.generateTokenStatusList('revocation', { iatSeconds: IAT });
    const verified = verifyStatusListToken(token, REVOCATION_URI, issuerJwk());
    expect(await readStatusBit(verified, 0)).toBe(0);
    expect(await readStatusBit(verified, 1)).toBe(1);
    expect(first.status).toEqual({ status_list: { idx: 0, uri: REVOCATION_URI } });
  });

  it('suspension リストのビットも vcId から更新できる', async () => {
    const vc = await issuer.issueVC(HOLDER, {});
    await issuer.setTokenStatus(vc.id ?? '', 'suspension', 1);

    const token = await issuer.generateTokenStatusList('suspension', { iatSeconds: IAT });
    const verified = verifyStatusListToken(token, SUSPENSION_URI, issuerJwk());
    expect(await readStatusBit(verified, 0)).toBe(1);
  });

  it('exportEntries / importEntries で vcId → idx を復元できる', async () => {
    const vc = await issuer.issueVC(HOLDER, {});
    const entries = issuer.exportEntries();
    expect(entries).toEqual([{ vcId: vc.id ?? '', indices: { revocation: 0, suspension: 0 } }]);

    const restored = new IssuerModule({
      issuer: ISSUER,
      signer: createPrivateKeySigner(SIGNER_KEY, 'ES256'),
      // 取り込む purpose はすべて設定済みであること（未設定 purpose は 3002）。
      statusLists: { revocation, suspension },
      now: () => NOW,
    });
    restored.importEntries(entries);
    await restored.setTokenStatus(vc.id ?? '', 'revocation', 1);
    expect(revocation.getStatus(0)).toBe(1);
  });

  it('credentialStatus: false なら status を付与しない', async () => {
    const vc = await issuer.issueVC(HOLDER, {}, { credentialStatus: false });
    expect(vc.status).toBeUndefined();
    expect(revocation.nextIndex).toBe(0);
  });

  it('statusListType が token-status-list 以外なら status を付与しない', async () => {
    const vc = await issuer.issueVC(HOLDER, {}, { format: 'data-integrity' });
    expect(vc.status).toBeUndefined();
    expect(revocation.nextIndex).toBe(0);
  });

  it('opts.types が VerifiableCredential の後ろに連結される', async () => {
    const vc = await issuer.issueVC(HOLDER, {}, { types: ['UniversityDegreeCredential'] });
    expect(vc.type).toEqual(['VerifiableCredential', 'UniversityDegreeCredential']);
  });

  it('指定したパススルー項目が VC のフィールドへ写像される', async () => {
    const vc = await issuer.issueVC(
      HOLDER,
      {},
      {
        credentialSchema: 'https://issuer.example/schema.json',
        refreshService: {
          id: 'https://issuer.example/refresh',
          type: 'OID4VCIRefreshService2025',
          url: 'https://issuer.example/refresh',
        },
        evidence: [{ type: ['DocumentVerification'], id: 'urn:uuid:ev-1' }],
        termsOfUse: [{ type: 'IssuerPolicy', id: 'urn:uuid:tou-1' }],
        derivedFrom: 'urn:uuid:parent-vc',
        revocationPropagation: 'strict',
        expirationDate: '2027-01-01T00:00:00Z',
      },
    );
    expect(vc.credentialSchema).toEqual({
      id: 'https://issuer.example/schema.json',
      type: 'JsonSchema',
    });
    expect(vc.refreshService?.url).toBe('https://issuer.example/refresh');
    expect(vc.evidence).toEqual([{ type: ['DocumentVerification'], id: 'urn:uuid:ev-1' }]);
    expect(vc.termsOfUse).toEqual([{ type: 'IssuerPolicy', id: 'urn:uuid:tou-1' }]);
    expect(vc.derivedFrom).toBe('urn:uuid:parent-vc');
    expect(vc.revocationPropagation).toBe('strict');
    expect(vc.expirationDate).toBe('2027-01-01T00:00:00Z');
  });

  // IssueOptions の対象外の cryptosuite / statusListVersion / sdDisclosable は、
  // 実行時に渡されても VC へ写像されず、既定動作を変えない。
  it('IssueOptions の対象外の項目（cryptosuite / suite / sdDisclosable / statusListVersion）は写像しない', async () => {
    const outOfScope = {
      cryptosuite: 'ecdsa-rdfc-2019',
      suite: 'ecdsa-rdfc-2019',
      sdDisclosable: ['degree'],
      statusListVersion: 'statuslist2021',
    } as Record<string, unknown>;

    const vc = await issuer.issueVC(HOLDER, { degree: 'BSc' }, outOfScope);

    // どのキーも VC のトップレベルに現れない。
    for (const key of Object.keys(outOfScope)) {
      expect(vc).not.toHaveProperty(key);
    }
    // `statusListVersion` は `statusListType` の代替として解釈されない
    // （既定 jwt → token-status-list のまま status が付く）。
    expect(vc.status?.status_list?.uri).toBe(REVOCATION_URI);
    // 生えるフィールドは既定発行と同一（スコープ外項目は既定挙動を一切変えない）。
    expect(Object.keys(vc).sort()).toEqual([
      '@context',
      'credentialSubject',
      'id',
      'issuanceDate',
      'issuer',
      'status',
      'type',
    ]);
  });

  it('opts.id / opts.issuanceDate が VC へ写像される', async () => {
    const vc = await issuer.issueVC(
      HOLDER,
      {},
      { id: 'urn:uuid:fixed-vc-id', issuanceDate: '2026-01-02T03:04:05Z' },
    );
    expect(vc.id).toBe('urn:uuid:fixed-vc-id');
    expect(vc.issuanceDate).toBe('2026-01-02T03:04:05Z');
  });

  it('未指定のオプションに対応するフィールドはプロパティ自体を生やさない', async () => {
    const vc = await issuer.issueVC(HOLDER, {});
    expect(Object.keys(vc).sort()).toEqual([
      '@context',
      'credentialSubject',
      'id',
      'issuanceDate',
      'issuer',
      'status',
      'type',
    ]);
  });

  it('Holder DID の形式が不正なら 3006 で拒否する', async () => {
    const promise = issuer.issueVC('not-a-did', {});
    await expect(promise).rejects.toThrow(VericertsError);
    await expect(promise).rejects.toMatchObject({
      code: ErrorCodes.HOLDER_DID_FORMAT_INVALID,
    });
  });

  it('未登録の vcId への setTokenStatus は 3070 で拒否する', async () => {
    const promise = issuer.setTokenStatus('urn:uuid:unknown', 'revocation', 1);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.VC_NOT_FOUND });
  });

  it('未設定 purpose への操作は 3018 で拒否する', async () => {
    const revocationOnly = new IssuerModule({
      issuer: ISSUER,
      signer: createPrivateKeySigner(SIGNER_KEY, 'ES256'),
      statusLists: { revocation },
      now: () => NOW,
    });
    const vc = await revocationOnly.issueVC(HOLDER, {});
    await expect(revocationOnly.setTokenStatus(vc.id ?? '', 'suspension', 1)).rejects.toMatchObject(
      { code: ErrorCodes.TOKEN_STATUS_LIST_UNSUPPORTED },
    );
    await expect(revocationOnly.generateTokenStatusList('suspension')).rejects.toMatchObject({
      code: ErrorCodes.TOKEN_STATUS_LIST_UNSUPPORTED,
    });
  });

  it('Status List の容量を使い切ると 3007 で拒否する', async () => {
    const tiny = createStatusList({ uri: REVOCATION_URI, issuer: ISSUER, size: 8 });
    const small = new IssuerModule({
      issuer: ISSUER,
      signer: createPrivateKeySigner(SIGNER_KEY, 'ES256'),
      statusLists: { revocation: tiny },
      now: () => NOW,
    });
    for (let i = 0; i < 8; i += 1) {
      await small.issueVC(HOLDER, {});
    }
    await expect(small.issueVC(HOLDER, {})).rejects.toMatchObject({
      code: ErrorCodes.STATUS_LIST_INDEX_EXHAUSTED,
    });
  });

  it('claims.id は検証済み holderDID で上書きされる（subject 詐称の防止）', async () => {
    const vc = await issuer.issueVC(HOLDER, { id: 'attacker-not-a-did', name: 'Alice' });
    expect(vc.credentialSubject.id).toBe(HOLDER);
    expect(vc.credentialSubject.name).toBe('Alice');
  });

  it('いずれかのリストが枯渇していれば他リストのインデックスを消費しない（確保のアトミック性）', async () => {
    const wide = createStatusList({ uri: REVOCATION_URI, issuer: ISSUER, size: 64 });
    const narrow = createStatusList({
      uri: SUSPENSION_URI,
      issuer: ISSUER,
      size: 1,
      purpose: 'suspension',
    });
    const mixed = new IssuerModule({
      issuer: ISSUER,
      signer: createPrivateKeySigner(SIGNER_KEY, 'ES256'),
      statusLists: { revocation: wide, suspension: narrow },
      now: () => NOW,
    });
    await mixed.issueVC(HOLDER, {});
    expect(wide.nextIndex).toBe(1);

    await expect(mixed.issueVC(HOLDER, {})).rejects.toMatchObject({
      code: ErrorCodes.STATUS_LIST_INDEX_EXHAUSTED,
    });
    // suspension の枯渇で失敗した発行が revocation のカーソルを進めていないこと。
    expect(wide.nextIndex).toBe(1);
    expect(narrow.nextIndex).toBe(1);
  });

  it('issuer が空文字なら構築時に 3002 で拒否する', () => {
    expect(
      () =>
        new IssuerModule({
          issuer: '',
          signer: createPrivateKeySigner(SIGNER_KEY, 'ES256'),
          statusLists: { revocation },
        }),
    ).toThrow(VericertsError);
  });
});
