/**
 * `didcomm/issue-credential.ts`（issue-credential/3.0 プロトコルメッセージ構築・抽出）の
 * テスト。
 */

import { describe, expect, it } from 'bun:test';
import { VericertsError } from '../../errors.js';
import {
  buildIssueCredentialIssueMessage,
  buildIssueCredentialOfferMessage,
  buildIssueCredentialRequestMessage,
  extractIssuedCredentialJwt,
  ISSUE_CREDENTIAL_ISSUE_TYPE,
  ISSUE_CREDENTIAL_OFFER_TYPE,
  ISSUE_CREDENTIAL_REQUEST_TYPE,
} from '../issue-credential.js';

describe('issue-credential メッセージのスレッド構築', () => {
  it('offer → request → issue が thid で一貫したスレッドになる', () => {
    const offer = buildIssueCredentialOfferMessage({
      fromDid: 'did:peer:2.issuer',
      toDid: 'did:peer:2.holder',
      credentialPreview: { degree: 'Bachelor of Arts' },
      comment: 'ご卒業おめでとうございます',
    });
    expect(offer.type).toBe(ISSUE_CREDENTIAL_OFFER_TYPE);
    expect(offer.thid).toBeUndefined();
    expect(offer.body.credential_preview).toEqual({ degree: 'Bachelor of Arts' });

    const request = buildIssueCredentialRequestMessage({
      fromDid: 'did:peer:2.holder',
      toDid: 'did:peer:2.issuer',
      offerId: offer.id,
    });
    expect(request.type).toBe(ISSUE_CREDENTIAL_REQUEST_TYPE);
    expect(request.thid).toBe(offer.id);

    const issue = buildIssueCredentialIssueMessage({
      fromDid: 'did:peer:2.issuer',
      toDid: 'did:peer:2.holder',
      requestId: request.id,
      credentialJwt: 'header.payload.signature',
    });
    expect(issue.type).toBe(ISSUE_CREDENTIAL_ISSUE_TYPE);
    expect(issue.thid).toBe(request.id);
  });
});

describe('extractIssuedCredentialJwt', () => {
  it('issue-credential メッセージの添付から JWT-VC を復元する', () => {
    const issue = buildIssueCredentialIssueMessage({
      fromDid: 'did:peer:2.issuer',
      toDid: 'did:peer:2.holder',
      requestId: 'req-1',
      credentialJwt: 'header.payload.signature',
    });
    expect(extractIssuedCredentialJwt(issue)).toBe('header.payload.signature');
  });

  it('type が issue-credential でないメッセージは DIDCOMM_UNPACKING_FAILED', () => {
    const offer = buildIssueCredentialOfferMessage({
      fromDid: 'did:peer:2.issuer',
      toDid: 'did:peer:2.holder',
      credentialPreview: {},
    });
    expect(() => extractIssuedCredentialJwt(offer)).toThrow(VericertsError);
    try {
      extractIssuedCredentialJwt(offer);
      expect.unreachable();
    } catch (error) {
      expect((error as VericertsError).code).toBe('9004');
    }
  });

  it('添付が無い issue-credential メッセージは DIDCOMM_UNPACKING_FAILED', () => {
    const malformed = {
      id: 'x',
      type: ISSUE_CREDENTIAL_ISSUE_TYPE,
      thid: 'req-1',
      body: {},
    };
    expect(() => extractIssuedCredentialJwt(malformed)).toThrow(VericertsError);
  });
});
