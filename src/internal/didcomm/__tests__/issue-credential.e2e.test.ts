/**
 * `didcomm/issue-credential.ts` の end-to-end 統合テスト。
 *
 * 実際に `issueCredential`（`credential/vc/issue.ts`）で署名した JWT-VC を issue-credential
 * メッセージへ添付し、抽出した JWT-VC が `verifyCredential` でそのまま検証に通ることを確認する
 * （添付の base64 往復がバイト単位で JWT を破壊しないことの回帰）。
 */

import { describe, expect, it } from 'bun:test';
import { issueCredential } from '../../credential/vc/issue.js';
import { createPrivateKeySigner } from '../../credential/vc/signer.js';
import type { VerifiableCredential } from '../../credential/vc/vc.js';
import { verifyCredential } from '../../credential/vc/verify.js';
import { getSecp256k1PublicKey, verifySecp256k1 } from '../../keymanager/signer.js';
import {
  buildIssueCredentialIssueMessage,
  buildIssueCredentialOfferMessage,
  buildIssueCredentialRequestMessage,
  extractIssuedCredentialJwt,
} from '../issue-credential.js';

const ISSUER_KEY = new Uint8Array(32).fill(11);
const NOW = 1_767_225_600;

function sampleVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:peer:2.issuer',
    credentialSubject: { id: 'did:peer:2.holder', name: 'Alice' },
    issuanceDate: '2025-12-01T00:00:00Z',
    expirationDate: '2027-01-01T00:00:00Z',
    id: 'urn:uuid:e2e-1633',
  };
}

describe('issue-credential の DIDComm 添付往復（実 VC 発行との統合）', () => {
  it('offer → request → issue のスレッドを通じて発行済み JWT-VC が破損なく届き検証に通る', () => {
    const signer = createPrivateKeySigner(ISSUER_KEY, 'ES256K');
    const credentialJwt = issueCredential(sampleVc(), signer, { nowSeconds: NOW });

    const offer = buildIssueCredentialOfferMessage({
      fromDid: 'did:peer:2.issuer',
      toDid: 'did:peer:2.holder',
      credentialPreview: { name: 'Alice' },
    });
    const request = buildIssueCredentialRequestMessage({
      fromDid: 'did:peer:2.holder',
      toDid: 'did:peer:2.issuer',
      offerId: offer.id,
    });
    const issueMessage = buildIssueCredentialIssueMessage({
      fromDid: 'did:peer:2.issuer',
      toDid: 'did:peer:2.holder',
      requestId: request.id,
      credentialJwt,
    });

    // スレッド全体が offer.id を起点に一貫している。
    expect(request.thid).toBe(offer.id);
    expect(issueMessage.thid).toBe(request.id);

    const extractedJwt = extractIssuedCredentialJwt(issueMessage);
    expect(extractedJwt).toBe(credentialJwt);

    const publicKey = getSecp256k1PublicKey(ISSUER_KEY, false);
    const result = verifyCredential(extractedJwt, {
      key: { verify: (digest, signature) => verifySecp256k1(digest, signature, publicKey) },
      nowSeconds: NOW,
    });
    expect(result.payload.iss).toBe('did:peer:2.issuer');
    expect((result.payload.vc as VerifiableCredential).credentialSubject.name).toBe('Alice');
  });
});
