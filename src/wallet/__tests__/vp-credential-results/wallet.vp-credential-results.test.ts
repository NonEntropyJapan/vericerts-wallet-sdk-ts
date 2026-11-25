/**
 * Wallet ファサードの `verifyPresentation` が内包 VC を検証することの回帰テスト。
 *
 * `verifyPresentation` は VP 署名と内包 VC をすべて検証し、各 VC の結果を `credentialResults` に返す。
 * 修正前のファサードは VP（holder）署名だけを検証し、
 * `vp.verifiableCredential` に詰められた VC は一切検証せずに成功を返していた。
 *
 * ファサードは内包 VC の発行者鍵を `iss` の DID 解決で自動補完する。ここでは did:key の
 * 自己発行・自己検証（実署名・ネット非依存）でその配線を確認する。
 */

import { describe, expect, it } from 'bun:test';
import {
  type IssuePresentationOptions,
  VC_V2_CONTEXT,
  type VerifiableCredential,
  type VerifiablePresentation,
} from '../../../internal/credential/index.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import type { TrustedIssuerList } from '../../../internal/trusted-issuer/types.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import {
  assertPresentationInvalid,
  assertPresentationValid,
  embeddedErrorCodes,
  issueCodes,
} from '../verification-result.fixtures.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** did:key を自己発行済みの Wallet・鍵 ID・DID を用意する。 */
async function setupIssuer() {
  const wallet = await createWallet({ storage: new MemoryStorage() });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
  const document = await wallet.createDID('key', { keyID: keyPair.id });
  return { wallet, keyID: keyPair.id, did: document.id };
}

function sampleVc(issuer: string, overrides: Partial<VerifiableCredential> = {}) {
  return {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer,
    credentialSubject: { id: issuer, name: 'Alice' },
    issuanceDate: '2025-01-01T00:00:00Z',
    expirationDate: '2030-01-01T00:00:00Z',
    id: 'urn:uuid:vc-1',
    ...overrides,
  } satisfies VerifiableCredential;
}

/** 内包 VC を持つ JWT-VP を発行する。 */
async function issueVpWith(
  wallet: Awaited<ReturnType<typeof setupIssuer>>['wallet'],
  keyID: string,
  did: string,
  entries: readonly string[],
  opts?: IssuePresentationOptions,
): Promise<string> {
  const vp: VerifiablePresentation = {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiablePresentation'],
    holder: did,
    verifiableCredential: entries,
  };
  return wallet.issuePresentation(vp, keyID, opts);
}

describe('Wallet.verifyPresentation の内包 VC 検証', () => {
  it('内包 VC の発行者鍵を iss の DID 解決で補完し、valid: true を返す', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const jwtVc = await wallet.issueCredential(sampleVc(did), keyID);
    const jwt = await issueVpWith(wallet, keyID, did, [jwtVc]);

    const verified = assertPresentationValid(
      await wallet.verifyPresentation(jwt, { allowUnbound: true }),
    );
    expect(verified.holderDID).toBe(did);
    expect(verified.warnings).toEqual([]);
    expect(verified.credentialResults).toHaveLength(1);
    expect(verified.credentialResults[0]).toMatchObject({
      valid: true,
      issuerDID: did,
      format: 'jwt_vc_json',
    });
  });

  it('署名を改竄した内包 VC は valid: false（VP 署名は通っても素通りさせない）', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const jwtVc = await wallet.issueCredential(sampleVc(did), keyID);
    const parts = jwtVc.split('.');
    const sig = parts[2] ?? '';
    const tampered = `${parts[0]}.${parts[1]}.${(sig[0] === 'A' ? 'B' : 'A') + sig.slice(1)}`;
    const jwt = await issueVpWith(wallet, keyID, did, [tampered]);

    const verified = assertPresentationInvalid(
      await wallet.verifyPresentation(jwt, { allowUnbound: true }),
    );
    // VP envelope（holder 鍵の署名）は正当なので、失敗は内包 VC 側だけ。
    expect(verified.presentationValid).toBe(true);
    expect(verified.holderDID).toBe(did);
    expect(verified.credentialResults[0]?.valid).toBe(false);
    expect(issueCodes(verified.errors)).toEqual(['3010']);
  });

  it('発行者 DID を解決できない内包 VC は fail-closed で valid: false', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    // iss が解決不能な DID の VC。鍵を組み立てられないため検証不能 = 成功にしない。
    const jwtVc = await wallet.issueCredential(sampleVc('did:example:unresolvable'), keyID);
    const jwt = await issueVpWith(wallet, keyID, did, [jwtVc]);

    const verified = assertPresentationInvalid(
      await wallet.verifyPresentation(jwt, { allowUnbound: true }),
    );
    expect(verified.presentationValid).toBe(true);
    expect(verified.credentialResults[0]).toMatchObject({
      valid: false,
      issuerDID: 'did:example:unresolvable',
    });
  });

  it('内包 SD-JWT VC も iss の DID 解決で検証される（Issuer 鍵は JWK として解決）', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const sdJwt = await wallet.issueSdJwt(keyID, {
      vct: 'https://example.com/credentials/identity',
      disclosureClaims: ['name'],
      claims: { name: 'Alice' },
      salts: { name: 'salt-name' },
      issuer: did,
    });
    const jwt = await issueVpWith(wallet, keyID, did, [sdJwt]);

    const verified = assertPresentationValid(
      await wallet.verifyPresentation(jwt, { allowUnbound: true }),
    );
    expect(verified.credentialResults[0]).toMatchObject({
      valid: true,
      issuerDID: did,
      format: 'dc+sd-jwt',
    });
  });

  it('clockSkewSeconds がファサード経由でも内包 VC へ中継される', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    // 発行（VC・VP）と検証で同じ時刻を使う。実時刻のまま発行すると、署名の合間に秒境界をまたいだとき
    // VP の `iat` が `nowSeconds` より未来になり、`clockSkewSeconds: 0` では提示自体が弾かれる。
    const nowSeconds = Math.floor(Date.now() / 1000);
    // 60 秒前に失効した VC。VC 既定の 120s 許容なら通り、0 を指定すれば 3024 で落ちる。
    const jwtVc = await wallet.issueCredential(
      sampleVc(did, { expirationDate: new Date((nowSeconds - 60) * 1000).toISOString() }),
      keyID,
      { nowSeconds },
    );
    const jwt = await issueVpWith(wallet, keyID, did, [jwtVc], { nowSeconds });

    const lenient = await wallet.verifyPresentation(jwt, { allowUnbound: true, nowSeconds });
    expect(lenient.valid).toBe(true);

    const strict = assertPresentationInvalid(
      await wallet.verifyPresentation(jwt, {
        allowUnbound: true,
        nowSeconds,
        clockSkewSeconds: 0,
      }),
    );
    expect(embeddedErrorCodes(strict.credentialResults[0])).toEqual(['3024']);
  });

  // 旧契約（内包 VC ゼロで valid: true）は 撤回。envelope が正当でも、証明すべき VC が
  // 無い提示は認可材料にならない（`every([])` の空真を塞いだ）。
  it('内包 VC を持たない VP は valid: false / presentationValid: true', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const jwt = await issueVpWith(wallet, keyID, did, []);
    const invalid = assertPresentationInvalid(
      await wallet.verifyPresentation(jwt, { allowUnbound: true }),
    );
    expect(invalid.presentationValid).toBe(true);
    expect(invalid.credentialResults).toEqual([]);
    expect(issueCodes(invalid.errors)).toEqual(['3002']);
  });
});

describe('Wallet.verifyPresentation の trustedIssuerList 中継', () => {
  const trustedIssuerListOf = (issuerDids: readonly string[]): TrustedIssuerList => ({
    id: 'til-1',
    type: 'TrustedIssuerList',
    version: 'TSLv1',
    listOperator: 'did:example:operator',
    listName: 'Test TIL',
    issuedAt: '2025-01-01T00:00:00Z',
    trustedIssuers: issuerDids.map((id) => ({ id, name: id })),
  });

  it('未指定なら isTrustedIssuer は null、登録済みなら true、未登録なら false', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const jwtVc = await wallet.issueCredential(sampleVc(did), keyID);
    const jwt = await issueVpWith(wallet, keyID, did, [jwtVc]);

    const unchecked = assertPresentationValid(
      await wallet.verifyPresentation(jwt, { allowUnbound: true }),
    );
    expect(unchecked.credentialResults[0]?.isTrustedIssuer).toBeNull();

    const trusted = assertPresentationValid(
      await wallet.verifyPresentation(jwt, {
        allowUnbound: true,
        trustedIssuerList: trustedIssuerListOf([did]),
      }),
    );
    expect(trusted.credentialResults[0]?.isTrustedIssuer).toBe(true);

    // 照合した結果「信頼リストに無い」は VC 自体の有効性とは別（valid のまま false）。
    const untrusted = assertPresentationValid(
      await wallet.verifyPresentation(jwt, {
        allowUnbound: true,
        trustedIssuerList: trustedIssuerListOf(['did:example:someone-else']),
      }),
    );
    expect(untrusted.credentialResults[0]?.isTrustedIssuer).toBe(false);
  });
});
