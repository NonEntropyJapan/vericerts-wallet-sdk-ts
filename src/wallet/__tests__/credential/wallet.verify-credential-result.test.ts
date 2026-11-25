/**
 * 高レベル `Wallet.verifyCredential`（判別共用体 Result 型）の回帰テスト
 *
 * 固定する性質は 3 つ:
 * - 検証の不成立は**例外にならず** `{ valid: false, errors }` として返る（`errors` は構造化された
 *   `VerificationIssue`。コードは `verifyCredentialStrict` が投げる `VericertsError` と同じ）。
 * - `valid: true` の枝にしか `data` が無い（未検証の VC を「検証済み」として読み出せない）。
 * - **検証の不成立以外の例外は握り潰さない**。`VericertsError` でない例外は Result へ丸めず
 *   そのまま reject する（想定外の不具合が「正常な検証失敗」に紛れないようにするため）。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../../internal/credential/index.js';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import type { DIDMethod } from '../../../internal/identity/did.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import {
  assertCredentialInvalid,
  assertCredentialValid,
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
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer,
    credentialSubject: { id: issuer, name: 'Alice' },
    issuanceDate: '2025-01-01T00:00:00Z',
    ...overrides,
  } satisfies VerifiableCredential;
}

/** 署名の 1 文字を書き換えて署名不一致にする。 */
function tamperSignature(jwt: string): string {
  const parts = jwt.split('.');
  const sig = parts[2] ?? '';
  return `${parts[0]}.${parts[1]}.${(sig[0] === 'A' ? 'B' : 'A') + sig.slice(1)}`;
}

describe('Wallet.verifyCredential（高レベル Result）', () => {
  it('正当な VC は valid: true + data を返し、例外を投げない', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const jwt = await wallet.issueCredential(sampleVc(did), keyID);

    const result = assertCredentialValid(await wallet.verifyCredential(jwt));

    expect(result.data.payload.iss).toBe(did);
    expect((result.data.payload.vc as VerifiableCredential).credentialSubject.name).toBe('Alice');
    expect(result.warnings).toEqual([]);
  });

  it('署名不一致は例外にならず valid: false / errors[3010] になる', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const tampered = tamperSignature(await wallet.issueCredential(sampleVc(did), keyID));

    const result = assertCredentialInvalid(await wallet.verifyCredential(tampered));

    expect(issueCodes(result.errors)).toEqual([ErrorCodes.SIG_INVALID]);
    expect(result.errors[0]?.message).toBeString();
    // 同じ入力を primitive に渡すと従来どおり例外になる（2 層が同じ判定を共有している証拠）。
    await expect(wallet.verifyCredentialStrict(tampered)).rejects.toBeInstanceOf(VericertsError);
  });

  it('期限切れ VC は valid: false / errors[3024]', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const jwt = await wallet.issueCredential(
      sampleVc(did, { expirationDate: '2025-06-01T00:00:00Z' }),
      keyID,
      { nowSeconds: 1_735_689_600 },
    );

    // 2026-01-01。exp（2025-06-01）を大きく過ぎており、既定スキュー 120s でも救えない。
    const result = assertCredentialInvalid(
      await wallet.verifyCredential(jwt, { nowSeconds: 1_767_225_600 }),
    );

    expect(issueCodes(result.errors)).toEqual([ErrorCodes.VC_EXPIRED]);
  });

  it('iss を欠く JWT は valid: false / errors[3002]（構造不正も Result に畳む）', async () => {
    const { wallet } = await setupIssuer();
    const header = Buffer.from(JSON.stringify({ alg: 'ES256K', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ foo: 'bar' })).toString('base64url');

    const result = assertCredentialInvalid(
      await wallet.verifyCredential(`${header}.${payload}.AA`),
    );

    expect(issueCodes(result.errors)).toEqual([ErrorCodes.VC_SCHEMA_INVALID]);
  });

  it('VericertsError でない例外は Result へ丸めず reject する（握り潰さない）', async () => {
    const { wallet, keyID } = await setupIssuer();
    // 解決時に素の Error を投げる DID メソッド。`VericertsError` ではないので検証の不成立ではない。
    const boom = new Error('resolver exploded');
    const method: DIDMethod = {
      method: () => 'boom',
      create: () => Promise.reject(boom),
      resolve: () => Promise.reject(boom),
      update: () => Promise.reject(boom),
      deactivate: () => Promise.reject(boom),
    };
    wallet.registerDIDMethod(method);
    const jwt = await wallet.issueCredential(sampleVc('did:boom:1'), keyID);

    await expect(wallet.verifyCredential(jwt)).rejects.toThrow(boom);
  });
});
