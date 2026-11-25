/**
 * wallet ファサードの発行/検証配線の統合テスト。
 *
 * deriveKey → createDID('key') で自己 DID を発行し、その鍵 ID で JWT-VC を発行（鍵は keymanager
 * 内に保持したまま署名）→ iss（自 DID）を resolver で解決して検証する往復を、実署名・ネット非依存
 * （did:key の自己発行・自己検証）で確認する:
 * - issueCredential → verifyCredentialStrict
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../../internal/credential/index.js';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import type { TrustChain } from '../../../internal/trust/federation/federation-types.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import { findLog, recordingLogger } from '../metrics/logger.fixtures.js';

// BIP-39 公式オールゼロ・エントロピーのニーモニック（passphrase なし）。
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** import + 既定パス derive + did:key 自己発行済みの Wallet・鍵 ID・DID を用意する。 */
async function setupIssuer() {
  const wallet = await createWallet({ storage: new MemoryStorage() });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
  const document = await wallet.createDID('key', { keyID: keyPair.id });
  return { wallet, keyID: keyPair.id, did: document.id };
}

describe('Wallet.issueCredential / verifyCredentialStrict', () => {
  it('did:key 自己発行 → 自己検証で往復できる（鍵非露出・ネット非依存）', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const vc: VerifiableCredential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: did,
      credentialSubject: { id: did, name: 'Alice' },
      issuanceDate: '2026-01-01T00:00:00Z',
    };

    const jwt = await wallet.issueCredential(vc, keyID);
    expect(jwt.split('.').length).toBe(3);

    const verified = await wallet.verifyCredentialStrict(jwt);
    expect(verified.payload.iss).toBe(did);
    expect((verified.payload.vc as VerifiableCredential).credentialSubject.name).toBe('Alice');
  });

  it('未登録鍵 ID での発行は 1004 を投げる', async () => {
    const { wallet, did } = await setupIssuer();
    const vc: VerifiableCredential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: did,
      credentialSubject: { id: did },
      issuanceDate: '2026-01-01T00:00:00Z',
    };
    try {
      await wallet.issueCredential(vc, 'nonexistent');
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('1004');
    }
  });

  it('iss を欠く JWT の検証は 3002 を投げる', async () => {
    const { wallet } = await setupIssuer();
    // iss を持たない最小 JWS（header.payload.signature）。
    const header = Buffer.from(JSON.stringify({ alg: 'ES256K', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ foo: 'bar' })).toString('base64url');
    const jwt = `${header}.${payload}.AA`;
    try {
      await wallet.verifyCredentialStrict(jwt);
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('3002');
    }
  });

  it('別鍵の did:key で署名を改竄すると 3010 で検証失敗する', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    // iss は自 DID（did）だが、別パスの鍵で署名 → 解決鍵と署名鍵が不一致になる。
    const otherKey = await wallet.deriveKey(ethereumPath(0, 1));
    expect(otherKey.id).not.toBe(keyID);
    const vc: VerifiableCredential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: did,
      credentialSubject: { id: did },
      issuanceDate: '2026-01-01T00:00:00Z',
    };
    const jwt = await wallet.issueCredential(vc, otherKey.id);
    try {
      await wallet.verifyCredentialStrict(jwt);
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('3010');
    }
  });
});

/**
 * ファサードが `issuerTrust` を検証関数へ受け渡すことの回帰。
 *
 * `verifyCredentialWith` はオプションを spread せず
 * 明示的に選び取るため、追加したオプションが黙って落ちても他のテストでは検知できない。
 * 落ちれば FC-11 の突合が Wallet 経由で一切効かなくなるので、受け渡し自体を固定する。
 */
describe('Wallet.verifyCredentialStrict - issuerTrust の受け渡し', () => {
  /** 成立していない Trust Chain（渡されたことが 5010 で分かる最小の目印）。 */
  const invalidChain: TrustChain = {
    valid: false,
    leaf: 'https://issuer.example.eu',
    trustAnchor: 'https://federation.example.eu',
    nodes: [],
    length: 0,
    revokedKeys: [],
  };

  /** 自己発行した JWT-VC を返す。 */
  async function issueSelfSigned(): Promise<{
    wallet: Awaited<ReturnType<typeof setupIssuer>>['wallet'];
    jwt: string;
  }> {
    const { wallet, keyID, did } = await setupIssuer();
    const vc: VerifiableCredential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: did,
      credentialSubject: { id: did, name: 'Alice' },
      issuanceDate: '2026-01-01T00:00:00Z',
    };
    return { wallet, jwt: await wallet.issueCredential(vc, keyID) };
  }

  it('issuerTrust を渡すと検証関数まで届く（不成立チェーンは 5010）', async () => {
    const { wallet, jwt } = await issueSelfSigned();

    // オプションが握り潰されていれば署名・時刻検証を通って解決してしまう。
    const error = await wallet
      .verifyCredentialStrict(jwt, { issuerTrust: { trustChain: invalidChain } })
      .then(() => undefined)
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.TRUST_CHAIN_INVALID);
  });

  it('issuerTrust 省略時は従来どおり検証できる（既定挙動を変えない）', async () => {
    const { wallet, jwt } = await issueSelfSigned();

    const verified = await wallet.verifyCredentialStrict(jwt);

    expect(verified.payload.iss).toBeString();
  });
});

describe('Wallet.verifyCredentialStrict のログ配線', () => {
  /** 記録ロガーを注入した Wallet で自己発行した JWT-VC を用意する。 */
  async function setupWithLogger() {
    const { logger, logs } = recordingLogger();
    const wallet = await createWallet({ storage: new MemoryStorage(), logger });
    await wallet.importMnemonic(TEST_MNEMONIC);
    const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
    const document = await wallet.createDID('key', { keyID: keyPair.id });
    const vc: VerifiableCredential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: document.id,
      credentialSubject: { id: document.id, name: 'Alice' },
      issuanceDate: '2026-01-01T00:00:00Z',
    };
    const jwt = await wallet.issueCredential(vc, keyPair.id);
    return { wallet, jwt, logs };
  }

  it('検証成功で info(vc.verify) を出す（component/operation/vc_format/duration_ms 付き）', async () => {
    const { wallet, jwt, logs } = await setupWithLogger();

    await wallet.verifyCredentialStrict(jwt);

    const attrs = findLog(logs, 'info', 'vc.verify')?.attrs;
    expect(attrs?.component).toBe('sdk.vc');
    expect(attrs?.operation).toBe('vc.verify');
    expect(attrs?.vc_format).toBe('jwt');
    expect(typeof attrs?.duration_ms).toBe('number');
    expect(findLog(logs, 'error', 'vc.verify')).toBeUndefined();
  });

  it('検証失敗で error(vc.verify) を error_code 付きで出し、例外はそのまま届く', async () => {
    const { wallet, logs } = await setupWithLogger();
    // iss を持たない最小 JWS（`verifyCredential` は 3002 で失敗する）。
    const header = Buffer.from(JSON.stringify({ alg: 'ES256K', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ foo: 'bar' })).toString('base64url');

    let caught: unknown;
    try {
      await wallet.verifyCredentialStrict(`${header}.${payload}.AA`);
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe('3002');
    const attrs = findLog(logs, 'error', 'vc.verify')?.attrs;
    expect(attrs?.component).toBe('sdk.vc');
    expect(attrs?.operation).toBe('vc.verify');
    expect(attrs?.vc_format).toBe('jwt');
    expect(attrs?.error_code).toBe('3002');
    expect(findLog(logs, 'info', 'vc.verify')).toBeUndefined();
  });
});
