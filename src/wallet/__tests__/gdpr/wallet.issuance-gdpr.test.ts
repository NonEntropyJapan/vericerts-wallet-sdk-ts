/**
 * Wallet ファサードの発行 API（`issueCredential` / `issueSdJwt`）に GDPR Art.9 ガードが
 * 効いていることの回帰テスト（エラーコード `10607`）。
 *
 * ガード本体は低レベル発行プリミティブ（`credential/vc/issue.ts` と
 * `credential/sdjwt/gdpr-guard.ts`）にあり、Wallet は委譲によって覆われる。委譲経路は
 * `credential/ops.ts` の薄いラッパで、将来ここが「自前で signing-input を組み立てる」形に
 * 変わるとガードが黙って外れる。実鍵・実 storage を通した往復で配線そのものを固定する。
 *
 * 検証内容:
 * - `Wallet.issueCredential` が Art.9 属性を含む VC を rejected Promise（`10607`）で拒否する。
 * - `Wallet.issueSdJwt` が平文クレーム / 開示クレームのどちらの Art.9 属性も `10607` で拒否する。
 * - 例外に属性名・クレーム値を載せない（PII 非開示）。
 * - 無害な VC / クレームは従来どおり発行でき、自己 DID で検証まで通る（過剰検知の回帰防止）。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../../internal/credential/index.js';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import type { Wallet } from '../../types.js';

// BIP-39 公式オールゼロ・エントロピーのニーモニック（passphrase なし）。
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const VCT = 'urn:test:identity';

/** import + 既定パス derive + did:key 自己発行済みの Wallet・鍵 ID・DID を用意する。 */
async function setupIssuer(): Promise<{ wallet: Wallet; keyID: string; did: string }> {
  const wallet = await createWallet({ storage: new MemoryStorage() });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
  const document = await wallet.createDID('key', { keyID: keyPair.id });
  return { wallet, keyID: keyPair.id, did: document.id };
}

/** 指定したクレームを持つ最小 VC を作る。 */
function vcWithClaims(did: string, claims: Record<string, unknown>): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: did,
    credentialSubject: { id: did, ...claims },
    issuanceDate: '2026-01-01T00:00:00Z',
  };
}

/** 属性ガードに対する代表的な違反クレーム（トップレベル / 入れ子 / 配列 / 命名揺れ）。 */
const VIOLATING_CLAIMS: readonly [string, Record<string, unknown>][] = [
  ['トップレベルの health', { health: 'HIV+' }],
  ['トップレベルの religion', { religion: 'x' }],
  ['入れ子の profile.diagnosis', { profile: { diagnosis: 'x' } }],
  ['配列要素の documents[0].national_id', { documents: [{ national_id: 'x' }] }],
  ['snake_case の birth_date', { birth_date: '1990-01-01' }],
];

describe('Wallet.issueCredential の Art.9 ガード', () => {
  for (const [label, claims] of VIOLATING_CLAIMS) {
    it(`${label} を含む VC の発行を 10607 で拒否する`, async () => {
      const { wallet, keyID, did } = await setupIssuer();
      const promise = wallet.issueCredential(vcWithClaims(did, claims), keyID);
      await expect(promise).rejects.toThrow(VericertsError);
      await expect(promise).rejects.toMatchObject({
        code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE,
      });
    });
  }

  it('VC 直下の evidence に潜む Art.9 属性も 10607 で拒否する', async () => {
    // `credentialSubject` だけを検査対象にすると素通りする経路。`evidence` は KYC 記録であり
    // Art.9 の生データが最も現れやすい。
    const { wallet, keyID, did } = await setupIssuer();
    const vc: VerifiableCredential = {
      ...vcWithClaims(did, { degree: 'BSc' }),
      evidence: [{ type: 'DocumentVerification', health: 'HIV+' }],
    };
    await expect(wallet.issueCredential(vc, keyID)).rejects.toMatchObject({
      code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE,
    });
  });

  it('例外に属性名・クレーム値を載せない（PII 非開示）', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    try {
      await wallet.issueCredential(vcWithClaims(did, { religion: 'secret-value' }), keyID);
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      const serialized = JSON.stringify({
        message: (error as VericertsError).message,
        context: (error as VericertsError).context,
      });
      expect(serialized).not.toContain('secret-value');
      expect(serialized).not.toContain('religion');
      // 発行はチェーンに書き込まないため `_ON_CHAIN`（10601）ではなく発行用の 10607。
      expect((error as VericertsError).code).toBe(ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE);
    }
  });

  // 陽性対照。これが無いとガードを厳しくしすぎる変更（正当な発行まで止める）を検知できない。
  it('無害な VC は従来どおり発行でき、自己 DID で検証まで通る', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const jwt = await wallet.issueCredential(vcWithClaims(did, { degree: 'BSc' }), keyID);

    const verified = await wallet.verifyCredentialStrict(jwt);
    expect(verified.payload.iss).toBe(did);
    expect((verified.payload.vc as VerifiableCredential).credentialSubject.degree).toBe('BSc');
  });
});

describe('Wallet.issueSdJwt の Art.9 ガード', () => {
  it('平文クレームの Art.9 属性を 10607 で拒否する', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const promise = wallet.issueSdJwt(keyID, {
      vct: VCT,
      issuer: did,
      disclosureClaims: [],
      claims: { health: 'HIV+' },
    });
    await expect(promise).rejects.toThrow(VericertsError);
    await expect(promise).rejects.toMatchObject({
      code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE,
    });
  });

  it('開示クレームの Art.9 属性を 10607 で拒否する（payload には digest しか残らない経路）', async () => {
    // SD-JWT 固有の核心。選択的開示にすると payload から属性名が消えるため、payload だけを
    // 走査するガードでは「まさに隠したい Art.9 属性」を取り逃す。
    const { wallet, keyID, did } = await setupIssuer();
    await expect(
      wallet.issueSdJwt(keyID, {
        vct: VCT,
        issuer: did,
        disclosureClaims: ['birth_date'],
        claims: { birth_date: '1990-01-01' },
      }),
    ).rejects.toMatchObject({ code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE });
  });

  it('入れ子の開示クレーム値に潜む Art.9 属性も 10607 で拒否する', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    await expect(
      wallet.issueSdJwt(keyID, {
        vct: VCT,
        issuer: did,
        disclosureClaims: ['medical'],
        claims: { medical: { record: { diagnosis: 'x' } } },
      }),
    ).rejects.toMatchObject({ code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE });
  });

  // 陽性対照。
  it('無害なクレームは従来どおり発行でき、検証で開示クレームを復元できる', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const sdJwt = await wallet.issueSdJwt(keyID, {
      vct: VCT,
      issuer: did,
      disclosureClaims: ['nickname'],
      claims: { nickname: 'Al', role: 'admin' },
    });

    const verified = await wallet.verifySdJwt(sdJwt, { expectedVct: VCT });
    expect(verified.claims.nickname).toBe('Al');
    expect(verified.claims.role).toBe('admin');
  });
});
