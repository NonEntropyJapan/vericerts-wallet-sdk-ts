/**
 * 高レベル `Wallet.verifyPresentation`（判別共用体 Result 型）の回帰テスト
 *
 * top-level `valid` は最終的な認可判定であり、
 * 「`presentationValid`（VP envelope）が真」**かつ**「全内包 VC が有効」のときだけ `true` になる。
 * envelope は正当だが内包 VC が 1 件でも invalid なら `valid: false` / `presentationValid: true` に
 * 倒す（部分成功は診断情報であって許可ではない）。`valid` を `presentationValid` と同一視する実装
 * （envelope さえ通れば許可）になっていれば、下の「1 件でも invalid」ケースが落ちる。
 *
 * 併せて固定するもの:
 * - 内包 VC を 1 件も含まない VP も `valid: false`（`errors` に `3002`）。`every([])` の空真で
 *   「何も証明しない提示」を許可にしない。
 * - envelope 自体が不成立なら `presentationValid: false` かつ `credentialResults: []`
 *   （未検証の VP が指す DID を解決しないため、内包 VC は評価していない）。
 * - 低レベル `verifyPresentationEnvelopeStrict` は同じ入力で**例外**になり、成功時も
 *   `credentialResults` を返さない（envelope だけを保証する primitive）。
 */

import { describe, expect, it } from 'bun:test';
import {
  VC_V2_CONTEXT,
  type VerifiableCredential,
  type VerifiablePresentation,
} from '../../../internal/credential/index.js';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
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

function sampleVc(issuer: string, id: string) {
  return {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer,
    credentialSubject: { id: issuer, name: 'Alice' },
    issuanceDate: '2025-01-01T00:00:00Z',
    expirationDate: '2035-01-01T00:00:00Z',
    id,
  } satisfies VerifiableCredential;
}

/** 署名の 1 文字を書き換えて署名不一致にする。 */
function tamperSignature(jwt: string): string {
  const parts = jwt.split('.');
  const sig = parts[2] ?? '';
  return `${parts[0]}.${parts[1]}.${(sig[0] === 'A' ? 'B' : 'A') + sig.slice(1)}`;
}

/** 内包 VC を持つ JWT-VP を発行する。 */
async function issueVpWith(
  wallet: Awaited<ReturnType<typeof setupIssuer>>['wallet'],
  keyID: string,
  did: string,
  entries: readonly string[],
): Promise<string> {
  const vp: VerifiablePresentation = {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiablePresentation'],
    holder: did,
    verifiableCredential: entries,
  };
  return wallet.issuePresentation(vp, keyID);
}

describe('Wallet.verifyPresentation（高レベル Result）', () => {
  it('envelope も全内包 VC も有効なら valid: true（data / credentialResults 付き）', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const vc = await wallet.issueCredential(sampleVc(did, 'urn:uuid:vc-1'), keyID);
    const jwt = await issueVpWith(wallet, keyID, did, [vc]);

    const result = assertPresentationValid(
      await wallet.verifyPresentation(jwt, { allowUnbound: true }),
    );

    expect(result.holderDID).toBe(did);
    expect(result.data.presentation.holder).toBe(did);
    expect(result.data.payload.iss).toBe(did);
    expect(result.credentialResults).toHaveLength(1);
    expect(result.credentialResults[0]?.valid).toBe(true);
    expect(result.warnings).toEqual([]);
  });

  it('envelope は正当でも内包 VC が 1 件でも invalid なら valid: false / presentationValid: true', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const good = await wallet.issueCredential(sampleVc(did, 'urn:uuid:vc-good'), keyID);
    const bad = tamperSignature(
      await wallet.issueCredential(sampleVc(did, 'urn:uuid:vc-bad'), keyID),
    );
    const jwt = await issueVpWith(wallet, keyID, did, [good, bad]);

    const result = assertPresentationInvalid(
      await wallet.verifyPresentation(jwt, { allowUnbound: true }),
    );

    // envelope（VP 署名・時刻・バインド）は通っている。落ちているのは内包 VC だけ。
    expect(result.presentationValid).toBe(true);
    // それでも top-level は deny。ここが `valid = presentationValid` 実装との分岐点。
    expect(result.valid).toBe(false);
    expect(result.holderDID).toBe(did);
    // 部分成功は診断情報として残す（どの VC が落ちたか分かる）。
    expect(result.credentialResults).toHaveLength(2);
    expect(result.credentialResults[0]?.valid).toBe(true);
    expect(embeddedErrorCodes(result.credentialResults[1])).toEqual([ErrorCodes.SIG_INVALID]);
    expect(issueCodes(result.errors)).toEqual([ErrorCodes.SIG_INVALID]);
  });

  it('内包 VC を 1 件も含まない VP は valid: false / presentationValid: true', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    // envelope は完全に正当な、`verifiableCredential: []` の holder 署名済み VP。
    const jwt = await issueVpWith(wallet, keyID, did, []);

    const result = assertPresentationInvalid(
      await wallet.verifyPresentation(jwt, { allowUnbound: true }),
    );

    // envelope（VP 署名・時刻）は通る。`every([])` の空真で top-level を許可にしないことが核心。
    expect(result.presentationValid).toBe(true);
    expect(result.valid).toBe(false);
    expect(result.holderDID).toBe(did);
    expect(result.credentialResults).toEqual([]);
    // 理由ゼロで deny すると呼び出し側に異常のシグナルが残らない。必ず 3002 を返す。
    expect(issueCodes(result.errors)).toEqual([ErrorCodes.VC_SCHEMA_INVALID]);
  });

  it('同じコードの内包 VC 失敗は errors 上で重複排除される', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const bad1 = tamperSignature(await wallet.issueCredential(sampleVc(did, 'urn:uuid:a'), keyID));
    const bad2 = tamperSignature(await wallet.issueCredential(sampleVc(did, 'urn:uuid:b'), keyID));
    const jwt = await issueVpWith(wallet, keyID, did, [bad1, bad2]);

    const result = assertPresentationInvalid(
      await wallet.verifyPresentation(jwt, { allowUnbound: true }),
    );

    expect(result.credentialResults).toHaveLength(2);
    expect(issueCodes(result.errors)).toEqual([ErrorCodes.SIG_INVALID]);
  });

  it('envelope 自体が不成立なら presentationValid: false / credentialResults: []', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const vc = await wallet.issueCredential(sampleVc(did, 'urn:uuid:vc-1'), keyID);
    const tampered = tamperSignature(await issueVpWith(wallet, keyID, did, [vc]));

    const result = assertPresentationInvalid(
      await wallet.verifyPresentation(tampered, { allowUnbound: true }),
    );

    expect(result.presentationValid).toBe(false);
    // 未検証の VP が指す DID は解決しない（内包 VC は評価していない）。
    expect(result.credentialResults).toEqual([]);
    expect(result.holderDID).toBeUndefined();
    expect(issueCodes(result.errors)).toEqual([ErrorCodes.SIG_INVALID]);
  });

  it('バインド未指定（3012）も envelope の不成立として Result に畳まれる', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const jwt = await wallet.issuePresentation(
      {
        '@context': [VC_V2_CONTEXT],
        type: ['VerifiablePresentation'],
        holder: did,
        verifiableCredential: [],
      },
      keyID,
      { audience: 'https://verifier.example', nonce: 'n-123' },
    );

    // 期待値を渡さない既定（束縛）モードの検証は 3012。
    const result = assertPresentationInvalid(await wallet.verifyPresentation(jwt));

    expect(result.presentationValid).toBe(false);
    expect(issueCodes(result.errors)).toEqual([ErrorCodes.HOLDER_BIND_MISMATCH]);
  });
});

describe('Wallet.verifyPresentationEnvelopeStrict（低レベル primitive）', () => {
  it('envelope だけを返す（内包 VC の結果も valid も持たない）', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    // 内包 VC は壊れているが、envelope primitive はそこを見ない。
    const bad = tamperSignature(await wallet.issueCredential(sampleVc(did, 'urn:uuid:bad'), keyID));
    const jwt = await issueVpWith(wallet, keyID, did, [bad]);

    const envelope = await wallet.verifyPresentationEnvelopeStrict(jwt, { allowUnbound: true });

    expect(envelope.holderDID).toBe(did);
    expect(envelope.presentation.holder).toBe(did);
    expect(Object.keys(envelope).sort()).toEqual([
      'header',
      'holderDID',
      'payload',
      'presentation',
    ]);
    // 同じ VP を高レベルに通すと内包 VC の不正で deny になる（primitive の保証範囲との差）。
    expect((await wallet.verifyPresentation(jwt, { allowUnbound: true })).valid).toBe(false);
  });

  it('envelope が不成立なら従来どおり例外を投げる（fail-closed）', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const tampered = tamperSignature(await issueVpWith(wallet, keyID, did, []));

    await expect(
      wallet.verifyPresentationEnvelopeStrict(tampered, { allowUnbound: true }),
    ).rejects.toBeInstanceOf(VericertsError);
  });
});
