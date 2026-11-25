/**
 * 検証 API 2 層（`verifyCredential` / `verifyCredentialStrict` / `verifyPresentation` /
 * `verifyPresentationEnvelopeStrict`）の `Object.prototype` 汚染耐性テスト。
 *
 * 本リポジトリはこの fail-safe 領域でプロトタイプ汚染の欠陥を繰り返し踏んでいる。
 * 高レベル Result 型を足したことで
 *
 * - 呼び出し側オプションの読み取り（低レベルと共有。汚染で検証が**緩む**方向）
 * - 低レベル結果 → Result への写し替え（新設。汚染で**診断が嘘になる**方向）
 *
 * の 2 箇所が新たに 4 メソッド分の入口を持つため、どちらも継承値を拾わないことを固定する。
 * 汚染値を拾う実装なら、オプションを**渡していない**正当な呼び出しが黙って挙動を変える。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../internal/__tests__/prototype-pollution.fixtures.js';
import {
  VC_V2_CONTEXT,
  type VerifiableCredential,
  type VerifiablePresentation,
} from '../../../internal/credential/index.js';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import type { TrustChain } from '../../../internal/trust/federation/federation-types.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import {
  assertCredentialInvalid,
  assertPresentationInvalid,
  embeddedErrorCodes,
  issueCodes,
} from '../verification-result.fixtures.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
/** 2020-01-01T00:00:00Z。実時刻（現在）から見て確実に過去。 */
const ISSUED_AT = 1_577_836_800;
const OTHER_SUBJECT_DID = 'did:example:someone-else';

/** 成立していない Trust Chain（渡されたことが 5010 で分かる目印）。 */
const INVALID_CHAIN: TrustChain = {
  valid: false,
  leaf: 'https://issuer.example.eu',
  trustAnchor: 'https://federation.example.eu',
  nodes: [],
  length: 0,
  revokedKeys: [],
};

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
    issuanceDate: '2020-01-01T00:00:00Z',
    ...overrides,
  } satisfies VerifiableCredential;
}

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

describe('verifyCredential / verifyCredentialStrict の Object.prototype 汚染耐性', () => {
  /** 2020-06-01 に失効済みの JWT-VC（実時刻では必ず期限切れ）。 */
  async function expiredCredential() {
    const { wallet, keyID, did } = await setupIssuer();
    const jwt = await wallet.issueCredential(
      sampleVc(did, { expirationDate: '2020-06-01T00:00:00Z' }),
      keyID,
      { nowSeconds: ISSUED_AT },
    );
    return { wallet, jwt };
  }

  it('継承した nowSeconds は期限切れ VC を通さない（高レベル）', async () => {
    const { wallet, jwt } = await expiredCredential();

    // `nowSeconds` を渡していない呼び出し。継承値を拾えば「2020-03 時点」の評価になり通ってしまう。
    const result = await withPollutedPrototypeAsync(
      { nowSeconds: ISSUED_AT + 60 * 60 * 24 * 60 },
      () => wallet.verifyCredential(jwt),
    );

    expect(issueCodes(assertCredentialInvalid(result).errors)).toEqual([ErrorCodes.VC_EXPIRED]);
  });

  it('継承した nowSeconds は期限切れ VC を通さない（primitive）', async () => {
    const { wallet, jwt } = await expiredCredential();

    const error = await withPollutedPrototypeAsync(
      { nowSeconds: ISSUED_AT + 60 * 60 * 24 * 60 },
      () =>
        wallet
          .verifyCredentialStrict(jwt)
          .then(() => undefined)
          .catch((e: unknown) => e),
    );

    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.VC_EXPIRED);
  });

  it('継承した issuerTrust は FC-11 の突合を起動しない（高レベル）', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const jwt = await wallet.issueCredential(sampleVc(did), keyID, { nowSeconds: ISSUED_AT });

    // `issuerTrust` を渡していない呼び出し。継承値を拾えば不成立チェーンで 5010 に落ちる。
    const result = await withPollutedPrototypeAsync(
      { issuerTrust: { trustChain: INVALID_CHAIN } },
      () => wallet.verifyCredential(jwt),
    );

    expect(result.valid).toBe(true);
  });
});

describe('verifyPresentation の Object.prototype 汚染耐性', () => {
  it('継承した delegations は委任提示を成立させない（fail-closed を維持）', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    // 提示者（did）とは別 subject の VC。`requireHolderBinding: true` なら 3012 になる。
    const foreign = await wallet.issueCredential(
      sampleVc(did, { credentialSubject: { id: OTHER_SUBJECT_DID } }),
      keyID,
    );
    const jwt = await issueVpWith(wallet, keyID, did, [foreign]);

    // `delegations` を渡していない呼び出し。継承値を拾えば第三者の VC が突合を素通りする。
    const result = await withPollutedPrototypeAsync(
      { delegations: [{ subjectDID: OTHER_SUBJECT_DID, holderDID: did, scope: ['present'] }] },
      () => wallet.verifyPresentation(jwt, { allowUnbound: true, requireHolderBinding: true }),
    );

    const invalid = assertPresentationInvalid(result);
    expect(embeddedErrorCodes(invalid.credentialResults[0])).toEqual([
      ErrorCodes.HOLDER_BIND_MISMATCH,
    ]);
  });

  it('継承した issuerTrust は内包 VC の検証へ中継されない（FC-11 の突合材料を攻撃者制御にしない）', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const vc = await wallet.issueCredential(sampleVc(did), keyID);
    const jwt = await issueVpWith(wallet, keyID, did, [vc]);

    // `issuerTrust` を渡していない呼び出し。継承値を拾えば不成立チェーンで内包 VC が 5010 に落ちる。
    const result = await withPollutedPrototypeAsync(
      { issuerTrust: { trustChain: INVALID_CHAIN } },
      () => wallet.verifyPresentation(jwt, { allowUnbound: true }),
    );

    expect(result.valid).toBe(true);
  });

  it('継承した requireHolderBinding は黙って厳格化しない（正当な bearer VC を落とさない）', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    // `sub` を持たない bearer VC。`requireHolderBinding: true` なら 3012 になる。
    const bearer = await wallet.issueCredential(
      { ...sampleVc(did), credentialSubject: { name: 'Alice' } },
      keyID,
    );
    const jwt = await issueVpWith(wallet, keyID, did, [bearer]);

    const result = await withPollutedPrototypeAsync({ requireHolderBinding: true }, () =>
      wallet.verifyPresentation(jwt, { allowUnbound: true }),
    );

    expect(result.valid).toBe(true);
  });

  it('継承した allowUnbound は既定（束縛必須）を緩めない（primitive / 高レベル共通）', async () => {
    const { wallet, keyID, did } = await setupIssuer();
    const jwt = await wallet.issuePresentation(
      {
        '@context': [VC_V2_CONTEXT],
        type: ['VerifiablePresentation'],
        holder: did,
        verifiableCredential: [],
      },
      keyID,
      { audience: 'https://verifier.example', nonce: 'n-1' },
    );

    const { result, strictError } = await withPollutedPrototypeAsync({ allowUnbound: true }, () =>
      Promise.all([
        wallet.verifyPresentation(jwt),
        wallet
          .verifyPresentationEnvelopeStrict(jwt)
          .then(() => undefined)
          .catch((e: unknown) => e),
      ]).then(([presentation, error]) => ({ result: presentation, strictError: error })),
    );

    expect(issueCodes(assertPresentationInvalid(result).errors)).toEqual([
      ErrorCodes.HOLDER_BIND_MISMATCH,
    ]);
    expect(strictError).toBeInstanceOf(VericertsError);
    expect((strictError as VericertsError).code).toBe(ErrorCodes.HOLDER_BIND_MISMATCH);
  });
});
