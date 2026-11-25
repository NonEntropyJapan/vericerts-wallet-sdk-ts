/**
 * `Wallet.createPresentation`統合テスト。
 *
 * `createPresentation` は `receiveCredential` / `presentPID` と同じパターンで、署名鍵・Holder DID を
 * アクティブペルソナから自動解決する（`wallet.receive-credential.test.ts` の `setupWallet` パターンを
 * 共有）。VC 選択は `matchCredentials` の選定ロジックをそのまま再利用するため、DCQL マッチの
 * 詳細な組み合わせは `match-credentials.test.ts` に譲り、ここでは Wallet 経由の配線（VC 保存 →
 * `vcIDs` 解決 → 署名 → `verifyPresentation` での往復検証・エラー面）を固定する。
 *
 * LoA（Level of Assurance）関連: `required_loa` を要求に付与した場合の
 * `LOA_MISMATCH`（10030）配線を末尾の `describe` ブロックで検証する。
 */

import { describe, expect, it } from 'bun:test';
import type { EvidenceEntry } from '../../../internal/credential/evidence-tou/types.js';
import type { VerifiableCredential } from '../../../internal/credential/index.js';
import { VericertsError } from '../../../internal/errors.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import type { Wallet } from '../../types.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const CLIENT_ID = 'https://verifier.example.com';
const RESPONSE_URI = 'https://verifier.example.com/callback';
const NONCE = 'n-0S6_WzA2Mj-0123456789';
const STATE = 'af0ifjsldkj';

/** DCQL クエリ（`credentialSubject.name` が `Bob`）を含む直接形式の requestURI。 */
function buildRequestUri(overrides: Record<string, string | undefined> = {}): string {
  const dcql = {
    credentials: [
      {
        id: 'degree',
        format: 'jwt_vc_json',
        claims: [{ path: ['credentialSubject', 'name'], values: ['Bob'] }],
      },
    ],
  };
  const params: Record<string, string | undefined> = {
    response_type: 'vp_token',
    client_id: CLIENT_ID,
    response_mode: 'direct_post',
    response_uri: RESPONSE_URI,
    nonce: NONCE,
    state: STATE,
    dcql_query: JSON.stringify(dcql),
    ...overrides,
  };
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      search.set(key, value);
    }
  }
  return `openid4vp://?${search.toString()}`;
}

function makeVc(id: string, name: string, evidence?: EvidenceEntry): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'UniversityDegree'],
    issuer: 'did:example:issuer',
    credentialSubject: { name },
    issuanceDate: '2025-01-01T00:00:00Z',
    id,
    ...(evidence !== undefined ? { evidence } : {}),
  };
}

/** import + ペルソナ作成・アクティブ化済みの Wallet を用意する（`wallet.receive-credential.test.ts` と同じ）。 */
async function setupWallet(): Promise<{ wallet: Wallet; did: string }> {
  const wallet = await createWallet({ storage: new MemoryStorage() });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const persona = await wallet.createPersona();
  await wallet.setActivePersona(persona.id);
  const active = await wallet.getActivePersona();
  return { wallet, did: active?.did ?? '' };
}

/** 与えた async 関数を実行し、VericertsError の code を返す（成功時は null）。 */
async function errorCode(fn: () => Promise<unknown>): Promise<string | null> {
  try {
    await fn();
    return null;
  } catch (error) {
    if (error instanceof VericertsError) {
      return error.code;
    }
    throw error;
  }
}

describe('Wallet.createPresentation', () => {
  it('アクティブペルソナの鍵で VP を署名し、verifyPresentation で往復検証できる', async () => {
    const { wallet, did } = await setupWallet();
    await wallet.storeCredential(makeVc('urn:vc:bob', 'Bob'));
    await wallet.storeCredential(makeVc('urn:vc:alice', 'Alice'));

    const result = await wallet.createPresentation(buildRequestUri(), ['urn:vc:bob']);

    expect(result.holder).toBe(did);
    expect(result.verifiableCredential).toHaveLength(1);
    const embedded = result.verifiableCredential[0] as unknown as VerifiableCredential;
    expect(embedded.id).toBe('urn:vc:bob');

    // 内包 VC は JSON-LD VC（object）で SDK に検証手段が無いため、ここでは envelope（VP 署名・
    // aud/nonce）だけを見る primitive を使う（高レベル `verifyPresentation` なら内包 VC が
    // fail-closed で `valid: false` になる）。
    const verified = await wallet.verifyPresentationEnvelopeStrict(result.jwt, {
      expectedAudience: CLIENT_ID,
      expectedNonce: NONCE,
    });
    expect(verified.payload.iss).toBe(did);
    expect(verified.presentation.holder).toBe(did);
  });

  it('要求に合致しない VC を選択した場合は VC_REQUIREMENT_MISMATCH(3080)', async () => {
    const { wallet } = await setupWallet();
    await wallet.storeCredential(makeVc('urn:vc:alice', 'Alice'));

    expect(
      await errorCode(() => wallet.createPresentation(buildRequestUri(), ['urn:vc:alice'])),
    ).toBe('3080');
  });

  it('未保存の vcID を選択した場合は VC_NOT_FOUND(3070)', async () => {
    const { wallet } = await setupWallet();

    expect(
      await errorCode(() => wallet.createPresentation(buildRequestUri(), ['urn:vc:missing'])),
    ).toBe('3070');
  });

  it('処理制限（Art.18）がかかった VC は候補から除外され VC_REQUIREMENT_MISMATCH(3080)', async () => {
    const { wallet } = await setupWallet();
    await wallet.storeCredential(makeVc('urn:vc:bob', 'Bob'));
    await wallet.setCredentialProcessingRestriction('urn:vc:bob', true);

    expect(
      await errorCode(() => wallet.createPresentation(buildRequestUri(), ['urn:vc:bob'])),
    ).toBe('3080');
  });

  it('markCredentialDisputed 済みの VC を提示すると presentationMetadata.disputed が true になる（Art.16 フォールバック）', async () => {
    const { wallet } = await setupWallet();
    await wallet.storeCredential(makeVc('urn:vc:bob', 'Bob'));
    await wallet.markCredentialDisputed('urn:vc:bob', 'issuer は訂正に応じない');

    const result = await wallet.createPresentation(buildRequestUri(), ['urn:vc:bob']);

    expect(result.presentationMetadata).toEqual({ disputed: true });
  });

  it('disputed でない VC のみの提示では presentationMetadata を付与しない', async () => {
    const { wallet } = await setupWallet();
    await wallet.storeCredential(makeVc('urn:vc:bob', 'Bob'));

    const result = await wallet.createPresentation(buildRequestUri(), ['urn:vc:bob']);

    expect(result.presentationMetadata).toBeUndefined();
  });

  it('vcIDs に重複がある場合、VP には重複排除して 1 件だけ埋め込む', async () => {
    const { wallet } = await setupWallet();
    await wallet.storeCredential(makeVc('urn:vc:bob', 'Bob'));

    const result = await wallet.createPresentation(buildRequestUri(), ['urn:vc:bob', 'urn:vc:bob']);

    expect(result.verifiableCredential).toHaveLength(1);
  });

  it('vcIDs が空の場合は VC_REQUIREMENT_MISMATCH(3080)（空 VP の署名オラクル化を防止）', async () => {
    const { wallet } = await setupWallet();
    await wallet.storeCredential(makeVc('urn:vc:bob', 'Bob'));

    expect(await errorCode(() => wallet.createPresentation(buildRequestUri(), []))).toBe('3080');
  });

  it('アクティブペルソナ未設定は PERSONA_NOT_FOUND(2005)', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC);

    expect(await errorCode(() => wallet.createPresentation(buildRequestUri(), []))).toBe('2005');
  });
});

describe('Wallet.createPresentation: LoA（Level of Assurance）判定', () => {
  it('requiredLoA 未指定の要求では、evidence の無い VC でも従来どおり VP を作成できる（checkLoa は no-op）', async () => {
    const { wallet } = await setupWallet();
    await wallet.storeCredential(makeVc('urn:vc:bob', 'Bob'));

    const result = await wallet.createPresentation(buildRequestUri(), ['urn:vc:bob']);

    expect(result.verifiableCredential).toHaveLength(1);
  });

  it('required_loa を満たす evidence を持つ VC は VP を作成できる', async () => {
    const { wallet } = await setupWallet();
    await wallet.storeCredential(
      makeVc('urn:vc:bob', 'Bob', { type: 'DocumentVerification', trustLevel: 'high' }),
    );

    const result = await wallet.createPresentation(
      buildRequestUri({ required_loa: 'substantial' }),
      ['urn:vc:bob'],
    );

    expect(result.verifiableCredential).toHaveLength(1);
  });

  it('required_loa を満たさない evidence（低い trustLevel）の VC は LOA_MISMATCH(10030)', async () => {
    const { wallet } = await setupWallet();
    await wallet.storeCredential(
      makeVc('urn:vc:bob', 'Bob', { type: 'DocumentVerification', trustLevel: 'low' }),
    );

    expect(
      await errorCode(() =>
        wallet.createPresentation(buildRequestUri({ required_loa: 'high' }), ['urn:vc:bob']),
      ),
    ).toBe('10030');
  });

  it('evidence を全く持たない VC に substantial 以上を要求すると LOA_MISMATCH(10030)（evidence 無しは low のみ充足）', async () => {
    const { wallet } = await setupWallet();
    await wallet.storeCredential(makeVc('urn:vc:bob', 'Bob'));

    expect(
      await errorCode(() =>
        wallet.createPresentation(buildRequestUri({ required_loa: 'substantial' }), ['urn:vc:bob']),
      ),
    ).toBe('10030');
  });

  it('複数選択 VC のうち 1 件でも要求 LoA を満たさなければ LOA_MISMATCH(10030)（fail-safe: 一部の高 LoA で相殺しない）', async () => {
    const { wallet } = await setupWallet();
    // DCQL クエリは credentialSubject.name === 'Bob' を要求するため、両 VC とも同名にして
    // 「候補集合に含まれる 2 件を選択したが、うち 1 件の evidence が不足」という状況を作る。
    await wallet.storeCredential(
      makeVc('urn:vc:high-loa', 'Bob', {
        type: 'PhysicalDocumentVerification',
        trustLevel: 'high',
      }),
    );
    await wallet.storeCredential(makeVc('urn:vc:low-loa', 'Bob', { type: 'SomethingUnknown' }));

    expect(
      await errorCode(() =>
        wallet.createPresentation(buildRequestUri({ required_loa: 'substantial' }), [
          'urn:vc:high-loa',
          'urn:vc:low-loa',
        ]),
      ),
    ).toBe('10030');
  });
});
