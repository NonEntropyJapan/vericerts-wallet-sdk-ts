/**
 * Wallet ファサードのメトリクス配線（統合）テスト。
 *
 * `createWallet({ metrics })` に注入した Metrics へ、実処理経路（DID 解決 / VC 検証）が
 * 必須メトリクス 4 種を実際に記録することを、実署名・ネット非依存（did:key の自己発行・
 * 自己検証）で確認する。ラベル値が ラベルの予算を通ってから注入先へ届くことも併せて固定する。
 *
 * 注入先には既定の in-memory 実装（`createInMemoryMetrics`）をそのまま使う。蓄積の意味論
 * （同一系列への積み上げ）は `internal/observability/__tests__` で単位テスト済みで、ここで
 * 記録専用のダミーを別に作ると同じ意味論を二重に実装することになるためである。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import type { NonceContext } from '../../../internal/auth/nonce/index.js';
import { createNonceStore } from '../../../internal/auth/nonce/index.js';
import type { VerifiableCredential } from '../../../internal/credential/index.js';
import {
  CNF,
  SESSION_SIGNER,
} from '../../../internal/credential/sdjwt/__tests__/key-binding.fixtures.js';
import { addKeyBinding } from '../../../internal/credential/sdjwt/verify.js';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import { KDF_TIMEOUT_MS } from '../../../internal/keymanager/__tests__/kdf-policy/kdf-timeout.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import type {
  HistogramSample,
  Labels,
  MetricSample,
} from '../../../internal/observability/metrics.js';
import { createInMemoryMetrics, MetricNames } from '../../../internal/observability/metrics.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import { expectRecordedInSeconds, timed } from './metrics-duration.js';

/** 実 Argon2id を通るため、並列負荷下でも既定 5000ms で落ちないよう猶予を広げる。 */
setDefaultTimeout(KDF_TIMEOUT_MS);

// BIP-39 公式オールゼロ・エントロピーのニーモニック（passphrase なし）。
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** 指定した `name` + ラベルの系列 1 件を探す（無ければ `undefined`）。 */
function findSample<T extends { name: string; labels: Labels }>(
  samples: readonly T[],
  name: string,
  labels: Labels,
): T | undefined {
  return samples.find((sample) => sample.name === name && Bun.deepEquals(sample.labels, labels));
}

/** in-memory Metrics を注入した Wallet と、その蓄積値の読み出し口を用意する。 */
async function setupWallet() {
  const { metrics, snapshot } = createInMemoryMetrics();
  const wallet = await createWallet({ storage: new MemoryStorage(), metrics });
  return { wallet, snapshot };
}

/** import + 既定パス derive + did:key 自己発行済みの Wallet を用意する。 */
async function setupIssuer() {
  const { wallet, snapshot } = await setupWallet();
  await wallet.importMnemonic(TEST_MNEMONIC);
  const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
  const document = await wallet.createDID('key', { keyID: keyPair.id });
  return { wallet, snapshot, keyID: keyPair.id, did: document.id };
}

describe('Wallet.resolveDID のメトリクス配線', () => {
  it('解決成功で total{method,result} と duration_seconds{method,cache} を記録する', async () => {
    const { wallet, snapshot, did } = await setupIssuer();

    const elapsedMs = await timed(() => wallet.resolveDID(did));

    const state = snapshot();
    const counter: MetricSample | undefined = findSample(
      state.counters,
      MetricNames.DID_RESOLVE_TOTAL,
      { method: 'key', result: 'success' },
    );
    expect(counter?.value).toBe(1);
    // `cache` は現状 `cold` 固定（Resolver にキャッシュ層が繋がっていない。did/observability.ts 参照）。
    const histogram: HistogramSample | undefined = findSample(
      state.histograms,
      MetricNames.DID_RESOLVE_DURATION_SECONDS,
      { method: 'key', cache: 'cold' },
    );
    expect(histogram?.count).toBe(1);
    // 単位は秒（`_seconds`）。上限は実測 ms の 1/1000 とし、実時間の絶対値では見ない
    // （ミリ秒のまま載せていれば実測 ms と同じ桁になって必ず落ちる）。
    expectRecordedInSeconds(histogram?.sum, elapsedMs);
  });

  it('解決失敗は result=failure として記録される', async () => {
    const { wallet, snapshot } = await setupWallet();

    // did:key は登録済みなので、不正な識別子はメソッド本体まで届いて失敗する（2001）。
    await expect(wallet.resolveDID('did:key:!!!invalid')).rejects.toThrow();

    const state = snapshot();
    expect(
      findSample(state.counters, MetricNames.DID_RESOLVE_TOTAL, {
        method: 'key',
        result: 'failure',
      })?.value,
    ).toBe(1);
    expect(
      findSample(state.histograms, MetricNames.DID_RESOLVE_DURATION_SECONDS, {
        method: 'key',
        cache: 'cold',
      })?.count,
    ).toBe(1);
  });

  it('未登録メソッドは ラベルの予算で method=other にまとめられる', async () => {
    const { wallet, snapshot } = await setupWallet();

    await expect(wallet.resolveDID('did:unknownmethod:xyz')).rejects.toThrow();

    expect(
      findSample(snapshot().counters, MetricNames.DID_RESOLVE_TOTAL, {
        method: 'other',
        result: 'failure',
      })?.value,
    ).toBe(1);
  });

  it('繰り返し解決すると同じ系列へ積み上がる', async () => {
    const { wallet, snapshot, did } = await setupIssuer();

    await wallet.resolveDID(did);
    await wallet.resolveDID(did);

    expect(
      findSample(snapshot().counters, MetricNames.DID_RESOLVE_TOTAL, {
        method: 'key',
        result: 'success',
      })?.value,
    ).toBe(2);
  });
});

describe('Wallet.verifyCredentialStrict のメトリクス配線', () => {
  /** 自己発行した JWT-VC と、その Wallet・蓄積値の読み出し口を用意する。 */
  async function setupSelfIssued() {
    const { wallet, snapshot, keyID, did } = await setupIssuer();
    const vc: VerifiableCredential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: did,
      credentialSubject: { id: did, name: 'Alice' },
      issuanceDate: '2026-01-01T00:00:00Z',
    };
    return { wallet, snapshot, jwt: await wallet.issueCredential(vc, keyID) };
  }

  it('検証成功で total{format,result,reason} と duration_seconds{format} を記録する', async () => {
    const { wallet, snapshot, jwt } = await setupSelfIssued();

    const elapsedMs = await timed(() => wallet.verifyCredentialStrict(jwt));

    const state = snapshot();
    expect(
      findSample(state.counters, MetricNames.VC_VERIFY_TOTAL, {
        format: 'jwt',
        result: 'success',
        reason: 'none',
      })?.value,
    ).toBe(1);
    const histogram = findSample(state.histograms, MetricNames.VC_VERIFY_DURATION_SECONDS, {
      format: 'jwt',
    });
    expect(histogram?.count).toBe(1);
    expectRecordedInSeconds(histogram?.sum, elapsedMs);
  });

  it('検証失敗は result=failure / reason=<error_code> として記録される', async () => {
    const { wallet, snapshot } = await setupSelfIssued();
    // iss を持たない最小 JWS（`verifyCredential` は 3002 で失敗する）。
    const header = Buffer.from(JSON.stringify({ alg: 'ES256K', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ foo: 'bar' })).toString('base64url');

    await expect(wallet.verifyCredentialStrict(`${header}.${payload}.AA`)).rejects.toThrow();

    const state = snapshot();
    expect(
      findSample(state.counters, MetricNames.VC_VERIFY_TOTAL, {
        format: 'jwt',
        result: 'failure',
        reason: '3002',
      })?.value,
    ).toBe(1);
    expect(
      findSample(state.histograms, MetricNames.VC_VERIFY_DURATION_SECONDS, { format: 'jwt' })
        ?.count,
    ).toBe(1);
  });
});

describe('Wallet.encrypt のメトリクス配線', () => {
  it('暗号化成功で duration_seconds{algorithm} を記録する', async () => {
    const { wallet, snapshot } = await setupWallet();

    const elapsedMs = await timed(() =>
      wallet.encrypt(new TextEncoder().encode('secret'), 'pw-correct'),
    );

    const histogram = findSample(
      snapshot().histograms,
      MetricNames.STORAGE_ENCRYPT_DURATION_SECONDS,
      { algorithm: 'aes-256-gcm' },
    );
    expect(histogram?.count).toBe(1);
    // KDF の実測は負荷次第で 1 秒を超える。単位の検査を実時間の絶対値でやらない。
    expectRecordedInSeconds(histogram?.sum, elapsedMs);
  });

  it('繰り返し暗号化すると同じ系列へ積み上がる', async () => {
    const { wallet, snapshot } = await setupWallet();

    await wallet.encrypt(new TextEncoder().encode('a'), 'pw');
    await wallet.encrypt(new TextEncoder().encode('b'), 'pw');

    expect(
      findSample(snapshot().histograms, MetricNames.STORAGE_ENCRYPT_DURATION_SECONDS, {
        algorithm: 'aes-256-gcm',
      })?.count,
    ).toBe(2);
  });
});

describe('nonce replay 検知のメトリクス配線', () => {
  const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
  const CLIENT = 'https://verifier.example/client';
  const CTX: NonceContext = { flow: 'oid4vp', clientId: CLIENT };

  /** cnf 付き SD-JWT を発行し、KB-JWT を付けた提示を返す（`wallet.replay-guard.test.ts` と同じ形）。 */
  async function setupPresented() {
    const { wallet, snapshot } = await setupWallet();
    await wallet.importMnemonic(TEST_MNEMONIC);
    const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
    const document = await wallet.createDID('key', { keyID: keyPair.id });
    const nowSeconds = Math.floor(Date.now() / 1000);

    const sdJwt = await wallet.issueSdJwt(keyPair.id, {
      vct: 'urn:test:identity',
      issuer: document.id,
      cnf: CNF,
      disclosureClaims: ['name'],
      claims: { name: 'Alice' },
    });
    const presented = addKeyBinding(sdJwt, SESSION_SIGNER, {
      nonce: NONCE,
      audience: CLIENT,
      iatSeconds: nowSeconds,
    });
    return { wallet, snapshot, presented, nowSeconds };
  }

  it('SD-JWT の 2 回目提示（replay）で context=oid4vp の total を記録する', async () => {
    const { wallet, snapshot, presented, nowSeconds } = await setupPresented();
    const store = createNonceStore({ backend: 'memory' });
    const opts = { nonce: NONCE, nonceStore: store, nonceContext: CTX, nowSeconds };

    await wallet.verifySdJwt(presented, opts);
    expect(
      findSample(snapshot().counters, MetricNames.NONCE_REPLAY_DETECTED_TOTAL, {
        context: 'oid4vp',
      }),
    ).toBeUndefined();

    await expect(wallet.verifySdJwt(presented, opts)).rejects.toMatchObject({
      code: ErrorCodes.REPLAY_DETECTED,
    });

    expect(
      findSample(snapshot().counters, MetricNames.NONCE_REPLAY_DETECTED_TOTAL, {
        context: 'oid4vp',
      })?.value,
    ).toBe(1);
  });

  it('replay 以外の失敗（nonce 未指定 4013）は記録しない', async () => {
    const { wallet, snapshot, presented, nowSeconds } = await setupPresented();
    const store = createNonceStore({ backend: 'memory' });

    await expect(
      wallet.verifySdJwt(presented, { nonceStore: store, nonceContext: CTX, nowSeconds }),
    ).rejects.toBeInstanceOf(VericertsError);

    expect(
      findSample(snapshot().counters, MetricNames.NONCE_REPLAY_DETECTED_TOTAL, {
        context: 'oid4vp',
      }),
    ).toBeUndefined();
  });
});

describe('WalletOptions.metrics 未注入時（in-memory 既定）', () => {
  it('DID 解決・VC 検証の往復が例外なく通り、挙動が変わらない', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC);
    const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
    const document = await wallet.createDID('key', { keyID: keyPair.id });
    const vc: VerifiableCredential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: document.id,
      credentialSubject: { id: document.id },
      issuanceDate: '2026-01-01T00:00:00Z',
    };

    const resolved = await wallet.resolveDID(document.id);
    const verified = await wallet.verifyCredentialStrict(
      await wallet.issueCredential(vc, keyPair.id),
    );

    expect(resolved.id).toBe(document.id);
    expect(verified.payload.iss).toBe(document.id);
  });
});
