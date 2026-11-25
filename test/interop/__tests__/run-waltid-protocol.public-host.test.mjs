// test/interop/__tests__/run-waltid-protocol.public-host.test.mjs
//
// walt.id の自己参照 URL（`https://localhost:8097` / `:8098`）が SDK の公開ホスト検査で拒否される
// 件の回帰テスト。拒否されるペアは実ピアへ接続する前に必ず 3004 になるため、
// fail（Nightly が毎晩同じ Issue を起票する）ではなく理由付き `skipped` として報告する。
// 実行: `bun test test/interop/__tests__/run-waltid-protocol.public-host.test.mjs`（要 Bun）。

import { describe, expect, it } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { FORMAT_JWT_VC, parseAuthorizationRequest } from 'vericerts-wallet-sdk';
import { receiveCredential } from 'vericerts-wallet-sdk/experimental';
import {
  NON_PUBLIC_RESPONSE_URI_REASON,
  offerPeerUrl,
  publicHostGuardSkipReason,
} from '../lib/waltid-public-host-guard.mjs';
import { run } from '../run-waltid-protocol.mjs';

const LOCAL_OFFER_URI = `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(
  'https://localhost:8097/draft13/credentialOffer?id=abc',
)}`;
const PUBLIC_OFFER_URI = `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(
  'https://issuer.interop.example/draft13/credentialOffer?id=abc',
)}`;
const requestUriWith = (responseUri) =>
  `openid4vp://authorize?response_type=vp_token&client_id=${encodeURIComponent(
    new URL(responseUri).origin,
  )}&response_mode=direct_post&response_uri=${encodeURIComponent(responseUri)}&nonce=test-nonce-0123456789abcdef&state=s`;

const issuerOffer = (offerUri) => async () => ({
  offerUri,
  issuerPublicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'fake' },
});

it('公開 receiveCredential は一度だけ stderr に警告し、結果 JSON を stdout に保つ', () => {
  const preload = fileURLToPath(
    new URL('../../../scripts/packed-consumer/preload-bun.mjs', import.meta.url),
  );
  const driver = fileURLToPath(new URL('../test-support/receive-warning.mjs', import.meta.url));
  const env = { ...process.env, VERICERTS_WALLET_SDK_SUPPRESS_EXPERIMENTAL_WARNINGS: '0' };
  const child = spawnSync(process.execPath, ['--preload', preload, driver], {
    encoding: 'utf8',
    env,
    timeout: 15_000,
  });
  expect(child.error).toBeUndefined();
  expect(child.status).toBe(0);
  const warnings =
    child.stderr.match(/\[vericerts-wallet-sdk\] `receiveCredential` is @deprecated:/g) ?? [];
  expect(warnings).toHaveLength(1);
  const output = JSON.parse(child.stdout);
  expect(output).toHaveLength(2);
  for (const { results } of output) {
    expect(results.map(({ status }) => status)).toEqual(['fail', 'fail']);
    expect(results[0].reason).not.toContain('malformed offer advanced past Receive');
    expect(results[1].causedBy).toBe('interop:waltid-issuer:vericerts');
  }
});

describe('SDK の公開ホスト検査が localhost の offer を実ピア接続前に拒否する（skip 判定の前提）', () => {
  it('実 receiveCredential に localhost の offer_uri を渡すと 3004 で、fetch は 1 度も呼ばれない', async () => {
    let fetchCalls = 0;
    const fetchImpl = async () => {
      fetchCalls += 1;
      throw new Error('should not be reached');
    };
    await expect(
      receiveCredential(LOCAL_OFFER_URI, {
        signer: {},
        holderDid: 'did:key:z6Mkfake',
        keyId: 'did:key:z6Mkfake#z6Mkfake',
        format: FORMAT_JWT_VC,
        fetchImpl,
      }),
    ).rejects.toMatchObject({ code: '3004' });
    expect(fetchCalls).toBe(0);
  });
});

describe('SDK の公開ホスト検査が localhost の response_uri を拒否する（skip 判定の前提）', () => {
  it('parseAuthorizationRequest は non_public_response_uri で失敗する', () => {
    expect(() =>
      parseAuthorizationRequest(requestUriWith('https://localhost:8098/present')),
    ).toThrow();
    try {
      parseAuthorizationRequest(requestUriWith('https://localhost:8098/present'));
    } catch (error) {
      expect(error.context.reason).toBe(NON_PUBLIC_RESPONSE_URI_REASON);
    }
  });
});

describe('publicHostGuardSkipReason / offerPeerUrl', () => {
  it('ループバック・localhost は理由を返し、公開ホストと URL 無し（判定不能）は undefined', () => {
    expect(publicHostGuardSkipReason('https://localhost:8097/x', 'offer')).toContain(
      'loopback host is rejected by SDK public-host guard',
    );
    expect(publicHostGuardSkipReason('https://127.0.0.1:8098/x', 'offer')).toBeDefined();
    expect(publicHostGuardSkipReason('https://issuer.interop.example/x', 'offer')).toBeUndefined();
    expect(publicHostGuardSkipReason(undefined, 'offer')).toBeUndefined();
    expect(publicHostGuardSkipReason(null, 'offer')).toBeUndefined();
  });

  it('offer の by-reference URI と by-value の credential_issuer の双方から取得先を取り出す', () => {
    expect(offerPeerUrl(LOCAL_OFFER_URI)).toBe(
      'https://localhost:8097/draft13/credentialOffer?id=abc',
    );
    const byValue = `openid-credential-offer://?credential_offer=${encodeURIComponent(
      JSON.stringify({ credential_issuer: 'https://localhost:8097/draft13' }),
    )}`;
    expect(offerPeerUrl(byValue)).toBe('https://localhost:8097/draft13');
    expect(offerPeerUrl('openid-credential-offer://?credential_offer=%7Bbroken')).toBeUndefined();
  });
});

describe('run: 公開ホスト検査で拒否されるピア URL は skipped として報告する', () => {
  it('localhost の offer は両ペアを skipped にし、Receive も Present も呼ばない', async () => {
    let touched = false;
    const mustNotRun = async () => {
      touched = true;
      throw new Error('should not be called');
    };
    const output = await run({
      createIssuerOfferImpl: issuerOffer(LOCAL_OFFER_URI),
      receiveCredentialImpl: mustNotRun,
      createVerifierRequestImpl: mustNotRun,
    });
    expect(output.results.map((r) => [r.pair, r.status])).toEqual([
      ['interop:waltid-issuer:vericerts', 'skipped'],
      ['interop:vericerts:waltid-verifier', 'skipped'],
    ]);
    expect(output.results[0].reason).toContain(
      'loopback host is rejected by SDK public-host guard',
    );
    expect(touched).toBe(false);
  });

  it('公開ホストの offer は skip せず Receive を駆動する（ピアが公開名になれば実駆動へ戻る）', async () => {
    let received = false;
    const output = await run({
      createIssuerOfferImpl: issuerOffer(PUBLIC_OFFER_URI),
      receiveCredentialImpl: async () => {
        received = true;
        return { raw: 'fake.jwt.vc' };
      },
      createVerifierRequestImpl: async () =>
        requestUriWith('https://verifier.interop.example/present'),
      buildVPTokenImpl: () => 'fake-vp-token',
      submitPresentationImpl: async () => undefined,
      pollVerifierSessionImpl: async () => ({ verified: true }),
    });
    expect(received).toBe(true);
    expect(output.results.map((r) => r.status)).toEqual(['pass', 'pass']);
  });

  it('Receive は通るが response_uri が localhost なら Present だけ skipped（submit しない）', async () => {
    let submitted = false;
    const output = await run({
      createIssuerOfferImpl: issuerOffer(PUBLIC_OFFER_URI),
      receiveCredentialImpl: async () => ({ raw: 'fake.jwt.vc' }),
      createVerifierRequestImpl: async () => requestUriWith('https://localhost:8098/present'),
      buildVPTokenImpl: () => 'fake-vp-token',
      submitPresentationImpl: async () => {
        submitted = true;
      },
    });
    expect(output.results[0]).toEqual({ pair: 'interop:waltid-issuer:vericerts', status: 'pass' });
    expect(output.results[1]).toMatchObject({
      pair: 'interop:vericerts:waltid-verifier',
      status: 'skipped',
    });
    expect(output.results[1].reason).toContain('non_public_response_uri');
    expect(submitted).toBe(false);
  });
});
