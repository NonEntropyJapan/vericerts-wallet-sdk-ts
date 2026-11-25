/**
 * `credential/` 配下 4 経路の応答**本文**読み出しが abort タイムアウトと 1 MiB 上限の内側に
 * あること。
 *
 * 退行時の形は 4 経路とも同じで、`clearTimeout` が fetch の `try` だけに付き、タイマを止めた
 * あとで `await response.text()` を無制限に読む。取得先 URL はいずれも攻撃者の影響下にある
 * （`manifestURL` / `manifest.issuer.id` / `issuerURL` / 受領済み VC 由来の
 * `refreshService.url`）ため、ヘッダだけ即返して本文を小出しにするサーバが呼び出し側を
 * 無期限に待たせ、同時に無制限のバイトをメモリへ流し込める。
 *
 * 回帰観点（修正前は前者がハングし、後者が素通りする）:
 * - ヘッダだけ返して本文を送らないサーバに対し、各経路のタイムアウトで abort されること
 * - 1 MiB を超える本文が「それ以外は正当な応答」であっても拒否されること
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { FetchLike } from '../../fetch-di.js';
import { MAX_DOCUMENT_BYTES } from '../../http/body-limit.js';
import { submitCredentialApplication } from '../manifest/application-response.js';
import { fetchCredentialManifest, parseCredentialManifest } from '../manifest/parse.js';
import { subscribePoll } from '../notification/poll.js';
import type { CredentialNotificationEvent } from '../notification/types.js';
import { callRefreshEndpoint } from '../refresh/refresh-endpoint.js';
import type { RefreshServiceConfig, VerifiableCredential } from '../vc/vc.js';

const SUPPORTED_SPEC_VERSION = 'https://identity.foundation/credential-manifest/spec/v1.0.0/';
const ENDPOINT = 'https://issuer.example/endpoint';

/** SDK が各経路で張るタイムアウト（ミリ秒）。テストでは 10 ms へ短縮して実測する。 */
const SDK_TIMEOUT_MS = 10_000;

/**
 * ヘッダは 200 で即座に返し、本文は 1 バイトも流さずに保持し続けるサーバ。
 *
 * 実 `fetch` は abort されると本文ストリームをエラーにするため、その挙動だけを再現する。
 * `signal` を記録するのは、タイマが本文読み出しまで生きていた（＝ abort が届いた）ことを
 * 例外を投げない経路（poll）でも観測するため。
 */
function stallingBodyFetch(): { fetchImpl: FetchLike; signalOf: () => AbortSignal | undefined } {
  let seen: AbortSignal | undefined;
  return {
    signalOf: () => seen,
    fetchImpl: (_url, init) => {
      seen = init.signal;
      return Promise.resolve(
        new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              init.signal.addEventListener('abort', () => {
                controller.error(new TypeError('The operation was aborted.'));
              });
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );
    },
  };
}

/**
 * `payload` に詰め物を足して 1 MiB を超えさせた、それ以外は正当な JSON 応答を返すサーバ。
 *
 * 上限が無い実装（退行時）はこの応答を正常に処理してしまうため、「上限が効いている」ことだけを
 * 各テストの差分にできる。
 */
function oversizedJsonFetch(payload: Record<string, unknown>): FetchLike {
  const padding = 'x'.repeat(MAX_DOCUMENT_BYTES + 1);
  const body = JSON.stringify({ ...payload, _padding: padding });
  return () => Promise.resolve(new Response(body, { status: 200 }));
}

/**
 * SDK が張るタイムアウトだけを 10 ms へ短縮して `start` を呼ぶ（実時間で 10 秒待たないため）。
 *
 * 対象 4 経路はいずれも `setTimeout` を最初の `await` より前（同期部分）で呼ぶので、Promise を
 * 受け取った直後にグローバルを差し戻せる。`requestedDelay` は「短縮していなければ何 ms 待つ
 * 予定だったか」であり、タイマが確かに SDK 側のものだったことの裏付けになる。
 */
function withShortenedTimeout<T>(start: () => T): {
  result: T;
  requestedDelay: number | undefined;
} {
  const realSetTimeout = globalThis.setTimeout;
  let requestedDelay: number | undefined;
  globalThis.setTimeout = ((handler: TimerHandler, delay?: number, ...args: unknown[]) => {
    requestedDelay = delay;
    return realSetTimeout(handler, 10, ...args);
  }) as typeof globalThis.setTimeout;
  try {
    return { result: start(), requestedDelay };
  } finally {
    globalThis.setTimeout = realSetTimeout;
  }
}

/** 退行時に無期限となる待ちで CI をハングさせず「失敗」として落とすための有限時間の打ち切り。 */
const HUNG = Symbol('hung');
async function settleWithin(pending: Promise<unknown>): Promise<unknown> {
  return Promise.race([
    pending.then(
      () => undefined,
      (error: unknown) => error,
    ),
    new Promise<symbol>((resolve) => {
      setTimeout(() => resolve(HUNG), 1_000);
    }),
  ]);
}

/** 非同期配送を待つ（microtask + macrotask フラッシュ）。 */
function flush(delayMs: number): Promise<unknown> {
  return new Promise((resolve) => setTimeout(resolve, delayMs));
}

const RAW_MANIFEST = {
  id: 'manifest-1',
  spec_version: SUPPORTED_SPEC_VERSION,
  issuer: { id: ENDPOINT, name: 'Example Issuer' },
  output_descriptors: [{ id: 'od-1', schema: 'https://schema.example/IdCard' }],
};

const VERIFIED_VC: VerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'IdentityCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { id: 'did:example:holder' },
  issuanceDate: '2026-01-01T00:00:00Z',
  id: 'urn:vc:issued',
};

const REFRESH_SERVICE: RefreshServiceConfig = {
  id: 'refresh-1',
  type: 'OID4VCIRefreshService2025',
  url: ENDPOINT,
};

describe('fetchCredentialManifest の本文読み出し', () => {
  test('ヘッダのみ返して本文を送らない取得先はタイムアウトで 3034 になる', async () => {
    const { fetchImpl } = stallingBodyFetch();
    const { result, requestedDelay } = withShortenedTimeout(() =>
      fetchCredentialManifest(ENDPOINT, { fetchImpl }),
    );
    expect(requestedDelay).toBe(SDK_TIMEOUT_MS);

    const outcome = await settleWithin(result);
    expect(outcome).not.toBe(HUNG);
    expect(outcome).toBeInstanceOf(VericertsError);
    expect(outcome).toMatchObject({ code: ErrorCodes.MANIFEST_FETCH_FAILED });
  });

  test('1 MiB を超える本文は正当な Manifest でも 3034 で拒否する', async () => {
    const pending = fetchCredentialManifest(ENDPOINT, {
      fetchImpl: oversizedJsonFetch(RAW_MANIFEST),
    });
    await expect(pending).rejects.toMatchObject({ code: ErrorCodes.MANIFEST_FETCH_FAILED });
  });
});

describe('submitCredentialApplication の本文読み出し', () => {
  const manifest = parseCredentialManifest(RAW_MANIFEST);
  /** 本文読み出しに到達する前に失敗するため、検証器が呼ばれたら失敗させる。 */
  const verifyReceived = (): Promise<VerifiableCredential> => {
    throw new Error('verifyReceived must not be reached');
  };

  test('ヘッダのみ返して本文を送らない Issuer はタイムアウトで打ち切られる', async () => {
    const { fetchImpl } = stallingBodyFetch();
    const { result, requestedDelay } = withShortenedTimeout(() =>
      submitCredentialApplication(manifest, {}, { fetchImpl, verifyReceived }),
    );
    expect(requestedDelay).toBe(SDK_TIMEOUT_MS);

    const outcome = await settleWithin(result);
    expect(outcome).not.toBe(HUNG);
    expect(outcome).toBeInstanceOf(VericertsError);
    expect(outcome).toMatchObject({ code: ErrorCodes.MANIFEST_SCHEMA_INVALID });
  });

  test('1 MiB を超える本文は正当な Credential Response でも拒否する', async () => {
    const pending = submitCredentialApplication(
      manifest,
      {},
      { fetchImpl: oversizedJsonFetch({ credential: 'raw-vc-string' }), verifyReceived },
    );
    await expect(pending).rejects.toMatchObject({ code: ErrorCodes.MANIFEST_SCHEMA_INVALID });
  });
});

describe('callRefreshEndpoint の本文読み出し', () => {
  test('ヘッダのみ返して本文を送らない Refresh Service はタイムアウトで 3030 になる', async () => {
    const { fetchImpl } = stallingBodyFetch();
    const { result, requestedDelay } = withShortenedTimeout(() =>
      callRefreshEndpoint(REFRESH_SERVICE, VERIFIED_VC, fetchImpl),
    );
    expect(requestedDelay).toBe(SDK_TIMEOUT_MS);

    const outcome = await settleWithin(result);
    expect(outcome).not.toBe(HUNG);
    expect(outcome).toBeInstanceOf(VericertsError);
    expect(outcome).toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
  });

  test('1 MiB を超える本文は新 VC を含んでいても 3030 で拒否する', async () => {
    const pending = callRefreshEndpoint(
      REFRESH_SERVICE,
      VERIFIED_VC,
      oversizedJsonFetch({ credential: 'refreshed-vc-string' }),
    );
    await expect(pending).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
  });
});

describe('poll の本文読み出し', () => {
  const ACCEPTED_EVENT = {
    event: 'credential_accepted',
    notification_id: 'notif-1',
    notification_issued_at: '2026-07-01T00:00:00Z',
    credential_configuration_id: 'UniversityDegree',
  };

  /** `schedule` DI で tick を捕まえ、1 回だけ手動で回す購読を張る。 */
  function subscribeOnce(fetchImpl: FetchLike): {
    tick: () => void;
    delivered: CredentialNotificationEvent[];
    unsubscribe: () => void;
  } {
    const delivered: CredentialNotificationEvent[] = [];
    let captured: () => void = () => undefined;
    const subscription = subscribePoll(
      'sub-1',
      ENDPOINT,
      (event) => {
        delivered.push(event);
      },
      {
        fetchImpl,
        schedule: (task) => {
          captured = task;
          return () => undefined;
        },
      },
    );
    return {
      delivered,
      tick: () => captured(),
      unsubscribe: () => {
        void subscription.unsubscribe();
      },
    };
  }

  test('ヘッダのみ返して本文を送らない Issuer では本文読み出し中に abort される', async () => {
    // poll は例外をイベント 0 件へ畳むため、「タイマが本文読み出しまで生きていた」ことは
    // signal が abort されたかどうかで観測する（退行時は fetch 完了時に clearTimeout され、
    // abort は永久に届かない）。
    const { fetchImpl, signalOf } = stallingBodyFetch();
    const { tick, delivered, unsubscribe } = subscribeOnce(fetchImpl);
    const { requestedDelay } = withShortenedTimeout(() => {
      tick();
    });
    expect(requestedDelay).toBe(SDK_TIMEOUT_MS);

    await flush(100);
    expect(signalOf()?.aborted).toBe(true);
    expect(delivered).toEqual([]);
    unsubscribe();
  });

  test('1 MiB を超える本文はイベントを含んでいても配送しない', async () => {
    const { tick, delivered, unsubscribe } = subscribeOnce(
      oversizedJsonFetch({ events: [ACCEPTED_EVENT] }),
    );
    tick();

    await flush(50);
    expect(delivered).toEqual([]);
    unsubscribe();
  });
});
