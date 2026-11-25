/**
 * `buildCredentialApplication` の `manifest.id` と `submitCredentialApplication` の
 * `manifest.issuer.id` の `Object.prototype` 汚染耐性。
 *
 * 同ファイルの `manifest.format` / `manifest.presentation_definition` は既に own 限定で読んでいるのに、
 * 同じ `manifest` に対する `id` / `issuer.id` だけが鎖読みで非対称だった。`manifest` は通常
 * `parseCredentialManifest` の戻り値だが、公開シグネチャ上は**呼び出し側が独自に組み立てた**
 * `CredentialManifest` も渡り得る（`parse.ts` の JSDoc がこの前提を明記）。own の `id` / `issuer` を
 * 持たないそうしたオブジェクトでは、汚染値が
 *
 * - `manifest_id` として Issuer への POST body に混入する、
 * - `submitEndpoint` を明示しない正当な呼び出しの**送信先**になる（申請が攻撃者のエンドポイントへ飛ぶ）、
 *
 * という害になる。データプロパティ汚染・アクセサ（getter）汚染の両形式を固定する。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../../errors.js';
import type { FetchLike } from '../../../../fetch-di.js';
import { buildCredentialApplication } from '../../application-build.js';
import { submitCredentialApplication } from '../../application-response.js';
import { parseCredentialManifest } from '../../parse.js';
import type { CredentialManifest, SubmitApplicationDependencies } from '../../types.js';

const SUPPORTED_SPEC_VERSION = 'https://identity.foundation/credential-manifest/spec/v1.0.0/';
const HONEST_MANIFEST_ID = 'manifest-1';
const HONEST_ENDPOINT = 'https://issuer.example/apply';
const ATTACKER_MANIFEST_ID = 'attacker-manifest';
const ATTACKER_ENDPOINT = 'https://attacker.example/apply';
const OUTPUT_DESCRIPTORS = [{ id: 'od-1', schema: 'https://schema.example/IdCard' }];

/** `parseCredentialManifest` 経由の正当な Manifest（own の `id` / `issuer.id` を持つ）。 */
function honestManifest(): CredentialManifest {
  return parseCredentialManifest({
    id: HONEST_MANIFEST_ID,
    spec_version: SUPPORTED_SPEC_VERSION,
    issuer: { id: HONEST_ENDPOINT },
    output_descriptors: OUTPUT_DESCRIPTORS,
  });
}

/**
 * `parseCredentialManifest` を経由せず呼び出し側が組み立てた Manifest（own の `id` 無し）。
 *
 * 型上は `id` 必須だが、型の無い JS 呼び出し側からは欠落したオブジェクトが渡り得る。
 */
function manifestWithoutOwnId(): CredentialManifest {
  return {
    spec_version: SUPPORTED_SPEC_VERSION,
    issuer: { id: HONEST_ENDPOINT },
    output_descriptors: OUTPUT_DESCRIPTORS,
  } as unknown as CredentialManifest;
}

/** 呼び出し側が組み立てた Manifest（own の `issuer` 自体が無い）。 */
function manifestWithoutOwnIssuer(): CredentialManifest {
  return {
    id: HONEST_MANIFEST_ID,
    spec_version: SUPPORTED_SPEC_VERSION,
    output_descriptors: OUTPUT_DESCRIPTORS,
  } as unknown as CredentialManifest;
}

/** 呼び出し側が組み立てた Manifest（`issuer` は own だがその `id` が無い）。 */
function manifestWithoutOwnIssuerId(): CredentialManifest {
  return {
    id: HONEST_MANIFEST_ID,
    spec_version: SUPPORTED_SPEC_VERSION,
    issuer: {},
    output_descriptors: OUTPUT_DESCRIPTORS,
  } as unknown as CredentialManifest;
}

/** 送信先 URL を記録する `fetchImpl` DI（正当な応答を返す）。 */
function recordingDeps(): { deps: SubmitApplicationDependencies; requestedUrls: string[] } {
  const requestedUrls: string[] = [];
  const fetchImpl: FetchLike = async (url) => {
    requestedUrls.push(url);
    return new Response(JSON.stringify({ transaction_id: 'tx-1' }), { status: 200 });
  };
  return {
    requestedUrls,
    deps: {
      fetchImpl,
      verifyReceived: async () => {
        throw new Error('not used');
      },
    },
  };
}

/** 同期呼び出しが指定の `VericertsError` で fail-closed に倒れることを検証する。 */
function expectSyncFailClosed(run: () => unknown, code: ErrorCode): void {
  let thrown: unknown;
  try {
    run();
  } catch (e) {
    thrown = e;
  }
  expect(thrown).toBeInstanceOf(VericertsError);
  expect((thrown as VericertsError).code).toBe(code);
}

/** 非同期呼び出しが指定の `VericertsError` で fail-closed に倒れることを検証する。 */
async function expectAsyncFailClosed(run: () => Promise<unknown>, code: ErrorCode): Promise<void> {
  let thrown: unknown;
  try {
    await run();
  } catch (e) {
    thrown = e;
  }
  expect(thrown).toBeInstanceOf(VericertsError);
  expect((thrown as VericertsError).code).toBe(code);
}

describe('buildCredentialApplication: manifest.id の Object.prototype 汚染耐性', () => {
  it('own の id を持たない Manifest は汚染値を manifest_id に採用せず 3031 へ倒れる（データ汚染）', () => {
    withPollutedPrototype({ id: ATTACKER_MANIFEST_ID }, () => {
      expectSyncFailClosed(
        () => buildCredentialApplication(manifestWithoutOwnId(), {}, { generateId: () => 'id-1' }),
        ErrorCodes.MANIFEST_SCHEMA_INVALID,
      );
    });
  });

  it('own の id を持たない Manifest は汚染値を manifest_id に採用せず 3031 へ倒れる（アクセサ汚染）', () => {
    withPollutedPrototypeAccessor({ id: () => ATTACKER_MANIFEST_ID }, () => {
      expectSyncFailClosed(
        () => buildCredentialApplication(manifestWithoutOwnId(), {}, { generateId: () => 'id-1' }),
        ErrorCodes.MANIFEST_SCHEMA_INVALID,
      );
    });
  });

  it('own の id を持つ Manifest は汚染下でも自身の id を manifest_id に採用する（非退行）', () => {
    withPollutedPrototype({ id: ATTACKER_MANIFEST_ID }, () => {
      const app = buildCredentialApplication(honestManifest(), {}, { generateId: () => 'id-1' });
      expect(app.manifest_id).toBe(HONEST_MANIFEST_ID);
    });
  });
});

describe('submitCredentialApplication: manifest.issuer.id の Object.prototype 汚染耐性', () => {
  it('own の issuer を持たない Manifest は汚染された送信先へ POST しない（データ汚染）', async () => {
    const { deps, requestedUrls } = recordingDeps();
    await withPollutedPrototypeAsync({ issuer: { id: ATTACKER_ENDPOINT } }, async () => {
      await expectAsyncFailClosed(
        () =>
          submitCredentialApplication(manifestWithoutOwnIssuer(), {}, deps, {
            generateId: () => 'id-1',
          }),
        ErrorCodes.ISSUER_COMMUNICATION_FAILED,
      );
    });
    expect(requestedUrls).toEqual([]);
  });

  it('own の issuer を持たない Manifest は汚染された送信先へ POST しない（アクセサ汚染）', async () => {
    const { deps, requestedUrls } = recordingDeps();
    await withPollutedPrototypeAccessorAsync(
      { issuer: () => ({ id: ATTACKER_ENDPOINT }) },
      async () => {
        await expectAsyncFailClosed(
          () =>
            submitCredentialApplication(manifestWithoutOwnIssuer(), {}, deps, {
              generateId: () => 'id-1',
            }),
          ErrorCodes.ISSUER_COMMUNICATION_FAILED,
        );
      },
    );
    expect(requestedUrls).toEqual([]);
  });

  it('issuer が own の id を持たない Manifest は汚染された送信先へ POST しない（データ汚染）', async () => {
    const { deps, requestedUrls } = recordingDeps();
    await withPollutedPrototypeAsync({ id: ATTACKER_ENDPOINT }, async () => {
      await expectAsyncFailClosed(
        () =>
          submitCredentialApplication(manifestWithoutOwnIssuerId(), {}, deps, {
            generateId: () => 'id-1',
          }),
        ErrorCodes.ISSUER_COMMUNICATION_FAILED,
      );
    });
    expect(requestedUrls).toEqual([]);
  });

  it('issuer が own の id を持たない Manifest は汚染された送信先へ POST しない（アクセサ汚染）', async () => {
    const { deps, requestedUrls } = recordingDeps();
    await withPollutedPrototypeAccessorAsync({ id: () => ATTACKER_ENDPOINT }, async () => {
      await expectAsyncFailClosed(
        () =>
          submitCredentialApplication(manifestWithoutOwnIssuerId(), {}, deps, {
            generateId: () => 'id-1',
          }),
        ErrorCodes.ISSUER_COMMUNICATION_FAILED,
      );
    });
    expect(requestedUrls).toEqual([]);
  });

  it('parseCredentialManifest 経由の Manifest は汚染下でも自身の issuer.id へ POST する（非退行）', async () => {
    const { deps, requestedUrls } = recordingDeps();
    await withPollutedPrototypeAsync(
      { id: ATTACKER_MANIFEST_ID, issuer: { id: ATTACKER_ENDPOINT } },
      async () => {
        const result = await submitCredentialApplication(honestManifest(), {}, deps, {
          generateId: () => 'id-1',
        });
        expect(result.transactionId).toBe('tx-1');
      },
    );
    expect(requestedUrls).toEqual([HONEST_ENDPOINT]);
  });
});
