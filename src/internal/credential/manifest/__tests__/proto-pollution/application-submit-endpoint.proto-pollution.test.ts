/**
 * `submitCredentialApplication` の `opts.submitEndpoint` の `Object.prototype` 汚染耐性
 *
 * `opts.submitEndpoint` は純データ（送信先 URL）。`Object.prototype.submitEndpoint` が汚染されると、
 * `submitEndpoint` を渡さない正当な呼び出しが `manifest.issuer.id` の代わりに攻撃者の HTTPS
 * エンドポイントへ Application を POST してしまう（`isHttpsUrl` は汚染値が `https:` であれば
 * 素通りするため防げない）。
 *
 * テストは実際に `fetchImpl` へ渡された URL を記録し、汚染下でも常に `manifest.issuer.id`
 * （Issuer が実際に公開したエンドポイント）へ POST されることを固定する。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import type { FetchLike } from '../../../../auth/oid4vci/oid4vci.js';
import { submitCredentialApplication } from '../../application-response.js';
import { parseCredentialManifest } from '../../parse.js';
import type { CredentialManifest, SubmitApplicationDependencies } from '../../types.js';

const SUPPORTED_SPEC_VERSION = 'https://identity.foundation/credential-manifest/spec/v1.0.0/';
const HONEST_ENDPOINT = 'https://issuer.example/apply';
const ATTACKER_ENDPOINT = 'https://attacker.example/apply';

function honestManifest(): CredentialManifest {
  return parseCredentialManifest({
    id: 'manifest-1',
    spec_version: SUPPORTED_SPEC_VERSION,
    issuer: { id: HONEST_ENDPOINT },
    output_descriptors: [{ id: 'od-1', schema: 'https://schema.example/IdCard' }],
  });
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

describe('submitCredentialApplication: submitEndpoint の Object.prototype 汚染耐性', () => {
  it('submitEndpoint 未指定の呼び出しは汚染 URL へ POST しない（データ汚染）', async () => {
    const { deps, requestedUrls } = recordingDeps();
    await withPollutedPrototypeAsync({ submitEndpoint: ATTACKER_ENDPOINT }, async () => {
      const result = await submitCredentialApplication(honestManifest(), {}, deps, {
        generateId: () => 'id-1',
      });
      expect(result.transactionId).toBe('tx-1');
    });
    expect(requestedUrls).toEqual([HONEST_ENDPOINT]);
  });

  it('submitEndpoint 未指定の呼び出しは汚染 URL へ POST しない（アクセサ汚染）', async () => {
    const { deps, requestedUrls } = recordingDeps();
    await withPollutedPrototypeAccessorAsync(
      { submitEndpoint: () => ATTACKER_ENDPOINT },
      async () => {
        const result = await submitCredentialApplication(honestManifest(), {}, deps, {
          generateId: () => 'id-1',
        });
        expect(result.transactionId).toBe('tx-1');
      },
    );
    expect(requestedUrls).toEqual([HONEST_ENDPOINT]);
  });

  it('submitEndpoint を明示指定した場合は汚染下でも指定どおりに送信する（非退行）', async () => {
    const { deps, requestedUrls } = recordingDeps();
    const explicitEndpoint = 'https://issuer.example/explicit-apply';
    await withPollutedPrototypeAsync({ submitEndpoint: ATTACKER_ENDPOINT }, async () => {
      await submitCredentialApplication(honestManifest(), {}, deps, {
        generateId: () => 'id-1',
        submitEndpoint: explicitEndpoint,
      });
    });
    expect(requestedUrls).toEqual([explicitEndpoint]);
  });
});
