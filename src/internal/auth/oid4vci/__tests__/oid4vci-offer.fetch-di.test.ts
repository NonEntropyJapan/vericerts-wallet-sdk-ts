/**
 * `parseCredentialOffer` の fetch DI シーム検証。
 *
 * 受領フローの初弾（`credential_offer_uri` の HTTPS GET）が、ホストアプリの注入した
 * `fetch`（証明書ピン留め / プロキシ済み）を通ることを確認する。`credential_offer_uri` は
 * QR / Deep Link 由来で攻撃者が選べる URL なので、ここだけグローバル `fetch` へ落ちると
 * その制御の外で取得が走る。
 */

import { describe, expect, it } from 'bun:test';
import { parseCredentialOffer } from '../offer/oid4vci-offer.js';

/** 参照渡し Offer の応答本文。 */
const SAMPLE_OFFER = {
  credential_issuer: 'https://issuer.example.com',
  credential_configuration_ids: ['UniversityDegree_jwt'],
};

/** 注入した fetch が受け取った引数（init は body の有無まで見る）。 */
interface RecordedCall {
  readonly input: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body: string | undefined;
}

/** JSON 応答を返す記録付きの fetch スタブを作る。 */
function recordingFetch(calls: RecordedCall[]) {
  return (
    input: string,
    init: { method: string; headers: Record<string, string>; signal: AbortSignal; body?: string },
  ): Promise<Response> => {
    calls.push({
      input,
      method: init.method,
      headers: init.headers,
      body: init.body,
    });
    return Promise.resolve(
      new Response(JSON.stringify(SAMPLE_OFFER), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
  };
}

describe('parseCredentialOffer — fetchImpl シーム', () => {
  it('参照渡しの初弾に注入した fetchImpl を使い、グローバル fetch を呼ばない', async () => {
    // 初弾がグローバルへ落ちたら即座に分かるよう、グローバル側は必ず失敗させる。
    const originalFetch = globalThis.fetch;
    // biome-ignore lint/suspicious/noExplicitAny: テスト用に globalThis.fetch を差し替える。
    (globalThis as any).fetch = () => Promise.reject(new Error('global fetch must not be used'));
    const calls: RecordedCall[] = [];
    const uri =
      'openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offers/123';
    try {
      const offer = await parseCredentialOffer(uri, recordingFetch(calls));
      expect(offer.credential_issuer).toBe('https://issuer.example.com');
    } finally {
      globalThis.fetch = originalFetch;
    }

    expect(calls).toHaveLength(1);
    expect(calls[0]?.input).toBe('https://issuer.example.com/offers/123');
    expect(calls[0]?.method).toBe('GET');
    expect(calls[0]?.headers.Accept).toBe('application/json');
    // GET に body を載せると実 fetch は Request 構築の時点で TypeError になる。
    expect(calls[0]?.body).toBeUndefined();
  });

  it('値渡し（credential_offer）では fetchImpl を呼ばない', async () => {
    const calls: RecordedCall[] = [];
    const inlineUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(
      JSON.stringify(SAMPLE_OFFER),
    )}`;

    const offer = await parseCredentialOffer(inlineUri, recordingFetch(calls));

    expect(calls).toHaveLength(0);
    expect(offer.credential_configuration_ids).toEqual(['UniversityDegree_jwt']);
  });
});
