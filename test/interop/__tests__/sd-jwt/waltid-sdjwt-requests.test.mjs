// test/interop/__tests__/sd-jwt/waltid-sdjwt-requests.test.mjs
//
// `pairs.json` の `waltidSdJwt` の設定が、walt.id issuer-api / verifier-api への実リクエスト本文に
// そのまま載ることの回帰テスト。
//
// 特に **presentation_definition の `constraints.fields[].path` に JSONPath（`$.vct` / `$.<claim>`）が
// 実際に含まれること**を固定する（同梱 README の「5. SD-JWT」参照）。
//
// パッケージをインストールした consumer で実行する（README 参照）。
//   bun test test/interop/__tests__/sd-jwt/waltid-sdjwt-requests.test.mjs

import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import { createSdJwtIssuerOffer } from '../../lib/waltid-sdjwt-issuer-offer.mjs';
import {
  createSdJwtVerifierRequest,
  sdJwtPresentationSubmission,
} from '../../lib/waltid-sdjwt-verifier-session.mjs';
import { run } from '../../run-waltid-sdjwt.mjs';
import {
  describeAdminBaseUrlRequired,
  ISSUER_ENV,
  useWaltidAdminEnv,
  VERIFIER_ENV,
} from '../../test-support/waltid-admin-env.mjs';

// 実 `create*` は URL の既定値を持たず、呼び出し時に env を読む。
useWaltidAdminEnv();

const PAIRS = JSON.parse(readFileSync(new URL('../../pairs.json', import.meta.url), 'utf8'));
const CONFIG = PAIRS.waltidSdJwt;
const CONTRACT = JSON.parse(
  readFileSync(new URL('../../contracts/matrix.json', import.meta.url), 'utf8'),
).sdJwt;

const OFFER_URI = `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(
  'https://issuer.interop.example/draft13/credentialOffer?id=abc',
)}`;
const REQUEST_URI =
  'openid4vp://authorize' +
  '?response_type=vp_token' +
  `&client_id=${encodeURIComponent('https://verifier.example.test')}` +
  '&response_mode=direct_post' +
  `&response_uri=${encodeURIComponent('https://verifier.example.test/present')}` +
  '&nonce=test-nonce-0123456789abcdef' +
  '&state=test-state';

/** walt.id が告知する `vct`（発行要求で渡した値ではなくこれが使われる）。 */
const ADVERTISED_VCT = 'https://issuer.interop.example/draft13/identity_credential';

/**
 * `createSdJwtIssuerOffer` が Offer 作成の**あとに**引く 2 本の応答。
 *
 * walt.id は credential configuration の告知値で `vct` を決めるため、ハーネスは Offer →
 * `credential_issuer` → Issuer Metadata の順に辿って告知値を読む。
 */
const ADVERTISED_VCT_RESPONSES = [
  JSON.stringify({ credential_issuer: 'https://issuer.interop.example/draft13' }),
  JSON.stringify({
    credential_configurations_supported: {
      'identity_credential_vc+sd-jwt': { format: 'dc+sd-jwt', vct: ADVERTISED_VCT },
    },
  }),
];

/** 呼び出しの URL と本文を記録し、`responses` を順に返す `fetchImpl` スタブ。 */
function recordingFetch(responses) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    const body = options?.body === undefined ? undefined : JSON.parse(options.body);
    calls.push({ url, body });
    const text = responses[calls.length - 1];
    if (text === undefined) {
      throw new Error(`recordingFetch: 想定より多く呼び出された (${calls.length} 回目: ${url})`);
    }
    return { ok: true, status: 200, text: async () => text };
  };
  return { calls, fetchImpl };
}

describe('createSdJwtIssuerOffer: pairs.json の設定が発行要求の本文に載る', () => {
  it('SD-JWT 用エンドポイント・credential configuration・vct・クレーム・選択的開示を送る', async () => {
    const { _comment, ...publicConfig } = CONFIG;
    expect(publicConfig).toEqual(CONTRACT);
    const sdJwtPairs = Object.values(CONTRACT.pairs);
    expect(PAIRS.knownIncompatible.some(({ pair }) => sdJwtPairs.includes(pair))).toBe(false);
    const { calls, fetchImpl } = recordingFetch([OFFER_URI, ...ADVERTISED_VCT_RESPONSES]);
    const { offerUri, issuerPublicKeyJwk, vct } = await createSdJwtIssuerOffer(fetchImpl, CONFIG);

    expect(offerUri).toBe(OFFER_URI);
    expect(issuerPublicKeyJwk).toMatchObject({ kty: 'OKP', crv: 'Ed25519' });
    // 告知された `vct` を返す（`pairs.json` には固定しない）。
    expect(vct).toBe(ADVERTISED_VCT);
    expect(calls).toHaveLength(3);
    // JWT-VC 版（`/openid4vc/jwt/issue`）ではなく SD-JWT 版のエンドポイントを叩く。
    expect(calls[0].url).toEndWith('/openid4vc/sdjwt/issue');
    expect(calls[0].body.credentialConfigurationId).toBe(CONFIG.credentialConfigurationId);
    // Offer → Issuer Metadata の順に、管理系ベース URL のまま辿る（版のセグメントを固定しない）。
    expect(calls[1].url).toEndWith('/draft13/credentialOffer?id=abc');
    expect(calls[2].url).toEndWith('/draft13/.well-known/openid-credential-issuer');
    // 発行日時が無いと受領が 8020 になるため `iat` を明示する。
    expect(typeof calls[0].body.credentialData.iat).toBe('number');
    for (const [claim, value] of Object.entries(CONFIG.claims)) {
      expect(calls[0].body.credentialData[claim]).toBe(value);
    }
    // 選択的開示の対象は設定どおりで、過不足なく `sd: true` が付く。
    expect(Object.keys(calls[0].body.selectiveDisclosure.fields).sort()).toEqual(
      [...CONFIG.selectiveDisclosureClaims].sort(),
    );
    for (const claim of CONFIG.selectiveDisclosureClaims) {
      expect(calls[0].body.selectiveDisclosure.fields[claim]).toEqual({ sd: true });
    }
  });

  it('選択的開示の対象が空の設定は設定ミスとして拒否する（選択的開示の無い SD-JWT を黙って発行しない）', async () => {
    const { fetchImpl } = recordingFetch([OFFER_URI]);
    await expect(
      createSdJwtIssuerOffer(fetchImpl, { ...CONFIG, selectiveDisclosureClaims: [] }),
    ).rejects.toThrow('selectiveDisclosureClaims');
  });

  it('Offer URI 以外が返ったら投げる（walt.id のレスポンス形式の変化を検知する）', async () => {
    const { fetchImpl } = recordingFetch(['{"message":"unexpected"}']);
    await expect(createSdJwtIssuerOffer(fetchImpl, CONFIG)).rejects.toThrow(
      'waltid-issuer sd-jwt offer creation failed',
    );
  });
});

describe('createSdJwtVerifierRequest: 提示要求に JSONPath が載る（§5 の非互換が出る経路）', () => {
  it('format / vct / input_descriptor の JSONPath・limit_disclosure を送る', async () => {
    const { calls, fetchImpl } = recordingFetch([REQUEST_URI]);
    const requestUri = await createSdJwtVerifierRequest(fetchImpl, CONFIG);

    expect(requestUri).toBe(REQUEST_URI);
    expect(calls[0].url).toEndWith('/openid4vc/verify');
    const requested = calls[0].body.request_credentials[0];
    expect(requested.format).toBe('vc+sd-jwt');
    expect(requested.vct).toBe(CONFIG.vct);
    expect(requested.input_descriptor.id).toBe(CONFIG.inputDescriptorId);
    expect(requested.input_descriptor.format).toEqual({ 'vc+sd-jwt': {} });

    // **JSONPath そのもの**。`$.vct` に加え、要求クレームごとに `$.<claim>` が載る。
    const paths = requested.input_descriptor.constraints.fields.flatMap((field) => field.path);
    expect(paths).toEqual(['$.vct', ...CONFIG.requestedClaims.map((claim) => `$.${claim}`)]);
    expect(requested.input_descriptor.constraints.limit_disclosure).toBe('required');
    // vct は「どれかの SD-JWT が来れば通る」ではなく、発行した型に一致することを要求する。
    expect(requested.input_descriptor.constraints.fields[0].filter.pattern).toBe(CONFIG.vct);
    // 署名と presentation_definition の両方を walt.id 側に評価させる（既定任せにしない）。
    expect(calls[0].body.vp_policies).toEqual(['signature_sd-jwt-vc', 'presentation-definition']);
  });

  it('要求クレームが空の設定は拒否する（JSONPath の要求が成立しないため）', async () => {
    const { fetchImpl } = recordingFetch([REQUEST_URI]);
    await expect(
      createSdJwtVerifierRequest(fetchImpl, { ...CONFIG, requestedClaims: [] }),
    ).rejects.toThrow('requestedClaims');
  });

  it('Authorization Request URI 以外が返ったら投げる', async () => {
    const { fetchImpl } = recordingFetch(['https://unexpected.example/']);
    await expect(createSdJwtVerifierRequest(fetchImpl, CONFIG)).rejects.toThrow(
      'waltid-verifier sd-jwt request creation failed',
    );
  });
});

describeAdminBaseUrlRequired([
  {
    name: 'createSdJwtIssuerOffer',
    env: ISSUER_ENV,
    // Offer 作成のあと、告知 vct のために Offer 本体と Issuer Metadata も引く。
    body: [OFFER_URI, ...ADVERTISED_VCT_RESPONSES],
    call: (f) => createSdJwtIssuerOffer(f, CONFIG),
  },
  {
    name: 'createSdJwtVerifierRequest',
    env: VERIFIER_ENV,
    body: REQUEST_URI,
    call: (f) => createSdJwtVerifierRequest(f, CONFIG),
  },
]);

describe('sdJwtPresentationSubmission: SD-JWT 提示用の descriptor_map', () => {
  it('取得した定義の input_descriptor id で、format vc+sd-jwt / path $ の 1 件を組む', () => {
    const submission = sdJwtPresentationSubmission(
      { id: 'definition-1', input_descriptors: [{ id: 'from-definition' }] },
      CONFIG.inputDescriptorId,
    );
    expect(submission.definition_id).toBe('definition-1');
    expect(submission.descriptor_map).toEqual([
      { id: 'from-definition', format: 'vc+sd-jwt', path: '$' },
    ]);
  });

  it('定義から descriptor id を読めなければ要求時に指定した id へ落とす', () => {
    const submission = sdJwtPresentationSubmission({ id: 'definition-1' }, 'interop-sd-jwt');
    expect(submission.descriptor_map[0].id).toBe('interop-sd-jwt');
  });

  it('定義が取得できなければ submission を送らない（undefined）', () => {
    expect(sdJwtPresentationSubmission(undefined, 'interop-sd-jwt')).toBeUndefined();
  });
});

describe('run: ドライバが実際に設定どおりの発行要求・提示要求を出す', () => {
  it('issuer / verifier の両方へ pairs.json の設定を載せ、提示は disclosedClaims と submission を伴う', async () => {
    // 発行要求 → Offer → Issuer Metadata（告知 vct）→ 提示要求 の順に引く。
    const { calls, fetchImpl: adminFetchImpl } = recordingFetch([
      OFFER_URI,
      ...ADVERTISED_VCT_RESPONSES,
      REQUEST_URI,
    ]);
    const presentations = [];
    const submissions = [];

    const output = await run({
      pairSuffix: '',
      adminFetchImpl,
      receiveCredentialImpl: async () => ({ raw: 'issuer.jwt.sd~disclosure~' }),
      verifySdJwtImpl: () => ({ claims: {} }),
      fetchPresentationDefinitionImpl: async () => ({
        id: 'definition-1',
        input_descriptors: [{ id: CONFIG.inputDescriptorId }],
      }),
      buildVPTokenImpl: (_request, inputs) => {
        presentations.push(inputs[0]);
        return 'issuer.jwt.sd~disclosure~kb.jwt.sig';
      },
      submitPresentationImpl: async (_request, _vpToken, options) => {
        submissions.push(options.presentationSubmission);
      },
      pollVerifierSessionImpl: async () => ({ verified: true }),
    });

    expect(output.results.map((r) => r.status)).toEqual(['pass', 'pass']);
    // 発行 → Offer → Issuer Metadata → 提示要求 の順（告知 vct の解決が間に入る）。
    expect(calls.map((c) => new URL(c.url).pathname)).toEqual([
      '/openid4vc/sdjwt/issue',
      '/draft13/credentialOffer',
      '/draft13/.well-known/openid-credential-issuer',
      '/openid4vc/verify',
    ]);
    // 提示要求の `vct` は告知値。発行要求で渡した値ではない（walt.id が上書きするため）。
    expect(calls[3].body.request_credentials[0].vct).toBe(ADVERTISED_VCT);
    const fields = calls[3].body.request_credentials[0].input_descriptor.constraints.fields;
    expect(fields.flatMap((field) => field.path)).toContain(`$.${CONFIG.requestedClaims[0]}`);
    // 提示は設定どおりのクレームだけを開示する（発行時に sd: true にした全クレームではない）。
    expect(presentations[0]).toMatchObject({
      format: 'vc+sd-jwt',
      sdJwt: 'issuer.jwt.sd~disclosure~',
      disclosedClaims: CONFIG.disclosedClaims,
    });
    expect(submissions[0].descriptor_map[0]).toEqual({
      id: CONFIG.inputDescriptorId,
      format: 'vc+sd-jwt',
      path: '$',
    });
  });
});
