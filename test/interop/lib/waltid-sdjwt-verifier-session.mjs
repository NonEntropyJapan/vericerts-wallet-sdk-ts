// test/interop/lib/waltid-sdjwt-verifier-session.mjs
//
// walt.id verifier-api への SD-JWT VC 提示要求（`POST /openid4vc/verify`）と、提示に添える
// `presentation_submission` の構築。
//
// walt.id の JSONPath 対応を検証するため、`presentation_definition` の `constraints.fields[].path` に
// JSONPath（`$.vct` / `$.<claim>`）を載せ、walt.id verifier が提示された SD-JWT VC の復元済み
// クレームへそれを突き合わせる。JSONPath を解釈できない版では、提示が正しくてもここで落ちる。
//
// セッション状態のポーリングと `presentation_definition_uri` の取得は JWT-VC 版と同一の管理系
// 呼び出しなので、`waltid-verifier-session.mjs` の実装をそのまま再 export して共有する（複製すると
// walt.id のレスポンス形式が変わったときに片方だけ直す事故が起きる）。

import { FORMAT_SD_JWT_VC } from '@vericerts/vericerts-wallet-sdk/oid4vp';
import { fetchJson, verifierAdminBaseUrl } from './waltid-admin-api.mjs';
import { fetchPresentationDefinition, pollVerifierSession } from './waltid-verifier-session.mjs';

export { fetchPresentationDefinition, pollVerifierSession };

/**
 * `presentation_definition` の `constraints.fields`。
 *
 * JSONPath をそのまま載せ、verifier の対応を確かめる。`$.vct` は提示された
 * SD-JWT VC の型を、`$.<claim>` は開示されたクレームの存在を要求する。`limit_disclosure: 'required'`
 * と組み合わせることで、ここに挙げたクレームだけが開示された提示を要求する。
 */
function constraintFields(vct, claims) {
  if (!Array.isArray(claims) || claims.length === 0) {
    throw new Error('waltid sd-jwt config: requestedClaims が空（JSONPath の要求が成立しない）');
  }
  return [
    { path: ['$.vct'], filter: { type: 'string', pattern: vct } },
    ...claims.map((claim) => ({
      path: [`$.${claim}`],
      filter: { type: 'string', pattern: '.*' },
    })),
  ];
}

/**
 * walt.id verifier-api に SD-JWT VC の Authorization Request 発行を要求する（管理系呼び出し）。
 *
 * @param fetchImpl `fetch` 互換（回帰テストは記録用スタブを注入する）。
 * @param config `pairs.json` の `waltidSdJwt`（`inputDescriptorId` / `requestedClaims`）。
 * @param vct 提示を要求する SD-JWT VC の型識別子。walt.id issuer が**告知した値**を渡す
 *            （`createSdJwtIssuerOffer` の戻り値。`pairs.json` には固定できない）。
 * @returns `openid4vp://…` の Authorization Request URI。失敗した場合は throw する。
 */
export async function createSdJwtVerifierRequest(fetchImpl = fetch, config, vct) {
  const adminBaseUrl = verifierAdminBaseUrl();
  const { ok, body } = await fetchJson(
    `${adminBaseUrl}/openid4vc/verify`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        request_credentials: [
          {
            format: FORMAT_SD_JWT_VC,
            vct,
            input_descriptor: {
              id: config.inputDescriptorId,
              format: { [FORMAT_SD_JWT_VC]: {} },
              constraints: {
                fields: constraintFields(vct, config.requestedClaims),
                limit_disclosure: 'required',
              },
            },
          },
        ],
        // SD-JWT VC の署名と、提示が presentation_definition を満たすことの両方を walt.id 側に
        // 評価させる。既定のポリシーに任せると版によって評価されず、通ったことが何の保証にも
        // ならない（JSONPath の突き合わせは `presentation-definition` ポリシーが行う）。
        vp_policies: ['signature_sd-jwt-vc', 'presentation-definition'],
        vc_policies: ['not-before', 'expired'],
      }),
    },
    fetchImpl,
  );
  if (!ok || typeof body !== 'string' || !body.startsWith('openid4vp://')) {
    throw new Error(`waltid-verifier sd-jwt request creation failed: ${JSON.stringify(body)}`);
  }
  return body;
}

/**
 * SD-JWT VC 提示の `presentation_submission` を組む。
 *
 * SDK の既定構築（`auth/oid4vp/presentation-submission.ts`）は JWT-VP 専用で、VP Token が
 * `<issuerJwt>~<disclosure>~<kbJwt>` の SD-JWT 提示だと `undefined` を返す。そのまま送ると
 * walt.id verifier は `No presentation submission or presentation format found.` で 400 を返す。
 * SD-JWT VC は VP Token 自体が提示単位なので、
 * `path: '$'` / `format: vc+sd-jwt` の descriptor 1 件を呼び出し側から明示する。
 *
 * @param presentationDefinition walt.id から取得した定義（`undefined` なら submission を送らない）。
 * @param fallbackDescriptorId 定義から descriptor id を読めない場合に使う id（要求時に指定した値）。
 * @returns `presentation_submission`。定義が無ければ `undefined`。
 */
export function sdJwtPresentationSubmission(presentationDefinition, fallbackDescriptorId) {
  if (presentationDefinition === undefined) {
    return undefined;
  }
  const descriptors = presentationDefinition.input_descriptors;
  const descriptorId = Array.isArray(descriptors) ? descriptors[0]?.id : undefined;
  const id = typeof descriptorId === 'string' ? descriptorId : fallbackDescriptorId;
  return {
    id: crypto.randomUUID(),
    definition_id: presentationDefinition.id,
    descriptor_map: [{ id, format: FORMAT_SD_JWT_VC, path: '$' }],
  };
}
