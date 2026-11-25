// test/interop/lib/waltid-sdjwt-issuer-offer.mjs
//
// walt.id issuer-api への SD-JWT VC の Offer 発行要求（`POST /openid4vc/sdjwt/issue`）。
//
// JWT-VC 版（`waltid-issuer-offer.mjs`）と関数を分ける理由: エンドポイント・リクエスト本文
// （`selectiveDisclosure`）・credential configuration がいずれも別物で、同じ関数に畳むと
// 呼び出し側からどちらの経路を駆動しているのか読めなくなる。
// `run-waltid-sdjwt.mjs` を Linterly の 1 ファイル 300 行上限に収めるために分けている。

import { readFileSync } from 'node:fs';
import { createPrivateKeySigner } from 'vericerts-wallet-sdk/credential';
import { fetchJson, issuerAdminBaseUrl } from './waltid-admin-api.mjs';

const ISSUER_FIXTURE = JSON.parse(
  readFileSync(new URL('../fixtures/waltid-issuer.json', import.meta.url), 'utf8'),
);

/** walt.id issuer-api の JWK 形式へ Ed25519 秘密鍵を変換する（JWT-VC 版と同形）。 */
function issuerJwk(seedHex, publicKeyJwk) {
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: publicKeyJwk.x,
    d: Buffer.from(seedHex, 'hex').toString('base64url'),
  };
}

/**
 * `selectiveDisclosure.fields`（`{ <claim>: { sd: true } }`）を組む。
 *
 * ここに挙げたクレームだけが Disclosure として切り出され、提示時に Holder が開示を選べる。
 * 空だと選択的開示の無い SD-JWT になり、提示側ペアが「選択的開示つきで提示する」という
 * テストの前提を失うため、空の設定は設定ミスとして即座に拒否する。
 */
function selectiveDisclosureFields(claims) {
  if (!Array.isArray(claims) || claims.length === 0) {
    throw new Error(
      'waltid sd-jwt config: selectiveDisclosureClaims が空（選択的開示が成立しない）',
    );
  }
  const fields = {};
  for (const claim of claims) {
    fields[claim] = { sd: true };
  }
  return { fields };
}

/**
 * Offer URI から Credential Issuer Identifier のパスを取り出し、管理系ベース URL に移し替える。
 *
 * Offer も Issuer Metadata も公開 FQDN（`https://issuer.waltid.interop.example:8097/<版>`）で告知される
 * が、管理系呼び出しは compose 内部の平文 HTTP を使う。ホストが違うだけでパスは同じなので、
 * パスだけを borrow する。**版のセグメント（`/draft13` 等）をハードコードしない**ため、
 * mutable tag で版の変わる `waltid-sdjwt-next` でも追従する。
 */
function adminUrlForOfferPath(adminBaseUrl, publicUrl) {
  let parsed;
  try {
    parsed = new URL(publicUrl);
  } catch {
    // 素の `TypeError: Invalid URL` だと、結果 JSON の reason から原因が読めない。
    throw new Error(`waltid-issuer sd-jwt: 絶対 URL ではない: ${publicUrl}`);
  }
  return `${adminBaseUrl}${parsed.pathname}${parsed.search}`;
}

/**
 * walt.id が credential configuration に対して**告知している `vct`** を取る。
 *
 * walt.id は発行要求の `credentialData.vct` を無視し、`credential_configurations_supported[id].vct`
 * の値で SD-JWT VC を発行する。さらに Credential Request の `vct` をこの告知値と突き合わせ、
 * 一致しなければ HTTP 400 `No matching issuance request found for this session` を返す
 * （`CIProvider.findMatchingIssuanceRequest`）。値は walt.id の `baseUrl`（ホスト・ポート）を含むため、
 * `pairs.json` に固定できない。
 */
async function fetchAdvertisedVct(adminBaseUrl, offerUri, config, fetchImpl) {
  const offerUrl = new URL(offerUri).searchParams.get('credential_offer_uri');
  if (offerUrl === null) {
    throw new Error(`waltid-issuer sd-jwt offer: credential_offer_uri が無い: ${offerUri}`);
  }
  const offer = await fetchJson(adminUrlForOfferPath(adminBaseUrl, offerUrl), {}, fetchImpl);
  const credentialIssuer = offer.body?.credential_issuer;
  if (typeof credentialIssuer !== 'string') {
    throw new Error(
      `waltid-issuer sd-jwt offer: Offer に credential_issuer が無い（HTTP ${offer.status}）`,
    );
  }
  const metadataUrl = adminUrlForOfferPath(
    adminBaseUrl,
    `${credentialIssuer}/.well-known/openid-credential-issuer`,
  );
  const metadata = await fetchJson(metadataUrl, {}, fetchImpl);
  const vct =
    metadata.body?.credential_configurations_supported?.[config.credentialConfigurationId]?.vct;
  if (typeof vct !== 'string' || vct === '') {
    throw new Error(
      `waltid-issuer sd-jwt: ${config.credentialConfigurationId} の vct が告知されていない` +
        `（HTTP ${metadata.status}）。SD-JWT VC の Credential Request は告知された vct を送る必要がある`,
    );
  }
  return vct;
}

/**
 * walt.id issuer-api に SD-JWT VC の Offer 発行を要求する（管理系呼び出し。平文 HTTP で十分）。
 *
 * @param fetchImpl `fetch` 互換（回帰テストは記録用スタブを注入する）。
 * @param config `pairs.json` の `waltidSdJwt`（`credentialConfigurationId` / `claims` /
 *               `selectiveDisclosureClaims`。`vct` は持たない。{@link fetchAdvertisedVct} 参照）。設定値がそのままリクエスト本文に載ることを
 *               `__tests__/sd-jwt/waltid-sdjwt-requests.test.mjs` が固定する。
 * @returns `{ offerUri, issuerPublicKeyJwk, vct }`。発行要求が失敗した場合は throw する。
 */
export async function createSdJwtIssuerOffer(fetchImpl = fetch, config) {
  const adminBaseUrl = issuerAdminBaseUrl();
  const issuerSigner = createPrivateKeySigner(
    Uint8Array.from(Buffer.from(ISSUER_FIXTURE.seedHex, 'hex')),
    ISSUER_FIXTURE.alg,
  );
  const jwk = issuerJwk(ISSUER_FIXTURE.seedHex, issuerSigner.publicKeyJwk);
  const { ok, body } = await fetchJson(
    `${adminBaseUrl}/openid4vc/sdjwt/issue`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        issuerKey: { type: 'jwk', jwk },
        issuerDid: ISSUER_FIXTURE.did,
        credentialConfigurationId: config.credentialConfigurationId,
        // `vct` は **walt.id が credential configuration の告知値で上書きする**ため、ここで渡しても
        // 発行される VC には載らない。受領後の照合に使う値は
        // `fetchAdvertisedVct` が告知から取る。
        //
        // **`iat` を明示する。** walt.id は credentialData に無ければ発行する SD-JWT に `iat` も
        // `nbf` も載せず、本 SDK の受領（`oid4vci/facade/decode.ts` の `toReceivedCredential`）は
        // 発行日時を必須にしているため 8020 `credential_issuance_date_missing` で落ちる。
        // `iat` は**ドライバの時刻**（walt.id は発行時刻を載せないため代替）。同一 compose 内なので
        // ずれは無視できる。受領が落ちたときにクロックずれを疑わないよう明記しておく。
        credentialData: { iat: Math.floor(Date.now() / 1000), ...config.claims },
        selectiveDisclosure: selectiveDisclosureFields(config.selectiveDisclosureClaims),
      }),
    },
    fetchImpl,
  );
  if (!ok || typeof body !== 'string' || !body.startsWith('openid-credential-offer://')) {
    throw new Error(`waltid-issuer sd-jwt offer creation failed: ${JSON.stringify(body)}`);
  }
  return {
    offerUri: body,
    issuerPublicKeyJwk: issuerSigner.publicKeyJwk,
    vct: await fetchAdvertisedVct(adminBaseUrl, body, config, fetchImpl),
  };
}
