#!/usr/bin/env bun
// test/interop/run-waltid-sdjwt.mjs
//
// walt.id issuer-api / verifier-api との **SD-JWT VC** 相互運用を実際に駆動する。
// 提示検証の JSONPath 対応を、SDK の公開 API と実ピアを使って確かめる。
//
// 駆動する 2 ペア（`pairs.json` の `waltidSdJwt.pairs`。`WALTID_SDJWT_PAIR_SUFFIX` で接尾辞を付けられる）:
//   - `interop:waltid-issuer:vericerts:sd-jwt`  walt.id が SD-JWT VC を発行 → 本 SDK が Receive + 検証
//   - `interop:vericerts:waltid-verifier:sd-jwt` 本 SDK が選択的開示つきで提示 → walt.id verifier が
//     `presentation_definition` の JSONPath（`$.vct` / `$.<claim>`）で突き合わせる
//
// 前提・TLS・公開ホスト検査の扱いは `run-waltid-protocol.mjs` と同一（同じ `waltid-driver` コンテナで
// 実行する。詳細はそちらの冒頭コメント）。walt.id の未起動・health 失敗・タイムアウトは `fail` にする
// （`skipped` にすると Issue 自動起票の対象外になり、一度も駆動されないまま Nightly が緑になる）。
// 公開ホスト検査（`lib/waltid-public-host-guard.mjs`）で拒否される場合だけ `skipped`。
// ただし**全ペアが skipped になったら両ペアを `fail` に倒す**（`lib/peer-clients.mjs` の JWT-VC 側と
// 同じガード。`failIfAllSkipped`）。全ペア skipped は実駆動されていない合図で、そのままだと起票も
// されずジョブが緑になる。
//
// 出力: `{ generatedAt, generator, results: PairResult[] }` を JSON で stdout に書く
// （`generate-report.mjs` の入力形式）。

import { readFileSync } from 'node:fs';
import { buildVPToken, parseAuthorizationRequest, submitPresentation } from 'vericerts-wallet-sdk';
import { createPrivateKeySigner, verifySdJwt } from 'vericerts-wallet-sdk/credential';
import { receiveCredential } from 'vericerts-wallet-sdk/experimental';
import { createDidKey } from 'vericerts-wallet-sdk/identity';
import { FORMAT_SD_JWT_VC, FORMAT_SD_JWT_VC_DC } from 'vericerts-wallet-sdk/oid4vp';
import { applyKnownIncompatible } from './lib/known-incompatible.mjs';
import {
  NON_PUBLIC_RESPONSE_URI_REASON,
  offerPeerUrl,
  publicHostGuardSkipReason,
} from './lib/waltid-public-host-guard.mjs';
import { createSdJwtIssuerOffer } from './lib/waltid-sdjwt-issuer-offer.mjs';
import {
  createSdJwtVerifierRequest,
  fetchPresentationDefinition,
  pollVerifierSession,
  sdJwtPresentationSubmission,
} from './lib/waltid-sdjwt-verifier-session.mjs';

const CONFIG = JSON.parse(readFileSync(new URL('./pairs.json', import.meta.url), 'utf8'));
const CA_CERT = readFileSync(new URL('./waltid/tls/ca-cert.pem', import.meta.url), 'utf8');

/** `test/interop/waltid/tls/` の自己署名 CA を信頼させる `fetchImpl`（Bun 専用の `tls.ca`）。 */
function tlsTrustingFetch(input, init) {
  return fetch(input, { ...init, tls: { ca: CA_CERT } });
}

/** Holder（本 SDK 側）の Ed25519 鍵を都度生成する（`run-waltid-protocol.mjs` と同じ作法）。 */
function createHolder() {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const signer = createPrivateKeySigner(seed, 'EdDSA');
  const publicKey = Buffer.from(signer.publicKeyJwk.x, 'base64url');
  const did = createDidKey('Ed25519', publicKey).id;
  const keyId = `${did}#${did.slice('did:key:'.length)}`;
  return { signer: { ...signer, kid: keyId }, did, keyId };
}

/** ペア名（`pairs.json` の設定 + 新版検知 job が渡す接尾辞）。 */
function pairNames(config, suffix) {
  return { issue: `${config.pairs.issue}${suffix}`, present: `${config.pairs.present}${suffix}` };
}

const reasonOf = (error) => String(error?.message ?? error);
const now = () => new Date().toISOString();

/**
 * 全ペアが `skipped` なら両ペアを `fail` に倒す（`lib/peer-clients.mjs` の JWT-VC 側と同形・同趣旨）。
 *
 * 同梱構成は公開ホスト検査を通る FQDN で実駆動するので、全ペアが skipped なのは walt.id の
 * `baseUrl` が公開ホスト検査を通らない名前へ退行した（公開ホスト検査で駆動前にスキップした）合図。skipped の
 * ままだと Issue 自動起票の対象外で、Offer→Receive→Present が一度も走らないまま Nightly が緑になる。
 * SD-JWT 経路は `run-peer-matrix.mjs` / `lib/peer-clients.mjs` を経由せず `docker compose run` で直接起動するため、このガードをランナー自身が持つ必要がある。とくに非ゲートの
 * `waltid-sdjwt-next` は mutable tag の新版を回すので、「新版が `baseUrl` 設定を無視する」という
 * 最もありがちな退行がちょうどこの形で無言化し、新版の退行を検知できなくなる。
 */
function failIfAllSkipped(results) {
  if (!results.every((result) => result.status === 'skipped')) {
    return results;
  }
  const reason = `walt.id SD-JWT の全ペアが skipped になった（実駆動されていない）: ${results
    .map((result) => result.reason)
    .join(' / ')}`;
  // `causedBy` は落とさない — 落とすと、全ペア skipped から fail へ上げたときに
  // 同じ原因の Issue が 2 件起票される。
  return results.map((result) => ({ ...result, status: 'fail', reason }));
}

/**
 * 出力の共通エンベロープ（レポートの「生成」欄にどのランナーの結果かを出す）。
 *
 * `knownIncompatible` の適用は他のランナーと同じ分類規則（登録どおりの理由の fail だけを
 * `known-incompatible`、想定外の pass は `unexpected-pass` の fail、登録外の理由の fail は fail
 * のまま。`lib/known-incompatible.mjs`）。現時点で SD-JWT のペアは登録していないため実質 no-op だが、
 * 登録したときに他ランナーと挙動が食い違わないよう経路は通しておく。
 */
function output(results, knownIncompatible) {
  return {
    generatedAt: now(),
    generator: 'test/interop/run-waltid-sdjwt.mjs',
    results: applyKnownIncompatible(failIfAllSkipped(results), knownIncompatible),
  };
}

/**
 * walt.id が発行した SD-JWT VC を Receive し、本 SDK で検証する（1 ペア目）。
 *
 * 公開ホスト検査で Offer が拒否された場合だけ `skipped` を返す。`receiveCredential` の
 * `verifyReceived` に `verifySdJwt` を渡し、Issuer 署名・`vct` 一致・Disclosure の digest 照合まで
 * 通ったものだけを受領成功とする（受け取れただけを pass にしない）。
 */
async function receiveFromWaltid(config, holder, deps) {
  const { offerUri, issuerPublicKeyJwk, vct } = await deps.createIssuerOfferImpl(
    deps.adminFetchImpl,
    config,
  );
  const skipReason = publicHostGuardSkipReason(offerPeerUrl(offerUri), 'credential offer');
  if (skipReason !== undefined) {
    return { skipReason };
  }
  const received = await deps.receiveCredentialImpl(offerUri, {
    signer: holder.signer,
    holderDid: holder.did,
    keyId: holder.keyId,
    // walt.id の credential configuration の format は `dc+sd-jwt`。旧識別子 `vc+sd-jwt` で送ると
    // `findMatchingIssuanceRequest` の format 突合で HTTP 400 `Format does not match` になる。
    format: FORMAT_SD_JWT_VC_DC,
    fetchImpl: deps.fetchImpl,
    verifyReceived: (raw) => {
      deps.verifySdJwtImpl(raw, { issuerKey: issuerPublicKeyJwk, expectedVct: vct });
    },
  });
  return { received, vct };
}

/**
 * 保持した SD-JWT VC を選択的開示つきで walt.id verifier へ提示する（2 ペア目）。
 *
 * `buildVPToken` が `disclosedClaims` のみを開示した提示部へ KB-JWT（`nonce` = 要求の nonce、
 * `aud` = client_id）を付ける。`presentation_submission` は SD-JWT 用に明示して組む
 * （SDK の既定構築は JWT-VP 専用。`lib/waltid-sdjwt-verifier-session.mjs` 参照）。
 */
async function presentToWaltid(config, holder, received, vct, deps) {
  const requestUri = await deps.createVerifierRequestImpl(deps.adminFetchImpl, config, vct);
  let request;
  try {
    request = parseAuthorizationRequest(requestUri);
  } catch (error) {
    // SDK が `response_uri` を公開ホスト検査で拒否した（`baseUrl` の退行）。ピア側の非互換では
    // ないので fail ではなく skipped。
    if (error?.context?.reason === NON_PUBLIC_RESPONSE_URI_REASON) {
      return {
        skipReason: `response_uri is rejected by SDK public-host guard (${NON_PUBLIC_RESPONSE_URI_REASON})`,
      };
    }
    throw error;
  }
  const vpToken = deps.buildVPTokenImpl(request, [
    {
      format: FORMAT_SD_JWT_VC,
      sdJwt: received.raw,
      disclosedClaims: config.disclosedClaims,
      signer: holder.signer,
    },
  ]);
  const presentationDefinition = await deps.fetchPresentationDefinitionImpl(
    requestUri,
    deps.fetchImpl,
  );
  const requestWithDefinition =
    presentationDefinition === undefined ? request : { ...request, presentationDefinition };
  await deps.submitPresentationImpl(requestWithDefinition, vpToken, {
    fetchImpl: deps.submitFetchImpl,
    presentationSubmission: sdJwtPresentationSubmission(
      presentationDefinition,
      config.inputDescriptorId,
    ),
  });
  return await deps.pollVerifierSessionImpl(requestUri, { fetchImpl: deps.adminFetchImpl });
}

/**
 * SD-JWT VC の発行 → 受領 → 提示 → 検証を 1 サイクル駆動する。各依存は既定で実装本体を使うが、
 * `__tests__/sd-jwt/` の回帰テストはプロトコル分岐（Offer→Receive 失敗時の扱い、verified
 * true/false → pass/fail、walt.id 未起動・タイムアウトが fail になること）を単体で検証するために
 * モックへ差し替える。
 */
export async function run({
  config = CONFIG.waltidSdJwt,
  knownIncompatible = CONFIG.knownIncompatible,
  pairSuffix = process.env.WALTID_SDJWT_PAIR_SUFFIX ?? '',
  fetchImpl = tlsTrustingFetch,
  adminFetchImpl = fetch,
  createIssuerOfferImpl = createSdJwtIssuerOffer,
  createVerifierRequestImpl = createSdJwtVerifierRequest,
  fetchPresentationDefinitionImpl = fetchPresentationDefinition,
  pollVerifierSessionImpl = pollVerifierSession,
  receiveCredentialImpl = receiveCredential,
  buildVPTokenImpl = buildVPToken,
  submitPresentationImpl = submitPresentation,
  verifySdJwtImpl = verifySdJwt,
  createHolderImpl = createHolder,
} = {}) {
  const pairs = pairNames(config, pairSuffix);
  const holder = createHolderImpl();
  // SDK は送信失敗（非 2xx・通信失敗・リダイレクト）をすべて 8035 に畳み、HTTP ステータスを
  // 読めるようにしない。ステータスだけ reason に添え、walt.id の拒否（400）を 5xx・通信失敗と
  // 区別できるようにする。
  let submitStatus;
  const deps = {
    adminFetchImpl,
    fetchImpl,
    createIssuerOfferImpl,
    createVerifierRequestImpl,
    fetchPresentationDefinitionImpl,
    pollVerifierSessionImpl,
    receiveCredentialImpl,
    buildVPTokenImpl,
    submitPresentationImpl,
    verifySdJwtImpl,
    submitFetchImpl: async (input, init) => {
      const response = await fetchImpl(input, init);
      submitStatus = response.status;
      return response;
    },
  };

  const results = [];
  let received;
  let receivedVct;
  try {
    const outcome = await receiveFromWaltid(config, holder, deps);
    if (outcome.skipReason !== undefined) {
      return output(
        [
          { pair: pairs.issue, status: 'skipped', reason: outcome.skipReason },
          {
            pair: pairs.present,
            status: 'skipped',
            reason: 'skipped: Offer → Receive をスキップしたため提示する SD-JWT VC が無い',
            causedBy: pairs.issue,
          },
        ],
        knownIncompatible,
      );
    }
    received = outcome.received;
    // 提示要求の `vct`（JSONPath `$.vct` の pattern）も walt.id の告知値に合わせる。
    receivedVct = outcome.vct;
    results.push({ pair: pairs.issue, status: 'pass' });
  } catch (error) {
    return output(
      [
        { pair: pairs.issue, status: 'fail', reason: reasonOf(error) },
        {
          pair: pairs.present,
          status: 'fail',
          reason: 'skipped: Offer → Receive が先に失敗し提示する SD-JWT VC が無い',
          // 先行ペア（issue）の失敗の巻き添え。同根なので別 Issue にしない。
          // status を fail のままにする理由は `failIfAllSkipped` の注釈と同じ。
          causedBy: pairs.issue,
        },
      ],
      knownIncompatible,
    );
  }

  try {
    const outcome = await presentToWaltid(config, holder, received, receivedVct, deps);
    if (outcome.skipReason !== undefined) {
      results.push({ pair: pairs.present, status: 'skipped', reason: outcome.skipReason });
    } else {
      results.push({
        pair: pairs.present,
        status: outcome.verified ? 'pass' : 'fail',
        reason: outcome.verified ? undefined : (outcome.reason ?? '検証が verified=false を返した'),
      });
    }
  } catch (error) {
    const detail = submitStatus === undefined ? '' : ` (HTTP ${submitStatus})`;
    results.push({ pair: pairs.present, status: 'fail', reason: `${reasonOf(error)}${detail}` });
  }

  return output(results, knownIncompatible);
}

// Bun 専用の実行時エントリポイントガード。`__tests__/sd-jwt/` が本モジュールを import するとき、
// 副作用（実際の walt.id への通信）が走らないようにする。
if (import.meta.main) {
  const result = await run();
  console.log(JSON.stringify(result, null, 2));
  if (result.results.some((r) => r.status === 'fail')) {
    process.exitCode = 1;
  }
}
