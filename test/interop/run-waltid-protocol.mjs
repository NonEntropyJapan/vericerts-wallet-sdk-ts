#!/usr/bin/env bun
// test/interop/run-waltid-protocol.mjs
//
// walt.id issuer-api / verifier-api の OID4VCI/OID4VP プロトコル層を実際に駆動する。
// 同じ SDK パッケージの公開 API を使い、Offer → Receive → Present を 1 サイクル駆動する。
//
// 前提: `docker compose -f test/interop/docker-compose.yml up -d waltid-issuer waltid-verifier
// waltid-tls-proxy` 済みで、本スクリプトは同じ compose ネットワーク内の `waltid-driver` サービス
// （`docker compose run waltid-driver`。`run-peer-matrix.mjs` が呼ぶ）で実行すること。
// ホストから直接実行しても、walt.id の `baseUrl` の FQDN（`*.waltid.interop.example`）は compose の
// network alias でしか解決できず、管理系 URL も compose 内部のものなので動かない。
// walt.id の Docker イメージは平文 HTTP でしか話さないが、
// 本 SDK の Holder クライアントは `credential_offer_uri` / `credential_issuer`（OID4VCI）・
// `response_uri`（OID4VP）に HTTPS **かつ公開ホスト**（`isPublicHttpsUrl`。ループバック・プライベート・
// `localhost` 系を拒否）を要求し、ローカル開発向けの例外を設けない。
// `test/interop/nginx/waltid-tls-proxy.conf` がテスト専用 CA 署名の証明書（`test/interop/waltid/tls/`、
// 非秘匿のテスト専用鍵）で TLS 終端したアドレス（issuer: 8097 / verifier: 8098）を経由し、walt.id の
// `baseUrl`（`test/interop/waltid/{issuer,verifier}-config/`）は公開ホスト検査を通る FQDN
// （`https://{issuer,verifier}.waltid.interop.example:…`）にしてある。
// `baseUrl` が公開ホスト検査を通らない名前へ退行した場合の安全網として、offer は駆動前に同じ検査
// （SDK の `isPublicHttpsUrl`）を当て、`response_uri` は SDK のパースが返す `non_public_response_uri`
// を検出して、拒否されるペアは fail ではなく
// `skipped`（理由付き）として報告する（fail のままだと Nightly が毎晩同じ Issue を起票し続け、
// 本物の退行と区別できない）。退行は `__tests__/waltid-public-host-config.test.mjs` が PR 時点で検知する。
//
// 出力: `run-peer-matrix.mjs` と同じ `PairResult`（`{ pair, status, reason? }`）の配列を JSON で
// stdout に書く。対象のペア名:
//   - `interop:waltid-issuer:vericerts`（Offer → Receive）
//   - `interop:vericerts:waltid-verifier`（→ Present）

import { readFileSync } from 'node:fs';
import {
  buildVPToken,
  FORMAT_JWT_VC,
  parseAuthorizationRequest,
  submitPresentation,
} from 'vericerts-wallet-sdk';
import { createPrivateKeySigner, verifyCredential } from 'vericerts-wallet-sdk/credential';
import { receiveCredential } from 'vericerts-wallet-sdk/experimental';
import { createDidKey } from 'vericerts-wallet-sdk/identity';
import { fetchJson } from './lib/waltid-admin-api.mjs';
import { createIssuerOffer } from './lib/waltid-issuer-offer.mjs';
import {
  NON_PUBLIC_RESPONSE_URI_REASON,
  offerPeerUrl,
  publicHostGuardSkipReason,
} from './lib/waltid-public-host-guard.mjs';
import {
  createVerifierRequest,
  fetchPresentationDefinition,
  pollVerifierSession,
} from './lib/waltid-verifier-session.mjs';

// issuer / verifier の管理系呼び出しは Linterly の 1 ファイル 300 行上限のため `lib/` へ分割した。
// 回帰テストと呼び出し側が従来どおり本モジュールから import できるよう再 export する。
export { createIssuerOffer, createVerifierRequest, fetchJson, pollVerifierSession };

const CA_CERT = readFileSync(new URL('./waltid/tls/ca-cert.pem', import.meta.url), 'utf8');

/** `test/interop/waltid/tls/` の自己署名 CA を信頼させる `fetchImpl`（Bun 専用の `tls.ca`）。 */
function tlsTrustingFetch(input, init) {
  return fetch(input, { ...init, tls: { ca: CA_CERT } });
}

/** Holder（本 SDK 側）の Ed25519 鍵を都度生成する。他ピアと異なり事前に知られる必要が無い。 */
function createHolder() {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const signer = createPrivateKeySigner(seed, 'EdDSA');
  const publicKey = Buffer.from(signer.publicKeyJwk.x, 'base64url');
  const did = createDidKey('Ed25519', publicKey).id;
  const keyId = `${did}#${did.slice('did:key:'.length)}`;
  // `buildVPToken` は `signer.kid` を JWT-VP のヘッダへ載せる。walt.id verifier は `kid` で holder の鍵を
  // 解決して VP の署名を検証するため、無いと `Missing key ID in JWS header` で拒否する。
  return { signer: { ...signer, kid: keyId }, did, keyId };
}

/**
 * Offer → Receive → Present を 1 サイクル駆動する。各依存は既定で実装本体を使うが、
 * `__tests__/run-waltid-protocol.test.mjs` はプロトコル分岐（Offer→Receive 失敗時の Present
 * スキップ、verified true/false → pass/fail のマッピング、例外の reason 化）を単体で検証する
 * ためにモックへ差し替える。
 */
export async function run({
  fetchImpl = tlsTrustingFetch,
  adminFetchImpl = fetch,
  createIssuerOfferImpl = createIssuerOffer,
  createVerifierRequestImpl = createVerifierRequest,
  fetchPresentationDefinitionImpl = fetchPresentationDefinition,
  pollVerifierSessionImpl = pollVerifierSession,
  receiveCredentialImpl = receiveCredential,
  buildVPTokenImpl = buildVPToken,
  submitPresentationImpl = submitPresentation,
  createHolderImpl = createHolder,
} = {}) {
  const results = [];
  const holder = createHolderImpl();

  // Offer → Receive
  let received;
  try {
    const { offerUri, issuerPublicKeyJwk } = await createIssuerOfferImpl(adminFetchImpl);
    const skipReason = publicHostGuardSkipReason(offerPeerUrl(offerUri), 'credential offer');
    if (skipReason !== undefined) {
      return {
        generatedAt: new Date().toISOString(),
        results: [
          { pair: 'interop:waltid-issuer:vericerts', status: 'skipped', reason: skipReason },
          {
            pair: 'interop:vericerts:waltid-verifier',
            status: 'skipped',
            reason: 'skipped: Offer → Receive をスキップしたため提示する VC が無い',
            causedBy: 'interop:waltid-issuer:vericerts',
          },
        ],
      };
    }
    received = await receiveCredentialImpl(offerUri, {
      signer: holder.signer,
      holderDid: holder.did,
      keyId: holder.keyId,
      format: FORMAT_JWT_VC,
      fetchImpl,
      verifyReceived: (raw) => {
        verifyCredential(raw, { key: { publicKeyJwk: issuerPublicKeyJwk } });
      },
    });
    results.push({ pair: 'interop:waltid-issuer:vericerts', status: 'pass' });
  } catch (error) {
    results.push({
      pair: 'interop:waltid-issuer:vericerts',
      status: 'fail',
      reason: String(error?.message ?? error),
    });
    // 提示まで進めなかった場合は、先行する issuer ペアを失敗の原因として記録する。
    // status は fail のままにする — skipped に落とすとジョブが緑になり、
    // `--fail-on-skipped` のゲートや「全ペア skipped は fail」判定とも矛盾する。
    results.push({
      pair: 'interop:vericerts:waltid-verifier',
      status: 'fail',
      reason: 'skipped: Offer → Receive が先に失敗した',
      causedBy: 'interop:waltid-issuer:vericerts',
    });
    return { generatedAt: new Date().toISOString(), results };
  }

  // → Present
  let submitStatus;
  const statusRecordingFetch = async (input, init) => {
    const response = await fetchImpl(input, init);
    submitStatus = response.status;
    return response;
  };
  try {
    const requestUri = await createVerifierRequestImpl(adminFetchImpl);
    let request;
    try {
      request = parseAuthorizationRequest(requestUri);
    } catch (error) {
      // SDK が `response_uri` を公開ホスト検査（`isPublicHttpsUrl`）で拒否した（`baseUrl` が公開ホスト検査を
      // 通らない名前へ退行した場合）。ピア側の退行ではないので fail ではなく skipped。
      if (error?.context?.reason === NON_PUBLIC_RESPONSE_URI_REASON) {
        results.push({
          pair: 'interop:vericerts:waltid-verifier',
          status: 'skipped',
          reason: `response_uri is rejected by SDK public-host guard (${NON_PUBLIC_RESPONSE_URI_REASON})`,
        });
        return { generatedAt: new Date().toISOString(), results };
      }
      throw error;
    }
    const vpToken = buildVPTokenImpl(request, [
      {
        format: FORMAT_JWT_VC,
        holder: holder.did,
        verifiableCredentials: [received.raw],
        signer: holder.signer,
      },
    ]);
    // walt.id は Presentation Definition を URI 参照で告知する。取得して載せると、`submitPresentation` が
    // `presentation_submission` を構築して送る（欠落すると walt.id は 400 で拒否する）。
    const presentationDefinition = await fetchPresentationDefinitionImpl(requestUri, fetchImpl);
    const requestWithDefinition =
      presentationDefinition === undefined ? request : { ...request, presentationDefinition };
    await submitPresentationImpl(requestWithDefinition, vpToken, {
      fetchImpl: statusRecordingFetch,
    });
    const { verified, reason } = await pollVerifierSessionImpl(requestUri, {
      fetchImpl: adminFetchImpl,
    });
    results.push({
      pair: 'interop:vericerts:waltid-verifier',
      status: verified ? 'pass' : 'fail',
      reason: verified ? undefined : (reason ?? '検証が verified=false を返した'),
    });
  } catch (error) {
    // SDK は送信失敗（非 2xx・通信失敗・リダイレクト）をすべて同じ 8035 に畳み、応答の本文も HTTP
    // ステータスも読まない。ステータスだけ reason に添え、`pairs.json` の `reasonIncludes` で既知の非互換
    // （400）を 5xx・通信失敗と区別できるようにする。
    const detail = submitStatus === undefined ? '' : ` (HTTP ${submitStatus})`;
    results.push({
      pair: 'interop:vericerts:waltid-verifier',
      status: 'fail',
      reason: `${String(error?.message ?? error)}${detail}`,
    });
  }

  return { generatedAt: new Date().toISOString(), results };
}

// Bun 専用の実行時エントリポイントガード。`__tests__/run-waltid-protocol.test.mjs` が本モジュールを
// import するとき、副作用（実際の walt.id への通信）が走らないようにする。
if (import.meta.main) {
  const output = await run();
  console.log(JSON.stringify(output, null, 2));
  const failed = output.results.filter((r) => r.status === 'fail');
  if (failed.length > 0) {
    process.exitCode = 1;
  }
}
