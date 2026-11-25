/**
 * EUDI PID / (Q)EAA の受領フロー（OID4VCI Pre-Authorized Code Flow）。
 *
 * 本モジュールは Wallet facade（`receivePID` / `receiveEAA`）が組み立てられるだけの内部関数を
 * 提供する。ファサード（`receivePID` / `receiveEAA`）への配線は `wallet/eudi/facade.ts` が担う。
 *
 * 受領は次の 1 本道で、PID と (Q)EAA の違いは**要求する vct と受領後の検証だけ**である。
 * したがって通信部（手順 1〜7）を単一のヘルパーへ括り、分岐は「どの vct を要求するか」の
 * 1 関数に閉じ込める。両者で通信部が二重化すると、片方だけ HTTPS 検査や deferred 拒否が
 * 抜ける事故が起き得るため。
 *
 * 1. Credential Offer URI を解析する（`parseCredentialOffer`）。
 * 2. pre-authorized_code grant を取り出す（**本スコープはこの grant のみ**。無ければ 3003）。
 * 3. Issuer Metadata から Credential / Nonce エンドポイントを解決する（`fetchIssuerMetadata`）。
 *    Token Endpoint は Authorization Server の Metadata（RFC 8414）から引く（`resolveTokenEndpoint`）。
 * 4. access_token を取得する（`requestTokenPreAuthorized`。WUA 添付は任意で、
 *    `client_assertion` は解決済み Token Endpoint を `aud` として**この地点で**組み立てる）。
 * 5. JWT Proof を生成する（`generateProofJWT`）。`nonce` は Token Response の `c_nonce` → Nonce Endpoint →
 *    省略の順、`aud` は Credential Issuer Identifier。
 * 6. Credential Endpoint から SD-JWT VC（`dc+sd-jwt`）を受領する（`requestCredential`）。
 * 7. 遅延発行（deferred）応答は本スコープ未対応として 8020 で拒否する。
 * 8. 受領した SD-JWT を解釈し（`decode.ts`）、PID は Rulebook 検証、(Q)EAA は Catalogue 解決を行う。
 *
 * **Authorization Code Flow は対象外。** Offer に pre-authorized_code grant が無い場合は
 * 別グラントへ暗黙にフォールバックせず `OFFER_URI_PARSE_FAILED`（3003）で fail-closed に落とす。
 * 未対応グラントを黙って無視すると、grant を差し替えた Offer で意図しない認可経路へ誘導できる。
 *
 * 呼び出し側入力（`ReceiveDeps`）の読み取り・検証は `deps.ts`、受領した SD-JWT の解釈と
 * Rulebook 違反のエラー写像は `decode.ts` が担う。
 *
 * セキュリティ上の注意:
 * - `deps` のフィールドは分割代入せず、`deps.ts` が 1 回だけ読んだ値だけを使う。特に
 *   `fetchImpl` を鎖で読むと、DI を**省略した**正当な呼び出しが攻撃者の fetch へ委譲され、
 *   Bearer access_token と受領 VC ごと渡る。
 * - 下流へ渡すオプションには `fetchImpl` を**常に own プロパティとして**載せる（値が
 *   `undefined` でも載せる）。載せずに省略すると、下流の `resolveInjectedFetch` が
 *   そのリテラルのプロトタイプ鎖を辿って `Object.prototype.fetchImpl` を掴む。
 * - 例外の `context` は固定識別子のみ。URL・本文・JWT・クレーム値・`cause` を載せない。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import type {
  AttestationCatalogueSource,
  EAACredential,
  PIDClaims,
  PIDCredential,
} from '../../../eudi/pid/index.js';
import { PID_VCT, resolveAttestationCatalogue } from '../../../eudi/pid/index.js';
import { isNonBlankString } from '../../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { FORMAT_SD_JWT_VC_DC } from '../../matcher.js';
import { resolveCredentialVct } from '../../oid4vci/facade/credential-definition.js';
import type { CredentialOffer } from '../../oid4vci/offer/oid4vci-offer.js';
import {
  PRE_AUTHORIZED_CODE_GRANT,
  parseCredentialOffer,
} from '../../oid4vci/offer/oid4vci-offer.js';
import { generateProofJWT, requestCredential } from '../../oid4vci/oid4vci.js';
import { resolveProofNonce } from '../../oid4vci/oid4vci-proof-nonce.js';
import { requestTokenPreAuthorized } from '../../oid4vci/token/oid4vci-token.js';
import { resolvePreAuthorizedTokenEndpoint } from '../../oid4vci/token/oid4vci-token-endpoint.js';
import { assertPIDSchemaValid, decodeReceivedCredential } from './decode.js';
import type { ResolvedDeps } from './deps.js';
import { resolveReceiveDeps } from './deps.js';
import { assertIssuerAllowed } from './issuer-allow-list.js';
import type { IssuerEndpoints } from './metadata.js';
import { fetchIssuerMetadata } from './metadata.js';
import { requestCNonce } from './nonce.js';
import type { ReceiveDeps } from './types.js';

/** Offer 由来の失敗（3003、再試行不可）。理由は固定識別子のみ。 */
function offerFailure(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED, { context: { reason } });
}

/** VC 受領の失敗（8020、再試行不可）。理由は固定識別子のみ。 */
function credentialFailure(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED, { context: { reason } });
}

/**
 * Offer から pre-authorized_code grant を取り出す。
 *
 * `grants` → grant → `pre-authorized_code` の**各段を own 限定**（`ownProperty`）で読む。
 * 鎖読みだと、grants を持たない Offer が `Object.prototype.grants` の汚染値を拾い、
 * 攻撃者の pre-authorized_code で Token Request が成立する（fail-open）。
 * `parseCredentialOffer` は grant の有無を許容するため、ここが唯一の fail-closed 地点である。
 *
 * @param offer 解析済み Credential Offer。
 * @returns pre-authorized_code と grant 本体（`authorization_server` の読み出しに使う）。
 * @throws pre-authorized_code grant が無い / 空の場合（VericertsError、code `3003`）。
 */
function extractPreAuthorizedGrant(offer: CredentialOffer): { code: string; grant: object } {
  const grants = ownProperty<unknown>(offer, 'grants');
  if (typeof grants !== 'object' || grants === null) {
    throw offerFailure('unsupported_grant');
  }
  const grant = ownProperty<unknown>(grants, PRE_AUTHORIZED_CODE_GRANT);
  if (typeof grant !== 'object' || grant === null) {
    throw offerFailure('unsupported_grant');
  }
  const code = ownProperty<unknown>(grant, 'pre-authorized_code');
  if (!isNonBlankString(code)) {
    throw offerFailure('unsupported_grant');
  }
  return { code, grant };
}

/**
 * access_token を取得する。
 *
 * `buildClientAttestation` が指定されている場合のみ、**解決済みの Token Endpoint を `aud` として**
 * `client_assertion` を組み立て、`client_assertion` / `client_assertion_type` を付ける。組み立てを
 * ここまで遅延させるのは、WUA-PoP の `aud` を「実際に送る先」に束縛できるのがこの地点だけだから
 * である（呼び出し側が事前に組み立てると `aud` が推測値になり、PoP がリプレイ可能になる）。
 *
 * 組み立て結果は `ClientAttestation` から own 限定で読んだ値をそのまま渡す（継承値を新しい
 * リテラルへ詰め直すと、下流 `assertClientAssertionPair` が汚染値と正当な指定を区別できない）。
 * 型の無い呼び出し側がオブジェクト以外を返した場合は `as` で流さず 8010 で fail-closed に落とす。
 */
async function requestAccessToken(
  endpoints: IssuerEndpoints,
  tokenEndpoint: string,
  preAuthorizedCode: string,
  deps: ResolvedDeps,
): ReturnType<typeof requestTokenPreAuthorized> {
  const build = deps.buildClientAttestation;
  if (build === undefined) {
    return requestTokenPreAuthorized(
      tokenEndpoint,
      {
        preAuthorizedCode,
        // 値が undefined でも own プロパティとして載せ、下流の DI 解決が汚染値を掴まないようにする。
        fetchImpl: deps.fetchImpl,
      },
      deps.metrics,
    );
  }
  // WUA-PoP の nonce には、AS が発行し、検証できる c_nonce を使う。
  // Nonce Endpoint を告知していない Issuer には、仕様に反する PoP を送らず fail-closed に倒す。
  // own 限定で読む（`metadata.ts` が常にキーを生やす対と合わせた多層防御。素の読みだと
  // `Object.prototype.nonceEndpoint` の汚染値を「告知された Nonce Endpoint」として採用しうる）。
  const nonceEndpoint = ownProperty<unknown>(endpoints, 'nonceEndpoint');
  if (!isNonBlankString(nonceEndpoint)) {
    throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED, {
      context: { reason: 'nonce_endpoint_unavailable' },
    });
  }
  const cNonce = await requestCNonce(nonceEndpoint, deps.fetchImpl);
  const attestation = build(tokenEndpoint, cNonce);
  if (typeof attestation !== 'object' || attestation === null) {
    throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED, {
      context: { reason: 'invalid_client_attestation' },
    });
  }
  // 組み立て結果は own 限定で読む。ここで読めない形（プロトタイプ上の getter で値を出す実装等）
  // をそのまま通すと、`assertClientAssertionPair` も `appendClientAssertionParams` も素通りし、
  // **`client_assertion` を付けないまま** Token Request が送られる。さらに `oid4vci-token.ts` の
  // HTTPS 必須検査は `clientAssertion !== undefined` を条件とするため同時に外れ、
  // `walletAttestation: true` の受領が無言で未認証・平文許容へダウングレードする。
  // 添付すると決めた以上、読めなければ送らずに落とす（fail-closed）。
  const clientAssertion = ownProperty<unknown>(attestation, 'clientAssertion');
  const clientAssertionType = ownProperty<unknown>(attestation, 'clientAssertionType');
  if (!isNonBlankString(clientAssertion) || !isNonBlankString(clientAssertionType)) {
    throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED, {
      context: { reason: 'invalid_client_attestation' },
    });
  }
  return requestTokenPreAuthorized(
    tokenEndpoint,
    {
      preAuthorizedCode,
      fetchImpl: deps.fetchImpl,
      clientAssertion,
      clientAssertionType,
    },
    deps.metrics,
  );
}

/**
 * Offer URI から SD-JWT VC の生文字列を受領するまでの共通フロー（手順 1〜7）。
 *
 * @param offerURI Credential Offer URI。
 * @param deps 検証済みの依存。
 * @param selectVct 要求する vct を Offer から決める関数（PID は固定、(Q)EAA は Offer 由来）。
 * @returns 受領した SD-JWT VC のコンパクト表現。
 * @throws grant 不正（code `3003`）、Metadata 取得失敗（`3004`）、Token Request 失敗（`8010`）、
 *         Credential Request 失敗・deferred 応答（`8020`）の場合（VericertsError）。
 */
async function receiveRawCredential(
  offerURI: string,
  deps: ResolvedDeps,
  selectVct: (offer: CredentialOffer) => string,
): Promise<string> {
  // 初弾（`credential_offer_uri` の GET）も後続の `fetchIssuerMetadata` と同じシームへ通す
  // （`wallet/options.ts` の「両受領経路とも `eudiFetchImpl`」契約）。
  const offer = await parseCredentialOffer(offerURI, deps.fetchImpl);
  const { code: preAuthorizedCode, grant } = extractPreAuthorizedGrant(offer);
  // 第 3 引数で `credentialVcts`（告知された `vct`）も解決させる。
  const ids = offer.credential_configuration_ids;
  const endpoints = await fetchIssuerMetadata(offer.credential_issuer, deps.fetchImpl, ids);
  // Token Endpoint は AS Metadata の `token_endpoint`（OID4VCI 1.0 §6。Issuer Metadata には無い）。
  // AS は grant の `authorization_server`（`authorization_servers` と照合）、無ければ先頭、それも無ければ
  // `credential_issuer` 自身。AS Metadata に到達できないときだけ旧 `token_endpoint` を使う。
  const { tokenEndpoint } = await resolvePreAuthorizedTokenEndpoint(
    grant,
    endpoints,
    offer.credential_issuer,
    deps.fetchImpl,
  );
  const token = await requestAccessToken(endpoints, tokenEndpoint, preAuthorizedCode, deps);
  // **EUDI 経路は常に `vct` を送る**（ARF / HAIP が SD-JWT VC を必須にするため従来形へ倒さない。
  // ファサードとの非対称の理由は `resolveCredentialVct` の JSDoc）。
  const vct = resolveCredentialVct(offer, endpoints) ?? selectVct(offer);
  const proofJwt = generateProofJWT(
    {
      nonce: await resolveProofNonce(token.cNonce, endpoints.nonceEndpoint, deps.fetchImpl),
      audience: offer.credential_issuer,
      issuer: deps.holderDid,
      keyId: deps.keyId,
    },
    deps.signer,
  );
  const result = await requestCredential({
    credentialEndpoint: endpoints.credentialEndpoint,
    accessToken: token.accessToken,
    format: FORMAT_SD_JWT_VC_DC,
    // SD-JWT VC は型を `vct` で伝える。`credentialDefinition` は 1.0 Final 形用に残す。
    vct,
    credentialDefinition: { type: [vct] },
    credentialConfigurationId: deps.finalCredentialRequest
      ? offer.credential_configuration_ids[0]
      : undefined,
    proofJwt,
    fetchImpl: deps.fetchImpl,
  });
  if (result.status === 'deferred') {
    // 遅延発行（Deferred Endpoint ポーリング）は本スコープ未対応。transaction_id は載せない。
    throw credentialFailure('deferred_not_supported');
  }
  return result.credential;
}

/**
 * PID を受領する。
 *
 * Credential Endpoint へは常に `vct=urn:eudi:pid:1` を要求し、受領した SD-JWT VC の `vct` が
 * それと一致することを確認してから ARF PID Rulebook 検証（`validatePIDSchema`）へ進む。
 * vct が異なる VC を PID として受け入れると、Rulebook 検証を通した「PID ではないもの」が
 * `PIDCredential` として下流（保管・提示）へ流れるため fail-closed に落とす。
 *
 * @param offerURI `openid-credential-offer://` 形式の Credential Offer URI。
 * @param deps 署名鍵・Holder DID / kid・HTTP シーム・Wallet Attestation。
 * @returns 受領・検証済みの PID Credential（`raw` に元の SD-JWT を保持する）。
 * @throws grant 不正（code `3003`）、Metadata 取得失敗（`3004`）、Token Request 失敗（`8010`）、
 *         Credential Request 失敗・deferred・復号失敗（`8020`）、必須属性欠落（`10002`）、
 *         スキーマ / vct 違反（`10001`）の場合（VericertsError）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export async function receivePIDCredential(
  offerURI: string,
  deps: ReceiveDeps,
): Promise<PIDCredential> {
  const resolved = resolveReceiveDeps(deps);
  const raw = await receiveRawCredential(offerURI, resolved, () => PID_VCT);
  const decoded = decodeReceivedCredential(raw);
  const vct = decoded.vct;
  if (vct !== PID_VCT) {
    // vct 不一致は「必須属性の欠落」ではなくスキーマ違反（10001）。`decode.ts` の写像と同じ根拠。
    throw new VericertsError(ErrorCodes.PID_SCHEMA_INVALID, {
      context: { reason: 'vct_mismatch' },
    });
  }
  // `vct` は上の比較で `typeof PID_VCT` に絞り込まれている（`PIDCredential.vct` はリテラル型）。
  const pid: PIDCredential = { vct, claims: decoded.claims as PIDClaims, raw };
  assertPIDSchemaValid(pid);
  return pid;
}

/**
 * (Q)EAA を受領する。
 *
 * 要求する vct は Offer の `credential_configuration_ids[0]`（Issuer Metadata の
 * `credential_configurations_supported` のキー）とし、Catalogue 解決は**受領した VC を解釈して
 * vct が確定してから**行う。要求時の configuration id と発行された VC の `vct` は必ずしも一致せず、
 * 未登録の型を掴まされていないかは受領後の値で判定しなければ意味がないため。
 *
 * @param offerURI `openid-credential-offer://` 形式の Credential Offer URI。
 * @param source 取得済み (Q)EAA Catalogue の参照源。
 * @param deps 署名鍵・Holder DID / kid・HTTP シーム・Wallet Attestation。
 * @returns 受領した (Q)EAA Credential（`raw` に元の SD-JWT を保持する）。
 * @throws grant 不正（code `3003`）、Metadata 取得失敗（`3004`）、Token Request 失敗（`8010`）、
 *         Credential Request 失敗・deferred・復号失敗・vct 欠落（`8020`）、
 *         Catalogue 未登録（`10003`）、Catalogue の `issuerAllowList` 外の Issuer（`8020`、
 *         `reason: 'issuer_not_allowed'`）の場合（VericertsError）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export async function receiveEAACredential(
  offerURI: string,
  source: AttestationCatalogueSource,
  deps: ReceiveDeps,
): Promise<EAACredential> {
  const resolved = resolveReceiveDeps(deps);
  const raw = await receiveRawCredential(offerURI, resolved, (offer) => {
    // `parseCredentialOffer` が非空配列を保証するが、`as` で流さず明示的に fail-closed にする。
    const configurationId = offer.credential_configuration_ids[0];
    if (!isNonBlankString(configurationId)) {
      throw offerFailure('missing_configuration_id');
    }
    return configurationId;
  });
  const decoded = decodeReceivedCredential(raw);
  const vct = decoded.vct;
  if (!isNonBlankString(vct)) {
    throw credentialFailure('missing_vct');
  }
  // Catalogue 未登録は 10003（`resolveAttestationCatalogue` が投げる）。`schemaUrl` による
  // JSON Schema 検証は別スコープ。
  const entry = resolveAttestationCatalogue(source, vct);
  assertIssuerAllowed(entry, decoded.iss);
  return { vct, claims: decoded.claims, raw };
}
