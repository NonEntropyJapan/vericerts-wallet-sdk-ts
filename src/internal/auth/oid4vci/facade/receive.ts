/**
 * ファサード `receiveCredential(offerURI)`。
 *
 * Offer URI から Metadata を取得し、選んだ grant の発行フローを実行する。
 *
 * 1. Offer URI をパースする（`parseCredentialOffer`）
 * 2. Issuer Metadata を引く（`fetchIssuerMetadata`。`token_endpoint` は必須でない）
 * 3. grant を判別する（`authorization_code` / `pre-authorized_code`）
 * 4. `authorization_code` なら AS Metadata を引き（`fetchAuthorizationServerMetadata`。
 *    `token_endpoint` もここから取る）、4 エンドポイントを揃えて `receiveCredentialViaAuthorizationCode`
 *    へ委譲する
 * 5. `pre-authorized_code` なら AS Metadata の `token_endpoint` へ Token → JWT Proof → Credential を
 *    直接繋ぐ
 * 6. 受領した生 VC を `ReceivedVerifiableCredential` に変換して返す（`toReceivedCredential`）
 *
 * **grant の優先順位は `authorization_code` が先である。** 両方を告知する Offer は、ユーザー認証を
 * 伴う認可（Issuer が属性を確認してから発行する）を意図しているとみなす。pre-authorized_code を
 * 優先すると、Issuer が認可を要求しているのに Wallet が認可を省いた経路を選ぶことになる。
 *
 * スコープ外（別モジュール／別フェーズの責務）:
 * - **受領した VC の署名検証は既定で行わない。** `deps.verifyReceived` を渡した場合のみ実行し、
 *   署名不一致相当の throw を `3010` へ正規化する（`3010` 以外の `VericertsError` は元のコード）。Issuer 鍵の解決（DID 解決 / `x5c` /
 *   Trust Anchor）は本モジュールが持たない依存だからである。**これは内部プリミティブ層の契約で
 *   あって Wallet 層の契約ではない** — `wallet.receiveCredential`も
 *   `wallet.receivePID` / `wallet.receiveEAA`も、`Wallet` が持つ DID Resolver で
 *   既定検証を行う（規則の実体は `wallet/issuer-trust/received-signature.ts`）。同じ層の内部プリミティブ
 *   （`requestCredential` / `receivePIDCredential` / `receiveEAACredential`）も本モジュールと
 *   同様に検証せず、呼び出し側（= Wallet 層）の責務としている。
 * - 遅延発行のポーリング。`{ status: 'deferred' }` は `VerifiableCredential` を
 *   返せないため `8020`（`reason: 'deferred_not_supported'`）へ倒す（`eudi/issuance/receive.ts` と同じ）。
 * - 永続化（Storage への保存）。返した `raw` を呼び出し側が保存する。
 *
 * セキュリティ上の注意:
 * - Offer は**攻撃者が影響し得る入力**である。`grants` とその中身は own 限定で読む（鎖読みだと
 *   grant を持たない Offer が `Object.prototype` の汚染値を拾い、攻撃者の `pre-authorized_code`
 *   で Token Request が成立する）。
 * - 4 エンドポイントの HTTPS は Metadata 取得側（`metadata.ts` / `oid4vci-as-metadata.ts`）と
 *   `receiveCredentialViaAuthorizationCode` の入口の二重で課される。
 * - 例外の `context` は固定識別子のみ。Offer・認可コード・access_token・VC 本文は載せない。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { fetchIssuerMetadata, type IssuerEndpoints } from '../../eudi/issuance/metadata.js';
import { receiveCredentialViaAuthorizationCode } from '../authz-flow/receive.js';
import { dpopProofRebuilder } from '../dpop-nonce/index.js';
import { resolveAuthorizationServer } from '../identifier/authorization-server.js';
import {
  AUTHORIZATION_CODE_GRANT,
  type AuthorizationCodeGrant,
  type CredentialOffer,
  PRE_AUTHORIZED_CODE_GRANT,
  parseCredentialOffer,
} from '../offer/oid4vci-offer.js';
import { generateProofJWT, requestCredential } from '../oid4vci.js';
import { fetchAuthorizationServerMetadata } from '../oid4vci-as-metadata.js';
import { credentialRequestDpop } from '../oid4vci-credential-dpop.js';
import { resolveProofNonce } from '../oid4vci-proof-nonce.js';
import { requestTokenPreAuthorized } from '../token/oid4vci-token.js';
import { resolvePreAuthorizedTokenEndpoint } from '../token/oid4vci-token-endpoint.js';
import {
  resolveCredentialConfigurationId,
  resolveCredentialDefinitionType,
  resolveCredentialVct,
} from './credential-definition.js';
import { toReceivedCredential } from './decode.js';
import { facadeFailure, type ResolvedReceiveDeps, resolveReceiveCredentialDeps } from './deps.js';
import type { ReceiveCredentialDeps, ReceivedVerifiableCredential } from './types.js';
import { preservedVerifyFailure } from './verify-failure.js';

/** Offer の `grants` を own 限定で読む（未告知なら `undefined`）。 */
function grantsOf(offer: CredentialOffer): object | undefined {
  const grants = ownProperty<unknown>(offer, 'grants');
  return typeof grants === 'object' && grants !== null ? grants : undefined;
}

/**
 * `authorization_code` 経路。AS Metadata を引いて 4 エンドポイントを揃え、
 * `receiveCredentialViaAuthorizationCode` へ委譲する。
 */
async function viaAuthorizationCode(
  offer: CredentialOffer,
  grant: AuthorizationCodeGrant,
  issuer: IssuerEndpoints,
  deps: ResolvedReceiveDeps,
): Promise<string> {
  // 認可 UI・`client_id`・`redirect_uri` はこの経路でのみ必須。未指定を「認可をスキップする」と
  // 解釈すると、ユーザーの同意も認可コードも無いまま Token Request へ進む経路が生まれる。
  if (deps.authorize === undefined) {
    throw facadeFailure('missing_authorize');
  }
  if (deps.clientId === undefined || deps.redirectUri === undefined) {
    throw facadeFailure('missing_client_registration');
  }
  const as = resolveAuthorizationServer(
    grant,
    issuer.authorizationServers,
    offer.credential_issuer,
  );
  const asEndpoints = await fetchAuthorizationServerMetadata(as, deps.fetchImpl);
  const result = await receiveCredentialViaAuthorizationCode(
    {
      endpoints: {
        parEndpoint: asEndpoints.parEndpoint,
        authorizationEndpoint: asEndpoints.authorizationEndpoint,
        // 認可コードを発行した AS の Token Endpoint で引き換える（RFC 6749 §4.1.3。OID4VCI 1.0 の
        // Issuer Metadata に `token_endpoint` は無い）。Issuer と AS が別ホストでも
        // コードと `code_verifier` は AS 以外へ流れない。
        tokenEndpoint: asEndpoints.tokenEndpoint,
        credentialEndpoint: issuer.credentialEndpoint,
        nonceEndpoint: issuer.nonceEndpoint,
      },
      // JWT Proof の `aud` は Credential Issuer Identifier（OID4VCI 1.0 §8.2.1.1）。
      credentialIssuer: offer.credential_issuer,
      // 認可応答の `iss` を AS Metadata の `issuer` と完全一致で照合させる（AS mix-up 対策）。
      authorizationServerIssuer: asEndpoints.issuer,
      clientId: deps.clientId,
      redirectUri: deps.redirectUri,
      format: deps.format,
      credentialDefinition: { type: resolveCredentialDefinitionType(offer, issuer) },
      vct: resolveCredentialVct(offer, issuer),
      credentialConfigurationId: resolveCredentialConfigurationId(
        offer,
        deps.finalCredentialRequest,
      ),
      scope: offer.credential_configuration_ids.join(' '),
      clientAssertion: deps.clientAssertion,
      clientAssertionType: deps.clientAssertionType,
    },
    {
      signer: deps.signer,
      holderDid: deps.holderDid,
      keyId: deps.keyId,
      authorize: deps.authorize,
      // 値が undefined でも own プロパティとして載せ、下流の DI 解決が汚染値を掴まないようにする。
      fetchImpl: deps.fetchImpl,
      createDpopProof: deps.createDpopProof,
      // 相関 ID は下位フローがそのまま PAR / Token / Credential の 3 経路へ載せる。
      correlationContext: deps.correlationContext,
    },
  );
  if (result.status === 'deferred') {
    throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED, {
      context: { reason: 'deferred_not_supported' },
    });
  }
  return result.credential;
}

/** `pre-authorized_code` 経路。Token → JWT Proof → Credential を直接繋ぐ。 */
async function viaPreAuthorizedCode(
  offer: CredentialOffer,
  grant: object,
  issuer: IssuerEndpoints,
  deps: ResolvedReceiveDeps,
): Promise<string> {
  const code = ownProperty<unknown>(grant, 'pre-authorized_code');
  // **多層防御。到達不能である。** `parseGrants`（`oid4vci-offer-grants.ts`）は
  // `pre-authorized_code` が非空文字列でない grant を `3003`（`context.reason` なし）で先に弾き、
  // 妥当だったときだけ `grants` にキーを加える。この検査は他の経路から渡された値にも同じ制約を適用する。
  if (typeof code !== 'string' || code.length === 0) {
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED, {
      context: { reason: 'unsupported_grant' },
    });
  }
  // Token Endpoint は AS Metadata の `token_endpoint`。AS は `authorization_code` 経路と同じ規則
  // （grant の `authorization_server` を `authorization_servers` と照合。無ければ先頭、それも無ければ
  // `credential_issuer` 自身。OID4VCI 1.0 §4.1.1 / §11.2.3）で選ぶ。旧 Draft の Issuer Metadata
  // `token_endpoint` は AS Metadata に**到達できない**ときだけ使う（検査起因の拒否は迂回しない）。
  const { tokenEndpoint } = await resolvePreAuthorizedTokenEndpoint(
    grant,
    issuer,
    offer.credential_issuer,
    deps.fetchImpl,
  );
  // Token Endpoint 用の proof（RFC 9449 §5）。`htu` は
  // 送信先ごとに束縛される（RFC 9449 §4.3）ため、Credential Endpoint 用とは
  // **別に生成する**（使い回すと `htu` が食い違って AS に拒否される）。`createDpopProof` 未指定なら
  // `undefined` のままで、`DPoP` ヘッダは出ない = 従来どおり Bearer 束縛の access_token を得る。
  const token = await requestTokenPreAuthorized(tokenEndpoint, {
    preAuthorizedCode: code,
    txCode: deps.txCode,
    clientAssertion: deps.clientAssertion,
    clientAssertionType: deps.clientAssertionType,
    dpop: deps.createDpopProof?.(tokenEndpoint),
    // `use_dpop_nonce`（RFC 9449 §8）を受けたら nonce 付き proof で 1 回だけ再送する。
    rebuildDpop: dpopProofRebuilder(deps.createDpopProof, tokenEndpoint),
    // Token と Credential で同じ相関 ID を載せる（1 回の受領操作 = 1 本のトレース）。
    correlationContext: deps.correlationContext,
    fetchImpl: deps.fetchImpl,
  });
  // `nonce` は Token Response の `c_nonce`（旧 Draft）→ Nonce Endpoint → 省略の順で解決する。
  // `aud` は Credential Issuer Identifier（OID4VCI 1.0 §8.2.1.1）。
  const proofJwt = generateProofJWT(
    {
      nonce: await resolveProofNonce(token.cNonce, issuer.nonceEndpoint, deps.fetchImpl),
      audience: offer.credential_issuer,
      issuer: deps.holderDid,
      keyId: deps.keyId,
    },
    deps.signer,
  );
  // **AS が DPoP 束縛トークンを返した場合にだけ** Credential Endpoint 用の proof を載せる。
  // 判定と `ath` 用の access_token 受け渡しは `credentialRequestDpop` に集約する。
  const credentialDpop = credentialRequestDpop(
    token.tokenType,
    token.accessToken,
    issuer.credentialEndpoint,
    deps.createDpopProof,
  );
  const result = await requestCredential({
    credentialEndpoint: issuer.credentialEndpoint,
    accessToken: token.accessToken,
    format: deps.format,
    credentialDefinition: { type: resolveCredentialDefinitionType(offer, issuer) },
    // SD-JWT VC は告知された `vct` で型を伝える。告知が無ければ従来どおり credential_definition。
    vct: resolveCredentialVct(offer, issuer),
    credentialConfigurationId: resolveCredentialConfigurationId(offer, deps.finalCredentialRequest),
    proofJwt,
    dpop: credentialDpop,
    rebuildDpop: dpopProofRebuilder(deps.createDpopProof, issuer.credentialEndpoint, {
      accessToken: token.accessToken,
    }),
    tokenType: token.tokenType,
    correlationContext: deps.correlationContext,
    fetchImpl: deps.fetchImpl,
  });
  if (result.status === 'deferred') {
    throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED, {
      context: { reason: 'deferred_not_supported' },
    });
  }
  return result.credential;
}

/**
 * Credential Offer URI から VC を受領し、解釈済みの結果を返す。
 *
 * Offer の grant に応じて `authorization_code`（PAR + PKCE）または `pre-authorized_code` を使う。
 *
 * @param offerURI OID4VCI Credential Offer URI（`openid-credential-offer:` スキーム）。
 * @param deps 署名鍵・Holder DID / kid・認可 UI 起動関数・client 登録情報・HTTP シーム等。
 * @returns 形式・クレーム・発行者などを含む受領結果（`raw` に生 VC を保持する）。
 * @throws `VericertsError`。Offer のパース失敗・grant 不明は code `3003`、Metadata 取得 /
 *         通信失敗は `3004`、依存不正・Token Request 失敗は `8010`、Credential Request 失敗・
 *         復号失敗・遅延発行は `8020`、`deps.verifyReceived` が `3010` 相当（署名不一致・非
 *         `VericertsError`）で失敗した場合は `3010`、それ以外の `VericertsError`（`3002` / `3024`
 *         等）で失敗した場合はそのコードをそのまま。
 *
 * @experimental 挙動・シグネチャが変わることがある（v1.0 で `@stable` 昇格予定）。
 */
export async function receiveCredential(
  offerURI: string,
  deps: ReceiveCredentialDeps,
): Promise<ReceivedVerifiableCredential> {
  const resolved = resolveReceiveCredentialDeps(deps);
  // 初弾（`credential_offer_uri` の GET）も後続の `fetchIssuerMetadata` と同じシームへ通す
  // （`wallet/options.ts` の「両受領経路とも `eudiFetchImpl`」契約）。
  const offer = await parseCredentialOffer(offerURI, resolved.fetchImpl);
  const issuer = await fetchIssuerMetadata(
    offer.credential_issuer,
    resolved.fetchImpl,
    offer.credential_configuration_ids,
  );

  const grants = grantsOf(offer);
  // grant は own 限定で読む。鎖読みだと grant を持たない Offer が `Object.prototype` の汚染値を
  // 拾い、攻撃者の `pre-authorized_code` で Token Request が成立する。
  const authorizationCode =
    grants === undefined
      ? undefined
      : ownProperty<AuthorizationCodeGrant>(grants, AUTHORIZATION_CODE_GRANT);
  const preAuthorized =
    grants === undefined ? undefined : ownProperty<object>(grants, PRE_AUTHORIZED_CODE_GRANT);

  let raw: string;
  if (authorizationCode !== undefined) {
    raw = await viaAuthorizationCode(offer, authorizationCode, issuer, resolved);
  } else if (preAuthorized !== undefined) {
    raw = await viaPreAuthorizedCode(offer, preAuthorized, issuer, resolved);
  } else {
    // grant の告知が無い Offer はどちらのフローも開始できない（fail-closed）。
    throw new VericertsError(ErrorCodes.OFFER_URI_PARSE_FAILED, {
      context: { reason: 'unsupported_grant' },
    });
  }

  if (resolved.verifyReceived !== undefined) {
    try {
      await resolved.verifyReceived(raw);
    } catch (failure) {
      // 署名不一致以外の失敗（3002 / 3024 等）は元のコードを保つ。
      const preserved = preservedVerifyFailure(failure);
      if (preserved !== undefined) throw preserved;
      // VC 本文・署名を載せないため cause は渡さない。
      throw new VericertsError(ErrorCodes.SIG_INVALID, {
        context: { reason: 'received_credential_signature_invalid' },
      });
    }
  }
  return toReceivedCredential(raw);
}
