/**
 * Wallet ファサード EUDI 統合テスト用フィクスチャ。
 *
 * 実鍵素材のみを使う（モック署名器は使わない）。Issuer 署名済み SD-JWT VC は Disclosure・digest・
 * 署名まで実際に計算して組み立てる。`createSdJwt` を使わないのは、PID の属性名（`family_name` 等）が
 * 発行経路の GDPR Art.9 ガードで `10607` に落ちるためで、受領済み PID を扱うテスト状況を作るには
 * Issuer 側の組み立てを再現する必要がある。
 *
 * ネットワークは**グローバル `fetch` を差し替えず**、`createWallet` の `eudiFetchImpl` で注入する。
 * OID4VCI の 3 経路（Metadata / Token / Credential）と OID4VP の `direct_post` 送信先を同じ
 * ルーティング表で扱い、要求 URL と body を記録する。
 */

import { base64urlnopad } from '@scure/base';
import type { FetchLike } from '../../../internal/auth/oid4vci/oid4vci.js';
import { encodeDisclosure } from '../../../internal/credential/sdjwt/disclosure.js';
import { createPrivateKeySigner } from '../../../internal/credential/vc/signer.js';
import type { AttestationCatalogueEntry } from '../../../internal/eudi/pid/index.js';
import { PID_VCT } from '../../../internal/eudi/pid/index.js';
import { createDidJwk } from '../../../internal/identity/jwk/method-jwk.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import type { WalletOptions } from '../../options.js';
import type { Wallet } from '../../types.js';

/** テスト用ニーモニック（BIP-39 のテストベクタ）。 */
export const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** Issuer（PID Provider 相当）の決定論的な P-256 秘密鍵。 */
const ISSUER_PRIVATE_KEY = new Uint8Array(32).fill(7);

/** Issuer の署名器（SD-JWT VC の Issuer-signed JWT に署名する）。 */
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_PRIVATE_KEY, 'ES256');

/** Credential Offer の `credential_issuer`。 */
export const ISSUER = 'https://issuer.example.eu';

/**
 * SD-JWT VC の `iss`（Issuer 識別子）。
 *
 * `receivePID` / `receiveEAA` は受領した VC の Issuer 署名を**既定で検証する**ため、
 * `iss` は Wallet の DID Resolver が解決できる DID でなければならない。ネットワークを踏まない
 * did:jwk を使い、上の秘密鍵に対応する公開鍵をそのまま識別子に埋め込む（`credential_issuer`
 * （= Offer / Metadata のホスト）とは別物である点に注意）。
 */
export const ISSUER_DID = createDidJwk(ISSUER_SIGNER.publicKeyJwk).id;

/**
 * 正規 Issuer の公開鍵 JWK（JWT VC Issuer Metadata の `jwks` に載せる）。
 *
 * `ISSUER_DID` が埋め込んでいるのと同じ鍵である。metadata 経路が DID 経路と同じ鍵へ到達することを
 * テスト側でも同じ 1 つの素材から確かめるため、JWK をそのまま公開する。
 */
export const ISSUER_PUBLIC_JWK: Readonly<Record<string, unknown>> = ISSUER_SIGNER.publicKeyJwk;

/** Issuer Metadata の well-known URL。 */
export const METADATA_URL = `${ISSUER}/.well-known/openid-credential-issuer`;

/** Issuer Metadata が宣言する Token Endpoint。 */
export const TOKEN_URL = `${ISSUER}/token`;

/** Issuer Metadata が宣言する Credential Endpoint。 */
export const CREDENTIAL_URL = `${ISSUER}/credential`;

/** Issuer Metadata が宣言する Nonce Endpoint（WUA 添付時に c_nonce を払い出す）。 */
export const NONCE_URL = `${ISSUER}/nonce`;

/** Nonce Endpoint が払い出す c_nonce（WUA-PoP の `nonce` に載る）。 */
export const AS_C_NONCE = 'as-issued-c-nonce-123';

/** (Q)EAA の VC Type URI。 */
export const EAA_VCT = 'urn:eudi:eaa:diploma:1';

/** Verifier の識別子（`client_id`）。 */
export const VERIFIER_CLIENT_ID = 'https://verifier.example.eu';

/** VP Token の送信先（`response_uri`。`client_id` と同一オリジンである必要がある）。 */
export const RESPONSE_URI = `${VERIFIER_CLIENT_ID}/response`;

/** ARF PID Rulebook の必須属性をすべて満たす PID クレーム。 */
export const VALID_PID_CLAIMS: Readonly<Record<string, unknown>> = {
  family_name: 'Bianchi',
  given_name: 'Mario',
  birth_date: '1980-05-17',
  issuance_date: '2026-01-10',
  expiry_date: '2031-01-10',
  issuing_authority: 'Ministero dell Interno',
  issuing_country: 'IT',
};

/** (Q)EAA のクレーム。 */
export const EAA_CLAIMS: Readonly<Record<string, unknown>> = {
  degree: 'Laurea Magistrale',
  institution: 'UniRoma',
};

/** `EAA_VCT` の Catalogue エントリ。 */
export const CATALOGUE_ENTRY: AttestationCatalogueEntry = {
  vct: EAA_VCT,
  rulebookUrl: 'https://catalogue.example.eu/diploma/rulebook',
  schemaUrl: 'https://catalogue.example.eu/diploma/schema.json',
  version: '1.0',
};

/** UTF-8 文字列を base64url（パディングなし）エンコードする。 */
function b64url(text: string): string {
  return base64urlnopad.encode(new TextEncoder().encode(text));
}

/**
 * Issuer 署名済みの SD-JWT VC を組み立てる（全クレームを選択的開示にする）。
 *
 * @param vct VC Type URI。
 * @param claims 開示可能なクレーム。
 * @returns SD-JWT VC のコンパクト表現（`<issuerJwt>~<d1>~...~`）。
 */
export function buildSdJwtVc(vct: string, claims: Readonly<Record<string, unknown>>): string {
  return buildSdJwtVcWith({ vct, claims });
}

/** {@link buildSdJwtVcWith} の入力（既定から外した部分だけを指定する）。 */
export interface SdJwtVcOverrides {
  /** VC Type URI。 */
  readonly vct: string;
  /** 開示可能なクレーム。 */
  readonly claims: Readonly<Record<string, unknown>>;
  /** `iss` に載せる Issuer 識別子（既定は {@link ISSUER_DID}）。 */
  readonly iss?: string;
  /** 署名に使う秘密鍵（既定は `iss` に対応する正規の Issuer 鍵）。 */
  readonly signingKey?: Uint8Array;
  /**
   * Issuer-signed JWT ヘッダに載せる `x5c`（標準 base64 の DER 配列）。
   *
   * 指定すると既定検証は DID 解決ではなく証明書チェーン経路へ入る。
   */
  readonly x5c?: readonly string[];
  /**
   * Issuer-signed JWT ヘッダに載せる `kid`。
   *
   * JWT VC Issuer Metadata 経路が JWK Set から鍵を選ぶときの手がかりになる。
   */
  readonly kid?: string;
  /** `exp`（Unix 秒）。省略時は載せない。過去の値を渡すと期限切れの VC になる。 */
  readonly exp?: number;
}

/**
 * `iss` と署名鍵を差し替えられる SD-JWT VC ビルダー（既定検証の回帰テスト用）。
 *
 * `signingKey` に別の鍵を渡すと「`iss` は正規 Issuer だが署名が一致しない」偽の VC になり、
 * `iss` に HTTPS URL を渡すと「DID Resolver で鍵を解決できない」VC になる。
 */
export function buildSdJwtVcWith(overrides: SdJwtVcOverrides): string {
  const signer =
    overrides.signingKey === undefined
      ? ISSUER_SIGNER
      : createPrivateKeySigner(overrides.signingKey, 'ES256');
  const disclosures = Object.entries(overrides.claims).map(([name, value], index) =>
    encodeDisclosure(name, value, `salt-${index}`),
  );
  const payload = {
    iss: overrides.iss ?? ISSUER_DID,
    vct: overrides.vct,
    iat: 1_767_000_000,
    ...(overrides.exp === undefined ? {} : { exp: overrides.exp }),
    _sd_alg: 'sha-256',
    _sd: disclosures.map((disclosure) => disclosure.digest),
  };
  const header: Record<string, unknown> = { alg: 'ES256', typ: 'dc+sd-jwt' };
  if (overrides.x5c !== undefined) {
    header.x5c = overrides.x5c;
  }
  if (overrides.kid !== undefined) {
    header.kid = overrides.kid;
  }
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const signature = signer.sign(new TextEncoder().encode(signingInput));
  const issuerJwt = `${signingInput}.${base64urlnopad.encode(signature)}`;
  return `${issuerJwt}~${disclosures.map((disclosure) => disclosure.encoded).join('~')}~`;
}

/** 正規 Issuer になりすます攻撃者の秘密鍵（`ISSUER_PRIVATE_KEY` とは別物）。 */
export const FORGED_ISSUER_PRIVATE_KEY = new Uint8Array(32).fill(9);

/** pre-authorized_code grant を持つ Credential Offer URI（値渡し）。 */
export function offerURI(configurationId: string = PID_VCT): string {
  const offer = {
    credential_issuer: ISSUER,
    credential_configuration_ids: [configurationId],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': 'pre-auth-code-123',
      },
    },
  };
  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
}

/** OID4VP Authorization Request URI（`direct_post`）を組み立てる。 */
export function requestURI(): string {
  const params = new URLSearchParams({
    response_type: 'vp_token',
    client_id: VERIFIER_CLIENT_ID,
    response_mode: 'direct_post',
    response_uri: RESPONSE_URI,
    nonce: 'n-0S6_WzA2Mj-0123456789',
    state: 'state-123',
  });
  return `openid4vp://?${params.toString()}`;
}

/** 1 回の HTTP 呼び出しの記録。 */
export interface FetchCall {
  /** 要求された URL。 */
  readonly url: string;
  /** 送信された body。 */
  readonly body: string;
}

/** URL でルーティングするスタブ fetch と、その呼び出し記録。 */
export interface StubFetch {
  /** `eudiFetchImpl` として注入する実装。 */
  readonly fetchImpl: FetchLike;
  /** 要求された URL / body の記録（呼ばれた順）。 */
  readonly calls: FetchCall[];
}

/** JSON 本文の 200 応答を返す（jwt-vc-issuer 系フィクスチャからも使うため export する）。 */
export function jsonResponse(body: Readonly<Record<string, unknown>>): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * OID4VCI の 3 経路と OID4VP の送信先を扱うスタブ fetch を作る。
 *
 * @param sdJwt Credential Endpoint が返す SD-JWT VC。
 * @param extraRoutes 追加の URL → 応答（WUA 発行エンドポイント等。既定の 4 経路が優先）。
 * @returns 注入する `fetchImpl` と呼び出し記録。
 */
export function createStub(
  sdJwt: string,
  extraRoutes: Readonly<Record<string, () => Response>> = {},
): StubFetch {
  const calls: FetchCall[] = [];
  const routes: Readonly<Record<string, () => Response>> = {
    ...extraRoutes,
    [METADATA_URL]: () =>
      jsonResponse({
        credential_issuer: ISSUER,
        credential_endpoint: CREDENTIAL_URL,
        token_endpoint: TOKEN_URL,
        // WUA-PoP は AS 発行 c_nonce を要求するため、Nonce Endpoint を
        // 告知していない Issuer への WUA 添付は 8010 に倒れる。既定は告知する構成にする。
        nonce_endpoint: NONCE_URL,
      }),
    [NONCE_URL]: () => jsonResponse({ c_nonce: AS_C_NONCE }),
    [TOKEN_URL]: () =>
      jsonResponse({
        access_token: 'access-token-abc',
        token_type: 'Bearer',
        expires_in: 300,
        c_nonce: 'c-nonce-xyz',
        c_nonce_expires_in: 300,
      }),
    [CREDENTIAL_URL]: () => jsonResponse({ credential: sdJwt }),
    [RESPONSE_URI]: () => new Response('', { status: 200 }),
  };
  const fetchImpl: FetchLike = (url, init) => {
    calls.push({ url, body: init.body });
    const route = Object.hasOwn(routes, url) ? routes[url] : undefined;
    return Promise.resolve(route === undefined ? new Response('', { status: 404 }) : route());
  };
  return { fetchImpl, calls };
}

/**
 * ニーモニック import とアクティブペルソナ設定まで済ませた Wallet を用意する。
 *
 * @param options `storage` 以外の追加オプション（`eudiCatalogue` / `eudiFetchImpl`）。
 * @returns 初期化済み Wallet。
 */
export async function setupWallet(options: Omit<WalletOptions, 'storage'>): Promise<Wallet> {
  const wallet = await createWallet({ storage: new MemoryStorage(), ...options });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const persona = await wallet.createPersona();
  await wallet.setActivePersona(persona.id);
  return wallet;
}

/** 送信された form body から `vp_token` を取り出す。 */
export function submittedVpToken(call: FetchCall | undefined): string {
  return new URLSearchParams(call?.body ?? '').get('vp_token') ?? '';
}
