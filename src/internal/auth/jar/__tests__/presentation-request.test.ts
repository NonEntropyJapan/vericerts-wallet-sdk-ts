/**
 * `parsePresentationRequest` の単体テスト。
 *
 * 回帰の要点は 2 つある。
 *
 * - 「`request_uri` 単独形式が**拒否ではなく処理される**」こと。従来 SDK は参照形式を
 *   `8030` で拒否するのみで、HAIP §5.1 が必須とする JAR 経由の提示要求が SDK 単体で成立しなかった。
 * - 参照形式が**必ず署名検証を経由する**こと。Trust Anchor を渡さない呼び出しでは
 *   参照形式が fail-closed に拒否され、署名が不正な Request Object も拒否される。
 *
 * あわせて直接形式が従来どおり同じ結果を返し、Trust Anchor を要求しないことも固定する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import type { FetchLike } from '../../../fetch-di.js';
import {
  makeKeyPair,
  signedCatalogue,
  spkiToBase64,
} from '../../../trust/arf/__tests__/arf-fixtures.js';
import { loadArfTrustAnchor } from '../../../trust/arf/index.js';
import { parseCertificate } from '../../../trust/etsi-tsl/index.js';
import { parsePresentationRequest } from '../presentation-request.js';
import { CLIENT_ID, jarClaims, makeJarSigner, REQUEST_URI, signJar } from './jar-fixtures.js';

const VERIFIER = makeJarSigner();
const TRUST = { trustAnchors: VERIFIER.anchors } as const;
const JAR_CLAIMS = jarClaims({ nonce: 'n-jar-0123456789abcdef0', state: 's-jar' });
const SIGNED_JAR = signJar(VERIFIER, { claims: JAR_CLAIMS });

/** ARF Catalogue エンベロープ（署名検証済み）を組み立てる。エントリは呼び出し側が指定する。 */
async function buildArfTrustAnchor(entries: Record<string, unknown>[]) {
  const key = makeKeyPair();
  const envelope = signedCatalogue({ entries }, key);
  return loadArfTrustAnchor('https://arf.example.eu/catalogue', {
    fetcher: async () => envelope,
    trustAnchorPublicKey: key.publicKey,
  });
}

function stubFetch(jwt: string, urls?: string[]): FetchLike {
  return async (url) => {
    urls?.push(url);
    return new Response(jwt, {
      status: 200,
      headers: { 'Content-Type': 'application/oauth-authz-req+jwt' },
    });
  };
}

function directUri(overrides: Record<string, string> = {}): string {
  const params = new URLSearchParams({
    response_type: 'vp_token',
    client_id: CLIENT_ID,
    response_mode: 'direct_post',
    response_uri: `${CLIENT_ID}/callback`,
    nonce: 'n-direct-0123456789abcdef',
    state: 's-direct',
    ...overrides,
  });
  return `openid4vp://?${params.toString()}`;
}

describe('parsePresentationRequest: request_uri 参照形式', () => {
  it('request_uri 単独形式が拒否されず、取得・検証・解析される', async () => {
    const urls: string[] = [];
    const request = await parsePresentationRequest(
      `openid4vp://?request_uri=${encodeURIComponent(REQUEST_URI)}`,
      { ...TRUST, fetchImpl: stubFetch(SIGNED_JAR, urls) },
    );

    expect(request.nonce).toBe('n-jar-0123456789abcdef0');
    expect(request.clientId).toBe(CLIENT_ID);
    expect(urls).toEqual([REQUEST_URI]);
  });

  it('client_id 併記の参照形式も取得・解析される', async () => {
    const params = new URLSearchParams({ client_id: CLIENT_ID, request_uri: REQUEST_URI });
    const request = await parsePresentationRequest(`openid4vp://?${params.toString()}`, {
      ...TRUST,
      fetchImpl: stubFetch(SIGNED_JAR),
    });
    expect(request.state).toBe('s-jar');
  });

  it('request_uri と response_type の混在では request_uri から取得する（RFC 9101 §6.3）', async () => {
    // 混在を直接形式として扱うと、Verifier が署名した Request Object を取得せず黙って捨て、
    // 署名の無いクエリパラメータ（deep link で書き換えられる側）を採用してしまう。RFC 9101
    // §5.2.1 は重複送信を認め §6.3 は Request Object 側の優先を定めるため、参照形式を優先する
    const urls: string[] = [];
    const request = await parsePresentationRequest(directUri({ request_uri: REQUEST_URI }), {
      ...TRUST,
      fetchImpl: stubFetch(SIGNED_JAR, urls),
    });
    // クエリ側の `nonce` ではなく Request Object の `nonce` が採用される。
    expect(request.nonce).toBe('n-jar-0123456789abcdef0');
    expect(request.state).toBe('s-jar');
    expect(urls).toEqual([REQUEST_URI]);
  });

  it('参照形式でも非 HTTPS の request_uri は 8030', async () => {
    const promise = parsePresentationRequest(
      'openid4vp://?request_uri=http://verifier.example.com/request/123',
      { ...TRUST, fetchImpl: stubFetch(SIGNED_JAR) },
    );
    await expect(promise).rejects.toMatchObject({
      code: ErrorCodes.OID4VP_REQUEST_PARSE_FAILED,
      context: { reason: 'non_https_request_uri' },
    });
  });
});

describe('parsePresentationRequest: 参照形式の署名検証', () => {
  it('Trust Anchor 未設定の呼び出しで参照形式が届いたら拒否する（fail-closed）', async () => {
    // 従来はここで署名を検証せずに解析まで通っていた（= 攻撃者が任意の提示要求を
    // 注入できた）。検証できない状態を「検証済み」に読み替えない。
    const promise = parsePresentationRequest(
      `openid4vp://?request_uri=${encodeURIComponent(REQUEST_URI)}`,
      { fetchImpl: stubFetch(SIGNED_JAR) },
    );
    await expect(promise).rejects.toMatchObject({
      code: ErrorCodes.OID4VP_REQUEST_PARSE_FAILED,
      context: { reason: 'jar_trust_anchors_unconfigured' },
    });
  });

  it('オプションを省略した呼び出しでも参照形式は拒否される', async () => {
    const promise = parsePresentationRequest(
      `openid4vp://?request_uri=${encodeURIComponent(REQUEST_URI)}`,
    );
    await expect(promise).rejects.toMatchObject({
      code: ErrorCodes.OID4VP_REQUEST_PARSE_FAILED,
      context: { reason: 'jar_trust_anchors_unconfigured' },
    });
  });

  it('署名が不正な Request Object は拒否される', async () => {
    const tampered = signJar(VERIFIER, {
      claims: JAR_CLAIMS,
      tamperedClaims: jarClaims({ nonce: 'attacker-nonce' }),
    });
    const promise = parsePresentationRequest(
      `openid4vp://?request_uri=${encodeURIComponent(REQUEST_URI)}`,
      { ...TRUST, fetchImpl: stubFetch(tampered) },
    );
    await expect(promise).rejects.toMatchObject({
      code: ErrorCodes.OID4VP_REQUEST_PARSE_FAILED,
      context: { reason: 'jar_signature_invalid' },
    });
  });

  it('deep link の client_id が Request Object と食い違えば拒否される', async () => {
    const params = new URLSearchParams({
      client_id: 'https://attacker.example',
      request_uri: REQUEST_URI,
    });
    const promise = parsePresentationRequest(`openid4vp://?${params.toString()}`, {
      ...TRUST,
      fetchImpl: stubFetch(SIGNED_JAR),
    });
    await expect(promise).rejects.toMatchObject({
      code: ErrorCodes.OID4VP_REQUEST_PARSE_FAILED,
      context: { reason: 'jar_client_id_mismatch' },
    });
  });

  it('trustAnchors: [] + arfTrustAnchor だけでも参照形式を解決できる', async () => {
    // `parsePresentationRequest` → `fetchJAR` → `verifyJarSignature` の経路で `arfTrustAnchor` が
    // 途中で取りこぼされず末端まで転送されることを固定する（TSL 層を使わない = `trustAnchors: []`
    // でも ARF 層単独で信頼の起点として成立すること）。
    const spki = parseCertificate(VERIFIER.rp.der).spki;
    const arfTrustAnchor = await buildArfTrustAnchor([
      { id: CLIENT_ID, role: 'relying-party', spki: spkiToBase64(spki) },
    ]);
    const request = await parsePresentationRequest(
      `openid4vp://?request_uri=${encodeURIComponent(REQUEST_URI)}`,
      { trustAnchors: [], arfTrustAnchor, fetchImpl: stubFetch(SIGNED_JAR) },
    );
    expect(request.nonce).toBe('n-jar-0123456789abcdef0');
  });

  it('明示した expectedClientId は deep link のクエリより優先される', async () => {
    // クエリの `client_id` は Request Object と一致するが、呼び出し側が別の相手を期待している。
    const params = new URLSearchParams({ client_id: CLIENT_ID, request_uri: REQUEST_URI });
    const promise = parsePresentationRequest(`openid4vp://?${params.toString()}`, {
      ...TRUST,
      expectedClientId: 'https://another.example',
      fetchImpl: stubFetch(SIGNED_JAR),
    });
    await expect(promise).rejects.toMatchObject({
      context: { reason: 'jar_client_id_mismatch' },
    });
  });
});

describe('parsePresentationRequest: 直接形式', () => {
  it('直接形式は HTTP 取得を行わずそのまま解析される', async () => {
    let called = false;
    const request = await parsePresentationRequest(directUri(), {
      ...TRUST,
      fetchImpl: async () => {
        called = true;
        return new Response('');
      },
    });

    expect(request.nonce).toBe('n-direct-0123456789abcdef');
    expect(request.responseMode).toBe('direct_post');
    expect(called).toBe(false);
  });

  it('直接形式は Trust Anchor を要求しない（署名対象が存在しない）', async () => {
    const request = await parsePresentationRequest(directUri());
    expect(request.nonce).toBe('n-direct-0123456789abcdef');
  });

  it('必須パラメータ欠落は従来どおり 8030', async () => {
    const promise = parsePresentationRequest('openid4vp://?response_type=vp_token');
    await expect(promise).rejects.toMatchObject({
      code: ErrorCodes.OID4VP_REQUEST_PARSE_FAILED,
    });
  });

  it('空クエリは 8030', async () => {
    try {
      await parsePresentationRequest('openid4vp://?');
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
  });
});
