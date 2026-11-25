/**
 * JWT VC Issuer Metadata 経路の回帰テスト —
 * **取得元 URL の組み立てと JWK Set からの鍵選択**。
 *
 * opt-in の境界（未指定なら取得しない・`x5c` が優先）は
 * `jwt-vc-issuer/wallet.eudi.receive-jwt-vc-issuer.test.ts` が持つ。ここで固定するのは、有効化したあとの
 * 「どこを引き、どの鍵を採るか」である。
 *
 * - well-known は `iss` の host と path の**あいだ**へ差し込む（draft-ietf-oauth-sd-jwt-vc §5）。
 * - `jwks` / `jwks_uri` はいずれか一方。`jwks_uri` は `iss` と同一 origin に限る。
 * - 鍵は `kid` で 1 つに絞れるときだけ採る（絞れなければ他の鍵へフォールバックしない）。
 */

import { describe, expect, it } from 'bun:test';
import { PID_VCT } from '../../../../internal/eudi/pid/index.js';
import { failureOf } from '../../failure.fixtures.js';
import {
  buildSdJwtVcWith,
  createStub,
  ISSUER,
  ISSUER_PUBLIC_JWK,
  jsonResponse,
  offerURI,
  setupWallet,
  VALID_PID_CLAIMS,
} from '../eudi-fixtures.js';
import {
  FOREIGN_JWKS_URL,
  JWKS_URL,
  metadataPidWallet,
  OTHER_JWK,
  redirectedJsonResponse,
} from './jwt-vc-issuer-fixtures.js';

describe('JWT VC Issuer Metadata の取得元', () => {
  it('iss がパスを持つ場合、well-known は host と path のあいだへ差し込む', async () => {
    // draft §5: `https://ex/tenant/1` の取得先は `https://ex/.well-known/jwt-vc-issuer/tenant/1`。
    // 末尾連結（`https://ex/tenant/1/.well-known/jwt-vc-issuer`）ではない。
    const iss = `${ISSUER}/tenant/1`;
    const tenantWellKnown = `${ISSUER}/.well-known/jwt-vc-issuer/tenant/1`;
    const sdJwt = buildSdJwtVcWith({ vct: PID_VCT, claims: VALID_PID_CLAIMS, iss });
    const stub = createStub(sdJwt, {
      [tenantWellKnown]: () => jsonResponse({ issuer: iss, jwks: { keys: [ISSUER_PUBLIC_JWK] } }),
    });
    const wallet = await setupWallet({
      eudiFetchImpl: stub.fetchImpl,
      jwtVcIssuerMetadataResolution: true,
    });

    const pid = await wallet.receivePID(offerURI());

    expect(pid.claims.family_name).toBe('Bianchi');
    expect(stub.calls.map((call) => call.url)).toContain(tenantWellKnown);
  });

  it('well-known が別 origin へリダイレクトしたら追随せず 3010', async () => {
    // origin 束縛は `jwks_uri` だけでなく **metadata 文書自体の取得**にも掛かる。片方だけ縛ると、
    // `/.well-known/jwt-vc-issuer` が内部ホストや攻撃者ホストへ 302 した先を読みに行き、
    // 「認証したのは iss の origin の TLS 証明書を持つホストだけ」という不変条件が迂回される。
    const { wallet } = await metadataPidWallet({
      wellKnownResponse: () =>
        redirectedJsonResponse(
          { issuer: ISSUER, jwks: { keys: [ISSUER_PUBLIC_JWK] } },
          'https://metadata.attacker.example/.well-known/jwt-vc-issuer',
        ),
    });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
  });

  it('well-known が同一 origin 内でリダイレクトした場合は受理する', async () => {
    // 束縛しているのは origin であってパスではない（`jwks_uri` 側と同じ規律）。
    const { wallet } = await metadataPidWallet({
      wellKnownResponse: () =>
        redirectedJsonResponse(
          { issuer: ISSUER, jwks: { keys: [ISSUER_PUBLIC_JWK] } },
          `${ISSUER}/.well-known/jwt-vc-issuer-v2`,
        ),
    });

    const pid = await wallet.receivePID(offerURI());

    expect(pid.claims.family_name).toBe('Bianchi');
  });

  it('同一 origin の jwks_uri を辿って受領できる', async () => {
    const { wallet, urls } = await metadataPidWallet({
      metadata: { issuer: ISSUER, jwks_uri: JWKS_URL },
      routes: { [JWKS_URL]: () => jsonResponse({ keys: [ISSUER_PUBLIC_JWK] }) },
    });

    const pid = await wallet.receivePID(offerURI());

    expect(pid.claims.family_name).toBe('Bianchi');
    expect(urls()).toContain(JWKS_URL);
  });

  it('別 origin の jwks_uri は取得せず 3010(issuer_key_unresolved)', async () => {
    // 認証したのは iss の origin だけ。別ホストに鍵を決めさせない（SSRF 踏み台の防止も兼ねる）。
    const { wallet, urls } = await metadataPidWallet({
      metadata: { issuer: ISSUER, jwks_uri: FOREIGN_JWKS_URL },
      routes: { [FOREIGN_JWKS_URL]: () => jsonResponse({ keys: [ISSUER_PUBLIC_JWK] }) },
    });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
    expect(urls()).not.toContain(FOREIGN_JWKS_URL);
  });

  it('同一 origin の jwks_uri が別 origin へリダイレクトしたら追随せず 3010', async () => {
    // origin 束縛は**取得後の最終 URL**まで及ぶ。取得前の URL だけを検査していると、同一 origin の
    // jwks_uri が内部ホストや攻撃者ホストへ 302 した先の鍵をそのまま採ってしまう（draft §10.1）。
    const { wallet } = await metadataPidWallet({
      metadata: { issuer: ISSUER, jwks_uri: JWKS_URL },
      routes: {
        [JWKS_URL]: () => redirectedJsonResponse({ keys: [ISSUER_PUBLIC_JWK] }, FOREIGN_JWKS_URL),
      },
    });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
  });

  it('同一 origin 内のリダイレクト（パス違い）は受理する', async () => {
    // 束縛しているのは origin であってパスではない。同一 origin にとどまる限り追随してよい。
    const { wallet } = await metadataPidWallet({
      metadata: { issuer: ISSUER, jwks_uri: JWKS_URL },
      routes: {
        [JWKS_URL]: () =>
          redirectedJsonResponse({ keys: [ISSUER_PUBLIC_JWK] }, `${ISSUER}/keys/v2.json`),
      },
    });

    const pid = await wallet.receivePID(offerURI());

    expect(pid.claims.family_name).toBe('Bianchi');
  });

  it('jwks と jwks_uri の両方を持つ metadata は 3010（どちらを採るか SDK が決めない）', async () => {
    const { wallet } = await metadataPidWallet({
      metadata: { issuer: ISSUER, jwks: { keys: [ISSUER_PUBLIC_JWK] }, jwks_uri: JWKS_URL },
      routes: { [JWKS_URL]: () => jsonResponse({ keys: [ISSUER_PUBLIC_JWK] }) },
    });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
  });

  it.each([
    ['query 付き', `${ISSUER}/?x=1`],
    ['fragment 付き', `${ISSUER}/#frag`],
  ])('%s の iss は well-known を 1 度も取得せず 3010', async (_label, iss) => {
    // draft §5 は `iss` を「query と fragment を持たない HTTPS URL」と定める。query / fragment を
    // 黙って捨てて取得すると、提示された識別子と問い合わせ先が食い違い `issuer` 完全一致検査が
    // 意味を失う。非 HTTPS と同じく**取得に行かずに**拒否することを固定する。
    const { wallet, urls } = await metadataPidWallet({ iss });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
    expect(urls().some((url) => url.includes('/.well-known/jwt-vc-issuer'))).toBe(false);
  });

  it('jwks も jwks_uri も無い metadata は 3010', async () => {
    const { wallet } = await metadataPidWallet({ metadata: { issuer: ISSUER } });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
  });
});

describe('JWT VC Issuer Metadata の鍵選択', () => {
  it('kid 指定時は kid 一致鍵だけを候補にする（複数鍵から正しい鍵を選ぶ）', async () => {
    const { wallet } = await metadataPidWallet({
      kid: 'issuer-key-1',
      metadata: {
        issuer: ISSUER,
        jwks: {
          keys: [
            { ...OTHER_JWK, kid: 'issuer-key-0' },
            { ...ISSUER_PUBLIC_JWK, kid: 'issuer-key-1' },
          ],
        },
      },
    });

    const pid = await wallet.receivePID(offerURI());

    expect(pid.claims.family_name).toBe('Bianchi');
  });

  it('kid 一致鍵が無ければ他の鍵へフォールバックせず 3010', async () => {
    // 「一致が無ければ全鍵を試す」形にすると kid を付ける意味（取り違えの検知）が消える。
    const { wallet } = await metadataPidWallet({
      kid: 'unknown-kid',
      metadata: { issuer: ISSUER, jwks: { keys: [{ ...ISSUER_PUBLIC_JWK, kid: 'issuer-key-1' }] } },
    });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
  });

  it('kid 無しで JWK Set が複数鍵なら 3010（どれか通る鍵を探さない）', async () => {
    const { wallet } = await metadataPidWallet({
      metadata: { issuer: ISSUER, jwks: { keys: [ISSUER_PUBLIC_JWK, OTHER_JWK] } },
    });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
  });

  it('オブジェクトでない要素を含む JWK Set は、kid 無しでも「1 鍵」と数えず 3010', async () => {
    // 非オブジェクト要素を黙って落とすと `{"keys": [null, <jwk>]}` が「ちょうど 1 鍵」になり、
    // kid 無しの条件（JWK Set がちょうど 1 鍵）が攻撃者の影響下で崩れる。
    const { wallet } = await metadataPidWallet({
      metadata: { issuer: ISSUER, jwks: { keys: [null, ISSUER_PUBLIC_JWK] } },
    });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
  });

  it('kid が非文字列なら「kid 無し」へ格下げせず 3010（1 鍵でも採らない）', async () => {
    // 文字列でない `kid` を「kid 無し」とみなすと、攻撃者は `kid: 123` を置くだけで緩いほうの
    // 規則（JWK Set がちょうど 1 鍵なら無条件に採る）へ落とし込め、鍵の指定を無効化できる。
    const { wallet } = await metadataPidWallet({
      kid: 123 as unknown as string,
      metadata: { issuer: ISSUER, jwks: { keys: [{ ...ISSUER_PUBLIC_JWK, kid: 'issuer-key-1' }] } },
    });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
  });

  it('kid が空文字なら「kid 無し」へ格下げせず 3010', async () => {
    const { wallet } = await metadataPidWallet({
      kid: '',
      metadata: { issuer: ISSUER, jwks: { keys: [{ ...ISSUER_PUBLIC_JWK, kid: 'issuer-key-1' }] } },
    });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
  });

  it('kid 指定でも非オブジェクト要素を含む JWK Set は拒否する（文書ごと不正とみなす）', async () => {
    const { wallet } = await metadataPidWallet({
      kid: 'issuer-key-1',
      metadata: {
        issuer: ISSUER,
        jwks: { keys: ['not-a-jwk', { ...ISSUER_PUBLIC_JWK, kid: 'issuer-key-1' }] },
      },
    });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
  });
});
