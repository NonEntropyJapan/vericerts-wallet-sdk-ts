/**
 * JWT VC Issuer Metadata（`/.well-known/jwt-vc-issuer`）による Issuer 鍵解決
 * の回帰テスト — **opt-in の境界**。
 *
 * 既定検証は `x5c`（ETSI TSL Trust Anchor 起点）と `iss` の DID 解決しか持たず、
 * `iss` が HTTPS URL で `x5c` を持たない Issuer（自ホストで JWK Set を公開する運用）は常に
 * `3010` で拒否されていた。この経路は **Issuer 自身のホストだけを信頼の起点とする**ため、
 * ここで固定する契約の中心は「**opt-in していない呼び出しの従来の挙動を保つこと**」
 * である。
 *
 * - `jwtVcIssuerMetadataResolution` 未指定なら well-known を**取得しに行かない**（`3010` のまま）。
 * - 有効化すれば `opts.verifyReceived` 無しで受領できる。
 * - `iss` と metadata の `issuer` の不一致・非 HTTPS の `iss` はいずれも fail-closed（`3010`）。
 * - `x5c` があるときは有効化していても metadata 経路へ落ちない（`x5c` が常に優先）。
 *
 * 取得元 URL の組み立てと JWK Set からの鍵選択は
 * `jwt-vc-issuer/wallet.eudi.receive-jwt-vc-issuer-keys.test.ts` が持つ。
 */

import { describe, expect, it } from 'bun:test';
import { PID_VCT } from '../../../../internal/eudi/pid/index.js';
import { failureOf } from '../../failure.fixtures.js';
import {
  buildSdJwtVcWith,
  createStub,
  FORGED_ISSUER_PRIVATE_KEY,
  ISSUER,
  ISSUER_DID,
  ISSUER_PUBLIC_JWK,
  jsonResponse,
  offerURI,
  setupWallet,
  VALID_PID_CLAIMS,
} from '../eudi-fixtures.js';
import { metadataPidWallet, WELL_KNOWN_URL } from './jwt-vc-issuer-fixtures.js';

describe('JWT VC Issuer Metadata による Issuer 鍵解決', () => {
  it('opt-in 未指定なら well-known を取得せず 3010(issuer_key_unresolved) のまま', async () => {
    // 従来の挙動（HTTPS iss は DID 解決できず fail-closed）が変わらないことを固定する。
    const { wallet, urls } = await metadataPidWallet({ options: {} });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
    expect(urls()).not.toContain(WELL_KNOWN_URL);
  });

  it('opt-in が true 以外（truthy な文字列）でも取得に行かない', async () => {
    // 既定の fail-closed 面を開くフラグなので、truthy な非真偽値では有効にならない。
    const { wallet, urls } = await metadataPidWallet({
      options: { jwtVcIssuerMetadataResolution: 'yes' as unknown as boolean },
    });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
    expect(urls()).not.toContain(WELL_KNOWN_URL);
  });

  it('opt-in すればインライン jwks で受領できる', async () => {
    const { wallet, urls } = await metadataPidWallet();

    const pid = await wallet.receivePID(offerURI());

    expect(pid.claims.family_name).toBe('Bianchi');
    expect(urls()).toContain(WELL_KNOWN_URL);
  });

  it('metadata の issuer が iss と一致しなければ 3010(issuer_key_unresolved)', async () => {
    // draft-ietf-oauth-sd-jwt-vc §5.3: 一致しない応答の中身は一切使ってはならない。
    const { wallet } = await metadataPidWallet({
      metadata: { issuer: 'https://other.example.eu', jwks: { keys: [ISSUER_PUBLIC_JWK] } },
    });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
  });

  it('非 HTTPS の iss は取得に行かず 3010(issuer_key_unresolved)', async () => {
    const { wallet, urls } = await metadataPidWallet({ iss: 'http://issuer.example.eu' });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
    expect(urls().some((url) => url.includes('/.well-known/jwt-vc-issuer'))).toBe(false);
  });

  it('鍵が解決できても署名が一致しなければ received_credential_signature_invalid', async () => {
    // 鍵解決（前段）と照合（後段）の理由コードが混ざらないことを固定する。
    const { wallet } = await metadataPidWallet({ signingKey: FORGED_ISSUER_PRIVATE_KEY });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'received_credential_signature_invalid',
    });
  });
});

describe('他経路との関係', () => {
  it('opt-in しても iss が DID なら従来どおり DID 解決で受領できる', async () => {
    // metadata 経路の追加が既存の DID 経路を狭めないこと（分岐の重なりが無いこと）。
    const { wallet, urls } = await metadataPidWallet({ iss: ISSUER_DID });

    const pid = await wallet.receivePID(offerURI());

    expect(pid.claims.family_name).toBe('Bianchi');
    expect(urls()).not.toContain(WELL_KNOWN_URL);
  });

  it('x5c があれば opt-in していても metadata 経路へ落ちない', async () => {
    // `x5c` は「このチェーンで検証せよ」という主張。その失敗を別経路で埋め合わせない。
    const sdJwt = buildSdJwtVcWith({
      vct: PID_VCT,
      claims: VALID_PID_CLAIMS,
      iss: ISSUER,
      x5c: ['not-a-certificate'],
    });
    const stub = createStub(sdJwt, {
      [WELL_KNOWN_URL]: () => jsonResponse({ issuer: ISSUER, jwks: { keys: [ISSUER_PUBLIC_JWK] } }),
    });
    const wallet = await setupWallet({
      eudiFetchImpl: stub.fetchImpl,
      jwtVcIssuerMetadataResolution: true,
    });

    expect(await failureOf(() => wallet.receivePID(offerURI()))).toEqual({
      code: '3010',
      reason: 'issuer_key_unresolved',
    });
    expect(stub.calls.map((call) => call.url)).not.toContain(WELL_KNOWN_URL);
  });

  it('receiveCredential も同じ経路で受領できる（両受領経路で規則が同一）', async () => {
    // OID4VCI の取得シームは receiveCredential では `opts.fetchImpl`、metadata 取得のシームは Wallet 生成時の
    // `eudiFetchImpl`（信頼材料と同じく Wallet スコープ）。ここでは同じスタブを両方へ渡す。
    const { wallet, fetchImpl } = await metadataPidWallet();

    const received = await wallet.receiveCredential(offerURI(), { fetchImpl });

    expect(received.format).toBe('sd-jwt');
  });
});
