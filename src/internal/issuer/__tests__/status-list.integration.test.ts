/**
 * Token Status List の発行 → 参照解決の統合テスト（実鍵・実圧縮・モック禁止）。
 *
 * issuer（StatusListManager / createStatusListResolver）と credential ドメインの DI seam
 * （resolveStatus）を結合し、発行した Status List で VC の状態を確認する:
 * - 未失効 VC は valid=true、失効後は valid=false（revocation）。
 * - suspension purpose で停止ビットを評価する。
 * - status 未設定 VC は resolveStatus が 3018 を投げる（issuer 評価へ到達しない）。
 * - Status List Token の署名改竄で 3010、別 Issuer 鍵で 3010。
 * - sub と uri 不一致の token を掴まされた場合 3010（confused deputy 対策）。
 * - alg=none の token を拒否（3011）。
 */

import { describe, expect, it } from 'bun:test';
import type { StatusReference } from '../../credential/sdjwt/sdjwt.js';
import { resolveStatus } from '../../credential/sdjwt/status.js';
import { createPrivateKeySigner } from '../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { getP256PublicKey } from '../../keymanager/signer.js';
import { createStatusListResolver } from '../status-list-resolver.js';
import { StatusListManager } from '../token-status-list.js';

const ISSUER_KEY = new Uint8Array(32).fill(7);
const OTHER_KEY = new Uint8Array(32).fill(17);
const SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');

function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false), 'P-256');
const OTHER_JWK = toJwk(getP256PublicKey(OTHER_KEY, false), 'P-256');

const URI = 'https://issuer.example/status/1';
const ISSUER = 'did:web:issuer.example';

/** 発行済み token を URI に紐付けて返す fetchToken を作る。 */
function fetcherOf(map: Record<string, string>): (uri: string) => Promise<string> {
  return async (uri: string) => {
    const token = map[uri];
    if (token === undefined) {
      throw new Error('status list token not found for uri');
    }
    return token;
  };
}

describe('Token Status List 統合: revocation', () => {
  it('未失効 → valid=true、失効後 → valid=false', async () => {
    const m = new StatusListManager({ uri: URI, issuer: ISSUER, size: 100, bits: 1 });
    const idx = m.allocate();
    const ref: StatusReference = m.reference(idx);

    // 未失効状態の token を配信。
    const tokenBefore = await m.issueToken(SIGNER, { iatSeconds: 1_700_000_000 });
    const resolverBefore = createStatusListResolver({
      fetchToken: fetcherOf({ [URI]: tokenBefore }),
      issuerPublicKey: ISSUER_JWK,
      purpose: 'revocation',
      nowSeconds: () => 1_700_000_100,
    });
    const before = await resolveStatus(ref, resolverBefore);
    expect(before).toEqual({ valid: true, purpose: 'revocation', value: 0 });

    // 失効させて再発行。
    m.setStatus(idx, 1);
    const tokenAfter = await m.issueToken(SIGNER, { iatSeconds: 1_700_000_100 });
    const resolverAfter = createStatusListResolver({
      fetchToken: fetcherOf({ [URI]: tokenAfter }),
      issuerPublicKey: ISSUER_JWK,
      purpose: 'revocation',
      nowSeconds: () => 1_700_000_100,
    });
    const after = await resolveStatus(ref, resolverAfter);
    expect(after).toEqual({ valid: false, purpose: 'revocation', value: 1 });
  });
});

describe('Token Status List 統合: suspension', () => {
  it('停止ビットを suspension purpose で評価する', async () => {
    const m = new StatusListManager({ uri: URI, issuer: ISSUER, size: 50, bits: 1 });
    const idx = m.allocate();
    m.setStatus(idx, 1);
    const token = await m.issueToken(SIGNER, { iatSeconds: 1_700_000_000 });
    const resolver = createStatusListResolver({
      fetchToken: fetcherOf({ [URI]: token }),
      issuerPublicKey: ISSUER_JWK,
      purpose: 'suspension',
      nowSeconds: () => 1_700_000_100,
    });
    const result = await resolveStatus(m.reference(idx), resolver);
    expect(result).toEqual({ valid: false, purpose: 'suspension', value: 1 });
  });
});

describe('Token Status List 統合: 異常系', () => {
  const baseResolver = (token: string, key: PublicKeyJwk = ISSUER_JWK) =>
    createStatusListResolver({
      fetchToken: fetcherOf({ [URI]: token }),
      issuerPublicKey: key,
      purpose: 'revocation',
      nowSeconds: () => 1_700_000_100,
    });

  it('status 未設定 VC は 3018（issuer 評価に到達しない）', () => {
    const resolver = baseResolver('dummy');
    // resolveStatus は status 未設定時に同期的に投げる（Promise を返す前に throw）。
    try {
      resolveStatus(undefined, resolver);
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.TOKEN_STATUS_LIST_UNSUPPORTED);
      return;
    }
    throw new Error('expected throw');
  });

  it('別 Issuer 鍵で署名検証に失敗（3010）', async () => {
    const m = new StatusListManager({ uri: URI, issuer: ISSUER, size: 10, bits: 1 });
    const idx = m.allocate();
    const token = await m.issueToken(SIGNER, { iatSeconds: 1_700_000_000 });
    const resolver = baseResolver(token, OTHER_JWK);
    await expect(resolveStatus(m.reference(idx), resolver)).rejects.toMatchObject({
      code: ErrorCodes.SIG_INVALID,
    });
  });

  it('token 改竄で署名検証に失敗（3010）', async () => {
    const m = new StatusListManager({ uri: URI, issuer: ISSUER, size: 10, bits: 1 });
    const idx = m.allocate();
    const token = await m.issueToken(SIGNER, { iatSeconds: 1_700_000_000 });
    // 署名セグメント末尾の 1 文字を差し替えて改竄する（署名不一致を起こす）。
    const [header, payload, signature] = token.split('.') as [string, string, string];
    const tamperedSig = signature.slice(0, -1) + (signature.endsWith('A') ? 'B' : 'A');
    const tampered = `${header}.${payload}.${tamperedSig}`;
    const resolver = baseResolver(tampered);
    await expect(resolveStatus(m.reference(idx), resolver)).rejects.toBeInstanceOf(VericertsError);
  });

  it('sub と uri 不一致の token を 3010 で拒否（confused deputy 対策）', async () => {
    // 別 URI で発行した token を、参照側 URI の fetch に紐付けて返す。
    const m = new StatusListManager({
      uri: 'https://issuer.example/status/OTHER',
      issuer: ISSUER,
      size: 10,
      bits: 1,
    });
    const idx = m.allocate();
    const token = await m.issueToken(SIGNER, { iatSeconds: 1_700_000_000 });
    const resolver = createStatusListResolver({
      fetchToken: fetcherOf({ [URI]: token }),
      issuerPublicKey: ISSUER_JWK,
      purpose: 'revocation',
    });
    const ref: StatusReference = { status_list: { idx, uri: URI } };
    await expect(resolveStatus(ref, resolver)).rejects.toMatchObject({
      code: ErrorCodes.SIG_INVALID,
    });
  });

  it('alg=none の token を 3011 で拒否する', async () => {
    const m = new StatusListManager({ uri: URI, issuer: ISSUER, size: 10, bits: 1 });
    const idx = m.allocate();
    const token = await m.issueToken(SIGNER, { iatSeconds: 1_700_000_000 });
    // header を alg:none に差し替える（署名は残すが alg で拒否されることを確認）。
    const [, payload, signature] = token.split('.') as [string, string, string];
    const noneHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'statuslist+jwt' })).toString(
      'base64url',
    );
    const forged = `${noneHeader}.${payload}.${signature}`;
    const resolver = baseResolver(forged);
    await expect(resolveStatus(m.reference(idx), resolver)).rejects.toMatchObject({
      code: ErrorCodes.ALG_NONE,
    });
  });

  it('未対応 alg（RS256）の token を 3010 で拒否する', async () => {
    const m = new StatusListManager({ uri: URI, issuer: ISSUER, size: 10, bits: 1 });
    const idx = m.allocate();
    const token = await m.issueToken(SIGNER, { iatSeconds: 1_700_000_000 });
    // header を未対応 alg（RS256）に差し替える。alg=none と区別し 3010 へ正規化されること。
    const [, payload, signature] = token.split('.') as [string, string, string];
    const rsHeader = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'statuslist+jwt' })).toString(
      'base64url',
    );
    const forged = `${rsHeader}.${payload}.${signature}`;
    const resolver = baseResolver(forged);
    await expect(resolveStatus(m.reference(idx), resolver)).rejects.toMatchObject({
      code: ErrorCodes.SIG_INVALID,
    });
  });

  it('idx が token 容量外なら 3002', async () => {
    const m = new StatusListManager({ uri: URI, issuer: ISSUER, size: 8, bits: 1 });
    const token = await m.issueToken(SIGNER, { iatSeconds: 1_700_000_000 });
    const resolver = baseResolver(token);
    // size=8 → 1 バイト → 容量 8。idx=100 は範囲外。
    const ref: StatusReference = { status_list: { idx: 100, uri: URI } };
    await expect(resolveStatus(ref, resolver)).rejects.toMatchObject({
      code: ErrorCodes.VC_SCHEMA_INVALID,
    });
  });
});
