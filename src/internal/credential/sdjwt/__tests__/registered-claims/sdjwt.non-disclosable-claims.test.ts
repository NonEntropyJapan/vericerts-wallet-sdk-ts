/**
 * 登録済み JWT クレームが `disclosureClaims` で隠せないことの回帰テスト。
 *
 * SD-JWT VC の `exp` / `nbf` を `disclosureClaims` に含めると、issuer-signed payload から
 * 平文の `exp` / `nbf` が消える。`assertTimeClaims` は「クレームが存在しない場合は評価を
 * スキップする」設計（`iat` 無しの既存 VC との後方互換）なので、この 2 つが噛み合うと
 * 期限切れ判定（3024 VC_EXPIRED）・未発効判定（3025 VC_NOT_YET_VALID）を無言で素通りできる。
 *
 * `draft-ietf-oauth-sd-jwt-vc` §2.2.2.3 は `iss` / `nbf` / `exp` / `cnf` / `vct` / `status` を
 * 選択的開示の対象にしては**ならない**（MUST NOT）と定める。一方 `sub` と `iat` は同項が
 * 選択的開示を**許容**（MAY）しており、`iat` を非開示にするのは本 SDK 固有のハードニング
 * （隠せると 4014 判定と FC-11 の発行時刻解決を同時に無効化できるため）。標準の要求と
 * 実装の追加制約を混同しないこと。
 *
 * 検証内容:
 * - `exp` を `disclosureClaims` に指定しても平文 payload に残り、期限切れが 3024 で拒否される。
 * - `nbf` を `disclosureClaims` に指定しても平文 payload に残り、未発効が 3025 で拒否される。
 * - `iat` は 平文に残る（既存挙動の固定）。
 * - `iss` / `vct` / `cnf` も Disclosure へ回らない。
 * - 登録済みでないクレームは従来どおり Disclosure へ回る（正常系の非退行）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getP256PublicKey } from '../../../../keymanager/signer.js';
import { createPrivateKeySigner } from '../../../vc/signer.js';
import { createSdJwt } from '../../sdjwt.js';
import { verifySdJwt } from '../../verify.js';

/** テスト用の固定秘密鍵。 */
const ISSUER_KEY = new Uint8Array(32).fill(7);

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false), 'P-256');
const VCT = 'https://example.com/credentials/identity';
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');

/** 固定の現在時刻（2026-01-01T00:00:00Z 近傍）。 */
const NOW = 1_767_225_600;

/** Issuer-signed JWT の payload をデコードする（署名検証はしない）。 */
function decodeIssuerPayload(sdJwt: string): Record<string, unknown> {
  const issuerJwt = sdJwt.split('~')[0] ?? '';
  const payloadPart = issuerJwt.split('.')[1] ?? '';
  return JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;
}

describe('登録済み JWT クレームは disclosureClaims で隠せない', () => {
  it('exp を disclosureClaims に指定しても平文に残り、期限切れは 3024 で拒否される', () => {
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      // 攻撃: 期限切れの `exp` を Disclosure へ回して検証をスキップさせる。
      disclosureClaims: ['exp', 'name'],
      claims: { name: 'Alice', exp: NOW - 10_000 },
      salts: { name: 'salt-name' },
      nowSeconds: NOW,
    });

    expect(decodeIssuerPayload(sdJwt).exp).toBe(NOW - 10_000);
    expect(() =>
      verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW, clockSkewSeconds: 0 }),
    ).toThrow(new VericertsError(ErrorCodes.VC_EXPIRED));
  });

  it('nbf を disclosureClaims に指定しても平文に残り、未発効は 3025 で拒否される', () => {
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      disclosureClaims: ['nbf', 'name'],
      claims: { name: 'Alice', nbf: NOW + 10_000 },
      salts: { name: 'salt-name' },
      nowSeconds: NOW,
    });

    expect(decodeIssuerPayload(sdJwt).nbf).toBe(NOW + 10_000);
    expect(() =>
      verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW, clockSkewSeconds: 0 }),
    ).toThrow(new VericertsError(ErrorCodes.VC_NOT_YET_VALID));
  });

  it('exp / nbf を同時に隠しても双方が平文に残る', () => {
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      disclosureClaims: ['exp', 'nbf', 'iat', 'name'],
      claims: { name: 'Alice', exp: NOW + 100, nbf: NOW - 100 },
      salts: { name: 'salt-name' },
      nowSeconds: NOW,
    });

    const payload = decodeIssuerPayload(sdJwt);
    expect(payload.exp).toBe(NOW + 100);
    expect(payload.nbf).toBe(NOW - 100);
    // `iat` は 既定付与され、平文に残る。
    expect(payload.iat).toBe(NOW);
    // 隠せたのは登録済みでない `name` だけ。
    expect(payload._sd).toEqual([expect.any(String)]);

    const result = verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW });
    expect(result.claims.name).toBe('Alice');
  });

  it('claims 経由で渡した iss / cnf / status も Disclosure へ回らない', () => {
    // `issuer` / `cnf` / `status` の各**オプション**は渡さず、`claims` 側に同名クレームを置く。
    // こうしないと payload 末尾でオプション由来の値が上書きするため、修正前のコードでも
    // テストが通ってしまう（トートロジー）。`claims` 経由なら平文から消えることを直接検出できる。
    const holderJwk = toJwk(getP256PublicKey(new Uint8Array(32).fill(9), false), 'P-256');
    const statusRef = { status_list: { idx: 3, uri: 'https://issuer.example/status/1' } };
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      disclosureClaims: ['iss', 'cnf', 'status', 'name'],
      claims: {
        name: 'Alice',
        iss: 'did:example:issuer',
        cnf: { jwk: holderJwk },
        status: statusRef,
      },
      salts: { name: 'salt-name' },
      nowSeconds: NOW,
    });

    const payload = decodeIssuerPayload(sdJwt);
    expect(payload.iss).toBe('did:example:issuer');
    expect(payload.cnf).toEqual({ jwk: holderJwk });
    expect(payload.status).toEqual(statusRef);
    // 隠せたのは登録済みでない `name` だけ。
    expect(payload._sd).toEqual([expect.any(String)]);
  });

  it('claims 経由の vct / iat / nbf / exp も Disclosure へ回らない', () => {
    // `vct` はオプションでも渡されるため、`claims` 側に別の値を置いて「Disclosure へ回るか」を
    // 直接見る。`claims` に入れないと payload 末尾のオプション由来の値が必ず勝ち、
    // 修正前でも pass するトートロジーになる。
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      disclosureClaims: ['vct', 'iat', 'nbf', 'exp', 'name'],
      claims: {
        name: 'Alice',
        vct: 'https://attacker.example/vct',
        iat: NOW,
        nbf: NOW - 100,
        exp: NOW + 100,
      },
      salts: { name: 'salt-name' },
      nowSeconds: NOW,
    });
    const payload = decodeIssuerPayload(sdJwt);
    expect(payload.iat).toBe(NOW);
    expect(payload.nbf).toBe(NOW - 100);
    expect(payload.exp).toBe(NOW + 100);
    // 隠せたのは登録済みでない `name` だけ（`vct` も Disclosure へ回っていない）。
    expect(payload._sd).toEqual([expect.any(String)]);
  });

  it('構造クレーム _sd / _sd_alg は Disclosure へ回らず digest 照合が壊れない', () => {
    // `claims` に `_sd` / `_sd_alg` を置いたうえで開示指定する。Disclosure へ回すと
    // payload の `_sd` が二重化・上書きされ、digest 照合（= 開示値の完全性）が壊れる。
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      disclosureClaims: ['_sd', '_sd_alg', 'name'],
      claims: { name: 'Alice', _sd: ['attacker-digest'], _sd_alg: 'attacker-alg' },
      salts: { name: 'salt-name' },
      nowSeconds: NOW,
    });

    const payload = decodeIssuerPayload(sdJwt);
    // `_sd` / `_sd_alg` は SDK が組み立てた正規の値であり、`claims` の値にも Disclosure にも
    // 置き換わっていないこと。
    expect(payload._sd_alg).toBe('sha-256');
    expect(payload._sd).toEqual([expect.any(String)]);
    expect(payload._sd).not.toContain('attacker-digest');

    // 検証が通り、開示クレームが復元できること（digest 照合が壊れていない）。
    const result = verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW });
    expect(result.claims.name).toBe('Alice');
  });

  it('登録済みでないクレームは従来どおり Disclosure へ回る（正常系）', () => {
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      disclosureClaims: ['name', 'age'],
      claims: { name: 'Alice', age: 30, nickname: 'Al' },
      salts: { name: 'salt-name', age: 'salt-age' },
      nowSeconds: NOW,
    });

    const payload = decodeIssuerPayload(sdJwt);
    expect(payload.name).toBeUndefined();
    expect(payload.age).toBeUndefined();
    expect(payload.nickname).toBe('Al');
    expect(payload._sd).toHaveLength(2);

    const result = verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW });
    expect(result.claims.name).toBe('Alice');
    expect(result.claims.age).toBe(30);
  });
});
