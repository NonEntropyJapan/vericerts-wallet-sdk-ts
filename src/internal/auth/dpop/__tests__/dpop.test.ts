/**
 * DPoP proof 生成（`createDpopProof`）と共通プリミティブのユニットテスト（実鍵・モック禁止）。
 *
 * 検証内容（RFC 9449 §4.2 / §6.1、RFC 7638 §3）:
 * - header が `{ typ: 'dpop+jwt', alg, jwk }` で、`jwk` に秘密鍵メンバ `d` を含まない。
 * - payload が `{ jti, htm, htu, iat }`。`ath` / `nonce` は指定時のみ出現する。
 * - `htu` からクエリ・フラグメントが除去される。
 * - `jti` 省略時に呼び出しごとに異なる値が生成される。
 * - `computeJwkThumbprint` が RFC 7638 正準 JSON の base64url(sha256(...)) と一致する。
 * - `computeAth` が base64url(sha256(token)) と一致する。
 * - `bindAccessTokenToDpopKey` が入力を破壊せず `cnf.jkt` を付与し、既存 `cnf` メンバを保持する。
 * - 生成側でも `x` / `y` の座標長・base64url 妥当性と `crv` を検証し、実在しない鍵に対して
 *   サムプリントを算出しない（4080）。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { bindAccessTokenToDpopKey, createDpopProof } from '../dpop.js';
import { computeAth, computeJwkThumbprint, type DpopAlg } from '../dpop-common.js';

/** テスト用の固定秘密鍵（alg ごとに別鍵）。 */
const KEYS: Record<DpopAlg, Uint8Array> = {
  ES256: new Uint8Array(32).fill(7),
  ES256K: new Uint8Array(32).fill(9),
};

/** 別鍵（サムプリントが異なることの確認用）。 */
const OTHER_KEY = new Uint8Array(32).fill(11);

/** 固定現在時刻（エポック秒）。 */
const NOW = 1_767_225_600;

const HTM = 'POST';
const HTU = 'https://api.example.com/mcp';
const ACCESS_TOKEN = 'access-token-abc123';
const NONCE = 'dpop-nonce-xyz';

/** コンパクト JWS を 3 セグメントへ分解する（noUncheckedIndexedAccess 対応）。 */
function splitJwt(jwt: string): [string, string, string] {
  const parts = jwt.split('.');
  expect(parts).toHaveLength(3);
  return [parts[0] as string, parts[1] as string, parts[2] as string];
}

/** base64url セグメントを JSON object にデコードする。 */
function decodeSeg(seg: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(seg, 'base64url').toString('utf8'));
}

/** 実行すると DPOP_PROOF_MALFORMED (4080) の VericertsError を投げることを表明する。 */
function expectMalformed(run: () => unknown): void {
  try {
    run();
    throw new Error('should have thrown');
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe(ErrorCodes.DPOP_PROOF_MALFORMED);
  }
}

describe.each<DpopAlg>(['ES256', 'ES256K'])('createDpopProof（%s）', (alg) => {
  const signer = createPrivateKeySigner(KEYS[alg], alg);

  it('header が typ/alg/公開鍵 jwk を持ち、秘密鍵メンバ d を含まない', () => {
    const proof = createDpopProof({ htm: HTM, htu: HTU, nowSeconds: NOW }, signer);
    const header = decodeSeg(splitJwt(proof)[0]);
    expect(header.typ).toBe('dpop+jwt');
    expect(header.alg).toBe(alg);
    const jwk = header.jwk as Record<string, unknown>;
    expect(Object.keys(jwk).sort()).toEqual(['crv', 'kty', 'x', 'y']);
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBe(alg === 'ES256' ? 'P-256' : 'secp256k1');
    expect(jwk.d).toBeUndefined();
  });

  it('payload が jti/htm/htu/iat を持ち、ath と nonce は既定で出現しない', () => {
    const proof = createDpopProof(
      { htm: HTM, htu: HTU, jti: '3b241101-e2bb-4255-8caf-4136c566a962', nowSeconds: NOW },
      signer,
    );
    const payload = decodeSeg(splitJwt(proof)[1]);
    expect(payload.jti).toBe('3b241101-e2bb-4255-8caf-4136c566a962');
    expect(payload.htm).toBe(HTM);
    expect(payload.htu).toBe(HTU);
    expect(payload.iat).toBe(NOW);
    expect('ath' in payload).toBe(false);
    expect('nonce' in payload).toBe(false);
  });

  it('accessToken 指定時のみ ath が入る', () => {
    const proof = createDpopProof(
      { htm: HTM, htu: HTU, accessToken: ACCESS_TOKEN, nowSeconds: NOW },
      signer,
    );
    const payload = decodeSeg(splitJwt(proof)[1]);
    expect(payload.ath).toBe(computeAth(ACCESS_TOKEN));
  });

  it('nonce 指定時のみ nonce が入る', () => {
    const proof = createDpopProof({ htm: HTM, htu: HTU, nonce: NONCE, nowSeconds: NOW }, signer);
    const payload = decodeSeg(splitJwt(proof)[1]);
    expect(payload.nonce).toBe(NONCE);
  });

  it('htu からクエリ・フラグメントが除去される', () => {
    const proof = createDpopProof(
      { htm: HTM, htu: 'https://api.example.com/mcp?x=1#f', nowSeconds: NOW },
      signer,
    );
    expect(decodeSeg(splitJwt(proof)[1]).htu).toBe('https://api.example.com/mcp');
  });

  it('jti 省略時は呼び出しごとに異なる値が生成される', () => {
    const first = decodeSeg(splitJwt(createDpopProof({ htm: HTM, htu: HTU }, signer))[1]);
    const second = decodeSeg(splitJwt(createDpopProof({ htm: HTM, htu: HTU }, signer))[1]);
    expect(typeof first.jti).toBe('string');
    expect(first.jti).not.toBe(second.jti);
  });

  it('nowSeconds 省略時は Date.now() ベースの iat になる', () => {
    const before = Math.floor(Date.now() / 1000);
    const payload = decodeSeg(splitJwt(createDpopProof({ htm: HTM, htu: HTU }, signer))[1]);
    const after = Math.floor(Date.now() / 1000);
    expect(payload.iat as number).toBeGreaterThanOrEqual(before);
    expect(payload.iat as number).toBeLessThanOrEqual(after);
  });

  it('htm が空文字列なら DPOP_PROOF_MALFORMED (4080)', () => {
    try {
      createDpopProof({ htm: '', htu: HTU, nowSeconds: NOW }, signer);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.DPOP_PROOF_MALFORMED);
    }
  });

  it('htu がパース不能なら DPOP_PROOF_MALFORMED (4080)', () => {
    try {
      createDpopProof({ htm: HTM, htu: 'not a uri', nowSeconds: NOW }, signer);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.DPOP_PROOF_MALFORMED);
    }
  });
});

describe('createDpopProof の alg 許容集合', () => {
  // 回帰テスト: `DpopAlg` を `CredentialAlg` の別名にしていた頃は、`CredentialAlg` に `EdDSA` が
  // 追加されるだけで生成側の許容集合が暗黙に広がった。DPoP では ES256 / ES256K だけを使う。
  it('DPoP 非対応 alg（EdDSA）の signer は DPOP_PROOF_MALFORMED (4080)', () => {
    const signer = createPrivateKeySigner(new Uint8Array(32).fill(13), 'EdDSA');
    expectMalformed(() => createDpopProof({ htm: HTM, htu: HTU, nowSeconds: NOW }, signer));
  });
});

describe.each<DpopAlg>(['ES256', 'ES256K'])('computeJwkThumbprint（%s）', (alg) => {
  const signer = createPrivateKeySigner(KEYS[alg], alg);
  const jwk = signer.publicKeyJwk as Record<string, string>;

  it('RFC 7638 正準 JSON の base64url(sha256(...)) と一致する', () => {
    // テスト内で独立に正準 JSON（メンバ辞書順・空白なし）を組み立てる。
    const canonical = `{"crv":"${jwk.crv}","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`;
    const expected = base64urlnopad.encode(sha256(new TextEncoder().encode(canonical)));
    expect(computeJwkThumbprint(signer.publicKeyJwk, alg)).toBe(expected);
  });

  it('同一鍵で決定的、異なる鍵で異なる', () => {
    const other = createPrivateKeySigner(OTHER_KEY, alg);
    expect(computeJwkThumbprint(signer.publicKeyJwk, alg)).toBe(
      computeJwkThumbprint(signer.publicKeyJwk, alg),
    );
    expect(computeJwkThumbprint(other.publicKeyJwk, alg)).not.toBe(
      computeJwkThumbprint(signer.publicKeyJwk, alg),
    );
  });

  it('秘密鍵メンバ d を含む JWK は DPOP_PROOF_MALFORMED (4080)', () => {
    try {
      computeJwkThumbprint({ ...jwk, d: 'private' }, alg);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.DPOP_PROOF_MALFORMED);
    }
  });
});

describe('computeAth', () => {
  it('base64url(sha256(token)) と一致する', () => {
    const expected = base64urlnopad.encode(sha256(new TextEncoder().encode(ACCESS_TOKEN)));
    expect(computeAth(ACCESS_TOKEN)).toBe(expected);
  });
});

describe('bindAccessTokenToDpopKey', () => {
  const signer = createPrivateKeySigner(KEYS.ES256, 'ES256');
  const jkt = computeJwkThumbprint(signer.publicKeyJwk, 'ES256');

  it('cnf.jkt を付与し、入力オブジェクトを破壊しない', () => {
    const payload = { sub: 'user-1', scope: 'mcp' };
    const bound = bindAccessTokenToDpopKey(payload, signer.publicKeyJwk, 'ES256');
    expect(bound.cnf.jkt).toBe(jkt);
    expect(bound.sub).toBe('user-1');
    expect('cnf' in payload).toBe(false);
    expect(bound).not.toBe(payload);
  });

  it('既存の cnf メンバを保持する', () => {
    const payload = { sub: 'user-1', cnf: { 'x5t#S256': 'cert-thumb' } };
    const bound = bindAccessTokenToDpopKey(payload, signer.publicKeyJwk, 'ES256');
    expect(bound.cnf.jkt).toBe(jkt);
    expect((bound.cnf as Record<string, unknown>)['x5t#S256']).toBe('cert-thumb');
    expect(payload.cnf).toEqual({ 'x5t#S256': 'cert-thumb' });
  });
});

describe('生成側の JWK 構造検証（4080）', () => {
  const signer = createPrivateKeySigner(KEYS.ES256, 'ES256');
  const jwk = signer.publicKeyJwk as Record<string, string>;

  it('bindAccessTokenToDpopKey は実在しない鍵にサムプリントを付与しない', () => {
    // 回帰: 座標長を検証していなかった頃は、デコードできない x / y でも cnf.jkt が返っていた。
    expectMalformed(() =>
      bindAccessTokenToDpopKey(
        { sub: 'u' },
        { kty: 'EC', crv: 'P-256', x: 'not-a-key', y: 'zz' },
        'ES256',
      ),
    );
  });

  it.each<[string, Record<string, unknown>]>([
    ['x / y のデコード長が 32 バイトでない', { kty: 'EC', crv: 'P-256', x: 'AAAA', y: 'AAAA' }],
    ['x / y が base64url でない', { kty: 'EC', crv: 'P-256', x: '!!!!', y: '!!!!' }],
  ])('computeJwkThumbprint: %s', (_label, invalidJwk) => {
    expectMalformed(() => computeJwkThumbprint(invalidJwk, 'ES256'));
  });

  it('crv が無い JWK は computeJwkThumbprint / bindAccessTokenToDpopKey とも拒否する', () => {
    const noCrv = { kty: 'EC', x: jwk.x as string, y: jwk.y as string };
    expectMalformed(() => computeJwkThumbprint(noCrv, 'ES256'));
    expectMalformed(() => bindAccessTokenToDpopKey({ sub: 'u' }, noCrv, 'ES256'));
  });
});

describe('DpopAlg の許容集合（4080）', () => {
  // 回帰: `DpopAlg` を `CredentialAlg` の別名にしていた頃は、`CredentialAlg` に `EdDSA` が
  // 追加されるだけで受理範囲が広がった。DPoP は ES256 / ES256K のみを受理する。
  it('EdDSA 署名器で createDpopProof は 4080 になる', () => {
    const edSigner = createPrivateKeySigner(new Uint8Array(32).fill(13), 'EdDSA');
    expect(() => createDpopProof({ htm: HTM, htu: HTU, nowSeconds: NOW }, edSigner)).toThrow(
      VericertsError,
    );
    try {
      createDpopProof({ htm: HTM, htu: HTU, nowSeconds: NOW }, edSigner);
      expect.unreachable();
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.DPOP_PROOF_MALFORMED);
    }
  });

  it.each(['ES256', 'ES256K'] as const)('%s の signer では従来どおり生成できる', (alg) => {
    const proof = createDpopProof(
      { htm: HTM, htu: HTU, nowSeconds: NOW },
      createPrivateKeySigner(KEYS[alg], alg),
    );
    expect(decodeSeg(splitJwt(proof)[0]).alg).toBe(alg);
  });
});
