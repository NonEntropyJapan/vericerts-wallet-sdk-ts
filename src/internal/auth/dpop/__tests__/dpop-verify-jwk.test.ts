/**
 * DPoP proof の header `alg` / `jwk` 検証に関する回帰テスト（実鍵・モック禁止）。
 *
 * RFC 9449 §4.3 の手順 5〜7 は `alg`、`jwk` による署名検証、秘密鍵の混入を扱う。
 * このテストでは SDK が許容するアルゴリズム、公開鍵の形式、署名不一致時のエラーを検証する。
 * - `alg` に `Object.prototype` のメンバ名を指定してもプロトタイプチェーン経由で
 *   「対応済み alg」と誤判定されず、`TypeError` ではなく 4080 になる（CRITICAL 回帰）。
 * - `alg` の許容集合が DPoP 固有の `DPOP_SUPPORTED_ALGS`（`ES256` / `ES256K`）に閉じており、
 *   共有レジストリ `ALG_SPECS` へ alg を追加しても DPoP の受理範囲が広がらない（MAJOR 回帰）。
 * - header `jwk` に `crv` が無い場合 → 4080。
 * - header `jwk` の `x` / `y` が 32 バイトへデコードできない / base64url でない場合 → 4080
 *   （署名検証まで進んで 4081 にならないこと）。
 * - 上記の追加検証によって、本物の署名不正（4081）が握り潰されないこと。
 *
 * `verifyDpopProof` の他の検証段階（鮮度・HTTP 束縛・`ath` / `jkt`）は `dpop-verify.test.ts`
 * が担う。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { signCompactJws } from '../../../credential/vc/compact-jws.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../errors.js';
import { ALG_SPECS } from '../../../identity/jwt/jwk-key.js';
import { DPOP_SUPPORTED_ALGS, type DpopAlg, isDpopAlg } from '../dpop-common.js';
import { verifyDpopProof } from '../dpop-verify.js';

/** テスト用の固定秘密鍵。 */
const PRIVATE_KEY = new Uint8Array(32).fill(7);

/** 別鍵（署名不一致の確認用）。 */
const OTHER_PRIVATE_KEY = new Uint8Array(32).fill(11);

/** 固定現在時刻（エポック秒）。 */
const NOW = 1_767_225_600;

const HTM = 'POST';
const HTU = 'https://api.example.com/mcp';

/** 検証条件の既定値（`htm` / `htu` / `nowSeconds` のみ）。 */
const BASE = { htm: HTM, htu: HTU, nowSeconds: NOW } as const;

/** 形式として妥当な payload（header 検証まで到達させるための素材）。 */
const CLAIMS = { jti: 'jti-1', htm: HTM, htu: HTU, iat: NOW };

/** 長さだけ正しい 32 バイト座標（base64url、パディングなし）。 */
const COORD_32 = base64urlnopad.encode(new Uint8Array(32).fill(3));

/** 形式として妥当な署名セグメント（署名検証まで到達しないケース用のダミー）。 */
const DUMMY_SIGNATURE = base64urlnopad.encode(new Uint8Array(64));

/** UTF-8 JSON を base64url（パディングなし）セグメントへ符号化する。 */
function seg(value: unknown): string {
  return base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(value)));
}

/** header / payload を指定してコンパクト JWS を手組みする（署名は検証させない）。 */
function assembleProof(header: unknown, payload: unknown = CLAIMS): string {
  return `${seg(header)}.${seg(payload)}.${DUMMY_SIGNATURE}`;
}

/** `verifyDpopProof` が指定コードの VericertsError を投げることを表明し、その例外を返す。 */
function expectCode(
  proof: string,
  options: Parameters<typeof verifyDpopProof>[1],
  code: ErrorCode,
): VericertsError {
  try {
    verifyDpopProof(proof, options);
    throw new Error('should have thrown');
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe(code);
    return e as VericertsError;
  }
}

describe('verifyDpopProof header alg のプロトタイプチェーンバイパス（4080）', () => {
  // 回帰テスト: `ALG_SPECS[alg] === undefined` で対応判定していた頃は、`Object.prototype` の
  // メンバ名（toString / constructor / __proto__ 等）を alg に指定すると継承値が返るため未対応の
  // alg が素通りし、`spec.verify` が関数でないことによる素の TypeError が漏れていた。
  // 現在は `Object.hasOwn` で自身のプロパティのみを見るため、必ず VericertsError(4080) になる。
  it.each([
    'toString',
    'constructor',
    'valueOf',
    'hasOwnProperty',
    '__proto__',
  ])('alg が Object.prototype のメンバ名 %s でも 4080（TypeError にならない）', (alg) => {
    // crv を意図的に省き、旧実装では spec.crv（undefined）と一致してしまう状況を再現する。
    const header = { typ: 'dpop+jwt', alg, jwk: { kty: 'EC', x: COORD_32, y: COORD_32 } };
    try {
      verifyDpopProof(assembleProof(header), BASE);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect(e).not.toBeInstanceOf(TypeError);
      expect((e as VericertsError).code).toBe(ErrorCodes.DPOP_PROOF_MALFORMED);
    }
  });
});

describe('verifyDpopProof header jwk の構造検証（4080）', () => {
  it('jwk に crv が無い', () => {
    const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: { kty: 'EC', x: COORD_32, y: COORD_32 } };
    expectCode(assembleProof(header), BASE, ErrorCodes.DPOP_PROOF_MALFORMED);
  });

  it('x / y のデコード長が 32 バイトでない場合は 4081 ではなく 4080', () => {
    const jwk = { kty: 'EC', crv: 'P-256', x: 'AAAA', y: 'AAAA' };
    const error = expectCode(
      assembleProof({ typ: 'dpop+jwt', alg: 'ES256', jwk }),
      BASE,
      ErrorCodes.DPOP_PROOF_MALFORMED,
    );
    expect(error.code).not.toBe(ErrorCodes.DPOP_SIGNATURE_INVALID);
  });

  it('x / y が base64url でない場合は 4081 ではなく 4080', () => {
    const jwk = { kty: 'EC', crv: 'P-256', x: '!!!!', y: '!!!!' };
    const error = expectCode(
      assembleProof({ typ: 'dpop+jwt', alg: 'ES256', jwk }),
      BASE,
      ErrorCodes.DPOP_PROOF_MALFORMED,
    );
    expect(error.code).not.toBe(ErrorCodes.DPOP_SIGNATURE_INVALID);
  });
});

describe('verifyDpopProof は本物の署名不正を握り潰さない（4081）', () => {
  it('jwk が正当でも別鍵で署名した proof は 4081', () => {
    const signer = createPrivateKeySigner(PRIVATE_KEY, 'ES256');
    const other = createPrivateKeySigner(OTHER_PRIVATE_KEY, 'ES256');
    const proof = signCompactJws(
      { typ: 'dpop+jwt', alg: 'ES256', jwk: signer.publicKeyJwk },
      CLAIMS,
      other,
    );
    expectCode(proof, BASE, ErrorCodes.DPOP_SIGNATURE_INVALID);
  });
});

describe('DPoP alg 許容集合は共有レジストリから独立している（4080）', () => {
  it('許容集合はちょうど ES256 / ES256K の 2 種類', () => {
    expect([...DPOP_SUPPORTED_ALGS].sort()).toEqual(['ES256', 'ES256K']);
  });

  it.each<DpopAlg>(['ES256', 'ES256K'])('%s は許容される', (alg) => {
    expect(isDpopAlg(alg)).toBe(true);
  });

  it.each([
    'none',
    'EdDSA',
    'Ed25519',
    'RS256',
    'HS256',
    'PS256',
    'ES384',
    'ES512',
    'es256',
    '',
  ])('未対応 alg %s は許容されない', (alg) => {
    expect(isDpopAlg(alg)).toBe(false);
  });

  // `it.each` は行が配列だと引数へ展開されるため、各ケースを 1 要素タプルで包む。
  it.each<[unknown]>([
    [undefined],
    [null],
    [123],
    [{}],
    [['ES256']],
    [new String('ES256')],
  ])('文字列でない alg %p は許容されない', (value) => {
    expect(isDpopAlg(value)).toBe(false);
  });

  // 回帰テスト: 許容判定を共有レジストリ ALG_SPECS のキー集合に委ねていた頃は、他機能のために
  // レジストリへ alg が追加されるだけで DPoP でも自動的に受理されてしまった（許容集合の暗黙拡大）。
  // 現在は DPoP 側で列挙を閉じているため、レジストリが増えても受理範囲は変わらない。
  it('ALG_SPECS に alg を追加しても DPoP は受理しない', () => {
    const injected = 'ES256-INJECTED';
    // 検証関数は無条件に成功させ、許容判定を素通りしたら署名検証を通ってしまう状況を再現する。
    ALG_SPECS[injected] = { crv: 'P-256', kty: 'EC', verify: () => true };
    try {
      expect(Object.hasOwn(ALG_SPECS, injected)).toBe(true);
      expect(isDpopAlg(injected)).toBe(false);
      const jwk = { kty: 'EC', crv: 'P-256', x: COORD_32, y: COORD_32 };
      expectCode(
        assembleProof({ typ: 'dpop+jwt', alg: injected, jwk }),
        BASE,
        ErrorCodes.DPOP_PROOF_MALFORMED,
      );
    } finally {
      delete ALG_SPECS[injected];
    }
  });
});
