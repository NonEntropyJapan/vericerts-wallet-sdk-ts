/**
 * VC の日付フィールドに対する null プロトタイプ耐性テスト。
 *
 * JWT-VC の payload は `parseJsonWithoutPrototype` を通ってデコードされるため、内包 VC
 * （`payload.vc`）のオブジェクト値は `Object.prototype` を継承せず `toString` / `valueOf` を
 * 持たない。`assertVerifiableCredential` は `issuanceDate` を string に narrow する一方
 * `expirationDate` は `!== undefined` を見るだけだったため、型不正な値が
 * `isoToNumericDate` → `Date.parse` に届き、暗黙の `ToPrimitive` が
 * `TypeError: No default value` になっていた（`verifyCredential` の文書化された失敗面 3002 を
 * 迂回して生の例外が漏れる）。
 *
 * **素のオブジェクトリテラルでは再現しない**（`Date.parse('[object Object]')` が `NaN` になり
 * 既存の `Number.isFinite` ガードで 3002 に倒れる）。必ずパース境界を通した値で検証すること。
 *
 * 塞ぎ方は 2 層:
 * - 構造検証の入口（`assertVerifiableCredential`）で `expirationDate` を string に narrow する。
 * - 共有シンク（`isoToNumericDate`）が非文字列を「解釈不能な ISO」と同じ 3002 へ正規化する。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getP256PublicKey } from '../../../../keymanager/signer.js';
import { parseJsonWithoutPrototype } from '../../../../prototype-safety/parse-json.js';
import { parseVerifiableCredential } from '../../../presentation/vc-assert.js';
import { isoToNumericDate } from '../../numeric-date.js';
import { createPrivateKeySigner } from '../../signer.js';
import { verifyCredential } from '../../verify.js';

/** テスト用の固定秘密鍵（ES256 / P-256）。 */
const P256_KEY = new Uint8Array(32).fill(7);
/** 固定の現在時刻（エポック秒、2026-01-01T00:00:00Z 近傍）。 */
const NOW = 1_767_225_600;
const ISSUANCE = '2025-12-01T00:00:00Z';
const EXPIRATION = '2027-01-01T00:00:00Z';

const signer = createPrivateKeySigner(P256_KEY, 'ES256');

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array): PublicKeyJwk {
  const enc = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: enc(pub.subarray(1, 33)), y: enc(pub.subarray(33, 65)) };
}

const jwk = toJwk(getP256PublicKey(P256_KEY, false));

/** 任意の payload を ES256 で署名してコンパクト JWS を組み立てる。 */
function signPayload(payload: Record<string, unknown>): string {
  const b64u = (text: string): string => base64urlnopad.encode(new TextEncoder().encode(text));
  const signingInput = `${b64u(JSON.stringify({ alg: 'ES256', typ: 'JWT' }))}.${b64u(JSON.stringify(payload))}`;
  return `${signingInput}.${base64urlnopad.encode(signer.sign(new TextEncoder().encode(signingInput)))}`;
}

/** VC 本文の JSON（`expirationDate` を任意の値に差し替えられる）。 */
function vcJson(expirationDate: unknown): Record<string, unknown> {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject' },
    issuanceDate: ISSUANCE,
    id: 'urn:uuid:1234',
    expirationDate,
  };
}

describe('VC の expirationDate 型検証', () => {
  it('expirationDate がオブジェクトの JWT-VC は TypeError にならず 3002 になる', () => {
    // envelope 側のクレームは正当な値で埋め、body 側の `expirationDate` だけを型不正にする
    // （`assertTimeClaims` を通過させ、envelope↔body 突合の日付変換まで到達させるため）。
    const vc = vcJson({});
    const jwt = signPayload({
      iss: 'did:example:issuer',
      sub: 'did:example:subject',
      jti: 'urn:uuid:1234',
      nbf: isoToNumericDate(ISSUANCE),
      exp: isoToNumericDate(EXPIRATION),
      vc,
    });

    let error: unknown;
    try {
      verifyCredential(jwt, { key: { publicKeyJwk: jwk }, nowSeconds: NOW });
    } catch (caught) {
      error = caught;
    }

    expect(error).not.toBeInstanceOf(TypeError);
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
  });

  it('parseVerifiableCredential は型不正な expirationDate を 3002 で拒否する', () => {
    // 構造検証の入口で塞ぐ層。JSON 文字列経由（＝パース境界）で null プロトタイプ値を作る。
    expect(() => parseVerifiableCredential(JSON.stringify(vcJson({})))).toThrow(VericertsError);

    const error = (() => {
      try {
        parseVerifiableCredential(JSON.stringify(vcJson({})));
        return undefined;
      } catch (caught) {
        return caught;
      }
    })();
    expect((error as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
  });

  it('isoToNumericDate は null プロトタイプ値を 3002 へ正規化する（共有シンクの層）', () => {
    const parsed = parseJsonWithoutPrototype('{"expirationDate":{}}') as Record<string, unknown>;
    const value = parsed.expirationDate as string;
    // 前提: パース境界を通った値は toString / valueOf を持たない（素のリテラルとの差分）。
    expect(Object.getPrototypeOf(value)).toBeNull();

    let error: unknown;
    try {
      isoToNumericDate(value);
    } catch (caught) {
      error = caught;
    }

    expect(error).not.toBeInstanceOf(TypeError);
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
  });

  it('妥当な expirationDate は従来どおり受理される（正常系）', () => {
    const vc = vcJson(EXPIRATION);
    const jwt = signPayload({
      iss: 'did:example:issuer',
      sub: 'did:example:subject',
      jti: 'urn:uuid:1234',
      nbf: isoToNumericDate(ISSUANCE),
      exp: isoToNumericDate(EXPIRATION),
      vc,
    });

    const verified = verifyCredential(jwt, { key: { publicKeyJwk: jwk }, nowSeconds: NOW });

    expect(verified.payload.exp).toBe(isoToNumericDate(EXPIRATION));
    expect(parseVerifiableCredential(JSON.stringify(vc)).expirationDate).toBe(EXPIRATION);
  });
});
