/**
 * `Object.prototype` 汚染下でも署名対象 payload に汚染値が載らないことの回帰テスト。
 *
 * SD-JWT VC の登録済みクレームの取り扱いを検証する。
 *
 * 欠陥時の挙動: `opts.cnf` / `opts.status` / `opts.issuer` をプロトタイプ鎖越しに読むため、
 * これらを省略した正当な発行でも汚染値が **issuer-signed JWT の payload（= 署名対象）** に
 * 焼き付く。`cnf` なら攻撃者の鍵への Holder バインド、`status` なら攻撃者が制御する
 * 失効リスト参照が署名済み VC に載る。`'iat' in opts.claims` は `Object.prototype.iat` 汚染で
 * 「呼び出し側が明示した」と誤判定し、既定 `iat` が付かず 4014（未来 iat）判定が無言で消える。
 *
 * 末尾の describe は同じ「読み取り規律」の欠陥を own アクセサ側から固定する。
 * `opts.claims` を 2 度読むと、1 回目（`Object.entries`）と 2 回目（`Object.hasOwn(…, 'iat')`）で
 * 別の値を返すアクセサにより、汚染なしでも既定 `iat` の抑止と平文／`_sd` の食い違いを作れる。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../../keymanager/signer.js';
import { createPrivateKeySigner } from '../../../vc/signer.js';
import { type CreateSdJwtOptions, createSdJwt, parseSdJwt } from '../../sdjwt.js';

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_KEY = new Uint8Array(32).fill(7);
const ATTACKER_KEY = new Uint8Array(32).fill(66);
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const ATTACKER_JWK = toJwk(getSecp256k1PublicKey(ATTACKER_KEY, false), 'secp256k1');
const HOLDER_JWK = toJwk(getP256PublicKey(new Uint8Array(32).fill(11), false), 'P-256');
const VCT = 'https://example.com/credentials/identity';
const ISSUED_AT = 1_000_000;

/** 発行した SD-JWT の issuer-signed payload をデコードする。 */
function payloadOf(sdJwt: string): Record<string, unknown> {
  const segment = parseSdJwt(sdJwt).issuerJwt.split('.')[1] as string;
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
}

/** `cnf` / `status` / `issuer` / `salts` / `nowSeconds` / `typ` をすべて省略した最小発行。 */
function issueMinimal(): string {
  return createSdJwt(ISSUER_SIGNER, {
    vct: VCT,
    disclosureClaims: ['name'],
    claims: { name: 'Alice' },
    nowSeconds: ISSUED_AT,
  });
}

describe('createSdJwt: Object.prototype 汚染', () => {
  it('cnf / status / iss を省略した発行に汚染値が混入しない', () => {
    const payload = withPollutedPrototype(
      {
        cnf: { jwk: ATTACKER_JWK },
        status: { status_list: { idx: 1, uri: 'https://attacker.example/status/1' } },
        issuer: 'did:example:attacker',
      },
      () => payloadOf(issueMinimal()),
    );
    expect(payload.cnf).toBeUndefined();
    expect(payload.status).toBeUndefined();
    expect(payload.iss).toBeUndefined();
    expect(Object.hasOwn(payload, 'cnf')).toBe(false);
    expect(Object.hasOwn(payload, 'status')).toBe(false);
    expect(Object.hasOwn(payload, 'iss')).toBe(false);
  });

  it('claims の iat 汚染で既定 iat が抑止されない', () => {
    // `'iat' in opts.claims` だと汚染値により「明示済み」と誤判定し、payload から iat が消える。
    const payload = withPollutedPrototype({ iat: 4_000_000_000 }, () => payloadOf(issueMinimal()));
    expect(payload.iat).toBe(ISSUED_AT);
  });

  it('nowSeconds を省略した発行で汚染値が iat に採用されない', () => {
    const before = Math.floor(Date.now() / 1000);
    const payload = withPollutedPrototype({ nowSeconds: 4_000_000_000 }, () =>
      payloadOf(
        createSdJwt(ISSUER_SIGNER, { vct: VCT, disclosureClaims: [], claims: { name: 'Alice' } }),
      ),
    );
    expect(payload.iat).toBeGreaterThanOrEqual(before);
    expect(payload.iat).toBeLessThan(4_000_000_000);
  });

  it('salts を省略した発行で汚染値が Disclosure の salt に使われない', () => {
    // salt が攻撃者に既知だと、_sd ダイジェストの事前計算で未開示クレームを当てられる。
    // 汚染キーは `salts` 自体（`opts.salts?.[name]` は `salts` 省略時に汚染 map を丸ごと拾う）。
    const polluted = withPollutedPrototype({ salts: { name: 'attacker-known-salt' } }, () =>
      createSdJwt(ISSUER_SIGNER, {
        vct: VCT,
        disclosureClaims: ['name'],
        claims: { name: 'Alice' },
        nowSeconds: ISSUED_AT,
      }),
    );
    const disclosure = parseSdJwt(polluted).disclosures[0];
    expect(disclosure).toBeDefined();
    expect((disclosure as { salt: string }).salt).not.toBe('attacker-known-salt');
  });

  it('salts に無いクレーム名の汚染が個別 salt として採用されない', () => {
    // `salts` は渡すが対象クレームの分は入れていない正当な呼び出し。`salts[name]` を直接読むと
    // `Object.prototype.email` の汚染値がそのクレームの salt になる（map 内の個別読み取り経路）。
    const polluted = withPollutedPrototype({ email: 'attacker-known-salt' }, () =>
      createSdJwt(ISSUER_SIGNER, {
        vct: VCT,
        disclosureClaims: ['email'],
        claims: { email: 'alice@example.com' },
        salts: {},
        nowSeconds: ISSUED_AT,
      }),
    );
    const disclosure = parseSdJwt(polluted).disclosures[0];
    expect(disclosure).toBeDefined();
    expect((disclosure as { salt: string }).salt).not.toBe('attacker-known-salt');
  });

  it('正常系: cnf / status / iss / salts を明示した発行は従来どおり payload に載る', () => {
    // 受理集合を狭める変更のため、正当な入力が落ちていないことを確認する。
    const status = { status_list: { idx: 42, uri: 'https://issuer.example/status/1' } };
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      cnf: { jwk: HOLDER_JWK },
      status,
      issuer: 'did:example:issuer',
      disclosureClaims: ['name'],
      claims: { name: 'Alice' },
      salts: { name: 'salt-name' },
      nowSeconds: ISSUED_AT,
    });
    const payload = payloadOf(sdJwt);
    expect(payload.cnf).toEqual({ jwk: HOLDER_JWK });
    expect(payload.status).toEqual(status);
    expect(payload.iss).toBe('did:example:issuer');
    expect(payload.iat).toBe(ISSUED_AT);
    expect((parseSdJwt(sdJwt).disclosures[0] as { salt: string }).salt).toBe('salt-name');
  });

  it('正常系: claims で iat を明示した発行は既定 iat で上書きされない', () => {
    const payload = payloadOf(
      createSdJwt(ISSUER_SIGNER, {
        vct: VCT,
        disclosureClaims: [],
        claims: { iat: 123 },
        nowSeconds: ISSUED_AT,
      }),
    );
    expect(payload.iat).toBe(123);
  });
});

/** 1 回目と 2 回目で別の値を返す own アクセサ `claims` を持つ発行オプションを作る。 */
function withSwappingClaims(
  first: Readonly<Record<string, unknown>>,
  second: Readonly<Record<string, unknown>>,
  disclosureClaims: readonly string[] = [],
): { opts: CreateSdJwtOptions; reads: () => number } {
  let reads = 0;
  const opts: Record<string, unknown> = { vct: VCT, disclosureClaims, nowSeconds: ISSUED_AT };
  Object.defineProperty(opts, 'claims', {
    get(): Readonly<Record<string, unknown>> {
      reads += 1;
      return reads === 1 ? first : second;
    },
    enumerable: true,
    configurable: true,
  });
  return { opts: opts as unknown as CreateSdJwtOptions, reads: () => reads };
}

describe('createSdJwt: opts.claims の 2 度読み', () => {
  it('2 回目に iat を返す own アクセサでも既定 iat が抑止されない', () => {
    // `Object.entries(opts.claims)` と `Object.hasOwn(opts.claims, 'iat')` が別々に読むと、
    // 1 回目（iat なし）で payload に iat が入らず、2 回目（iat あり）で既定 iat も抑止され、
    // **署名済み SD-JWT から iat が 1 つも消える**（未来 iat 判定 4014 が無言でスキップされる）。
    const { opts, reads } = withSwappingClaims({ degree: 'BSc' }, { degree: 'BSc', iat: 1 });
    const payload = payloadOf(createSdJwt(ISSUER_SIGNER, opts));
    expect(payload.iat).toBe(ISSUED_AT);
    expect(reads()).toBe(1);
  });

  it('平文クレームと Disclosure が同じ 1 回の読み取りに基づく', () => {
    // 逆順（1 回目に iat あり）だと、列挙したクレーム集合と `_sd` へコミットした集合を
    // 食い違わせられる。読み取りが 1 回なら、載る平文・隠す Disclosure・iat 判定がすべて一致する。
    const { opts, reads } = withSwappingClaims({ name: 'Alice', iat: 123 }, { name: 'Mallory' }, [
      'name',
    ]);
    const sdJwt = createSdJwt(ISSUER_SIGNER, opts);
    const payload = payloadOf(sdJwt);
    expect(payload.iat).toBe(123);
    expect(Object.hasOwn(payload, 'name')).toBe(false);
    expect(parseSdJwt(sdJwt).disclosures).toEqual([
      expect.objectContaining({ claimName: 'name', value: 'Alice' }),
    ]);
    expect(reads()).toBe(1);
  });

  it('claims を省略した発行で Object.prototype.claims の汚染がクレーム集合を供給しない', () => {
    // 鎖読みだと、`claims` を渡していない呼び出しに汚染側がクレーム集合を丸ごと供給できる。
    const payload = withPollutedPrototype({ claims: { degree: 'AttackerDegree' } }, () =>
      payloadOf(
        createSdJwt(ISSUER_SIGNER, {
          vct: VCT,
          disclosureClaims: [],
          nowSeconds: ISSUED_AT,
        } as unknown as CreateSdJwtOptions),
      ),
    );
    expect(Object.hasOwn(payload, 'degree')).toBe(false);
    expect(payload.iat).toBe(ISSUED_AT);
  });
});
