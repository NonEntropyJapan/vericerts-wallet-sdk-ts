/**
 * JWT-VC の JWS ヘッダ `kid` の自動付与の回帰テスト。
 *
 * didkit-http は `kid`（DID URL）からしか検証鍵を解決せず、`kid` が無いと `missing public key` で拒否する。
 * `kid` は VCDM 1.1 §6.3.1 で任意（MAY）なので、発行者が署名鍵自身の `did:key` のときに限り
 * `did:key:Z#Z` を自動で載せる。固定するのは次の不変条件:
 *
 * - 署名鍵自身の `did:key` が発行者 → ヘッダに `did:key:Z#Z`（キー順 `alg` → `kid` → `typ`）。
 * - `signer.kid` の明示指定は常に優先する。
 * - 発行者が署名鍵と別の鍵の `did:key` / `did:key` 以外 / 不正な `did:key` → `kid` を載せない（従来どおり）。
 * - 同期・非同期のどちらの発行 API でも同じヘッダになる。
 * - `kid` 付きの JWT-VC も従来どおり検証できる。
 * - `Object.prototype.kid` の汚染を明示指定と取り違えない。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { createDidKey } from '../../../identity/method-key.js';
import { getEd25519PublicKey } from '../../../keymanager/ed25519.js';
import { issueCredential, issueCredentialAsync } from '../issue.js';
import { createPrivateKeySigner } from '../signer.js';
import type { VerifiableCredential } from '../vc.js';
import { verifyCredential } from '../verify.js';

const ED_KEY = new Uint8Array(32).fill(5);
const OTHER_ED_KEY = new Uint8Array(32).fill(6);
const NOW = 1_767_225_600;
const ISSUED_AT = '2025-12-01T00:00:00Z';

/** 鍵に対応する `did:key` と検証メソッド id。 */
function didKeyOf(privateKey: Uint8Array): { did: string; kid: string } {
  const doc = createDidKey('Ed25519', getEd25519PublicKey(privateKey));
  const kid = doc.verificationMethod?.[0]?.id;
  if (kid === undefined) {
    throw new Error('did:key の検証メソッドが無い');
  }
  return { did: doc.id, kid };
}

function vcFor(issuer: string): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer,
    issuanceDate: ISSUED_AT,
    credentialSubject: { id: 'did:example:subject', name: 'x' },
  };
}

/** コンパクト JWS のヘッダ部を生 JSON 文字列へ戻す（キー順を保持する）。 */
function headerJson(jws: string): string {
  return Buffer.from(jws.split('.')[0] ?? '', 'base64url').toString('utf8');
}

const signer = () => createPrivateKeySigner(ED_KEY, 'EdDSA');

// プロトタイプ汚染の再現用（既存の jws-header-unification.test.ts と同じ書き方）。
const polluted = Object.prototype as unknown as Record<string, unknown>;

afterEach(() => {
  Reflect.deleteProperty(polluted, 'kid');
});

describe('issueCredential の kid 自動付与', () => {
  const { did, kid } = didKeyOf(ED_KEY);

  it('発行者が署名鍵自身の did:key のとき、ヘッダに did:key:Z#Z を alg → kid → typ の順で載せる', () => {
    const jws = issueCredential(vcFor(did), signer(), { nowSeconds: NOW });
    expect(headerJson(jws)).toBe(JSON.stringify({ alg: 'EdDSA', kid, typ: 'JWT' }));
    expect(kid).toBe(`${did}#${did.slice('did:key:'.length)}`);
  });

  it('非同期発行でも同じヘッダになる', async () => {
    const sync = issueCredential(vcFor(did), signer(), { nowSeconds: NOW });
    const async_ = await issueCredentialAsync(vcFor(did), signer(), { nowSeconds: NOW });
    expect(headerJson(async_)).toBe(headerJson(sync));
    expect(async_).toBe(sync);
  });

  it('signer.kid の明示指定は自動付与より優先する', () => {
    const explicit = 'did:example:other#key-9';
    const jws = issueCredential(vcFor(did), { ...signer(), kid: explicit }, { nowSeconds: NOW });
    expect(headerJson(jws)).toBe(JSON.stringify({ alg: 'EdDSA', kid: explicit, typ: 'JWT' }));
  });

  it('発行者が署名鍵と別の鍵の did:key のときは kid を載せない（別の鍵を引かせない）', () => {
    const other = didKeyOf(OTHER_ED_KEY);
    const jws = issueCredential(vcFor(other.did), signer(), { nowSeconds: NOW });
    expect(headerJson(jws)).toBe('{"alg":"EdDSA","typ":"JWT"}');
  });

  it('did:key 以外の発行者は kid を載せない（従来どおり）', () => {
    const jws = issueCredential(vcFor('did:web:example.com'), signer(), { nowSeconds: NOW });
    expect(headerJson(jws)).toBe('{"alg":"EdDSA","typ":"JWT"}');
  });

  it('不正な did:key の発行者でも、kid を載せないだけで発行は失敗しない', () => {
    const jws = issueCredential(vcFor('did:key:zNotAKey'), signer(), { nowSeconds: NOW });
    expect(headerJson(jws)).toBe('{"alg":"EdDSA","typ":"JWT"}');
  });

  it('kid 付きの JWT-VC も従来どおり検証できる', () => {
    const jws = issueCredential(vcFor(did), signer(), { nowSeconds: NOW });
    const result = verifyCredential(jws, {
      key: { publicKeyJwk: signer().publicKeyJwk },
      nowSeconds: NOW,
    });
    expect(result.header.kid).toBe(kid);
    expect(result.payload.iss).toBe(did);
  });

  it('Object.prototype.kid の汚染を signer の明示指定と取り違えない', () => {
    polluted.kid = 'did:evil#key';
    const jws = issueCredential(vcFor(did), signer(), { nowSeconds: NOW });
    expect(headerJson(jws)).toBe(JSON.stringify({ alg: 'EdDSA', kid, typ: 'JWT' }));
  });

  it('汚染された Object.prototype.kid は、自動付与できない発行者のヘッダにも載らない', () => {
    polluted.kid = 'did:evil#key';
    const jws = issueCredential(vcFor('did:web:example.com'), signer(), { nowSeconds: NOW });
    expect(headerJson(jws)).toBe('{"alg":"EdDSA","typ":"JWT"}');
  });
});
