/**
 * Entity Statement の EdDSA（Ed25519）署名検証テスト（実鍵・モック禁止）。
 *
 * ES256 経路は `statement.test.ts` が担当し、本ファイルは
 * `statement.ts` が EdDSA を受理するようになったことの正常系を固定する。
 *
 * 検証内容:
 * - EdDSA 署名の Entity Statement を正しい OKP 鍵集合で検証できる。
 * - kid 不一致は全鍵フォールバックせず拒否する。
 * - 別の Ed25519 鍵では TRUST_CHAIN_INVALID（fail-closed の維持）。
 * - EC 鍵と OKP 鍵が混在する JWKS でも、1 本目の不一致で候補ループを打ち切らない。
 */

import { describe, expect, it } from 'bun:test';
import { createPrivateKeySigner } from '../../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getEd25519PublicKey } from '../../../../keymanager/ed25519.js';
import { decodeAndVerifyStatement } from '../../statement/statement.js';
import { LEAF_KEY, toJwk, validPeriod } from '../federation-fixtures.js';

const ISS = 'https://leaf.example.eu';
const ED_SEED = new Uint8Array(32).fill(31);
const ED_OTHER_SEED = new Uint8Array(32).fill(37);

/** Ed25519 シードから OKP 公開鍵 JWK を構築する（`y` を持たない。RFC 8037）。 */
function toOkpJwk(seed: Uint8Array, kid?: string): PublicKeyJwk {
  const jwk: Record<string, unknown> = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: Buffer.from(getEd25519PublicKey(seed)).toString('base64url'),
  };
  if (kid !== undefined) {
    jwk.kid = kid;
  }
  return jwk as PublicKeyJwk;
}

/**
 * Entity Statement を EdDSA で署名する。
 *
 * `federation-fixtures.signStatement` は P-256 ハードコードのため、EdDSA では
 * `createPrivateKeySigner` 経由で組み立てる（事前ハッシュの要否は signer が吸収する）。
 */
function signEdStatement(
  seed: Uint8Array,
  payload: Record<string, unknown>,
  header: Record<string, unknown> = {},
): string {
  const signer = createPrivateKeySigner(seed, 'EdDSA');
  const b64u = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
  const headerSeg = b64u({ alg: 'EdDSA', typ: 'entity-statement+jwt', ...header });
  const payloadSeg = b64u(payload);
  const signingInput = `${headerSeg}.${payloadSeg}`;
  const signature = signer.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${Buffer.from(signature).toString('base64url')}`;
}

describe('decodeAndVerifyStatement（EdDSA / Ed25519）', () => {
  it('EdDSA 署名の Entity Statement を OKP 鍵集合で検証できる', () => {
    const jwks = { keys: [toOkpJwk(ED_SEED, 'ed-1')] };
    const jwt = signEdStatement(
      ED_SEED,
      { iss: ISS, sub: ISS, ...validPeriod(), jwks },
      {
        kid: 'ed-1',
      },
    );
    const statement = decodeAndVerifyStatement(jwt, jwks);
    expect(statement.iss).toBe(ISS);
    expect(statement.jwks.keys.length).toBe(1);
  });

  it('header.kid が JWKS に無ければ、署名鍵が JWKS に在っても TRUST_CHAIN_INVALID', () => {
    const jwks = { keys: [toOkpJwk(ED_SEED, 'actual-kid')] };
    const jwt = signEdStatement(
      ED_SEED,
      { iss: ISS, sub: ISS, ...validPeriod(), jwks },
      {
        kid: 'nonexistent-kid',
      },
    );
    let caught: unknown;
    try {
      decodeAndVerifyStatement(jwt, jwks);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.TRUST_CHAIN_INVALID);
  });

  it('別の Ed25519 鍵では TRUST_CHAIN_INVALID', () => {
    const jwks = { keys: [toOkpJwk(ED_OTHER_SEED, 'ed-1')] };
    const jwt = signEdStatement(
      ED_SEED,
      { iss: ISS, sub: ISS, ...validPeriod(), jwks },
      {
        kid: 'ed-1',
      },
    );
    let caught: unknown;
    try {
      decodeAndVerifyStatement(jwt, jwks);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.TRUST_CHAIN_INVALID);
  });

  // 回帰: JWKS の 1 本目が alg と kty 不一致（EC × EdDSA）でも候補ループを中断しない。
  it('EC 鍵が先頭にある JWKS でも後続の OKP 鍵で検証できる', () => {
    const jwks = { keys: [toJwk(LEAF_KEY, 'ec-1'), toOkpJwk(ED_SEED, 'ed-1')] };
    const jwt = signEdStatement(ED_SEED, { iss: ISS, sub: ISS, ...validPeriod(), jwks });
    expect(decodeAndVerifyStatement(jwt, jwks).iss).toBe(ISS);
  });
});
