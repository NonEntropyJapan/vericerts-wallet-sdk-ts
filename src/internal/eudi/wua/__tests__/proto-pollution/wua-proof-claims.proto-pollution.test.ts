/**
 * WUA-PoP の署名対象クレーム / cnf バインド検査の `Object.prototype` 汚染耐性。
 *
 * `proof.ts` は組み立てた claims をそのまま署名する。必須クレームをプロトタイプ鎖で読むと、
 * その項目を**省略した**正当な生成でも汚染値が **署名済み WUA-PoP JWT** に載る:
 *
 * - `aud`: 攻撃者が選んだ Authorization Server 向けの PoP を署名させられる。
 * - `nonce`: AS の `c_nonce` が差し替わり、リプレイ防止が無効化される。
 * - `jwt`: `iss`（`wua.jwt` の `sub` クレームから取る、`walletInstanceIdOf`）が別 Wallet Instance
 *   を騙る、かつ `client_assertion` の前半に攻撃者の用意した WUA が載る（
 *   `walletInstanceId` フィールドを廃止した 現在、`iss` はこの経路でのみ汚染され得る）。
 * - `cnf` / `cnf.jwk`: `cnf` を持たない WUA でもバインド検査が素通りする（fail-open）。
 *
 * 一方 `signer.publicKeyJwk` は KMS / HSM 鍵ラッパが getter で公開し得るため own 限定にはできない。
 * クラスベース signer が退行しないこと（own 化しすぎの回帰）も併せて検証する。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { type CredentialSigner, createPrivateKeySigner } from '../../../../credential/vc/signer.js';
import { type ErrorCode, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { buildClientAttestation, buildWuaProofOfPossession } from '../../proof.js';
import type { WalletUnitAttestation, WuaConfirmation, WuaPopOptions } from '../../types.js';
import { parseWalletUnitAttestation } from '../../wua.js';
import { makeWuaJwt, toP256Jwk, WSCD_PRIVATE_KEY, wscdSigner } from '../wua-fixtures.js';

const PROVIDER_KEY = new Uint8Array(32).fill(3);
const NOW = 1_712_400_000;
const OPTS: WuaPopOptions = { aud: 'https://as.example', nonce: 'c_nonce_123' };

/** WSCD 鍵の公開鍵 JWK（`cnf.jwk` と一致する正当な値）。 */
const WSCD_JWK = toP256Jwk(WSCD_PRIVATE_KEY);

function decodePayload(jwt: string): Record<string, unknown> {
  const [, payloadSeg] = jwt.split('.');
  return JSON.parse(new TextDecoder().decode(base64urlnopad.decode(payloadSeg ?? ''))) as Record<
    string,
    unknown
  >;
}

function baseWua(): WalletUnitAttestation {
  return parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
}

/** 指定キーを**自身のプロパティとして持たない** WUA を作る（継承値だけが見える状態）。 */
function wuaWithout(omitted: string): WalletUnitAttestation {
  const full = baseWua() as unknown as Record<string, unknown>;
  const partial: Record<string, unknown> = {};
  for (const key of Object.keys(full)) {
    if (key !== omitted) {
      partial[key] = full[key];
    }
  }
  return partial as unknown as WalletUnitAttestation;
}

/** `publicKeyJwk` を**持たない** signer（アクセサ汚染が見えるオブジェクトリテラル）。 */
function signerWithoutPublicKeyJwk(privateKey: Uint8Array): CredentialSigner {
  const inner = createPrivateKeySigner(privateKey, 'ES256');
  return {
    alg: 'ES256',
    sign: (signingInput: Uint8Array) => inner.sign(signingInput),
  } as unknown as CredentialSigner;
}

/** KMS / HSM 鍵ラッパ相当。公開鍵を getter（prototype アクセサ）として公開する。 */
class KmsBackedSigner implements CredentialSigner {
  readonly alg = 'ES256' as const;
  readonly #inner = createPrivateKeySigner(WSCD_PRIVATE_KEY, 'ES256');

  get publicKeyJwk(): PublicKeyJwk {
    return this.#inner.publicKeyJwk;
  }

  sign(signingInput: Uint8Array): Uint8Array {
    return this.#inner.sign(signingInput);
  }
}

function expectVericertsCode(fn: () => unknown, code: ErrorCode): void {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe(code);
    return;
  }
  throw new Error(`expected VericertsError ${code} but nothing was thrown`);
}

describe('WUA-PoP 署名対象クレームの Object.prototype 汚染耐性', () => {
  it('aud を省略した opts で継承した aud を署名せず fail-closed に拒否する', () => {
    const wua = baseWua();
    const opts = { nonce: 'c_nonce_123' } as unknown as WuaPopOptions;
    withPollutedPrototype({ aud: 'https://attacker-as.example' }, () => {
      expectVericertsCode(() => buildWuaProofOfPossession(wua, opts, wscdSigner(), NOW), '10104');
    });
  });

  it('nonce を省略した opts で継承した nonce を署名せず fail-closed に拒否する', () => {
    const wua = baseWua();
    const opts = { aud: 'https://as.example' } as unknown as WuaPopOptions;
    withPollutedPrototype({ nonce: 'attacker-nonce' }, () => {
      expectVericertsCode(() => buildWuaProofOfPossession(wua, opts, wscdSigner(), NOW), '10104');
    });
  });

  it('jwt を持たない WUA で継承した jwt から sub(iss) を組み立てず fail-closed に拒否する', () => {
    // WalletUnitAttestation は walletInstanceId を持たない。`iss` は
    // `wua.jwt` を own 限定でデコードして `sub` を読む（`walletInstanceIdOf`）ため、
    // `jwt` 自体が汚染源になり得る。
    const wua = wuaWithout('jwt');
    withPollutedPrototype({ jwt: makeWuaJwt(PROVIDER_KEY) }, () => {
      expectVericertsCode(() => buildWuaProofOfPossession(wua, OPTS, wscdSigner(), NOW), '10104');
    });
  });

  it('汚染下でも明示的に渡した aud / nonce と自身の jwt 由来の iss が署名済み PoP に載る（正常系）', () => {
    const wua = baseWua();
    const pop = withPollutedPrototype(
      {
        aud: 'https://attacker-as.example',
        nonce: 'attacker-nonce',
        jwt: makeWuaJwt(PROVIDER_KEY, { sub: 'urn:uuid:attacker-instance' }),
      },
      () => buildWuaProofOfPossession(wua, OPTS, wscdSigner(), NOW),
    );
    const claims = decodePayload(pop);
    expect(claims.aud).toBe('https://as.example');
    expect(claims.nonce).toBe('c_nonce_123');
    expect(claims.iss).toBe(decodePayload(wua.jwt).sub);
  });
});

describe('cnf バインド検査の Object.prototype 汚染耐性', () => {
  it('cnf を持たない WUA で継承した cnf を採用せず 10104 で拒否する', () => {
    const wua = wuaWithout('cnf');
    withPollutedPrototype({ cnf: { jwk: WSCD_JWK } }, () => {
      expectVericertsCode(() => buildWuaProofOfPossession(wua, OPTS, wscdSigner(), NOW), '10104');
    });
  });

  it('cnf.jwk を持たない WUA で継承した jwk を採用せず 10104 で拒否する', () => {
    const wua = { ...wuaWithout('cnf'), cnf: {} as unknown as WuaConfirmation };
    withPollutedPrototype({ jwk: WSCD_JWK }, () => {
      expectVericertsCode(() => buildWuaProofOfPossession(wua, OPTS, wscdSigner(), NOW), '10104');
    });
  });

  it('publicKeyJwk を持たない signer で継承値（アクセサ汚染）を採用せず 10104 で拒否する', () => {
    const wua = baseWua();
    // 汚染値が `cnf.jwk` と一致するため、鎖読みだと**任意の鍵**でバインド検査が素通りする。
    const foreignSigner = signerWithoutPublicKeyJwk(new Uint8Array(32).fill(9));
    withPollutedPrototypeAccessor({ publicKeyJwk: () => ({ ...WSCD_JWK }) }, () => {
      expectVericertsCode(() => buildWuaProofOfPossession(wua, OPTS, foreignSigner, NOW), '10104');
    });
  });

  it('publicKeyJwk を getter で公開するクラスベース signer は従来どおり署名できる（正常系）', () => {
    const wua = baseWua();
    const pop = buildWuaProofOfPossession(wua, OPTS, new KmsBackedSigner(), NOW);
    const claims = decodePayload(pop);
    expect(claims.iss).toBe(decodePayload(wua.jwt).sub);
    expect(claims.aud).toBe('https://as.example');
    expect(claims.nonce).toBe('c_nonce_123');
  });
});

describe('client_assertion 組み立ての Object.prototype 汚染耐性', () => {
  it('jwt を持たない WUA で継承した jwt を client_assertion に載せず 10102 で拒否する', () => {
    const wua = wuaWithout('jwt');
    withPollutedPrototype({ jwt: 'attacker.wua.jwt' }, () => {
      expectVericertsCode(() => buildClientAttestation(wua, 'pop.jwt.sig'), '10102');
    });
  });

  it('汚染下でも自身の jwt を持つ WUA は従来どおり組み立てられる（正常系）', () => {
    const wua = baseWua();
    const attestation = withPollutedPrototype({ jwt: 'attacker.wua.jwt' }, () =>
      buildClientAttestation(wua, 'pop.jwt.sig'),
    );
    expect(attestation.clientAssertion).toBe(`${wua.jwt}~pop.jwt.sig`);
  });
});
