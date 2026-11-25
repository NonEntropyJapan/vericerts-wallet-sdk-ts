/**
 * `publicKeyJwkMatches` の JWK メンバ鎖読みによる cnf バインド検査バイパスの回帰テスト。
 *
 * `publicKeyJwkMatches` は WUA-PoP の署名鍵バインド検査（`assertSignerBoundToCnf`）と
 * WSCD バインド検査（`verifyWscdBinding`）が共有する同一性判定である。
 *
 * `cnfJwk[field]` / `otherJwk[field]` / `cnfJwk.kty` / `cnfJwk.y` を鎖読みすると、
 * `cnf.jwk` が `{}` のような**空オブジェクト**で届いた場合に `Object.prototype` の
 * `kty` / `crv` / `x` / `y` 汚染だけで**両辺が同じ継承値を拾い**、一致判定が成立して
 * バインド検査が素通りする（fail-open）。呼び出し元が `cnf.jwk` を own 読みしても、
 * `cnf.jwk` が own に存在する限りこの経路は塞げない。
 *
 * あわせて `verifyWscdBinding` は `wua.cnf.jwk` 自体を鎖読みしていたため、`cnf` / `jwk` を
 * 持たない WUA でも汚染値が比較基準に化ける。両方を own 限定へ統一する。
 *
 * 期待値は「空 JWK / メンバ欠落 ＋ 汚染では一致と判定されない（fail-closed）」。
 * 修正を鎖読みへ戻すと本ファイルの各テストは失敗する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import type { CredentialSigner } from '../../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { publicKeyJwkMatches } from '../../jwk-match.js';
import { buildWuaProofOfPossession } from '../../proof.js';
import type { WalletUnitAttestation } from '../../types.js';
import { WUA_VCT } from '../../types.js';
import { verifyWscdBinding } from '../../wua.js';

/** 攻撃者が `Object.prototype` に仕込む EC 鍵メンバ一式。 */
const POLLUTED_EC_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: 'attacker-controlled-x',
  y: 'attacker-controlled-y',
} as const;

const REAL_JWK: PublicKeyJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'real-x',
  y: 'real-y',
} as PublicKeyJwk;

/** `cnf.jwk` を差し替えた WUA を組み立てる。`omitCnf` 指定時は `cnf` を own に持たせない。 */
function buildWua(jwk: unknown, omitCnf = false): WalletUnitAttestation {
  const wua: Record<string, unknown> = {
    jwt: 'header.payload.signature',
    vct: WUA_VCT,
    walletProviderDID: 'https://wallet-provider.example',
    issuedAt: new Date(1_700_000_000 * 1000).toISOString(),
    expiresAt: new Date(1_900_000_000 * 1000).toISOString(),
  };
  if (!omitCnf) {
    wua.cnf = { jwk };
  }
  return wua as unknown as WalletUnitAttestation;
}

/** `publicKeyJwk` を own で公開する最小の署名器スタブ。 */
function buildSigner(publicKeyJwk: unknown): CredentialSigner {
  return {
    alg: 'ES256',
    publicKeyJwk,
    sign: () => new Uint8Array(64),
  } as unknown as CredentialSigner;
}

/** 10102 で拒否されることを表明する。 */
function expectWuaRejected(fn: () => unknown): void {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe(ErrorCodes.WUA_VERIFICATION_FAILED);
    return;
  }
  throw new Error('汚染下で素通りした（fail-open）');
}

describe('publicKeyJwkMatches / prototype pollution', () => {
  it('正常系: 同一の JWK 同士は一致し、異なる JWK 同士は一致しない', () => {
    expect(publicKeyJwkMatches({ ...REAL_JWK }, { ...REAL_JWK })).toBe(true);
    expect(publicKeyJwkMatches({ ...REAL_JWK }, { ...REAL_JWK, x: 'other-x' })).toBe(false);
  });

  it('正常系: OKP（Ed25519）は `y` を持たなくても一致する', () => {
    const okp = { kty: 'OKP', crv: 'Ed25519', x: 'okp-x' };
    expect(publicKeyJwkMatches({ ...okp }, { ...okp })).toBe(true);
  });

  it('空 JWK 同士は `kty` / `crv` / `x` / `y` 汚染下でも一致と判定されない', () => {
    withPollutedPrototype(POLLUTED_EC_JWK, () => {
      // 鎖読みだと両辺が同じ継承値を拾い、全フィールドが一致して `true` になる。
      expect(publicKeyJwkMatches({}, {})).toBe(false);
    });
  });

  it('片側だけ空 JWK でも汚染下で一致と判定されない', () => {
    withPollutedPrototype(POLLUTED_EC_JWK, () => {
      expect(publicKeyJwkMatches({}, { ...POLLUTED_EC_JWK })).toBe(false);
      expect(publicKeyJwkMatches({ ...POLLUTED_EC_JWK }, {})).toBe(false);
    });
  });

  it('`y` を own に持たない EC JWK 同士は `y` 汚染下でも一致と判定されない', () => {
    const ecNoY = { kty: 'EC', crv: 'P-256', x: 'real-x' };
    withPollutedPrototype({ y: 'attacker-y' }, () => {
      // 鎖読みだと両辺が汚染 `y` を拾って EC 分岐が成立する。
      expect(publicKeyJwkMatches({ ...ecNoY }, { ...ecNoY })).toBe(false);
    });
  });

  it('OKP（`y` なし）でも片側だけ空の JWK は汚染下で一致しない', () => {
    // 既存ケースは全て EC のため、末尾の `y` own 読みが先に false を返して `kty` / `crv` / `x` の
    // 片側 own 読みの差分を隠していた。OKP は `y` を持たないためループ内の own 読みだけが
    // 唯一の防御線になる。
    const okp = { kty: 'OKP', crv: 'Ed25519', x: 'okp-x' } as const;
    withPollutedPrototype(okp, () => {
      // 鎖読みだと両辺（あるいは片側）が同じ継承値を拾い、`y` も双方 undefined で `true` に化ける。
      expect(publicKeyJwkMatches({ ...okp }, {})).toBe(false);
      expect(publicKeyJwkMatches({}, { ...okp })).toBe(false);
      expect(publicKeyJwkMatches({}, {})).toBe(false);
    });
  });

  it('OKP 判定は `y` 汚染で「双方 y なし」の要件を誤らない', () => {
    const okp = { kty: 'OKP', crv: 'Ed25519', x: 'okp-x' };
    withPollutedPrototype({ y: 'attacker-y' }, () => {
      // 鎖読みだと `cnfJwk.y === undefined` が false になり、正当な OKP 一致が壊れる。
      expect(publicKeyJwkMatches({ ...okp }, { ...okp })).toBe(true);
    });
  });
});

describe('verifyWscdBinding / prototype pollution', () => {
  it('空の `cnf.jwk` は汚染下でも WSCD 鍵と一致せず 10102 で拒否される', () => {
    const wua = buildWua({});
    // WSCD 鍵は汚染値そのものを渡す。鎖読みだと空の `cnf.jwk` が同じ継承値を拾って一致し、
    // バインド検査が成立してしまう（汚染と無関係に落ちるトートロジーにしない）。
    withPollutedPrototype(POLLUTED_EC_JWK, () => {
      expectWuaRejected(() =>
        verifyWscdBinding(wua, { ...POLLUTED_EC_JWK } as unknown as PublicKeyJwk),
      );
    });
  });

  it('`cnf.jwk` を own に持たない WUA は汚染下でもバインド検査を素通りしない', () => {
    // `cnf` は own に存在するが `jwk` は own に無い。外側の `ownProperty(wua, 'cnf')` では
    // 塞げず、**内側の `ownProperty(cnf, 'jwk')`** だけがこの経路を止める。
    const wua = buildWua(undefined);
    (wua as unknown as Record<string, unknown>).cnf = {};
    withPollutedPrototype({ jwk: { ...POLLUTED_EC_JWK } }, () => {
      expectWuaRejected(() =>
        verifyWscdBinding(wua, { ...POLLUTED_EC_JWK } as unknown as PublicKeyJwk),
      );
    });
  });

  it('`cnf` を own に持たない WUA は汚染下でもバインド検査を素通りしない', () => {
    const wua = buildWua(undefined, true);
    withPollutedPrototype({ ...POLLUTED_EC_JWK, cnf: { jwk: { ...POLLUTED_EC_JWK } } }, () => {
      expectWuaRejected(() =>
        verifyWscdBinding(wua, { ...POLLUTED_EC_JWK } as unknown as PublicKeyJwk),
      );
    });
  });

  it('正常系: 一致する WSCD 鍵は従来どおり受理される', () => {
    const wua = buildWua({ ...REAL_JWK });
    expect(() => verifyWscdBinding(wua, { ...REAL_JWK })).not.toThrow();
  });
});

describe('assertSignerBoundToCnf / prototype pollution', () => {
  const opts = { aud: 'https://as.example', nonce: 'c-nonce-1' };

  it('空の `cnf.jwk` は汚染下でも署名鍵バインド検査を素通りしない', () => {
    const wua = buildWua({});
    const signer = buildSigner({});
    withPollutedPrototype(POLLUTED_EC_JWK, () => {
      try {
        buildWuaProofOfPossession(wua, opts, signer, 1_700_000_100);
      } catch (e) {
        expect(e).toBeInstanceOf(VericertsError);
        expect((e as VericertsError).code).toBe(ErrorCodes.PASSKEY_ASSERTION_INVALID);
        return;
      }
      throw new Error('assertSignerBoundToCnf が汚染下で素通りした（fail-open）');
    });
  });

  it('`y` を持たない EC 鍵同士は `y` 汚染下でも署名鍵バインド検査を素通りしない', () => {
    const ecNoY = { kty: 'EC', crv: 'P-256', x: 'real-x' };
    const wua = buildWua({ ...ecNoY });
    const signer = buildSigner({ ...ecNoY });
    withPollutedPrototype({ y: 'attacker-y' }, () => {
      try {
        buildWuaProofOfPossession(wua, opts, signer, 1_700_000_100);
      } catch (e) {
        expect(e).toBeInstanceOf(VericertsError);
        expect((e as VericertsError).code).toBe(ErrorCodes.PASSKEY_ASSERTION_INVALID);
        return;
      }
      throw new Error('assertSignerBoundToCnf が汚染下で素通りした（fail-open）');
    });
  });
});
