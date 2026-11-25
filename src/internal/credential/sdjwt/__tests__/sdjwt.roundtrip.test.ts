/**
 * SD-JWT / SD-JWT VC の発行 → 選択的開示 → 検証ラウンドトリップのユニットテスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - 発行 → 一部開示 → 検証成功（Issuer 署名検証 + Disclosure digest 照合 / 実鍵 / ネット非依存）。
 * - 未開示クレームが復元できないこと。
 * - Disclosure 改竄で検証失敗（3010）。
 * - KB-JWT の往復成功 / cnf 不一致で 3012。
 * - vct / cnf / status の保持。vct 不一致で 3010。
 * - status 参照解決インターフェース（解決器 DI / 未設定で 3018）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import type { CredentialAlg } from '../../vc/jws.js';
import { createPrivateKeySigner } from '../../vc/signer.js';
import {
  type ConfirmationClaim,
  createSdJwt,
  parseSdJwt,
  type StatusReference,
  selectDisclosures,
} from '../sdjwt.js';
import { resolveStatus, type StatusListResolver } from '../status.js';
import { addKeyBinding, verifySdJwt } from '../verify.js';

/** テスト用の固定秘密鍵。 */
const ISSUER_KEY = new Uint8Array(32).fill(7);
const HOLDER_KEY = new Uint8Array(32).fill(11);
const OTHER_KEY = new Uint8Array(32).fill(13);

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const OTHER_ISSUER_KEY = new Uint8Array(32).fill(17);
const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false), 'P-256');
// 同じ ES256（P-256）の別鍵。crv 不一致ではなく純粋な署名不一致を検証するため。
const OTHER_ISSUER_JWK = toJwk(getP256PublicKey(OTHER_ISSUER_KEY, false), 'P-256');
const HOLDER_JWK = toJwk(getSecp256k1PublicKey(HOLDER_KEY, false), 'secp256k1');

const VCT = 'https://example.com/credentials/identity';
const CNF: ConfirmationClaim = { jwk: HOLDER_JWK };
const STATUS: StatusReference = {
  status_list: { idx: 42, uri: 'https://issuer.example/status/1' },
};

const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const HOLDER_SIGNER = createPrivateKeySigner(HOLDER_KEY, 'ES256K' as CredentialAlg);
const OTHER_SIGNER = createPrivateKeySigner(OTHER_KEY, 'ES256K' as CredentialAlg);

/** vct / cnf / status / 開示クレームを含む SD-JWT を発行する。 */
function issue(): string {
  return createSdJwt(ISSUER_SIGNER, {
    vct: VCT,
    issuer: 'did:example:issuer',
    cnf: CNF,
    status: STATUS,
    disclosureClaims: ['name', 'age_over_18', 'email'],
    claims: {
      name: 'Alice',
      age_over_18: true,
      email: 'alice@example.com',
      sub: 'did:example:holder',
    },
    salts: { name: 'salt-name', age_over_18: 'salt-age', email: 'salt-email' },
  });
}

describe('SD-JWT 発行 → 選択的開示 → 検証', () => {
  it('一部開示で開示クレームのみ復元され、未開示は復元されない', () => {
    const sdJwt = issue();
    // name と age_over_18 のみ開示（email は伏せる）。
    const presented = selectDisclosures(sdJwt, ['name', 'age_over_18']);
    const result = verifySdJwt(presented, { issuerKey: ISSUER_JWK, expectedVct: VCT });

    expect(result.vct).toBe(VCT);
    expect(result.claims.name).toBe('Alice');
    expect(result.claims.age_over_18).toBe(true);
    // 未開示クレームは復元されない。
    expect(result.claims.email).toBeUndefined();
    // 平文クレーム（非開示対象）は常に残る。
    expect(result.claims.sub).toBe('did:example:holder');
    expect(result.claims.iss).toBe('did:example:issuer');
  });

  it('全開示で全クレームが復元される', () => {
    const sdJwt = issue();
    const result = verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK });
    expect(result.claims.name).toBe('Alice');
    expect(result.claims.email).toBe('alice@example.com');
  });

  it('vct / cnf / status を保持する', () => {
    const sdJwt = issue();
    const result = verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK });
    expect(result.vct).toBe(VCT);
    expect(result.cnf?.jwk.x).toBe(HOLDER_JWK.x);
    expect(result.status?.status_list.idx).toBe(42);
    expect(result.status?.status_list.uri).toBe('https://issuer.example/status/1');
  });

  it('vct 不一致は SIG_INVALID（3010）', () => {
    const sdJwt = issue();
    expect(() =>
      verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, expectedVct: 'urn:other:vct' }),
    ).toThrow(new VericertsError(ErrorCodes.SIG_INVALID));
  });

  it('Issuer 署名が別鍵だと SIG_INVALID（3010）', () => {
    const sdJwt = issue();
    expect(() => verifySdJwt(sdJwt, { issuerKey: OTHER_ISSUER_JWK })).toThrow(
      new VericertsError(ErrorCodes.SIG_INVALID),
    );
  });

  it('Disclosure 改竄（_sd に無い digest）は SIG_INVALID（3010）', () => {
    const sdJwt = issue();
    const parts = sdJwt.split('~');
    // 先頭 Disclosure の値を別物に差し替える（digest が _sd と一致しなくなる）。
    const forged = Buffer.from(JSON.stringify(['salt-name', 'name', 'Mallory'])).toString(
      'base64url',
    );
    parts[1] = forged;
    const tampered = parts.join('~');
    expect(() => verifySdJwt(tampered, { issuerKey: ISSUER_JWK })).toThrow(
      new VericertsError(ErrorCodes.SIG_INVALID),
    );
  });

  it('parseSdJwt は Issuer-signed JWT と Disclosure を分解する', () => {
    const sdJwt = issue();
    const parts = parseSdJwt(sdJwt);
    expect(parts.disclosures.length).toBe(3);
    expect(parts.keyBinding).toBeUndefined();
    expect(parts.disclosures.map((d) => d.claimName).sort()).toEqual([
      'age_over_18',
      'email',
      'name',
    ]);
  });
});

describe('SD-JWT Key Binding（KB-JWT）', () => {
  const NONCE = 'verifier-nonce-123';
  const AUD = 'https://verifier.example';
  const IAT = 1_767_225_600;

  it('cnf 鍵で署名した KB-JWT は検証成功する', () => {
    const presented = selectDisclosures(issue(), ['name']);
    const bound = addKeyBinding(presented, HOLDER_SIGNER, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    const result = verifySdJwt(bound, {
      issuerKey: ISSUER_JWK,
      audience: AUD,
      nonce: NONCE,
      requireKeyBinding: true,
    });
    expect(result.keyBindingVerified).toBe(true);
    expect(result.claims.name).toBe('Alice');
  });

  it('cnf と別鍵で署名した KB-JWT は HOLDER_BIND_MISMATCH（3012）', () => {
    const presented = selectDisclosures(issue(), ['name']);
    // cnf は HOLDER_JWK だが OTHER_SIGNER で署名する。
    const bound = addKeyBinding(presented, OTHER_SIGNER, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    expect(() =>
      verifySdJwt(bound, { issuerKey: ISSUER_JWK, audience: AUD, nonce: NONCE }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('nonce 不一致は HOLDER_BIND_MISMATCH（3012）', () => {
    const presented = selectDisclosures(issue(), ['name']);
    const bound = addKeyBinding(presented, HOLDER_SIGNER, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    expect(() =>
      verifySdJwt(bound, { issuerKey: ISSUER_JWK, audience: AUD, nonce: 'wrong-nonce' }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('audience 不一致は HOLDER_BIND_MISMATCH（3012）', () => {
    const presented = selectDisclosures(issue(), ['name']);
    const bound = addKeyBinding(presented, HOLDER_SIGNER, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    expect(() =>
      verifySdJwt(bound, {
        issuerKey: ISSUER_JWK,
        audience: 'https://attacker.example',
        nonce: NONCE,
      }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('KB-JWT 必須なのに無いと HOLDER_BIND_MISMATCH（3012）', () => {
    const presented = selectDisclosures(issue(), ['name']);
    expect(() =>
      // audience / nonce は `requireKeyBinding: true` の必須入力。指定しないと
      // 「KB-JWT 欠落」ではなく期待値欠落で 3012 になり、本ケースを検証できなくなる。
      verifySdJwt(presented, {
        issuerKey: ISSUER_JWK,
        audience: AUD,
        nonce: NONCE,
        requireKeyBinding: true,
      }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('提示部の sd_hash 改竄（Disclosure 追加）で KB 検証失敗（3012）', () => {
    const full = issue();
    const presented = selectDisclosures(full, ['name']);
    const bound = addKeyBinding(presented, HOLDER_SIGNER, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    // KB-JWT はそのままに、提示部へ別の Disclosure を後付け挿入して sd_hash を崩す。
    const emailDisclosure = parseSdJwt(full).disclosures.find((d) => d.claimName === 'email');
    const kbStart = bound.lastIndexOf('~') + 1;
    const presentPart = bound.slice(0, kbStart);
    const kb = bound.slice(kbStart);
    const injected = `${presentPart}${emailDisclosure?.encoded}~${kb}`;
    expect(() =>
      verifySdJwt(injected, { issuerKey: ISSUER_JWK, audience: AUD, nonce: NONCE }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });
});

describe('SD-JWT VC status 参照解決', () => {
  it('status 設定済みは解決器に委譲する', async () => {
    const result = verifySdJwt(issue(), { issuerKey: ISSUER_JWK });
    const resolver: StatusListResolver = {
      resolve: async (ref) => ({
        valid: ref.status_list.idx === 42,
        purpose: 'revocation',
        value: 0,
      }),
    };
    const status = await resolveStatus(result.status, resolver);
    expect(status.valid).toBe(true);
    expect(status.purpose).toBe('revocation');
  });

  it('status 未設定は TOKEN_STATUS_LIST_UNSUPPORTED（3018）', async () => {
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      disclosureClaims: ['name'],
      claims: { name: 'Alice' },
      salts: { name: 'salt-name' },
    });
    const result = verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK });
    const resolver: StatusListResolver = {
      resolve: async () => ({ valid: true, purpose: 'revocation', value: 0 }),
    };
    expect(() => resolveStatus(result.status, resolver)).toThrow(
      new VericertsError(ErrorCodes.TOKEN_STATUS_LIST_UNSUPPORTED),
    );
  });
});
