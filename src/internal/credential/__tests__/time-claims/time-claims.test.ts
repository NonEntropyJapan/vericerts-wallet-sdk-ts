/**
 * クロックスキュープロファイルと `clockSkewSeconds` オプション検証のテスト（実鍵・モック禁止）。
 *
 * 時計ずれの許容値と境界条件を 3 つの入口
 * （`verifyCredential` / `verifyPresentation` / `verifySdJwt`）で横断的に検証する:
 * - テナントは既定（= 上限キャップ）より厳しい値のみ指定でき、緩い値・非負整数でない値は
 *   `CLOCK_SKEW_OPTION_INVALID`（4015）で拒否する。
 * - オプション検証は署名検証（暗号処理）より前に走る（構造不正な入力でも 4015 が優先する）。
 * - キャップは種別ごとに異なる（VP の 30s は VC の 120s より厳しい）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import { issuePresentation } from '../../presentation/issue.js';
import { verifyPresentation } from '../../presentation/presentation.js';
import { VC_V2_CONTEXT, type VerifiablePresentation } from '../../presentation/vp.js';
import { createSdJwt, selectDisclosures } from '../../sdjwt/sdjwt.js';
import { addKeyBinding, verifySdJwt } from '../../sdjwt/verify.js';
import { CLOCK_SKEW_PROFILE } from '../../time-claims.js';
import { issueCredential } from '../../vc/issue.js';
import type { CredentialAlg } from '../../vc/jws.js';
import { createPrivateKeySigner } from '../../vc/signer.js';
import type { VerifiableCredential } from '../../vc/vc.js';
import { verifyCredential } from '../../vc/verify.js';

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_KEY = new Uint8Array(32).fill(37);
const HOLDER_KEY = new Uint8Array(32).fill(41);
const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false), 'P-256');
const HOLDER_JWK = toJwk(getSecp256k1PublicKey(HOLDER_KEY, false), 'secp256k1');
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const HOLDER_SIGNER = createPrivateKeySigner(HOLDER_KEY, 'ES256K' as CredentialAlg);
const VCT = 'https://example.com/credentials/identity';
const AUD = 'https://verifier.example';
const NONCE = 'n-1';

/** 固定の現在時刻 N（2026-01-01T00:00:00Z）。 */
const N = 1_767_225_600;

/** 有効な JWT-VC（nbf は過去・exp は未来）。 */
const VALID_JWT_VC = ((): string => {
  const vc: VerifiableCredential = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: new Date((N - 10_000) * 1000).toISOString(),
    expirationDate: new Date((N + 10_000) * 1000).toISOString(),
    id: 'urn:uuid:opt',
  };
  return issueCredential(vc, ISSUER_SIGNER, { nowSeconds: N });
})();

/** 有効な JWT-VP（aud / nonce バインド付き）。 */
const VALID_JWT_VP = ((): string => {
  const vp: VerifiablePresentation = {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiablePresentation'],
    holder: 'did:example:issuer',
    verifiableCredential: [VALID_JWT_VC],
    id: 'urn:uuid:vp-opt',
  };
  return issuePresentation(vp, ISSUER_SIGNER, { audience: AUD, nonce: NONCE, nowSeconds: N });
})();

/** 有効な SD-JWT VC（cnf 付き・KB-JWT なし）。 */
const VALID_SD_JWT = createSdJwt(ISSUER_SIGNER, {
  vct: VCT,
  cnf: { jwk: HOLDER_JWK },
  disclosureClaims: ['name'],
  claims: { name: 'Alice' },
  salts: { name: 'salt-name' },
  nowSeconds: N,
});

/** 有効な SD-JWT VC + KB-JWT（`iat` は KB キャップ 30s ちょうどの未来）。 */
const SD_JWT_WITH_KB_AT_CAP = addKeyBinding(
  selectDisclosures(VALID_SD_JWT, ['name']),
  HOLDER_SIGNER,
  { nonce: NONCE, audience: AUD, iatSeconds: N + CLOCK_SKEW_PROFILE.kbJwt },
);

/** 検証入口ごとの上限キャップと呼び出し方。 */
interface EntryPoint {
  /** 入口名（テスト名に使う）。 */
  readonly name: string;
  /** このトークン種別で許容する時計ずれの上限（秒）。 */
  readonly cap: number;
  /** 有効なフィクスチャを指定スキューで検証する（成功時は何も投げない）。 */
  readonly verifyValid: (clockSkewSeconds?: number) => void;
  /** 構造不正な入力を指定スキューで検証する。 */
  readonly verifyMalformed: (clockSkewSeconds: number) => void;
}

const ENTRY_POINTS: readonly EntryPoint[] = [
  {
    name: 'verifyCredential',
    cap: CLOCK_SKEW_PROFILE.vc,
    verifyValid: (clockSkewSeconds) => {
      verifyCredential(VALID_JWT_VC, {
        key: { publicKeyJwk: ISSUER_JWK },
        nowSeconds: N,
        ...(clockSkewSeconds !== undefined ? { clockSkewSeconds } : {}),
      });
    },
    verifyMalformed: (clockSkewSeconds) => {
      verifyCredential('not.a.valid.jwt', {
        key: { publicKeyJwk: ISSUER_JWK },
        nowSeconds: N,
        clockSkewSeconds,
      });
    },
  },
  {
    name: 'verifyPresentation',
    cap: CLOCK_SKEW_PROFILE.vp,
    verifyValid: (clockSkewSeconds) => {
      verifyPresentation(VALID_JWT_VP, {
        key: { publicKeyJwk: ISSUER_JWK },
        expectedAudience: AUD,
        expectedNonce: NONCE,
        nowSeconds: N,
        ...(clockSkewSeconds !== undefined ? { clockSkewSeconds } : {}),
      });
    },
    verifyMalformed: (clockSkewSeconds) => {
      verifyPresentation('not.a.valid.jwt', {
        key: { publicKeyJwk: ISSUER_JWK },
        expectedAudience: AUD,
        expectedNonce: NONCE,
        nowSeconds: N,
        clockSkewSeconds,
      });
    },
  },
  {
    name: 'verifySdJwt',
    cap: CLOCK_SKEW_PROFILE.vc,
    verifyValid: (clockSkewSeconds) => {
      verifySdJwt(VALID_SD_JWT, {
        issuerKey: ISSUER_JWK,
        nowSeconds: N,
        ...(clockSkewSeconds !== undefined ? { clockSkewSeconds } : {}),
      });
    },
    verifyMalformed: (clockSkewSeconds) => {
      verifySdJwt('not-a-sd-jwt', { issuerKey: ISSUER_JWK, nowSeconds: N, clockSkewSeconds });
    },
  },
];

const OPTION_INVALID = new VericertsError(ErrorCodes.CLOCK_SKEW_OPTION_INVALID);

for (const entry of ENTRY_POINTS) {
  describe(`clockSkewSeconds のオプション検証（${entry.name}、上限 ${entry.cap}s）`, () => {
    /** キャップに依存する不正値の一覧（ラベル, 値）。 */
    const invalidValues: readonly (readonly [string, number])[] = [
      [`上限 +1（${entry.cap + 1}）`, entry.cap + 1],
      ['負値（-1）', -1],
      ['非整数（1.5）', 1.5],
      ['NaN', Number.NaN],
      ['Infinity', Number.POSITIVE_INFINITY],
      ["文字列 '30'", '30' as unknown as number],
    ];

    for (const [label, value] of invalidValues) {
      it(`${label} は CLOCK_SKEW_OPTION_INVALID（4015）`, () => {
        expect(() => entry.verifyValid(value)).toThrow(OPTION_INVALID);
      });
    }

    it('上限ちょうどは受理する', () => {
      expect(() => entry.verifyValid(entry.cap)).not.toThrow();
    });

    it('0（最も厳しい設定）は受理する', () => {
      expect(() => entry.verifyValid(0)).not.toThrow();
    });

    it('未指定は既定（= 上限キャップ）で検証し受理する', () => {
      expect(() => entry.verifyValid(undefined)).not.toThrow();
    });

    it('構造不正な入力でも、暗号処理より前に 4015 で拒否する', () => {
      // オプション検証を後回しにすると 2001 / 3010 が先に出る。fail fast の契約を固定する。
      expect(() => entry.verifyMalformed(entry.cap + 1)).toThrow(OPTION_INVALID);
    });
  });
}

describe('種別ごとのキャップの差', () => {
  it('verifyPresentation は 60 を拒否する（VP のキャップは 30。VC の 120 ではない）', () => {
    // ClockSkewKind の取り違え（vp に vc のキャップを使う等）を検知する。
    expect(() =>
      verifyPresentation(VALID_JWT_VP, {
        key: { publicKeyJwk: ISSUER_JWK },
        expectedAudience: AUD,
        expectedNonce: NONCE,
        nowSeconds: N,
        clockSkewSeconds: 60,
      }),
    ).toThrow(OPTION_INVALID);
  });

  it('verifySdJwt は 31 をオプションとして受理する（VC のキャップは 120。VP の 30 を誤用していない）', () => {
    const result = verifySdJwt(SD_JWT_WITH_KB_AT_CAP, {
      issuerKey: ISSUER_JWK,
      audience: AUD,
      nonce: NONCE,
      nowSeconds: N,
      clockSkewSeconds: 31,
    });
    expect(result.keyBindingVerified).toBe(true);
  });

  it('clockSkewSeconds: 31 でも KB-JWT は 30 にクランプされる（iat = N+31 は 4014）', () => {
    // クランプを外すと 31 がそのまま KB へ効いて N+31 が受理されるため、この境界だけが
    // クランプの有無を判別できる（N+30 はクランプ有無どちらでも受理される）。
    const kbJustOverCap = addKeyBinding(selectDisclosures(VALID_SD_JWT, ['name']), HOLDER_SIGNER, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: N + CLOCK_SKEW_PROFILE.kbJwt + 1,
    });
    expect(() =>
      verifySdJwt(kbJustOverCap, {
        issuerKey: ISSUER_JWK,
        audience: AUD,
        nonce: NONCE,
        nowSeconds: N,
        clockSkewSeconds: 31,
      }),
    ).toThrow(new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED));
  });
});

describe('CLOCK_SKEW_PROFILE', () => {
  it('トークン種別ごとに時計ずれの上限を設定する', () => {
    expect(CLOCK_SKEW_PROFILE).toEqual({
      vc: 120,
      vp: 30,
      kbJwt: 30,
      dpopProof: 30,
      token: 60,
    });
  });
});
