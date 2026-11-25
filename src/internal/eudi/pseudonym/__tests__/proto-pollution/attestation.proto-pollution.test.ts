/**
 * Pseudonym Attestation の署名対象クレームへの汚染混入テスト。
 *
 * `issuePseudonymAttestation` は組み立てた claims をそのまま署名する。必須オプションを
 * プロトタイプ鎖で読むと、それらを**省略した**入力でも汚染値が **署名済み Attestation** に載る:
 *
 * - `issuer`: `iss` が攻撃者の選んだ発行者になり、別 Wallet Instance を騙る Attestation になる。
 * - `nowSeconds`: `iat` / `exp` が攻撃者の選んだ時刻になり、任意時点で有効な Attestation になる。
 *
 * いずれも「汚染値が載らない」＝ fail-closed に拒否されることを、生成 JWT をデコードして確認する。
 * `lifetimeSeconds`は `eudi/__tests__/proto-pollution/eudi-signed-output` が担保する。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { VericertsError } from '../../../../errors.js';
import type { PseudonymAttestationOptions } from '../../attestation.js';
import { issuePseudonymAttestation } from '../../attestation.js';

const MASTER_SEED = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff);
const RP = 'rp-a.example';
const ISSUER = 'urn:wallet-instance:test';
const NOW = 1_700_000_000;

/** 攻撃者が仕込む汚染値。 */
const EVIL_ISSUER = 'urn:wallet-instance:attacker';
const EVIL_NOW = 4_100_000_000;

function decodePayload(jwt: string): Record<string, unknown> {
  const [, payloadSeg] = jwt.split('.');
  return JSON.parse(new TextDecoder().decode(base64urlnopad.decode(payloadSeg ?? ''))) as Record<
    string,
    unknown
  >;
}

/** 必須プロパティを**省略した**オプションを組み立てる（省略キーは生やさない）。 */
function optsWithout(present: Partial<PseudonymAttestationOptions>): PseudonymAttestationOptions {
  return present as PseudonymAttestationOptions;
}

describe('Pseudonym Attestation の必須クレームの Object.prototype 汚染耐性', () => {
  it('issuer を省略した発行は、継承した issuer を iss に載せず 10201 で拒否する', () => {
    const error = withPollutedPrototype({ issuer: EVIL_ISSUER }, () => {
      try {
        const { jwt } = issuePseudonymAttestation(
          RP,
          MASTER_SEED,
          optsWithout({ nowSeconds: NOW }),
        );
        // 署名されてしまった場合は汚染値が載っていないことまで確認する（載っていれば欠陥）。
        return decodePayload(jwt).iss;
      } catch (e) {
        return e;
      }
    });
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe('10201');
  });

  it('nowSeconds を省略した発行は、継承した nowSeconds を iat / exp に載せず 10201 で拒否する', () => {
    const error = withPollutedPrototype({ nowSeconds: EVIL_NOW }, () => {
      try {
        const { jwt } = issuePseudonymAttestation(RP, MASTER_SEED, optsWithout({ issuer: ISSUER }));
        const payload = decodePayload(jwt);
        return { iat: payload.iat, exp: payload.exp };
      } catch (e) {
        return e;
      }
    });
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe('10201');
  });

  it('汚染下でも明示的に渡した issuer / nowSeconds がそのまま署名される（正常系）', () => {
    const { jwt } = withPollutedPrototype({ issuer: EVIL_ISSUER, nowSeconds: EVIL_NOW }, () =>
      issuePseudonymAttestation(RP, MASTER_SEED, { issuer: ISSUER, nowSeconds: NOW }),
    );
    const payload = decodePayload(jwt);
    expect(payload.iss).toBe(ISSUER);
    expect(payload.iat).toBe(NOW);
    expect(payload.exp).toBe(NOW + 24 * 60 * 60);
  });
});
