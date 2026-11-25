/**
 * DPoP proof の時刻オプションの `Object.prototype` 汚染耐性テスト。
 *
 * `options.nowSeconds` をプロトタイプ鎖で読むと、`nowSeconds` を**省略した**正当な検証でも
 * 汚染値が「現在時刻」として使われ、`iat` の鮮度窓（±30 s）を過ぎた**古い DPoP proof が
 * そのまま受理される**（リプレイ）。`clockSkewSeconds` / `maxAgeSeconds` も同じ経路で
 * 実効の鮮度窓を動かす。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { createPrivateKeySigner } from '../../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { createDpopProof } from '../../dpop.js';
import { verifyDpopProof } from '../../dpop-verify.js';

const KEY = new Uint8Array(32).fill(7);
const HTM = 'POST';
const HTU = 'https://api.example.com/mcp';

/** 実時刻。汚染値（過去）と区別できるよう実際の now を使う。 */
const REAL_NOW = Math.floor(Date.now() / 1000);
/** 鮮度窓（±30 s）より十分過去の時刻。 */
const STALE_IAT = REAL_NOW - 10_000;

const signer = createPrivateKeySigner(KEY, 'ES256');

/** 指定した `iat` の proof を生成する。 */
function proofAt(iat: number): string {
  return createDpopProof(
    { htm: HTM, htu: HTU, jti: '3b241101-e2bb-4255-8caf-4136c566a962', nowSeconds: iat },
    signer,
  );
}

describe('verifyDpopProof の時刻オプション汚染耐性', () => {
  it('継承した nowSeconds では古い DPoP proof を受理しない', () => {
    const proof = proofAt(STALE_IAT);
    expect(() =>
      withPollutedPrototype({ nowSeconds: STALE_IAT }, () =>
        // nowSeconds は渡していない。汚染値を拾えば「まだ新鮮」と判定されリプレイが通る。
        verifyDpopProof(proof, { htm: HTM, htu: HTU }),
      ),
    ).toThrow(new VericertsError(ErrorCodes.DPOP_PROOF_EXPIRED));
  });

  it('継承した maxAgeSeconds では鮮度窓を広げられない', () => {
    const proof = proofAt(STALE_IAT);
    expect(() =>
      // `maxAgeSeconds` はキャップ 30 以下しか受理しないため、汚染値を拾うと 4015 になる。
      // own 限定で読めばそもそも「未指定」として既定 30 が使われ、4082 で拒否される。
      withPollutedPrototype({ maxAgeSeconds: 10_000 }, () =>
        verifyDpopProof(proof, { htm: HTM, htu: HTU }),
      ),
    ).toThrow(new VericertsError(ErrorCodes.DPOP_PROOF_EXPIRED));
  });

  it('継承した clockSkewSeconds では未来方向の窓を広げられない', () => {
    const future = proofAt(REAL_NOW + 10_000);
    expect(() =>
      withPollutedPrototype({ clockSkewSeconds: 10_000 }, () =>
        verifyDpopProof(future, { htm: HTM, htu: HTU }),
      ),
    ).toThrow(new VericertsError(ErrorCodes.DPOP_PROOF_EXPIRED));
  });

  it('明示的に渡した nowSeconds は従来どおり基準時刻になる（正常系）', () => {
    const proof = proofAt(STALE_IAT);
    const verified = verifyDpopProof(proof, { htm: HTM, htu: HTU, nowSeconds: STALE_IAT });
    expect(verified.iat).toBe(STALE_IAT);
  });

  it('新鮮な proof は従来どおり受理される（正常系）', () => {
    const proof = proofAt(REAL_NOW);
    expect(verifyDpopProof(proof, { htm: HTM, htu: HTU }).iat).toBe(REAL_NOW);
  });
});
