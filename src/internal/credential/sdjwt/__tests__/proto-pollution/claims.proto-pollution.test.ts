/**
 * `recoverClaims` の `_sd` / `_sd_alg` own 読み取りの回帰テスト（同クラス）。
 *
 * `claims.ts` の `recoverClaims` が `payload._sd` / `payload._sd_alg` をプロトタイプ鎖で読んでいた。
 * `payload` は Issuer-signed JWT を `JSON.parse` した素のオブジェクトで、プロトタイプは
 * `Object.prototype` である。したがって **そのクレームを持たない** SD-JWT の検証時に汚染値が
 * 「payload に実際に入っていた値」として扱われる:
 *
 * - `_sd`（fail-open）: 選択的開示クレームが 1 つも無い（`_sd` を持たない）VC の検証で
 *   `Object.prototype._sd` の digest 配列から `digestSet` が構築され、Issuer が署名していない
 *   digest に対応する **偽造 Disclosure が `_sd` 照合を通過して平文クレームとして復元される**。
 *   復元値は `VerifiedSdJwt.claims` として「検証済み」の顔で返る。
 * - `_sd_alg`（fail-closed / 可用性）: `_sd_alg` を持たない VC が汚染値（`sha-256` 以外）を拾い、
 *   正当な VC が一律 3010 で拒否される。
 *
 * ここで読む対象は `JSON.parse` 済みの payload（外部入力の素のオブジェクト）であり、クラス
 * インスタンスにも関数値にもならない。したがって `nonObjectPrototypeProperty` ではなく
 * `ownProperty`（own 限定）が正しい（`own-property.ts` の使い分け）。
 *
 * 汚染は共有フィクスチャ `internal/__tests__/prototype-pollution.fixtures.ts` の
 * `withPollutedPrototype` で仕込む（非列挙・必ず復元）。
 *
 * 各「汚染下で閉じる」テストには、**同じ Disclosure が `_sd` を実際に持つ payload では受理される**
 * ことを示す対照テストを添える。拒否が「Disclosure 自体が壊れている」等の無関係な理由ではなく
 * `_sd` の有無に起因することを担保し、テストがトートロジーになるのを防ぐ。
 *
 * 親ディレクトリ `sdjwt/__tests__/` は Linterly のディレクトリ行数上限（2000 行）を既に超過している
 * ため、本ファイルはサブディレクトリに置く。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getP256PublicKey } from '../../../../keymanager/signer.js';
import { createPrivateKeySigner } from '../../../vc/signer.js';
import { encodeDisclosure } from '../../disclosure.js';
import { verifySdJwt } from '../../verify.js';

const b64uText = (text: string): string => Buffer.from(text).toString('base64url');

function toJwk(pub: Uint8Array): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_KEY = new Uint8Array(32).fill(7);
const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false));
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');

const VCT = 'https://example.com/credentials/identity';
const NOW = Math.floor(Date.parse('2026-01-01T00:00:00Z') / 1000);

/** Issuer が署名していない、攻撃者が組み立てた Disclosure。 */
const FORGED = encodeDisclosure('isAdmin', true, 'fixed-salt-for-test');

const baseOpts = { issuerKey: ISSUER_JWK, nowSeconds: NOW } as const;

/**
 * 任意の payload を手組みし、実 issuer 鍵で署名した SD-JWT を作る。
 *
 * `createSdJwt` は `_sd` / `_sd_alg` を常に付与するため、それらを**持たない** payload
 * （汚染が実際に効く経路）を作るには手組みする必要がある。
 */
function issuerJwtWithRawPayload(
  payload: Record<string, unknown>,
  disclosures: readonly string[] = [],
): string {
  const header = { alg: 'ES256', typ: 'dc+sd-jwt' };
  const signingInput = `${b64uText(JSON.stringify(header))}.${b64uText(JSON.stringify(payload))}`;
  const sig = ISSUER_SIGNER.sign(new TextEncoder().encode(signingInput));
  const issuerJwt = `${signingInput}.${Buffer.from(sig).toString('base64url')}`;
  return `${[issuerJwt, ...disclosures].join('~')}~`;
}

/** 汚染下で `verifySdJwt` を実行し、成功値か送出された例外のどちらかを返す。 */
function verifyUnderPollution(
  props: Readonly<Record<string, unknown>>,
  sdJwt: string,
): { ok: true; claims: Readonly<Record<string, unknown>> } | { ok: false; error: unknown } {
  return withPollutedPrototype(props, () => {
    try {
      return { ok: true as const, claims: verifySdJwt(sdJwt, baseOpts).claims };
    } catch (error) {
      return { ok: false as const, error };
    }
  });
}

describe('claims.ts: recoverClaims の `_sd` own 読み取り', () => {
  it('_sd を持たない SD-JWT は Object.prototype._sd 汚染下でも偽造 Disclosure を受理しない', () => {
    // 鎖読みだと digestSet が汚染値で構築され、Issuer 未署名の FORGED が `_sd` 照合を通過して
    // claims.isAdmin === true が「検証済み」として返る（fail-open）。
    const sdJwt = issuerJwtWithRawPayload({ vct: VCT, iat: NOW }, [FORGED.encoded]);
    const outcome = verifyUnderPollution({ _sd: [FORGED.digest] }, sdJwt);
    expect(outcome.ok).toBe(false);
    expect(outcome.ok ? null : outcome.error).toEqual(new VericertsError(ErrorCodes.SIG_INVALID));
  });

  it('対照: 同じ Disclosure は `_sd` に digest を実際に持つ payload では受理される', () => {
    // 上の拒否が Disclosure の不備ではなく `_sd` の有無に起因することを示す（トートロジー防止）。
    const sdJwt = issuerJwtWithRawPayload(
      { vct: VCT, iat: NOW, _sd: [FORGED.digest], _sd_alg: 'sha-256' },
      [FORGED.encoded],
    );
    expect(verifySdJwt(sdJwt, baseOpts).claims.isAdmin).toBe(true);
  });

  it('`_sd` を持つ payload では own 値が汚染を shadow する（余計な digest を受理しない）', () => {
    // 空の `_sd` を明示的に持つ VC。own 読みなら汚染値ではなく `[]` が使われ、FORGED は拒否。
    const sdJwt = issuerJwtWithRawPayload({ vct: VCT, iat: NOW, _sd: [] }, [FORGED.encoded]);
    const outcome = verifyUnderPollution({ _sd: [FORGED.digest] }, sdJwt);
    expect(outcome.ok).toBe(false);
    expect(outcome.ok ? null : outcome.error).toEqual(new VericertsError(ErrorCodes.SIG_INVALID));
  });

  it('汚染下でも `_sd` を持たない正当な VC は退行しない（Disclosure 無し）', () => {
    const sdJwt = issuerJwtWithRawPayload({ vct: VCT, iat: NOW });
    const outcome = verifyUnderPollution({ _sd: [FORGED.digest] }, sdJwt);
    expect(outcome.ok).toBe(true);
    // `_sd` / `_sd_alg` は復元クレームに載せない（汚染値が claims へ漏れないことも兼ねる）。
    expect(outcome.ok ? Object.hasOwn(outcome.claims, '_sd') : true).toBe(false);
  });
});

describe('claims.ts: recoverClaims の `_sd_alg` own 読み取り', () => {
  it('_sd_alg を持たない SD-JWT は Object.prototype._sd_alg 汚染下でも受理される', () => {
    // 鎖読みだと汚染値 'sha-512' を「payload の _sd_alg」として拾い、正当な VC が一律 3010。
    const sdJwt = issuerJwtWithRawPayload({ vct: VCT, iat: NOW, _sd: [] });
    const outcome = verifyUnderPollution({ _sd_alg: 'sha-512' }, sdJwt);
    expect(outcome.ok).toBe(true);
  });

  it('対照: `_sd_alg` に未対応値を実際に持つ payload は従来どおり 3010 で拒否される', () => {
    // 汚染なしでも未対応 `_sd_alg` は拒否される（ダウングレード防止のガードが生きている）。
    const sdJwt = issuerJwtWithRawPayload({ vct: VCT, iat: NOW, _sd: [], _sd_alg: 'sha-512' });
    expect(() => verifySdJwt(sdJwt, baseOpts)).toThrow(new VericertsError(ErrorCodes.SIG_INVALID));
  });

  it('汚染が無い通常の検証は退行しない（`_sd_alg` 明示あり / 欠落ともに受理）', () => {
    expect(
      verifySdJwt(issuerJwtWithRawPayload({ vct: VCT, iat: NOW, _sd: [], _sd_alg: 'sha-256' }), {
        ...baseOpts,
      }).vct,
    ).toBe(VCT);
    expect(verifySdJwt(issuerJwtWithRawPayload({ vct: VCT, iat: NOW }), baseOpts).vct).toBe(VCT);
  });
});
