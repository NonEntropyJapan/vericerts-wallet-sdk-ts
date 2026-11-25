/**
 * 公開受理集合 `ACCEPTED_SD_JWT_VC_TYPS` の可変性汚染に対する回帰テスト（実鍵・モック禁止）。
 *
 * 可変な `Set` を `ReadonlySet` 型で隠しただけの公開値は、利用者側の
 * `(SET as Set<string>).add('kb+jwt')` 一発でプロセス全体の受理集合を恒久的に広げ、
 * `assertAcceptedSdJwtVcTypIfPresent` による typ 混同ガードを無力化する。
 *
 * 検証内容:
 * - 公開値への直接変更（`add` / `delete` / `clear`）は `TypeError` で拒否される。
 * - `Set.prototype.add.call` によるプロトタイプ経由の汚染も `TypeError` で拒否され、ビューの
 *   中身自体が書き換わらない。
 * - 双方の汚染を試みたあとでも、`verifySdJwt` / `toQueryableFromSdJwt` は `kb+jwt` を `3002` で
 *   拒否し続ける（ガードは公開値ではなく module-private の権威集合を読む）。
 * - `forEach` のコールバック第 3 引数はビュー自身であり、そこから可変な実体が漏れない。
 * - 読み取り操作（`has` / `size` / スプレッド / `new Set` / `forEach`）は従来どおり動く。
 *
 * import は到達可能な公開 API（公開 barrel）経由とし、内部ヘルパは経由しない。
 */

import { describe, expect, it } from 'bun:test';
import {
  ACCEPTED_SD_JWT_VC_TYPS,
  createPrivateKeySigner,
  ErrorCodes,
  getP256PublicKey,
  type PublicKeyJwk,
  SD_JWT_VC_TYP,
  SD_JWT_VC_TYP_LEGACY,
  toQueryableFromSdJwt,
  VericertsError,
  verifySdJwt,
} from '../../../../../index.js';

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_KEY = new Uint8Array(32).fill(7);
const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false));
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const VCT = 'https://example.com/credentials/identity';
const FOREIGN_TYP = 'kb+jwt';

/** 汚染操作を実行し、投げられた例外を返す（投げない実装でも呼び出しを継続させる）。 */
function captureError(attempt: () => unknown): unknown {
  try {
    attempt();
  } catch (error) {
    return error;
  }
  return undefined;
}

/** 任意のヘッダを手組みし、実 issuer 鍵で署名した SD-JWT（Disclosure なし）を作る。 */
function issueWithRawHeader(header: Record<string, unknown>): string {
  const b64uText = (t: string): string => Buffer.from(t).toString('base64url');
  const payload = { vct: VCT, _sd: [], _sd_alg: 'sha-256' };
  const signingInput = `${b64uText(JSON.stringify(header))}.${b64uText(JSON.stringify(payload))}`;
  const sig = ISSUER_SIGNER.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${Buffer.from(sig).toString('base64url')}~`;
}

describe('ACCEPTED_SD_JWT_VC_TYPS は変更不能ビューである', () => {
  it('正当なメンバ（新旧 typ）だけを含む', () => {
    expect([...ACCEPTED_SD_JWT_VC_TYPS].sort()).toEqual(
      [SD_JWT_VC_TYP, SD_JWT_VC_TYP_LEGACY].sort(),
    );
  });

  it('読み取り操作は従来どおり動く（非破壊的変更であることの表明）', () => {
    expect(ACCEPTED_SD_JWT_VC_TYPS.has(SD_JWT_VC_TYP)).toBe(true);
    expect(ACCEPTED_SD_JWT_VC_TYPS.has(FOREIGN_TYP)).toBe(false);
    expect(ACCEPTED_SD_JWT_VC_TYPS.size).toBe(2);
    expect(new Set(ACCEPTED_SD_JWT_VC_TYPS).size).toBe(2);
    const collected: string[] = [];
    ACCEPTED_SD_JWT_VC_TYPS.forEach((typ) => {
      collected.push(typ);
    });
    expect(collected.sort()).toEqual([SD_JWT_VC_TYP, SD_JWT_VC_TYP_LEGACY].sort());
  });

  it('add / delete / clear は TypeError で拒否する', () => {
    const mutable = ACCEPTED_SD_JWT_VC_TYPS as unknown as Set<string>;
    expect(() => mutable.add(FOREIGN_TYP)).toThrow(TypeError);
    expect(() => mutable.delete(SD_JWT_VC_TYP)).toThrow(TypeError);
    expect(() => mutable.clear()).toThrow(TypeError);
  });

  it('forEach のコールバック第 3 引数から可変な実体が漏れない', () => {
    // 素の `Set.prototype.forEach` は `this`（＝ビューが包む可変 `Set`）を第 3 引数に渡すため、
    // 実体に束縛したままだとコールバック内から受理集合を恒久的に広げられてしまう。
    const errors: unknown[] = [];
    ACCEPTED_SD_JWT_VC_TYPS.forEach((_typ, _typ2, set) => {
      expect(set).toBe(ACCEPTED_SD_JWT_VC_TYPS);
      errors.push(captureError(() => (set as Set<string>).add(FOREIGN_TYP)));
    });
    expect(errors).toHaveLength(2);
    for (const error of errors) {
      expect(error).toBeInstanceOf(TypeError);
    }
    expect(ACCEPTED_SD_JWT_VC_TYPS.has(FOREIGN_TYP)).toBe(false);
    expect(ACCEPTED_SD_JWT_VC_TYPS.size).toBe(2);
  });
});

describe('公開受理集合を汚染しても typ 混同ガードは広がらない', () => {
  it('直接変更とプロトタイプ経由の汚染の双方を通しても kb+jwt は 3002 で拒否される', () => {
    // 汚染は 2 経路とも拒否されるはずだが、ここでは throw を待たずに素通りさせる。拒否が
    // 効かない実装でもガード側の表明まで必ず到達させ、本丸（受理範囲が広がらないこと）を
    // 検証するためである。捕捉した例外は後段でまとめて表明する。
    const errors = [
      captureError(() => (ACCEPTED_SD_JWT_VC_TYPS as unknown as Set<string>).add(FOREIGN_TYP)),
      captureError(() => Set.prototype.add.call(ACCEPTED_SD_JWT_VC_TYPS, FOREIGN_TYP)),
    ];

    const foreign = issueWithRawHeader({ alg: 'ES256', typ: FOREIGN_TYP });
    expect(() => toQueryableFromSdJwt(foreign)).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
    expect(() => verifySdJwt(foreign, { issuerKey: ISSUER_JWK })).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
    // 汚染そのものも両経路とも拒否され、ビューの中身も無傷である（多層防御の 1 段目）。
    expect(errors[0]).toBeInstanceOf(TypeError);
    expect(errors[1]).toBeInstanceOf(TypeError);
    expect(ACCEPTED_SD_JWT_VC_TYPS.has(FOREIGN_TYP)).toBe(false);
    expect(ACCEPTED_SD_JWT_VC_TYPS.size).toBe(2);
  });
});
