/**
 * 公開 format 集合（`SD_JWT_VC_FORMATS` / `SUPPORTED_DCQL_FORMATS`）の可変性汚染に対する
 * 回帰テスト（実鍵・モック禁止）。
 *
 * 可変な `Set` を `ReadonlySet` 型で隠しただけの公開値は、利用者側の
 * `(SET as Set<string>).add(...)` 一発でプロセス全体の受理 format を恒久的に広げる。
 * さらに `SD_JWT_VC_FORMATS` は `ACCEPTED_SD_JWT_VC_TYPS` と同一インスタンスの再エクスポート
 * だったため、片方への汚染が SD-JWT VC の typ 混同ガードにまで波及していた。
 *
 * 検証内容:
 * - `SD_JWT_VC_FORMATS` は `ACCEPTED_SD_JWT_VC_TYPS` と別インスタンスであり、汚染しても
 *   `toQueryableFromSdJwt` は `kb+jwt` を `3002` で拒否し続ける。
 * - `SUPPORTED_DCQL_FORMATS` を汚染しても `evaluateDcql` は未対応 format を `8050` で拒否し続ける。
 * - 双方とも直接変更・プロトタイプ経由の変更をいずれも `TypeError` で拒否し、ビューの中身が
 *   書き換わらない。読み取り操作は従来どおり動く。
 * - `forEach` のコールバック第 3 引数はビュー自身であり、そこから可変な実体が漏れない。
 * - 双方は別インスタンスでありながら中身が一致する＝メンバ列挙の SSOT（`typ.ts` の正準リスト
 *   `ACCEPTED_SD_JWT_VC_TYP_VALUES`）が 1 か所であり、公開ビューを別の公開ビューから派生させて
 *   いない。
 *
 * import は到達可能な公開 API（公開 barrel）経由とし、内部ヘルパは経由しない。例外は
 * `ACCEPTED_SD_JWT_VC_TYP_VALUES` だけで、これは公開 API に出さない正準リストそのものが
 * 検証対象であるため内部モジュールから直接読む。
 */

import { describe, expect, it } from 'bun:test';
import {
  ACCEPTED_SD_JWT_VC_TYPS,
  createPrivateKeySigner,
  createSdJwt,
  ErrorCodes,
  evaluateDcql,
  parseDcqlQuery,
  SD_JWT_VC_FORMATS,
  SD_JWT_VC_TYP,
  SD_JWT_VC_TYP_LEGACY,
  SUPPORTED_DCQL_FORMATS,
  toQueryableFromSdJwt,
  VericertsError,
} from '../../../index.js';
// メンバ列挙の SSOT は公開 API ではないため、この 1 件だけ内部モジュールから直接読む
// （「両ビューが同一の正準リストから組み立てられている」ことが検証対象そのものであるため）。
import { ACCEPTED_SD_JWT_VC_TYP_VALUES } from '../../credential/sdjwt/typ.js';

const ISSUER_SIGNER = createPrivateKeySigner(new Uint8Array(32).fill(7), 'ES256');
const VCT = 'https://example.com/pid';
const FOREIGN_TYP = 'kb+jwt';
const UNSUPPORTED_FORMAT = 'ldp_vc';
/** 対応する検証経路がないため、ネゴシエーションで提示できない形式。 */
const DEFERRED_FORMATS = [UNSUPPORTED_FORMAT, 'vc+cose', 'bbs+'] as const;

/** 既定発行（`dc+sd-jwt`）の SD-JWT VC を 1 件作る。 */
function issueSdJwt(): string {
  return createSdJwt(ISSUER_SIGNER, {
    vct: VCT,
    disclosureClaims: ['nickname'],
    claims: { nickname: 'ali', jti: 'urn:sdjwt:1' },
    salts: { nickname: 'salt-nick' },
  });
}

/** 実発行 SD-JWT の JWS ヘッダを差し替える（署名検証を伴わない経路の入力を作る）。 */
function withHeader(sdJwt: string, header: Record<string, unknown>): string {
  const [issuerJwt, ...rest] = sdJwt.split('~');
  const [, payloadSeg, signatureSeg] = (issuerJwt as string).split('.');
  const headerSeg = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  return [`${headerSeg}.${payloadSeg}.${signatureSeg}`, ...rest].join('~');
}

/**
 * 汚染操作を実行し、投げられた例外を返す（投げない実装でも呼び出しを継続させる）。
 *
 * 変更が拒否されること自体より「ガードが広がらないこと」の表明を優先するため、ここでは
 * `expect().toThrow()` で打ち切らず、例外を持ち帰って後段で表明する。
 */
function captureError(attempt: () => unknown): unknown {
  try {
    attempt();
  } catch (error) {
    return error;
  }
  return undefined;
}

/** 直接変更とプロトタイプ経由という 2 経路で汚染を試み、それぞれの例外を返す。 */
function attemptPollution(view: ReadonlySet<string>, value: string): readonly unknown[] {
  return [
    captureError(() => (view as Set<string>).add(value)),
    captureError(() => Set.prototype.add.call(view, value)),
  ];
}

/** 2 経路の汚染がいずれも拒否され、ビューの中身が無傷であることを表明する。 */
function expectPollutionRejected(
  errors: readonly unknown[],
  view: ReadonlySet<string>,
  value: string,
  size: number,
): void {
  expect(errors[0]).toBeInstanceOf(TypeError);
  expect(errors[1]).toBeInstanceOf(TypeError);
  expect(view.has(value)).toBe(false);
  expect(view.size).toBe(size);
}

/**
 * `forEach` のコールバック第 3 引数から可変な実体が漏れないことを表明する。
 *
 * 素の `Set.prototype.forEach` は `this`（＝ビューが包む可変 `Set`）を第 3 引数に渡すため、
 * 実体に束縛したままだとコールバック内から公開集合を恒久的に広げられてしまう。
 */
function expectForEachDoesNotLeak(view: ReadonlySet<string>, value: string, size: number): void {
  const errors: unknown[] = [];
  view.forEach((_member, _member2, set) => {
    expect(set).toBe(view);
    errors.push(captureError(() => (set as Set<string>).add(value)));
  });
  expect(errors).toHaveLength(size);
  for (const error of errors) {
    expect(error).toBeInstanceOf(TypeError);
  }
  expect(view.has(value)).toBe(false);
  expect(view.size).toBe(size);
}

describe('SD_JWT_VC_FORMATS は独立した変更不能ビューである', () => {
  it('ACCEPTED_SD_JWT_VC_TYPS と同一インスタンスではない', () => {
    expect(SD_JWT_VC_FORMATS).not.toBe(ACCEPTED_SD_JWT_VC_TYPS);
  });

  it('ACCEPTED_SD_JWT_VC_TYPS と中身が一致し、双方が同一の正準リスト由来である', () => {
    // 別インスタンスでありながら中身は必ず一致する＝メンバ列挙の SSOT が 1 か所であることの表明。
    // どちらかが独自にリテラルを書き写すと、メンバ追加時にこの表明が落ちる。
    const canonical = [...ACCEPTED_SD_JWT_VC_TYP_VALUES].sort();
    expect(SD_JWT_VC_FORMATS).not.toBe(ACCEPTED_SD_JWT_VC_TYPS);
    expect([...SD_JWT_VC_FORMATS].sort()).toEqual([...ACCEPTED_SD_JWT_VC_TYPS].sort());
    expect([...SD_JWT_VC_FORMATS].sort()).toEqual(canonical);
    expect([...ACCEPTED_SD_JWT_VC_TYPS].sort()).toEqual(canonical);
  });

  it('正当なメンバだけを含み、読み取り操作は従来どおり動く', () => {
    expect([...SD_JWT_VC_FORMATS].sort()).toEqual([SD_JWT_VC_TYP, SD_JWT_VC_TYP_LEGACY].sort());
    expect(SD_JWT_VC_FORMATS.has(SD_JWT_VC_TYP)).toBe(true);
    expect(SD_JWT_VC_FORMATS.size).toBe(2);
    expect(new Set(SD_JWT_VC_FORMATS).size).toBe(2);
  });

  it('forEach のコールバック第 3 引数から可変な実体が漏れない', () => {
    expectForEachDoesNotLeak(SD_JWT_VC_FORMATS, FOREIGN_TYP, 2);
  });

  it('汚染を試みても toQueryableFromSdJwt は kb+jwt を 3002 で拒否し続ける', () => {
    // 汚染は throw を待たずに素通りさせる（拒否が効かない実装でもガード側の表明まで必ず
    // 到達させ、本丸を検証するため）。
    const errors = attemptPollution(SD_JWT_VC_FORMATS, FOREIGN_TYP);

    const foreign = withHeader(issueSdJwt(), { alg: 'ES256', typ: FOREIGN_TYP });
    expect(() => toQueryableFromSdJwt(foreign)).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
    expectPollutionRejected(errors, SD_JWT_VC_FORMATS, FOREIGN_TYP, 2);
  });
});

describe('SUPPORTED_DCQL_FORMATS は変更不能ビューである', () => {
  /** 指定 format を要求する最小の DCQL クエリを組み立てる。 */
  function queryFor(format: string) {
    return parseDcqlQuery({ credentials: [{ id: 'q1', format }] });
  }

  it('正当なメンバだけを含み、読み取り操作は従来どおり動く', () => {
    expect([...SUPPORTED_DCQL_FORMATS].sort()).toEqual(
      ['jwt_vc_json', 'jwt_vc_json-ld', SD_JWT_VC_TYP, SD_JWT_VC_TYP_LEGACY].sort(),
    );
    for (const format of DEFERRED_FORMATS) {
      // `jwt_vc_json-ld` は JWS Enveloping Proof を
      // `jwt_vc_json` と共有する実装済みフォーマットなので、この集合には含めない。
      expect(SUPPORTED_DCQL_FORMATS.has(format)).toBe(false);
    }
    expect(SUPPORTED_DCQL_FORMATS.size).toBe(4);
  });

  it('forEach のコールバック第 3 引数から可変な実体が漏れない', () => {
    expectForEachDoesNotLeak(SUPPORTED_DCQL_FORMATS, UNSUPPORTED_FORMAT, 4);
  });

  it('汚染を試みても evaluateDcql は未対応 format を 8050 で拒否し続ける', () => {
    const errors = attemptPollution(SUPPORTED_DCQL_FORMATS, UNSUPPORTED_FORMAT);

    expect(() => evaluateDcql(queryFor(UNSUPPORTED_FORMAT), [])).toThrow(
      new VericertsError(ErrorCodes.FORMAT_NEGOTIATION_FAILED, {
        context: { format: UNSUPPORTED_FORMAT },
      }),
    );
    expectPollutionRejected(errors, SUPPORTED_DCQL_FORMATS, UNSUPPORTED_FORMAT, 4);
    // 正当な format は引き続き通る（受理判定は権威集合が決める）。
    expect(
      evaluateDcql(queryFor(SD_JWT_VC_TYP), [toQueryableFromSdJwt(issueSdJwt())]),
    ).toHaveLength(1);
  });
});
