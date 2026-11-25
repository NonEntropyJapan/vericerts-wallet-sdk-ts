/**
 * `PresentationRequest.requiredLoA`（Verifier 拡張パラメータ `required_loa`）の
 * パースのユニットテスト。
 *
 * `__tests__/` 直下ではなくサブディレクトリへ切り出すのは 1 ディレクトリ行数上限（.linterly.yml）
 * 対応（`create-presentation/` と同じ理由。`request.test.ts` は既に 300 行の 1 ファイル上限にも
 * 達しているため、`requiredLoA` 専用ケースは元々別ファイルに分離が必要だった）。
 *
 * 検証内容:
 * - URL クエリ形式 / JAR JWT 形式の両方で `required_loa` を `requiredLoA` として展開する。
 * - `low` / `substantial` / `high` 以外の値（大文字表記・前後空白等の表記ゆれを含む）は
 *   `OID4VP_REQUEST_PARSE_FAILED`（8030）で fail-closed 拒否する。告知されたのに認識できない値を
 *   「未指定」へ丸めると、`checkLoa` フックの LoA 判定自体が無言でスキップされ実質 fail-open になる
 *   ため（`evidence-tou/evidence.ts` の `isLoA` を再利用）。
 * - パラメータ自体が無い場合は `requiredLoA` を own プロパティとして持たない（LoA 判定は不要という
 *   正当な「未指定」であり、`Object.hasOwn` で判定できることの確認。汚染耐性は
 *   `proto-pollution/request.proto-pollution.test.ts` が別途担う）。
 */

import { describe, expect, it } from 'bun:test';
import { createSdJwt } from '../../../credential/sdjwt/sdjwt.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { parseAuthorizationRequest, parseJarRequest } from '../../request.js';

const CLIENT_ID = 'https://verifier.example.com';
const RESPONSE_URI = 'https://verifier.example.com/callback';
const NONCE = 'n-0S6_WzA2Mj-0123456789';
const STATE = 'af0ifjsldkj';

const DCQL = {
  credentials: [
    { id: 'pid', format: 'vc+sd-jwt', meta: { vct_values: ['https://example.com/pid'] } },
  ],
};

/** 正常系の URL クエリを組み立てる。 */
function buildUri(overrides: Record<string, string | undefined> = {}): string {
  const params: Record<string, string | undefined> = {
    response_type: 'vp_token',
    client_id: CLIENT_ID,
    response_mode: 'direct_post',
    response_uri: RESPONSE_URI,
    nonce: NONCE,
    state: STATE,
    dcql_query: JSON.stringify(DCQL),
    ...overrides,
  };
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      search.set(key, value);
    }
  }
  return `openid4vp://?${search.toString()}`;
}

describe('parseAuthorizationRequest: required_loa', () => {
  it('required_loa を requiredLoA として展開する', () => {
    const req = parseAuthorizationRequest(buildUri({ required_loa: 'substantial' }));
    expect(req.requiredLoA).toBe('substantial');
  });

  it('low / substantial / high 以外の値は 8030 で fail-closed 拒否する', () => {
    let err: unknown;
    try {
      parseAuthorizationRequest(buildUri({ required_loa: 'bogus' }));
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(VericertsError);
    expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  });

  it.each([
    'HIGH',
    'High',
    'substantial ',
  ])('大文字表記・前後空白等の表記ゆれ（%s）も 8030 で拒否する', (value) => {
    expect(() => parseAuthorizationRequest(buildUri({ required_loa: value }))).toThrow(
      new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED),
    );
  });

  it('required_loa を指定しない場合は own プロパティとして requiredLoA を持たない', () => {
    const req = parseAuthorizationRequest(buildUri());
    expect(Object.hasOwn(req, 'requiredLoA')).toBe(false);
  });
});

describe('parseJarRequest: required_loa', () => {
  const JAR_KEY = new Uint8Array(32).fill(7);
  const signer = createPrivateKeySigner(JAR_KEY, 'ES256');

  /** OID4VP パラメータを payload に持つ JAR JWT（コンパクト JWS）を実署名で作る。 */
  function buildJarJwt(payload: Record<string, unknown>): string {
    const sdJwt = createSdJwt(signer, { vct: 'jar', disclosureClaims: [], claims: payload });
    return sdJwt.split('~')[0] as string;
  }

  const BASE_CLAIMS = {
    response_type: 'vp_token',
    client_id: CLIENT_ID,
    response_mode: 'direct_post',
    response_uri: RESPONSE_URI,
    nonce: NONCE,
    state: STATE,
  };

  it('JAR payload の required_loa を requiredLoA として展開する', () => {
    const jwt = buildJarJwt({ ...BASE_CLAIMS, required_loa: 'high' });
    expect(parseJarRequest(jwt).requiredLoA).toBe('high');
  });

  it('JAR payload の required_loa が不正な値なら 8030 で fail-closed 拒否する', () => {
    const jwt = buildJarJwt({ ...BASE_CLAIMS, required_loa: 'invalid-level' });
    let err: unknown;
    try {
      parseJarRequest(jwt);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(VericertsError);
    expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  });

  it('JAR payload の required_loa が大文字表記（HIGH）なら 8030 で拒否する', () => {
    const jwt = buildJarJwt({ ...BASE_CLAIMS, required_loa: 'HIGH' });
    expect(() => parseJarRequest(jwt)).toThrow(
      new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED),
    );
  });

  it('JAR payload に required_loa が無い場合は own プロパティとして requiredLoA を持たない', () => {
    const jwt = buildJarJwt(BASE_CLAIMS);
    expect(Object.hasOwn(parseJarRequest(jwt), 'requiredLoA')).toBe(false);
  });
});
