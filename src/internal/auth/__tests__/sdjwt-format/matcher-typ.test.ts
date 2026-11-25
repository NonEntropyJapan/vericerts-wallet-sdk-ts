/**
 * SD-JWT VC の `typ` = DCQL format 識別子の接続テスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - `toQueryableFromSdJwt` が Issuer-signed JWT の `typ` から format を導出する
 *   （既定発行 = `dc+sd-jwt` / 移行期間の opt-in 発行 = `vc+sd-jwt`）。
 * - 受理対象外の `typ` は `verifySdJwt` と同じ失敗面（`3002`）に倒す。
 * - `typ` 欠落は受理し、format は旧識別子 `vc+sd-jwt` として扱う（旧 Issuer 由来とみなす後方互換）。
 * - 既定発行 SD-JWT が `dc+sd-jwt` を要求する DCQL クエリで実際にマッチする（end-to-end 接続）。
 */

import { describe, expect, it } from 'bun:test';
import { createSdJwt } from '../../../credential/sdjwt/sdjwt.js';
import { SD_JWT_VC_TYP, SD_JWT_VC_TYP_LEGACY } from '../../../credential/sdjwt/typ.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { evaluateDcql, parseDcqlQuery, SUPPORTED_DCQL_FORMATS } from '../../dcql/dcql.js';
import {
  FORMAT_SD_JWT_VC,
  FORMAT_SD_JWT_VC_DC,
  SD_JWT_VC_FORMATS,
  selectMatchingCredentials,
  toQueryableFromSdJwt,
} from '../../matcher.js';

const ISSUER_KEY = new Uint8Array(32).fill(7);
const signer = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const VCT = 'https://example.com/pid';

/** 開示クレーム nickname を持つ SD-JWT VC を発行する（`typ` 未指定なら既定 `dc+sd-jwt`）。 */
function issueSdJwt(typ?: typeof SD_JWT_VC_TYP_LEGACY): string {
  return createSdJwt(signer, {
    vct: VCT,
    issuer: 'did:example:issuer',
    disclosureClaims: ['nickname'],
    claims: { nickname: 'ali', sub: 'did:example:holder', jti: 'urn:sdjwt:1' },
    salts: { nickname: 'salt-nick' },
    ...(typ !== undefined ? { typ } : {}),
  });
}

/** 実発行 SD-JWT の JWS ヘッダを差し替える（署名は検証しないため再署名しない）。 */
function withHeader(sdJwt: string, header: Record<string, unknown>): string {
  const [issuerJwt, ...rest] = sdJwt.split('~');
  const [, payloadSeg, signatureSeg] = (issuerJwt as string).split('.');
  const headerSeg = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  return [`${headerSeg}.${payloadSeg}.${signatureSeg}`, ...rest].join('~');
}

describe('toQueryableFromSdJwt — typ からの format 導出', () => {
  it('既定発行（dc+sd-jwt）の SD-JWT を format=dc+sd-jwt に正規化する', () => {
    const q = toQueryableFromSdJwt(issueSdJwt());
    expect(q.format).toBe(SD_JWT_VC_TYP);
    expect(q.format).toBe(FORMAT_SD_JWT_VC_DC);
    expect(q.vct).toBe(VCT);
  });

  it('opt-in 発行（vc+sd-jwt）の SD-JWT を format=vc+sd-jwt に正規化する（後方互換）', () => {
    const q = toQueryableFromSdJwt(issueSdJwt(SD_JWT_VC_TYP_LEGACY));
    expect(q.format).toBe(SD_JWT_VC_TYP_LEGACY);
    expect(q.format).toBe(FORMAT_SD_JWT_VC);
    expect(q.vct).toBe(VCT);
  });

  it('typ 欠落の Issuer-signed JWT は受理し、format は旧識別子 vc+sd-jwt になる', () => {
    // 署名対象の `typ` を持たない＝`dc+sd-jwt` へ改称される前の旧 Issuer 由来とみなす。
    const stripped = withHeader(issueSdJwt(), { alg: 'ES256' });
    const q = toQueryableFromSdJwt(stripped);
    expect(q.format).toBe(SD_JWT_VC_TYP_LEGACY);
    expect(q.format).toBe(FORMAT_SD_JWT_VC);
    expect(q.vct).toBe(VCT);
  });

  it('別 typ（kb+jwt）の Issuer-signed JWT は 3002 で拒否する（typ 混同の遮断）', () => {
    const tampered = withHeader(issueSdJwt(), { alg: 'ES256', typ: 'kb+jwt' });
    expect(() => toQueryableFromSdJwt(tampered)).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });
});

describe('SUPPORTED_DCQL_FORMATS / SD_JWT_VC_FORMATS', () => {
  it('新旧いずれの SD-JWT VC format も DCQL 対応 format に含む', () => {
    expect(SUPPORTED_DCQL_FORMATS.has(SD_JWT_VC_TYP)).toBe(true);
    expect(SUPPORTED_DCQL_FORMATS.has(SD_JWT_VC_TYP_LEGACY)).toBe(true);
    expect(SUPPORTED_DCQL_FORMATS.has('jwt_vc_json')).toBe(true);
  });

  it('SD_JWT_VC_FORMATS は新旧 2 種のみを含む', () => {
    expect([...SD_JWT_VC_FORMATS].sort()).toEqual([SD_JWT_VC_TYP, SD_JWT_VC_TYP_LEGACY].sort());
  });
});

describe('DCQL end-to-end — 既定発行 SD-JWT と dc+sd-jwt クエリの接続', () => {
  /** format だけを差し替えた同一条件の DCQL クエリを組み立てる。 */
  function queryFor(format: string) {
    return parseDcqlQuery({
      credentials: [
        { id: 'q1', format, meta: { vct_values: [VCT] }, claims: [{ path: ['nickname'] }] },
      ],
    });
  }

  it('dc+sd-jwt を要求するクエリに既定発行 SD-JWT がマッチする', () => {
    const creds = [toQueryableFromSdJwt(issueSdJwt())];
    const matches = evaluateDcql(queryFor(SD_JWT_VC_TYP), creds);
    expect(matches).toHaveLength(1);
    expect(matches[0]?.credentialId).toBe('urn:sdjwt:1');

    const { matchedIndexes } = selectMatchingCredentials(queryFor(SD_JWT_VC_TYP), creds);
    expect(matchedIndexes).toEqual([0]);
  });

  it('vc+sd-jwt のみを要求するクエリには既定発行 SD-JWT がマッチしない（format 一致が効く）', () => {
    const creds = [toQueryableFromSdJwt(issueSdJwt())];
    expect(evaluateDcql(queryFor(SD_JWT_VC_TYP_LEGACY), creds)).toHaveLength(0);
    expect(selectMatchingCredentials(queryFor(SD_JWT_VC_TYP_LEGACY), creds).matchedIndexes).toEqual(
      [],
    );
  });

  it('opt-in 発行 SD-JWT は vc+sd-jwt クエリにマッチする（受理側の後方互換）', () => {
    const creds = [toQueryableFromSdJwt(issueSdJwt(SD_JWT_VC_TYP_LEGACY))];
    expect(evaluateDcql(queryFor(SD_JWT_VC_TYP_LEGACY), creds)).toHaveLength(1);
    expect(evaluateDcql(queryFor(SD_JWT_VC_TYP), creds)).toHaveLength(0);
  });

  it('typ 欠落クレデンシャルは vc+sd-jwt を要求するクエリにマッチする（旧 Issuer 保護の実効）', () => {
    // 「欠落を受理する」だけでは不十分で、format 照合は完全一致のため旧識別子に倒さないと
    // 移行期間に大多数を占める vc+sd-jwt 要求に 1 件もマッチしない。その実効を表明する。
    const creds = [toQueryableFromSdJwt(withHeader(issueSdJwt(), { alg: 'ES256' }))];
    const matches = evaluateDcql(queryFor(SD_JWT_VC_TYP_LEGACY), creds);
    expect(matches).toHaveLength(1);
    expect(matches[0]?.credentialId).toBe('urn:sdjwt:1');
    expect(selectMatchingCredentials(queryFor(SD_JWT_VC_TYP_LEGACY), creds).matchedIndexes).toEqual(
      [0],
    );
  });

  it('typ 欠落クレデンシャルは dc+sd-jwt のみの要求には被覆されない（完全一致照合）', () => {
    const creds = [toQueryableFromSdJwt(withHeader(issueSdJwt(), { alg: 'ES256' }))];
    expect(evaluateDcql(queryFor(SD_JWT_VC_TYP), creds)).toHaveLength(0);
  });
});
