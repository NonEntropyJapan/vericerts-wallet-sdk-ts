/**
 * 実発行 SD-JWT VC と format-negotiation の end-to-end 接続テスト（実鍵・モック禁止）。
 *
 * 実発行した SD-JWT の `typ` と `alg` が Verifier の要求に合うかを照合する。
 *
 * 検証内容:
 * - `createSdJwt` で実際に発行した SD-JWT の JWS ヘッダ `typ` から導出した format で
 *   `NegotiableCredential` を組み立て、`selectBestVC` / `canFulfillFormats` に流せる
 *   （format 文字列をテスト側でリテラル指定しない）。
 * - 既定発行（`dc+sd-jwt`）と移行期間の opt-in 発行（`vc+sd-jwt`）の双方を扱える。
 * - `typ` は署名対象のため後から変換できず、`dc+sd-jwt` のみの要求を旧 typ 発行では被覆できない。
 * - `SELECTIVE_DISCLOSURE_FORMATS` / `PRIVACY_TIER` のキーが実発行由来の format と一致する。
 * - 実 JWS ヘッダの `alg` に基づきダウングレード拒否（要求 `alg` 外の候補除外）が効く。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { createSdJwt, parseSdJwt } from '../../sdjwt/sdjwt.js';
import {
  assertAcceptedSdJwtVcTypIfPresent,
  SD_JWT_VC_TYP,
  SD_JWT_VC_TYP_LEGACY,
  type SdJwtVcTyp,
} from '../../sdjwt/typ.js';
import { decodeCompactJws } from '../../vc/jws.js';
import { createPrivateKeySigner } from '../../vc/signer.js';
import { canFulfillFormats, selectBestVC } from '../select.js';
import {
  type NegotiableCredential,
  PRIVACY_TIER,
  SELECTIVE_DISCLOSURE_FORMATS,
  type VpFormatRequirement,
} from '../types.js';

const ISSUER_KEY = new Uint8Array(32).fill(7);
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const VCT = 'https://example.com/pid';

/** 決定的タイブレーク（常に先頭を優先）。 */
const alwaysA = () => 0;

/** 開示クレームを 1 つ持つ SD-JWT VC を実鍵で発行する（`typ` 未指定なら既定 `dc+sd-jwt`）。 */
function issueSdJwt(jti: string, typ?: SdJwtVcTyp): string {
  return createSdJwt(ISSUER_SIGNER, {
    vct: VCT,
    issuer: 'did:example:issuer',
    disclosureClaims: ['nickname'],
    claims: { nickname: 'ali', jti },
    salts: { nickname: 'salt-nick' },
    ...(typ !== undefined ? { typ } : {}),
  });
}

/**
 * 実発行 SD-JWT VC 文字列から format-negotiation の候補（`NegotiableCredential`）を組み立てる。
 *
 * format は Issuer-signed JWT の JWS ヘッダ `typ` から導出する（SD-JWT VC では `typ` と
 * credential format 識別子が同一文字列。`typ.ts` が SSOT）。受理対象外の `typ` は `3002` で
 * 拒否し、欠落時は旧識別子 `vc+sd-jwt` を用いる（署名された `typ` を持たない＝改称前の旧 Issuer
 * 由来とみなす。`toQueryableFromSdJwt` と同一の導出）。
 * `alg` も実ヘッダから取るため、ダウングレード拒否は実発行の署名アルゴリズムで判定される。
 */
function toNegotiableFromSdJwt(sdJwt: string): NegotiableCredential {
  const { issuerJwt } = parseSdJwt(sdJwt);
  const { header, payload } = decodeCompactJws(issuerJwt);
  assertAcceptedSdJwtVcTypIfPresent(header.typ);
  const format = header.typ ?? SD_JWT_VC_TYP_LEGACY;
  return {
    id: typeof payload.jti === 'string' ? payload.jti : '',
    format,
    ...(typeof header.alg === 'string' ? { alg: header.alg } : {}),
    ...(typeof payload.vct === 'string' ? { vct: payload.vct } : {}),
    // 選択後に VP 構築へ渡す元クレデンシャル（実発行した SD-JWT 文字列そのもの）。
    source: sdJwt,
  };
}

const DEFAULT_SD_JWT = issueSdJwt('urn:sdjwt:dc-1');
const LEGACY_SD_JWT = issueSdJwt('urn:sdjwt:legacy-1', SD_JWT_VC_TYP_LEGACY);
const DEFAULT_CANDIDATE = toNegotiableFromSdJwt(DEFAULT_SD_JWT);
const LEGACY_CANDIDATE = toNegotiableFromSdJwt(LEGACY_SD_JWT);

/** 比較用の W3C JWT-VC 候補（SD-JWT ではないため format は固定値）。 */
const JWT_VC_CANDIDATE: NegotiableCredential = {
  id: 'urn:jwtvc:1',
  format: 'jwt_vc_json',
  alg: 'ES256',
};

describe('実発行 SD-JWT からの候補構築', () => {
  it('既定発行の候補 format は実ヘッダ typ 由来の dc+sd-jwt', () => {
    expect(DEFAULT_CANDIDATE.format).toBe(SD_JWT_VC_TYP);
    expect(DEFAULT_CANDIDATE.alg).toBe('ES256');
    expect(DEFAULT_CANDIDATE.vct).toBe(VCT);
    expect(DEFAULT_CANDIDATE.id).toBe('urn:sdjwt:dc-1');
  });

  it('旧 typ opt-in 発行の候補 format は実ヘッダ typ 由来の vc+sd-jwt', () => {
    expect(LEGACY_CANDIDATE.format).toBe(SD_JWT_VC_TYP_LEGACY);
    expect(LEGACY_CANDIDATE.id).toBe('urn:sdjwt:legacy-1');
  });

  it('受理対象外の typ を持つ SD-JWT は候補化の時点で 3002 で拒否する', () => {
    // JWS ヘッダのみ `kb+jwt` に差し替えた SD-JWT（署名は検証しない経路のため再署名は不要）。
    const [issuerJwt = '', ...rest] = DEFAULT_SD_JWT.split('~');
    const [, payloadSeg = '', signatureSeg = ''] = issuerJwt.split('.');
    const headerSeg = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'kb+jwt' })).toString(
      'base64url',
    );
    const tampered = [`${headerSeg}.${payloadSeg}.${signatureSeg}`, ...rest].join('~');
    expect(() => toNegotiableFromSdJwt(tampered)).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('実発行由来の format が選択的開示フォーマット / PRIVACY_TIER に一致する', () => {
    // 実際に Disclosure を伴って発行されていること（選択的開示対応の実体）。
    expect(parseSdJwt(DEFAULT_SD_JWT).disclosures).toHaveLength(1);
    for (const candidate of [DEFAULT_CANDIDATE, LEGACY_CANDIDATE]) {
      expect(SELECTIVE_DISCLOSURE_FORMATS.has(candidate.format)).toBe(true);
      expect(PRIVACY_TIER[candidate.format]).toBe(80);
    }
  });
});

describe('selectBestVC — 実発行 SD-JWT 候補', () => {
  it('dc+sd-jwt を最優先で要求すれば既定発行の候補が選ばれる', () => {
    const request: VpFormatRequirement = {
      [SD_JWT_VC_TYP]: { alg: ['ES256'] },
      jwt_vc_json: { alg: ['ES256'] },
    };
    const result = selectBestVC(request, [JWT_VC_CANDIDATE, DEFAULT_CANDIDATE], {
      randomTiebreak: alwaysA,
    });
    expect(result.chosen.id).toBe(DEFAULT_CANDIDATE.id);
    // 選択結果は実発行した SD-JWT 文字列をそのまま VP 構築へ引き渡せる。
    expect(result.chosen.source).toBe(DEFAULT_SD_JWT);
  });

  it('新旧双方を保持し dc+sd-jwt を最優先で要求すれば既定発行の候補が勝つ', () => {
    const request: VpFormatRequirement = {
      [SD_JWT_VC_TYP]: { alg: ['ES256'] },
      [SD_JWT_VC_TYP_LEGACY]: { alg: ['ES256'] },
    };
    const result = selectBestVC(request, [LEGACY_CANDIDATE, DEFAULT_CANDIDATE], {
      randomTiebreak: alwaysA,
    });
    expect(result.chosen.id).toBe(DEFAULT_CANDIDATE.id);
    expect(result.alternatives.map((a) => a.id)).toEqual([LEGACY_CANDIDATE.id]);
  });

  it('旧 typ 発行の候補だけでは dc+sd-jwt 要求を満たせず 3050 になる', () => {
    const request: VpFormatRequirement = { [SD_JWT_VC_TYP]: { alg: ['ES256'] } };
    expect(() => selectBestVC(request, [LEGACY_CANDIDATE], { randomTiebreak: alwaysA })).toThrow(
      VericertsError,
    );
  });

  it('要求 alg（ES384）外の実発行候補はダウングレード拒否で除外される', () => {
    const request: VpFormatRequirement = { [SD_JWT_VC_TYP]: { alg: ['ES384'] } };
    expect(() => selectBestVC(request, [DEFAULT_CANDIDATE], { randomTiebreak: alwaysA })).toThrow(
      VericertsError,
    );
  });
});

describe('canFulfillFormats — 実発行 SD-JWT 候補', () => {
  it('既定発行の候補は dc+sd-jwt 要求を被覆する', () => {
    const request: VpFormatRequirement = { [SD_JWT_VC_TYP]: { alg: ['ES256'] } };
    const coverage = canFulfillFormats(request, [DEFAULT_CANDIDATE]);
    expect(coverage.fullyCovered).toBe(true);
    expect(coverage.matchedFormats).toEqual([SD_JWT_VC_TYP]);
  });

  it('旧 typ 発行の候補は dc+sd-jwt 要求を被覆できない（typ はクロスマッチしない）', () => {
    const request: VpFormatRequirement = { [SD_JWT_VC_TYP]: { alg: ['ES256'] } };
    const coverage = canFulfillFormats(request, [LEGACY_CANDIDATE]);
    expect(coverage.fullyCovered).toBe(false);
    expect(coverage.unmatchedFormats).toEqual([SD_JWT_VC_TYP]);
  });

  it('旧 typ 発行の候補は vc+sd-jwt 要求なら被覆できる（移行期間の後方互換）', () => {
    const request: VpFormatRequirement = { [SD_JWT_VC_TYP_LEGACY]: { alg: ['ES256'] } };
    const coverage = canFulfillFormats(request, [LEGACY_CANDIDATE]);
    expect(coverage.fullyCovered).toBe(true);
    expect(coverage.matchedFormats).toEqual([SD_JWT_VC_TYP_LEGACY]);
  });
});
