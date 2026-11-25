/**
 * `jwt_vc_json-ld`（JSON-LD JWT-VC）の format ネゴシエーション回帰テスト。
 *
 * `__tests__/` 直下ではなくサブディレクトリへ切り出すのは 1 ディレクトリ行数上限
 * （.linterly.yml）対応（`match-credentials/` 等と同じ理由）。
 *
 * `jwt_vc_json-ld` は `jwt_vc_json` と同じ JWS Enveloping Proof で保護される実装済みフォーマット
 * であり、未実装の `ldp_vc` / `vc+cose` / `bbs+`
 * とは異なり DCQL で受理する。一方、SDK の `VerifiableCredential` 型は
 * `@context` を無条件に必須とするため、同じクレームを持つ VC の本文は両 format で区別できない。
 * したがって format は VC 本文から推定せず、`toQueryableFromVc` の第 2 引数として呼び出し側が
 * 明示する。
 *
 * 検証内容:
 * - `jwt_vc_json-ld` を要求する DCQL は 8050 にならず、同ラベルの保持にマッチする。
 * - 両ラベルは双方向に完全一致であり、黙って別名として同一視されない。
 * - `toQueryableFromVc` の第 2 引数省略時は従来どおり `jwt_vc_json`（後方互換）。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../../credential/vc/vc.js';
import { evaluateDcql, parseDcqlQuery } from '../../dcql/dcql.js';
import {
  FORMAT_JWT_VC,
  FORMAT_JWT_VC_JSON_LD,
  selectMatchingCredentials,
  toQueryableFromVc,
} from '../../matcher.js';

/** JSON-LD 色の強い VC（複数 `@context` / 複数 `type`）。本文は jwt_vc_json と区別できない。 */
const VC: VerifiableCredential = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://www.w3.org/ns/credentials/examples/v2',
  ],
  type: ['VerifiableCredential', 'UniversityDegreeCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { name: 'Carol', degree: 'BSc' },
  issuanceDate: '2025-01-01T00:00:00Z',
  id: 'urn:vc:jsonld:1',
};

/** 指定 format を単一要件として要求する DCQL クエリを組み立てる。 */
function queryFor(format: string) {
  return parseDcqlQuery({
    credentials: [{ id: 'q1', format, claims: [{ path: ['credentialSubject', 'name'] }] }],
  });
}

describe('toQueryableFromVc の format ラベル', () => {
  it('第 2 引数省略時は従来どおり jwt_vc_json（後方互換の回帰ガード）', () => {
    const q = toQueryableFromVc(VC);
    expect(q.format).toBe(FORMAT_JWT_VC);
    expect(q.format).toBe('jwt_vc_json');
  });

  it('第 2 引数で jwt_vc_json-ld を指定でき、format 以外の抽出は同一', () => {
    const base = toQueryableFromVc(VC);
    const jsonLd = toQueryableFromVc(VC, FORMAT_JWT_VC_JSON_LD);
    expect(jsonLd.format).toBe('jwt_vc_json-ld');
    expect(jsonLd.format).not.toBe(base.format);
    expect(jsonLd.id).toBe('urn:vc:jsonld:1');
    expect(jsonLd.id).toBe(base.id);
    // claims は VC オブジェクトをそのまま辿れる構造のまま（ラベル付与は本文に触れない）。
    expect(jsonLd.claims).toBe(base.claims);
    expect(jsonLd.vct).toBeUndefined();
  });
});

describe('evaluateDcql（jwt_vc_json-ld）', () => {
  it('jwt_vc_json-ld の要求は 8050 で拒否されず同ラベルの保持にマッチする', () => {
    const matches = evaluateDcql(queryFor(FORMAT_JWT_VC_JSON_LD), [
      toQueryableFromVc(VC, FORMAT_JWT_VC_JSON_LD),
    ]);
    expect(matches).toHaveLength(1);
    expect(matches[0]?.credentialId).toBe('urn:vc:jsonld:1');
    expect(matches[0]?.matchedClaims).toEqual(['credentialSubject.name']);
  });

  it('jwt_vc_json-ld の要求は既定ラベル（jwt_vc_json）の保持にマッチしない', () => {
    // format 照合は完全一致。両ラベルを黙って同一視する変更をここで落とす。
    expect(evaluateDcql(queryFor(FORMAT_JWT_VC_JSON_LD), [toQueryableFromVc(VC)])).toHaveLength(0);
  });

  it('jwt_vc_json の要求は jwt_vc_json-ld ラベルの保持にマッチしない（逆方向）', () => {
    expect(
      evaluateDcql(queryFor(FORMAT_JWT_VC), [toQueryableFromVc(VC, FORMAT_JWT_VC_JSON_LD)]),
    ).toHaveLength(0);
    // 既定ラベルの保持には従来どおりマッチする（既存挙動の非退行）。
    expect(evaluateDcql(queryFor(FORMAT_JWT_VC), [toQueryableFromVc(VC)])).toHaveLength(1);
  });
});

describe('selectMatchingCredentials（jwt_vc_json-ld）', () => {
  it('ラベル付きの候補だけを index で選定する', () => {
    const query = queryFor(FORMAT_JWT_VC_JSON_LD);
    const credentials = [toQueryableFromVc(VC), toQueryableFromVc(VC, FORMAT_JWT_VC_JSON_LD)];
    const { matches, matchedIndexes } = selectMatchingCredentials(query, credentials);
    expect(matchedIndexes).toEqual([1]);
    expect(matches).toHaveLength(1);
  });
});
