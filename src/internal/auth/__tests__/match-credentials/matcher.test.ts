/**
 * 保持クレデンシャル正規化 + マッチ VC 選定のユニットテスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - toQueryableFromVc: W3C JWT-VC の credentialSubject path 解決。
 * - toQueryableFromSdJwt: 実署名 SD-JWT VC の payload + 開示 Disclosure マージと vct 抽出。
 * - selectMatchingCredentials: マッチ index の正確な特定（id 空・重複に依存しない）。
 */

import { describe, expect, it } from 'bun:test';
import { createSdJwt } from '../../../credential/sdjwt/sdjwt.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import type { VerifiableCredential } from '../../../credential/vc/vc.js';
import { parseDcqlQuery, type QueryableCredential } from '../../dcql/dcql.js';
import {
  FORMAT_JWT_VC,
  FORMAT_SD_JWT_VC,
  FORMAT_SD_JWT_VC_DC,
  selectMatchingCredentials,
  toQueryableFromSdJwt,
  toQueryableFromVc,
} from '../../matcher.js';

const ISSUER_KEY = new Uint8Array(32).fill(7);
const signer = createPrivateKeySigner(ISSUER_KEY, 'ES256');

const VC: VerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'UniversityDegree'],
  issuer: 'did:example:issuer',
  credentialSubject: { name: 'Bob', degree: 'BSc' },
  issuanceDate: '2025-01-01T00:00:00Z',
  id: 'urn:vc:1',
};

const VCT = 'https://example.com/pid';

/** 開示クレーム name/age を持つ SD-JWT VC を発行する。 */
function issueSdJwt(): string {
  return createSdJwt(signer, {
    vct: VCT,
    issuer: 'did:example:issuer',
    disclosureClaims: ['nickname', 'age'],
    claims: {
      nickname: 'ali',
      age: 30,
      sub: 'did:example:holder',
      jti: 'urn:sdjwt:1',
    },
    salts: { nickname: 'salt-nick', age: 'salt-age' },
  });
}

describe('toQueryableFromVc', () => {
  it('format=jwt_vc_json で credentialSubject path を解決できる', () => {
    const q = toQueryableFromVc(VC);
    expect(q.format).toBe(FORMAT_JWT_VC);
    expect(q.id).toBe('urn:vc:1');
    expect(q.vct).toBeUndefined();
    expect((q.claims.credentialSubject as Record<string, unknown>).name).toBe('Bob');
  });

  it('id 未設定の VC は空文字列の id になる', () => {
    const { id: _omitted, ...rest } = VC;
    const q = toQueryableFromVc(rest as VerifiableCredential);
    expect(q.id).toBe('');
  });
});

describe('toQueryableFromSdJwt', () => {
  it('payload 平文 + 開示 Disclosure をマージし vct を抽出する', () => {
    const q = toQueryableFromSdJwt(issueSdJwt());
    // 既定発行の typ（`dc+sd-jwt`）がそのまま format 識別子になる。
    expect(q.format).toBe(FORMAT_SD_JWT_VC_DC);
    expect(q.vct).toBe(VCT);
    expect(q.id).toBe('urn:sdjwt:1');
    // 開示済み Disclosure はクレームとして解決できる。
    expect(q.claims.nickname).toBe('ali');
    expect(q.claims.age).toBe(30);
    // 平文クレームも残る。
    expect(q.claims.sub).toBe('did:example:holder');
    // SD-JWT 内部クレームは除外される。
    expect(q.claims._sd).toBeUndefined();
    expect(q.claims._sd_alg).toBeUndefined();
  });

  it('開示されていない Disclosure を落とすとクレームが解決できなくなる', () => {
    const full = issueSdJwt();
    const parts = full.split('~').filter((s) => s.length > 0);
    const issuerJwt = parts[0] as string;
    const disclosures = parts.slice(1);
    // age の Disclosure（claimName を含む base64url）を除外して再構成する。
    const ageDisclosure = disclosures.find((d) =>
      Buffer.from(d, 'base64url').toString('utf8').includes('age'),
    );
    expect(ageDisclosure).toBeDefined();
    const kept = disclosures.filter((d) => d !== ageDisclosure);
    const reduced = `${issuerJwt}~${kept.join('~')}~`;

    const q = toQueryableFromSdJwt(reduced);
    // nickname は残り解決できるが、開示を落とした age は解決できない。
    expect(q.claims.nickname).toBe('ali');
    expect(q.claims.age).toBeUndefined();
  });
});

describe('selectMatchingCredentials', () => {
  it('マッチした index を正確に返す（DCQL: SD-JWT のみ要求）', () => {
    const creds: QueryableCredential[] = [
      toQueryableFromVc(VC),
      toQueryableFromSdJwt(issueSdJwt()),
    ];
    const query = parseDcqlQuery({
      credentials: [
        {
          id: 'q1',
          format: FORMAT_SD_JWT_VC_DC,
          meta: { vct_values: [VCT] },
          claims: [{ path: ['nickname'] }],
        },
      ],
    });
    const { matches, matchedIndexes } = selectMatchingCredentials(query, creds);
    expect(matches).toHaveLength(1);
    expect(matches[0]?.credentialId).toBe('urn:sdjwt:1');
    expect(matchedIndexes).toEqual([1]);
  });

  it('id が空・重複でも index 単位で正しく選定する', () => {
    const { id: _omitted, ...noId } = VC;
    const a = toQueryableFromVc(noId as VerifiableCredential); // id=''
    const b = toQueryableFromVc({
      ...noId,
      credentialSubject: { other: 1 },
    } as VerifiableCredential); // id=''
    const query = parseDcqlQuery({
      credentials: [
        { id: 'q1', format: 'jwt_vc_json', claims: [{ path: ['credentialSubject', 'name'] }] },
      ],
    });
    const { matchedIndexes } = selectMatchingCredentials(query, [a, b]);
    // a は name を持つ、b は持たない → index 0 のみ。
    expect(matchedIndexes).toEqual([0]);
  });

  it('該当なしなら空の index を返す', () => {
    const creds = [toQueryableFromVc(VC)];
    const query = parseDcqlQuery({
      credentials: [{ id: 'q1', format: FORMAT_SD_JWT_VC }],
    });
    const { matchedIndexes } = selectMatchingCredentials(query, creds);
    expect(matchedIndexes).toEqual([]);
  });
});
