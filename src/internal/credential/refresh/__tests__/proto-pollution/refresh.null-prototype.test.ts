/**
 * VC リフレッシュの null プロトタイプ耐性テスト。
 *
 * `shouldRefresh` / `refreshCredential` は VC 本文の `expirationDate` を
 * `ownProperty<string>(vc, 'expirationDate')` で読むが、これは **cast のみで `typeof` 検証が無い**。
 * VC がパース境界（`parseJsonWithoutPrototype`）由来だと型不正な値は `toString` / `valueOf` を
 * 持たないため、`isoToNumericDate` の `Date.parse` で暗黙の `ToPrimitive` が
 * `TypeError: No default value` になる。
 *
 * これは公開 API の失敗面（3033 / 3023 / FO-9 の fail-safe 分岐）を迂回して生の例外を漏らす。修正後は
 * 解釈不能な ISO 文字列（`"not-a-date"`）を渡した場合と**同じ 3002** に倒れる。
 *
 * **素のオブジェクトリテラルでは再現しない**（`Date.parse('[object Object]')` が `NaN` になり、
 * 既存の `Number.isFinite` ガードで 3002 に倒れる）ため、必ず JSON 文字列を通すこと。
 */

import { describe, expect, it } from 'bun:test';
import type { FetchLike } from '../../../../auth/oid4vci/oid4vci.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { parseJsonWithoutPrototype } from '../../../../prototype-safety/parse-json.js';
import type { VerifiableCredential } from '../../../vc/vc.js';
import {
  type RefreshDependencies,
  type RefreshPolicy,
  refreshCredential,
  shouldRefresh,
} from '../../refresh.js';

const NOW = Date.parse('2026-07-01T00:00:00Z');

const POLICY: RefreshPolicy = { vcType: 'IdentityCredential', autoRefresh: true };

/** `expirationDate` を任意の値にした VC を**パース境界経由**で作る。 */
function nullProtoVc(expirationDate: unknown): VerifiableCredential {
  const vc = parseJsonWithoutPrototype(
    JSON.stringify({
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential', 'IdentityCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: { id: 'did:example:holder' },
      issuanceDate: '2026-01-01T00:00:00Z',
      id: 'urn:vc:old',
      expirationDate,
      refreshService: {
        id: 'refresh-1',
        type: 'OID4VCIRefreshService2025',
        url: 'https://issuer.example/refresh',
      },
    }),
  ) as VerifiableCredential;
  // 前提: パース境界を通った値は toString / valueOf を持たない（素のリテラルとの差分）。
  expect(Object.getPrototypeOf(vc)).toBeNull();
  return vc;
}

/** 呼び出し回数を数える `fetch`（エンドポイントに到達していないことの確認用）。 */
function countingFetch(calls: { count: number }): FetchLike {
  return async () => {
    calls.count += 1;
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
}

describe('リフレッシュの expirationDate 型検証', () => {
  it('shouldRefresh は型不正な expirationDate で TypeError にならず 3002 になる', () => {
    const vc = nullProtoVc({});

    let error: unknown;
    try {
      shouldRefresh(vc, POLICY, NOW);
    } catch (caught) {
      error = caught;
    }

    expect(error).not.toBeInstanceOf(TypeError);
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
  });

  it('refreshCredential は型不正な expirationDate で TypeError にならず 3002 になる', async () => {
    const vc = nullProtoVc({});
    const calls = { count: 0 };
    const deps: RefreshDependencies = {
      verifyRefreshed: async () => vc,
      fetchImpl: countingFetch(calls),
    };

    const error = await refreshCredential(vc, {}, deps).then(
      () => undefined,
      (caught: unknown) => caught,
    );

    expect(error).not.toBeInstanceOf(TypeError);
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
    // 期限判定が成立しないまま更新要求を飛ばさない（fail-closed）。
    expect(calls.count).toBe(0);
  });

  it('解釈不能な ISO 文字列と同じ失敗コードに揃っている（挙動の一貫性）', () => {
    const stringCase = (() => {
      try {
        shouldRefresh(nullProtoVc('not-a-date'), POLICY, NOW);
        return undefined;
      } catch (caught) {
        return caught;
      }
    })();

    expect((stringCase as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
  });

  it('妥当な expirationDate は従来どおり判定される（正常系）', async () => {
    const soon = new Date(NOW + 3 * 24 * 60 * 60 * 1000).toISOString();
    const far = new Date(NOW + 30 * 24 * 60 * 60 * 1000).toISOString();
    expect(shouldRefresh(nullProtoVc(soon), POLICY, NOW)).toBe(true);
    expect(shouldRefresh(nullProtoVc(far), POLICY, NOW)).toBe(false);

    const calls = { count: 0 };
    const vc = nullProtoVc(far);
    const result = await refreshCredential(
      vc,
      { now: NOW },
      { verifyRefreshed: async () => vc, fetchImpl: countingFetch(calls) },
    );
    // しきい値未達なので入れ替えずに旧 VC を返す（エンドポイントも呼ばない）。
    expect(result.refreshed).toBe(false);
    expect(result.credential).toBe(vc);
    expect(calls.count).toBe(0);
  });
});
