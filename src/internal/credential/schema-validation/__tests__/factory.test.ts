/**
 * `createSchemaValidator`（ファクトリ）のテスト。
 *
 * Fail-open の時間上限をインスタンスごとに検証する。
 *
 * `schema-validation/fail-safe.ts` の Fail-open ウィンドウはプロセス共有の
 * モジュール `Map` が既定で、無関係な検証フロー間で計時が混線し、計時キー数の上限（既定 256）に
 * 達すると当該プロセスの以降の呼び出しが恒久的に Fail-open できなくなる DoS があった。
 * `internal/issuer/status-list-resolver.ts` の `createStatusListResolver` と同じ、インスタンスへ
 * ウィンドウを閉じ込めるパターンに揃えた（`factory.ts`）。
 *
 * 検証内容:
 * - 既定パス（引数なしで `createSchemaValidator()` を呼ぶ）でも FO-3 / FO-4 が正しく機能する。
 * - 別インスタンスは互いに独立したウィンドウを持つ（旧実装の DoS / 混線が起きない）。
 * - `validateClaimsAgainstSchema`（ディスパッチャ）は W3C 経路と SD-JWT 経路の両方へ
 *   同じインスタンスのウィンドウを渡すが、経路プレフィックス（`w3c:` / `sdjwt-vct:`）により
 *   同一 URL 文字列でもキーが衝突しない。
 *
 * 各テストは（モジュール既定の共有スキーマキャッシュを使うため）互いに異なる URL を使う。
 * 同じ URL を成功レスポンスで使い回すと、後続テストの取得失敗を検証したいケースで
 * キャッシュ済みの旧スキーマが返り、fail-open の計時そのものを検証できなくなるため。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { FAIL_OPEN_AUDIT_EVENTS } from '../../../failsafe/index.js';
import { createSchemaValidator } from '../factory.js';
import { buildSdJwt, buildVc, createFetchStub, PERSON_SCHEMA } from './fixtures.js';

/** Fail-open の成立条件（同意 + 監査記録先）を揃えたオプション。ウィンドウはファクトリが持つ。 */
function failOpenGrant() {
  return { requestConsent: () => true, onPolicyEvent: () => {} };
}

describe('createSchemaValidator — 既定パス（引数なし）', () => {
  it('validateClaimsAgainstCredentialSchema の取得失敗を FO-3 として警告通過させる', async () => {
    const url = 'https://issuer.example.com/factory/default-path/fo3';
    const validator = createSchemaValidator();
    const stub = createFetchStub({ [url]: { status: 500 } });
    const vc = buildVc({ name: '山田太郎' }, { id: url, type: 'JsonSchema' });

    const result = await validator.validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000,
      ...failOpenGrant(),
    });

    expect(result).toEqual({
      valid: true,
      schemaAvailable: false,
      warnings: [FAIL_OPEN_AUDIT_EVENTS['FO-3']],
    });
  });

  it('同意 / 監査記録先が無ければ既定パスでも Fail-closed のまま', async () => {
    // ウィンドウをインスタンスへ閉じ込めても、同意 + 監査記録要件は変わらない。
    const url = 'https://issuer.example.com/factory/default-path/no-consent';
    const validator = createSchemaValidator();
    const stub = createFetchStub({ [url]: { status: 500 } });
    const vc = buildVc({ name: '山田太郎' }, { id: url, type: 'JsonSchema' });

    const promise = validator.validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000,
    });

    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.SCHEMA_FETCH_FAILED });
  });

  it('validateClaimsAgainstTypeMetadata も既定パスで FO-4 を警告通過させる', async () => {
    const vct = 'https://issuer.example.com/factory/default-path/vct';
    const metadata = {
      vct,
      schema: {
        type: 'object',
        required: ['given_name'],
        properties: {
          given_name: { type: 'string', minLength: 1 },
          nickname: { type: 'string', maxLength: 8 },
        },
      },
    };
    const validator = createSchemaValidator();
    const stub = createFetchStub({ [vct]: { json: metadata } });

    const result = await validator.validateClaimsAgainstTypeMetadata(
      vct,
      { given_name: '太郎', nickname: 'ながすぎるニックネームです' },
      { fetchImpl: stub.fetchImpl, nowMs: 1000, ...failOpenGrant() },
    );

    expect(result.valid).toBe(true);
    expect(result.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-4']]);
  });

  it('validateClaimsAgainstSchema（ディスパッチャ）も既定パスで動く', async () => {
    const url = 'https://issuer.example.com/factory/default-path/dispatch';
    const validator = createSchemaValidator();
    const stub = createFetchStub({ [url]: { json: PERSON_SCHEMA } });

    const result = await validator.validateClaimsAgainstSchema(
      buildVc({ name: '山田太郎', nickname: 'たろ' }, { id: url, type: 'JsonSchema' }),
      { fetchImpl: stub.fetchImpl, nowMs: 1000 },
    );

    expect(result).toEqual({
      valid: true,
      schemaAvailable: true,
      warnings: [],
      route: 'w3c-vc-credential-schema',
    });
  });
});

describe('createSchemaValidator — インスタンスごとに独立したウィンドウを持つ', () => {
  it('別インスタンスの計時は互いに影響しない（旧実装のプロセス共有 Map を撤去した効果）', async () => {
    const url = 'https://issuer.example.com/factory/instance-isolation';
    const validatorA = createSchemaValidator();
    const validatorB = createSchemaValidator();
    const vc = buildVc({ name: '山田太郎' }, { id: url, type: 'JsonSchema' });
    const failing = createFetchStub({ [url]: { status: 500 } });

    // A で 61 秒分の Fail-open 予算を使い切る。
    await validatorA.validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: failing.fetchImpl,
      nowMs: 0,
      ...failOpenGrant(),
    });
    const exhausted = validatorA.validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: failing.fetchImpl,
      nowMs: 61_000,
      ...failOpenGrant(),
    });
    await expect(exhausted).rejects.toMatchObject({ code: ErrorCodes.SCHEMA_FETCH_FAILED });

    // 同じ URL・同じ内容のクレデンシャルでも B は独立したウィンドウなので、t=0 として新規に許可される。
    const stillFresh = await validatorB.validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: failing.fetchImpl,
      nowMs: 61_000,
      ...failOpenGrant(),
    });
    expect(stillFresh.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-3']]);
  });
});

describe('createSchemaValidator — 経路プレフィックスで W3C / SD-JWT のキー空間を分ける', () => {
  it('同じ URL 文字列を vct とスキーマ URL の両方に使っても Fail-open 予算は独立する', async () => {
    // 1 インスタンスのウィンドウを両経路で共有する（ディスパッチャの既定挙動）。プレフィックスが
    // 無ければ、片方の経路で 60 秒の予算を使い切ると、たまたま同じ URL 文字列を使うだけの
    // もう片方の経路まで巻き添えで Fail-closed になってしまう。
    const sharedUrl = 'https://issuer.example.com/factory/shared-identifier';
    const validator = createSchemaValidator();
    const vc = buildVc({ name: '山田太郎' }, { id: sharedUrl, type: 'JsonSchema' });
    const sdJwt = buildSdJwt({ given_name: '太郎' }, sharedUrl);

    const w3cFailing = createFetchStub({ [sharedUrl]: { status: 500 } });
    // W3C 経路の予算を t=0 〜 61 秒で使い切る。
    await validator.validateClaimsAgainstSchema(vc, {
      fetchImpl: w3cFailing.fetchImpl,
      nowMs: 0,
      ...failOpenGrant(),
    });
    const w3cExhausted = validator.validateClaimsAgainstSchema(vc, {
      fetchImpl: w3cFailing.fetchImpl,
      nowMs: 61_000,
      ...failOpenGrant(),
    });
    await expect(w3cExhausted).rejects.toMatchObject({ code: ErrorCodes.SCHEMA_FETCH_FAILED });

    // 同じ URL 文字列を vct に使う SD-JWT 経路は、W3C 側の予算切れの影響を受けず新規に許可される。
    const sdJwtFailing = createFetchStub({ [sharedUrl]: { status: 500 } });
    const sdJwtResult = await validator.validateClaimsAgainstSchema(sdJwt, {
      fetchImpl: sdJwtFailing.fetchImpl,
      nowMs: 61_000,
      ...failOpenGrant(),
    });
    expect(sdJwtResult.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-3']]);
  });
});
