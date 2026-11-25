/**
 * `createSchemaValidator`（ファクトリ）の `Object.prototype` 汚染耐性。
 *
 * `dispatch.ts` は `factoryOptions` / `options` の任意プロパティを
 * `ownProperty` / `nonObjectPrototypeProperty` 経由でのみ読む規律を持つが、その上流にある
 * `factory.ts` が `factoryOptions.requestConsent` のような素のプロパティアクセスで読み、新しい
 * オブジェクトリテラルへ詰め直していたため、この読み取り規律が無効化されていた。
 *
 * 実際に成立していた攻撃（「同意・監査ゲートを経由しないと fail-open できない」
 * を無効化する）:
 * ```js
 * Object.prototype.requestConsent = () => true;
 * Object.prototype.onPolicyEvent = () => {};
 * createSchemaValidator().validateClaimsAgainstCredentialSchema(vc, { fetchImpl, nowMs })
 *   // 同意コールバック未指定でも fail-open が成立してしまっていた
 * ```
 *
 * 加えて `validateClaimsAgainstSchema`（ディスパッチャ経由）は `options.credentialSchemaOptions` /
 * `options.typeMetadataOptions` を同様に素のプロパティアクセスで読んでいたため、
 * `Object.prototype.credentialSchemaOptions` に `failOpenWindow` を仕込むと、当該オプションを
 * 渡していない呼び出しでインスタンス固有の Fail-open ウィンドウが攻撃者提供の
 * オブジェクトへ丸ごと差し替わってしまう。
 *
 * 各テストは `finally` で `Object.prototype` の汚染を必ず戻す `withPollutedPrototypeAsync` を使う。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { FAIL_OPEN_AUDIT_EVENTS } from '../../../../failsafe/index.js';
import { createSchemaValidator } from '../../factory.js';
import { buildVc, createFetchStub } from '../fixtures.js';

describe('createSchemaValidator の Object.prototype 汚染耐性', () => {
  it('継承した requestConsent / onPolicyEvent で validateClaimsAgainstCredentialSchema を fail-open させない', async () => {
    const url = 'https://issuer.example.com/factory/proto-pollution/credential-schema';
    let consentCalls = 0;
    const leaked: unknown[] = [];
    const stub = createFetchStub({ [url]: { status: 500 } });
    const vc = buildVc({ name: '山田太郎' }, { id: url, type: 'JsonSchema' });

    // `createSchemaValidator()` 自体も汚染下で呼ぶ（＝ factoryOptions を読む時点で汚染が効いている
    // 状態を再現する。実運用でも汚染は生成の前後を問わず持続するため、生成時点を汚染の外に置くと
    // 検出したい欠陥を見逃す）。
    const promise = withPollutedPrototypeAsync(
      {
        requestConsent: () => {
          consentCalls += 1;
          return true;
        },
        onPolicyEvent: (record: unknown) => {
          leaked.push(record);
        },
      },
      () =>
        createSchemaValidator().validateClaimsAgainstCredentialSchema(vc, {
          fetchImpl: stub.fetchImpl,
          nowMs: 1000,
        }),
    );

    // 同意コールバック・監査記録先を明示的に渡していない以上、Fail-open は成立しない（fail-closed）。
    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.SCHEMA_FETCH_FAILED });
    // 攻撃者の同意コールバック・監査シンクが一度も呼ばれていないこと。
    expect(consentCalls).toBe(0);
    expect(leaked).toEqual([]);
  });

  it('継承した requestConsent / onPolicyEvent で validateClaimsAgainstTypeMetadata を fail-open させない', async () => {
    const vct = 'https://issuer.example.com/factory/proto-pollution/type-metadata';
    let consentCalls = 0;
    const stub = createFetchStub({ [vct]: { status: 500 } });

    const promise = withPollutedPrototypeAsync(
      {
        requestConsent: () => {
          consentCalls += 1;
          return true;
        },
        onPolicyEvent: () => {},
      },
      () =>
        createSchemaValidator().validateClaimsAgainstTypeMetadata(
          vct,
          { given_name: '太郎' },
          { fetchImpl: stub.fetchImpl, nowMs: 1000 },
        ),
    );

    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    expect(consentCalls).toBe(0);
  });

  it('継承した credentialSchemaOptions.failOpenWindow でインスタンス固有のウィンドウを差し替えられない', async () => {
    const url = 'https://issuer.example.com/factory/proto-pollution/dispatch-window';
    let attackerWindowCalls = 0;
    const attackerWindow = {
      allow: () => {
        attackerWindowCalls += 1;
        return true;
      },
      clear: () => {
        attackerWindowCalls += 1;
      },
    };
    const validator = createSchemaValidator();
    const stub = createFetchStub({ [url]: { status: 500 } });
    const vc = buildVc({ name: '山田太郎' }, { id: url, type: 'JsonSchema' });

    const result = await withPollutedPrototypeAsync(
      { credentialSchemaOptions: { failOpenWindow: attackerWindow } },
      () =>
        validator.validateClaimsAgainstSchema(vc, {
          fetchImpl: stub.fetchImpl,
          nowMs: 1000,
          requestConsent: () => true,
          onPolicyEvent: () => {},
        }),
    );

    // 正しくファクトリ自身のウィンドウが使われ、Fail-open が成立していること。
    expect(result.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-3']]);
    // 攻撃者のウィンドウが一度も呼ばれていないこと（＝差し替わっていない）。
    expect(attackerWindowCalls).toBe(0);
  });

  it('明示的に渡した requestConsent / onPolicyEvent は従来どおり Fail-open を成立させる（正常系）', async () => {
    const url = 'https://issuer.example.com/factory/proto-pollution/normal-path';
    const records: unknown[] = [];
    const validator = createSchemaValidator();
    const stub = createFetchStub({ [url]: { status: 500 } });
    const vc = buildVc({ name: '山田太郎' }, { id: url, type: 'JsonSchema' });

    const result = await validator.validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000,
      requestConsent: () => true,
      onPolicyEvent: (record) => {
        records.push(record);
      },
    });

    expect(result).toEqual({
      valid: true,
      schemaAvailable: false,
      warnings: [FAIL_OPEN_AUDIT_EVENTS['FO-3']],
    });
    expect(records).toHaveLength(1);
  });
});
