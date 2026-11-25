/**
 * `options.nowMs` の `Object.prototype` 汚染による Fail-open 60 秒上限の恒久バイパス
 *
 * `validateClaimsAgainstCredentialSchema`（`vc/credential-schema/validate.ts`）と
 * `validateClaimsAgainstTypeMetadata`（`sdjwt/type-metadata/resolve.ts`）はどちらも
 * `const now = options.nowMs ?? Date.now();` という素のプロパティアクセスで現在時刻を読んでいた。
 * 同じファイル内の他の任意プロパティ（`credentialSchema` / `credentialSubject` 等）は
 * `ownProperty` で own 限定に読む規律を徹底しているのに、fail-open の時間上限
 * （既定 60 秒）を計時するこの `now` だけがその規律から漏れていた。
 *
 * `Object.prototype.nowMs` に固定値を仕込むと、`options` に `nowMs` を明示しない呼び出しは
 * 毎回その固定値を読む。`now - start` が常に一定値になるため `window.allow` は常に許可し、
 * 60 秒の上限は実時間がどれだけ経過しても発動しない（fail-open が無期限に継続する）。
 *
 * 本テストは、`Object.prototype.nowMs` を固定値に汚染したまま `Date.now` を実時間の経過
 * （0ms → 61,000ms、61 秒後）を表すようスパイし、2 回目の呼び出しで Fail-closed に戻ることを
 * 確認する。修正前は `options.nowMs`（汚染された固定値）がそのまま採用され `Date.now`
 * スパイが一切呼ばれないため、2 回目も Fail-open が継続し本テストは失敗する。
 */

import { describe, expect, it, spyOn } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes } from '../../../../errors.js';
import { FAIL_OPEN_AUDIT_EVENTS } from '../../../../failsafe/index.js';
import { createFailOpenWindow } from '../../../../failsafe-policy/index.js';
import { validateClaimsAgainstTypeMetadata } from '../../../sdjwt/type-metadata/resolve.js';
import { validateClaimsAgainstCredentialSchema } from '../../../vc/credential-schema/validate.js';
import { buildSdJwt, buildVc, createFetchStub, SCHEMA_URL, VCT_URL } from '../fixtures.js';

/** 攻撃者が `Object.prototype` へ仕込む「常に同じ値を返す」固定 `nowMs`。 */
const POLLUTED_FIXED_NOW_MS = 5000;

describe('options.nowMs の Object.prototype 汚染による Fail-open 60 秒上限バイパス', () => {
  it('validateClaimsAgainstCredentialSchema: 固定 nowMs 汚染下でも実時間 61 秒後は Fail-closed に戻る', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { status: 500 } });
    const vc = buildVc({ name: '山田太郎' }, { id: SCHEMA_URL, type: 'JsonSchema' });
    const sharedOptions = {
      fetchImpl: stub.fetchImpl,
      failOpenWindow: createFailOpenWindow(),
      requestConsent: () => true,
      onPolicyEvent: () => {},
      // `nowMs` は意図的に渡さない。攻撃者の汚染値だけが「呼び出し側が省略した」状態を再現する。
    };

    const dateSpy = spyOn(Date, 'now');
    try {
      // 実時間は 0ms → 61,000ms（61 秒後）と進む。`nowMs` を own では一切渡していないため、
      // 修正後のコードはここを読んで時間経過を正しく検知するはずである。
      dateSpy.mockReturnValueOnce(0).mockReturnValueOnce(61_000);

      await withPollutedPrototype({ nowMs: POLLUTED_FIXED_NOW_MS }, async () => {
        // 1 回目: 新規キーのため無条件に Fail-open が成立する。
        const first = await validateClaimsAgainstCredentialSchema(vc, sharedOptions);
        expect(first).toEqual({
          valid: true,
          schemaAvailable: false,
          warnings: [FAIL_OPEN_AUDIT_EVENTS['FO-3']],
        });

        // 2 回目（実時間で 61 秒後）: 60 秒上限を超えているため Fail-closed に戻り、
        // 元のスキーマ取得失敗（3015）がそのまま伝播するはず。
        // 修正前は素の `options.nowMs` アクセスが汚染された固定値 5000 を読み続け、
        // `nowSeconds` が変化しない（`Date.now` スパイも呼ばれない）ため、
        // ここでも Fail-open が継続し reject しない（本テストが失敗する）。
        await expect(
          validateClaimsAgainstCredentialSchema(vc, sharedOptions),
        ).rejects.toMatchObject({ code: ErrorCodes.SCHEMA_FETCH_FAILED });
      });
    } finally {
      dateSpy.mockRestore();
    }
  });

  it('validateClaimsAgainstTypeMetadata: 固定 nowMs 汚染下でも実時間 61 秒後は Fail-closed に戻る', async () => {
    const stub = createFetchStub({ [VCT_URL]: { status: 500 } });
    const { claims, vct } = buildSdJwt({ given_name: '太郎' });
    const sharedOptions = {
      fetchImpl: stub.fetchImpl,
      failOpenWindow: createFailOpenWindow(),
      requestConsent: () => true,
      onPolicyEvent: () => {},
    };

    const dateSpy = spyOn(Date, 'now');
    try {
      dateSpy.mockReturnValueOnce(0).mockReturnValueOnce(61_000);

      await withPollutedPrototype({ nowMs: POLLUTED_FIXED_NOW_MS }, async () => {
        const first = await validateClaimsAgainstTypeMetadata(vct, claims, sharedOptions);
        expect(first).toEqual({
          valid: true,
          schemaAvailable: false,
          warnings: [FAIL_OPEN_AUDIT_EVENTS['FO-3']],
        });

        await expect(
          validateClaimsAgainstTypeMetadata(vct, claims, sharedOptions),
        ).rejects.toMatchObject({ code: ErrorCodes.TYPE_METADATA_FETCH_FAILED });
      });
    } finally {
      dateSpy.mockRestore();
    }
  });
});
