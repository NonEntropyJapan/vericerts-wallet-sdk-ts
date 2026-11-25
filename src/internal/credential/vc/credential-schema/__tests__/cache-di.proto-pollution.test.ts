/**
 * `schemaCache` DI の鎖読みによるスキーマ検証の素通り。
 *
 * `options.schemaCache ?? default` と鎖読みすると、`Object.prototype.schemaCache` が汚染された環境で
 * 攻撃者の `get()` が空スキーマ `{}` を返し、スキーマの取得すら行わず `valid: true` になる。
 * 正規に注入したキャッシュ（クラスインスタンス）は引き続き使われることも固定する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { CredentialSchemaCache } from '../cache.js';
import { validateClaimsAgainstCredentialSchema, validateCredentialSchema } from '../validate.js';
import { buildVc, createFetchStub, PERSON_SCHEMA, SCHEMA_URL } from './fixtures.js';

/** 常に空スキーマを返す攻撃者のキャッシュ。 */
const EVIL_CACHE = { get: () => ({}), set: () => undefined };

/**
 * `name` が必須のスキーマに対し違反する VC（`name` が数値）。
 *
 * 既定キャッシュはモジュール共有のため、テスト間で取得結果が漏れないよう URL をテストごとに変える。
 */
function violatingVc(url: string) {
  return buildVc({ name: 42 }, { id: url, type: 'JsonSchema' });
}

describe('schemaCache の汚染耐性', () => {
  it('Object.prototype.schemaCache を汚染しても違反 VC は valid:false で、スキーマを取得する', async () => {
    const url = `${SCHEMA_URL}?case=claims`;
    const stub = createFetchStub({ [url]: { json: PERSON_SCHEMA } });
    const result = await withPollutedPrototypeAsync({ schemaCache: EVIL_CACHE }, () =>
      validateClaimsAgainstCredentialSchema(violatingVc(url), { fetchImpl: stub.fetchImpl }),
    );
    expect(result.valid).toBe(false);
    expect(stub.requested).toEqual([url]);
  });

  it('validateCredentialSchema も汚染された schemaCache で素通りしない', async () => {
    const url = `${SCHEMA_URL}?case=strict`;
    const stub = createFetchStub({ [url]: { json: PERSON_SCHEMA } });
    const result = await withPollutedPrototypeAsync({ schemaCache: EVIL_CACHE }, () =>
      validateCredentialSchema(violatingVc(url), undefined, { fetchImpl: stub.fetchImpl }),
    );
    expect(result.valid).toBe(false);
    expect(stub.requested).toEqual([url]);
  });

  it('明示的に注入したクラスインスタンスのキャッシュは従来どおり使われる', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });
    const cache = new CredentialSchemaCache();
    const options = { fetchImpl: stub.fetchImpl, schemaCache: cache, nowMs: 1000 };
    await validateCredentialSchema(violatingVc(SCHEMA_URL), undefined, options);
    await validateCredentialSchema(violatingVc(SCHEMA_URL), undefined, options);
    expect(stub.requested).toEqual([SCHEMA_URL]);
  });
});
