/**
 * `credentialSchema.digestSRI`（スキーマ文書のハッシュ固定）の宣言は取得前に 3061 で拒否する。
 *
 * SDK は取得文書の生バイト列に対するダイジェストを照合しない。宣言を黙って捨てると、ホストを乗っ取って
 * 差し替えた全許可スキーマでも `valid: true` になる。SD-JWT VC の `vct#integrity`と
 * 同じ共通ヘルパ・同じエラーコード（3061 / `integrity_unverifiable`）で拒否する。
 */

import { describe, expect, it } from 'bun:test';
import { createHash } from 'node:crypto';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { VerifiableCredential } from '../../vc.js';
import { CredentialSchemaCache } from '../cache.js';
import { validateClaimsAgainstCredentialSchema, validateCredentialSchema } from '../validate.js';
import { buildVc, createFetchStub, PERSON_SCHEMA, SCHEMA_URL } from './fixtures.js';

/** ホスト乗っ取り後の「何でも通る」スキーマ。 */
const PERMISSIVE_SCHEMA = {};
const GENUINE = JSON.stringify(PERSON_SCHEMA);
const sri = (body: string) => `sha256-${createHash('sha256').update(body).digest('base64')}`;

function withReference(extra: Record<string, unknown>, claims: Record<string, unknown> = {}) {
  return buildVc({ name: 1, ...claims }, {
    id: SCHEMA_URL,
    type: 'JsonSchema',
    ...extra,
  } as VerifiableCredential['credentialSchema']);
}

async function expectUnverifiable(promise: Promise<unknown>): Promise<void> {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(VericertsError);
  expect((error as VericertsError).code).toBe(ErrorCodes.TYPE_METADATA_INVALID);
  expect((error as VericertsError).context).toMatchObject({ reason: 'integrity_unverifiable' });
}

const declarations: [string, Record<string, unknown>][] = [
  ['正しい SRI（sha256）', { digestSRI: sri(GENUINE) }],
  ['すり替え後の文書に対する SRI（不一致のはず）', { digestSRI: sri('{}') }],
  ['sha384', { digestSRI: `sha384-${createHash('sha384').update(GENUINE).digest('base64')}` }],
  ['sha512', { digestSRI: `sha512-${createHash('sha512').update(GENUINE).digest('base64')}` }],
  ['digestMultibase', { digestMultibase: 'uEiAbc' }],
  ['空文字列', { digestSRI: '' }],
  ['null', { digestSRI: null }],
  ['undefined（キーだけ存在）', { digestSRI: undefined }],
  ['数値', { digestSRI: 123 }],
  ['配列', { digestSRI: [sri(GENUINE)] }],
  ['空配列', { digestSRI: [] }],
  ['オブジェクト', { digestSRI: { sha256: 'x' } }],
  ['大文字キー（DIGESTSRI）', { DIGESTSRI: sri(GENUINE) }],
  ['大小混在キー（DigestSri）', { DigestSri: sri(GENUINE) }],
  ['小文字キー（digestsri）', { digestsri: sri(GENUINE) }],
];

describe('credentialSchema.digestSRI のピン留め', () => {
  it.each(
    declarations,
  )('%s が宣言された VC は、取得せず 3061 で拒否する（validateCredentialSchema）', async (_label, extra) => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERMISSIVE_SCHEMA } });
    await expectUnverifiable(
      validateCredentialSchema(withReference(extra), undefined, {
        fetchImpl: stub.fetchImpl,
        schemaCache: new CredentialSchemaCache(),
      }),
    );
    expect(stub.requested).toEqual([]);
  });

  it.each(
    declarations,
  )('%s が宣言された VC は、fail-open 入口でも取得せず 3061 で拒否する', async (_label, extra) => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERMISSIVE_SCHEMA } });
    await expectUnverifiable(
      validateClaimsAgainstCredentialSchema(withReference(extra), {
        fetchImpl: stub.fetchImpl,
        schemaCache: new CredentialSchemaCache(),
        // FO-3 / FO-4 の許可があっても完全性の失敗は通さない。
        requestConsent: () => true,
        onPolicyEvent: () => {},
      }),
    );
    expect(stub.requested).toEqual([]);
  });

  it('キャッシュ済みのスキーマがあっても宣言があれば拒否する', async () => {
    const cache = new CredentialSchemaCache();
    cache.set(SCHEMA_URL, PERMISSIVE_SCHEMA, Date.now());
    await expectUnverifiable(
      validateCredentialSchema(withReference({ digestSRI: sri(GENUINE) }), undefined, {
        schemaCache: cache,
      }),
    );
  });

  it('明示引数 schema を渡しても、VC が宣言したハッシュ固定は黙って捨てない', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERMISSIVE_SCHEMA } });
    await expectUnverifiable(
      validateCredentialSchema(withReference({ digestSRI: sri(GENUINE) }), SCHEMA_URL, {
        fetchImpl: stub.fetchImpl,
        schemaCache: new CredentialSchemaCache(),
      }),
    );
  });

  it('credentialSchema が配列で、JSON Schema 系の 2 件目だけが宣言していても拒否する', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERMISSIVE_SCHEMA } });
    const vc = buildVc({ name: 1 }, [
      { id: SCHEMA_URL, type: 'JsonSchema' },
      { id: SCHEMA_URL, type: 'JsonSchema', digestSRI: sri(GENUINE) },
    ] as VerifiableCredential['credentialSchema']);
    await expectUnverifiable(
      validateClaimsAgainstCredentialSchema(vc, {
        fetchImpl: stub.fetchImpl,
        schemaCache: new CredentialSchemaCache(),
      }),
    );
    expect(stub.requested).toEqual([]);
  });

  it('宣言が無ければ従来どおり検証する（スキーマ違反は valid:false、適合は valid:true）', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });
    const options = { fetchImpl: stub.fetchImpl, schemaCache: new CredentialSchemaCache() };
    const bad = await validateCredentialSchema(withReference({}), undefined, options);
    expect(bad.valid).toBe(false);
    const good = await validateCredentialSchema(
      withReference({}, { name: '山田太郎' }),
      undefined,
      options,
    );
    expect(good.valid).toBe(true);
  });

  it('JSON Schema 系でない参照（未対応の type）の digestSRI は、使わないスキーマなので拒否しない', async () => {
    const vc = buildVc({ name: 1 }, {
      id: SCHEMA_URL,
      type: 'JsonSchemaCredential',
      digestSRI: sri(GENUINE),
    } as VerifiableCredential['credentialSchema']);
    const result = await validateClaimsAgainstCredentialSchema(vc, {});
    expect(result).toMatchObject({ valid: true, schemaAvailable: false });
  });

  it('Object.prototype の汚染（digestSRI）を宣言として扱わない（own 限定）', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });
    const proto = Object.prototype as Record<string, unknown>;
    proto.digestSRI = sri(GENUINE);
    try {
      const result = await validateCredentialSchema(
        withReference({}, { name: '山田太郎' }),
        undefined,
        {
          fetchImpl: stub.fetchImpl,
          schemaCache: new CredentialSchemaCache(),
        },
      );
      expect(result.valid).toBe(true);
    } finally {
      delete proto.digestSRI;
    }
  });
});
