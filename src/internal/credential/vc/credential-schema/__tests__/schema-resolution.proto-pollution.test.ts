/**
 * `credentialSchema` 経路のスキーマ解決・クレーム読み取りの汚染耐性。
 *
 * `validate.ts` は `vc.credentialSchema` / `vc.credentialSubject` をプロトタイプ鎖で読んでいた。
 * `Object.prototype` が汚染された環境では、
 *
 * - `credentialSchema` を**持たない**正当な VC でも継承値を「VC が指定したスキーマ参照」として
 *   採用し、**攻撃者が指定した URL から JSON Schema を取得して検証する**（SSRF / 検証すり替え）、
 * - `credentialSubject` を**持たない** VC でも継承値を検証対象クレームとして採用する、
 *
 * という結果になる。前者は「拒否されたか」だけでは不十分なので、`stub.requested` が空である
 * ことまで確認して**取得しに行っていない**ことを直接検証する。
 *
 * 検証はすべて「当該プロパティを**省略した** VC」で行う（明示指定は汚染と無関係に通るため
 * 無価値）。`buildVc` は `credentialSchema` が `undefined` ならキーごと落とす。
 * `credentialSubject` は必須フィールドのため、分割代入でキーごと落とした値を使う。
 *
 * 兄弟モジュール `vc/issue.ts` の同種テスト（`vc/__tests__/proto-pollution-issue/`）と同方針。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { VerifiableCredential } from '../../vc.js';
import { CredentialSchemaCache } from '../cache.js';
import type { ValidateCredentialSchemaOptions } from '../types.js';
import {
  resolveSchemaUrl,
  validateClaimsAgainstCredentialSchema,
  validateCredentialSchema,
} from '../validate.js';
import { buildVc, createFetchStub, type FetchStub, PERSON_SCHEMA, SCHEMA_URL } from './fixtures.js';

/** 攻撃者が `Object.prototype` 経由で指定するスキーマ URL。 */
const EVIL_SCHEMA_URL = 'https://attacker.example.com/evil-schema.json';
/** 汚染で仕込む `credentialSchema` 参照（JSON Schema 系なので鎖読みだと採用される）。 */
const EVIL_REFERENCE = { id: EVIL_SCHEMA_URL, type: 'JsonSchema' };
/** 汚染で仕込むクレーム（スキーマに適合する = 鎖読みだと検証が通ってしまう）。 */
const EVIL_SUBJECT = { name: '攻撃者の氏名' };

/**
 * 正規 URL と汚染 URL の**両方**を取得可能にしたスタブ。
 *
 * 汚染 URL を未登録にすると取得失敗（3015）で間接的に落ちてしまい、「取りに行ったか」と
 * 「取りに行った先が落ちたか」が区別できない。取得できる状態にしておけば、鎖読みの実装では
 * 攻撃者のスキーマで検証が**成功してしまう**ことがそのまま失敗として現れる。
 */
function evilReachableStub(): FetchStub {
  return createFetchStub({
    [SCHEMA_URL]: { json: PERSON_SCHEMA },
    [EVIL_SCHEMA_URL]: { json: PERSON_SCHEMA },
  });
}

/** 既定キャッシュを共有しないよう、テストごとに専用キャッシュを渡す。 */
function options(stub: FetchStub): ValidateCredentialSchemaOptions {
  return { fetchImpl: stub.fetchImpl, schemaCache: new CredentialSchemaCache(), nowMs: 1000 };
}

/** 型のない JS 呼び出し（プロパティ欠落）を再現するためのキャスト。 */
function omit<T>(value: unknown): T {
  return value as T;
}

/** `credentialSubject` を持たない VC（スキーマ参照は明示的に持つ）。 */
function vcWithoutSubject(): VerifiableCredential {
  const { credentialSubject: _omitted, ...rest } = buildVc(
    { name: '山田太郎' },
    { id: SCHEMA_URL, type: 'JsonSchema' },
  );
  return omit<VerifiableCredential>(rest);
}

describe('resolveSchemaUrl の汚染耐性', () => {
  it('credentialSchema を持たない VC は継承したスキーマ参照を採用せず 3016 に倒す', () => {
    const vc = buildVc({ name: '山田太郎' });

    expect(() =>
      withPollutedPrototype({ credentialSchema: EVIL_REFERENCE }, () => resolveSchemaUrl(vc)),
    ).toThrow(new VericertsError(ErrorCodes.SCHEMA_NOT_SPECIFIED));
  });

  it('アクセサ汚染の credentialSchema でも採用しない', () => {
    const vc = buildVc({ name: '山田太郎' });

    expect(() =>
      withPollutedPrototypeAccessor({ credentialSchema: () => EVIL_REFERENCE }, () =>
        resolveSchemaUrl(vc),
      ),
    ).toThrow(new VericertsError(ErrorCodes.SCHEMA_NOT_SPECIFIED));
  });
});

describe('validateCredentialSchema の汚染耐性', () => {
  it('credentialSchema を持たない VC は汚染された URL を取得せず 3016 で拒否する', async () => {
    const stub = evilReachableStub();
    const vc = buildVc({ name: '山田太郎' });

    const promise = withPollutedPrototypeAsync({ credentialSchema: EVIL_REFERENCE }, () =>
      validateCredentialSchema(vc, undefined, options(stub)),
    );

    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.SCHEMA_NOT_SPECIFIED });
    // 受入条件の核心: 攻撃者の URL へ取得しに行っていないこと。
    expect(stub.requested).toEqual([]);
  });

  it('アクセサ汚染の credentialSchema でも汚染された URL を取得しない', async () => {
    const stub = evilReachableStub();
    const vc = buildVc({ name: '山田太郎' });

    const promise = withPollutedPrototypeAccessorAsync(
      { credentialSchema: () => EVIL_REFERENCE },
      () => validateCredentialSchema(vc, undefined, options(stub)),
    );

    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.SCHEMA_NOT_SPECIFIED });
    expect(stub.requested).toEqual([]);
  });

  it('credentialSubject を持たない VC は継承したクレームを検証対象にしない', async () => {
    // 汚染値はスキーマに適合するため、鎖読みだと `valid: true`（検証したことになってしまう）。
    const stub = evilReachableStub();

    const result = await withPollutedPrototypeAsync({ credentialSubject: EVIL_SUBJECT }, () =>
      validateCredentialSchema(vcWithoutSubject(), undefined, options(stub)),
    );

    expect(result.valid).toBe(false);
    expect(result.errors?.some((error) => error.required)).toBe(true);
    expect(stub.requested).toEqual([SCHEMA_URL]);
  });

  it('アクセサ汚染の credentialSubject でも検証対象にしない', async () => {
    const stub = evilReachableStub();

    const result = await withPollutedPrototypeAccessorAsync(
      { credentialSubject: () => EVIL_SUBJECT },
      () => validateCredentialSchema(vcWithoutSubject(), undefined, options(stub)),
    );

    expect(result.valid).toBe(false);
  });
});

describe('validateClaimsAgainstCredentialSchema（fail-safe 版）の汚染耐性', () => {
  it('継承した credentialSchema を採用せず schemaAvailable: false で通過する', async () => {
    const stub = evilReachableStub();
    const vc = buildVc({ name: '山田太郎' });

    const result = await withPollutedPrototypeAsync({ credentialSchema: EVIL_REFERENCE }, () =>
      validateClaimsAgainstCredentialSchema(vc, options(stub)),
    );

    expect(result).toEqual({ valid: true, schemaAvailable: false, warnings: [] });
    expect(stub.requested).toEqual([]);
  });

  it('アクセサ汚染の credentialSchema でも schemaAvailable: false で通過する', async () => {
    const stub = evilReachableStub();
    const vc = buildVc({ name: '山田太郎' });

    const result = await withPollutedPrototypeAccessorAsync(
      { credentialSchema: () => EVIL_REFERENCE },
      () => validateClaimsAgainstCredentialSchema(vc, options(stub)),
    );

    expect(result).toEqual({ valid: true, schemaAvailable: false, warnings: [] });
    expect(stub.requested).toEqual([]);
  });

  it('継承した credentialSubject をクレームとして採用しない', async () => {
    const stub = evilReachableStub();

    const result = await withPollutedPrototypeAsync({ credentialSubject: EVIL_SUBJECT }, () =>
      validateClaimsAgainstCredentialSchema(vcWithoutSubject(), options(stub)),
    );

    // 汚染値を採用していれば適合（`valid: true`）になる。採用しなければルートの型違反 = 必須違反。
    expect(result.valid).toBe(false);
    expect(result.schemaAvailable).toBe(true);
  });
});

describe('credentialSchema 経路の正常系（own 化しすぎの回帰検出）', () => {
  it('明示的に credentialSchema / credentialSubject を持つ VC は従来どおり検証される', async () => {
    const stub = evilReachableStub();
    const vc = buildVc(
      { name: '山田太郎', nickname: 'たろ' },
      { id: SCHEMA_URL, type: 'JsonSchema' },
    );

    const result = await validateCredentialSchema(vc, undefined, options(stub));

    expect(result.valid).toBe(true);
    expect(stub.requested).toEqual([SCHEMA_URL]);
  });

  it('非列挙の own プロパティで持つ credentialSchema も解決できる', () => {
    // `ownProperty` は `Object.hasOwn` 判定なので列挙可否を問わない。スプレッド由来の
    // own 化しすぎ（列挙可能なキーだけ拾う実装）への退行を検出する。
    const vc = buildVc({ name: '山田太郎' });
    Object.defineProperty(vc, 'credentialSchema', {
      value: { id: SCHEMA_URL, type: 'JsonSchema' },
      enumerable: false,
    });

    expect(resolveSchemaUrl(vc)).toBe(SCHEMA_URL);
  });
});
