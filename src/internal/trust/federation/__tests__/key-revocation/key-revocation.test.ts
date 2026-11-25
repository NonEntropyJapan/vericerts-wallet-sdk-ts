/**
 * 鍵無効化宣言（`revoked_keys`）のパース・集約・判定のユニットテスト。
 *
 * 検証内容:
 * - parseRevokedKeys: 正常系 / 未設定 / 非配列 / 要素の構造不正 → TRUST_CHAIN_INVALID（5010）。
 * - findKeyRevocation: `iat >= revoked_at` の境界（含む）・kid 不一致・同一 kid の最早採用・
 *   `sub` 不一致（別エンティティの同名 kid を巻き込まない）。
 * - collectRevokedKeys: entity-configuration ノードを無視し subordinate-statement のみ集約し、
 *   各宣言に宣言元 Statement の `sub` を紐付ける。
 * - assertKeyNotRevoked: 該当時に FEDERATION_KEY_REVOKED（5012）を送出し、kid 等を漏らさない。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../../errors.js';
import type {
  EntityStatement,
  RevokedKeyDeclaration,
  ScopedRevokedKeyDeclaration,
  TrustChainNode,
} from '../../federation-types.js';
import {
  assertKeyNotRevoked,
  collectRevokedKeys,
  findKeyRevocation,
  KEY_REVOCATION_PROPAGATION_MAX_SECONDS,
  parseRevokedKeys,
} from '../../revocation/key-revocation.js';

/** 判定に使う基準時刻（エポック秒）。 */
const T = 1_767_225_600;

/** 宣言対象のエンティティ（`node` が作る Statement の `sub` と一致させる）。 */
const SUB = 'https://child.example.eu';

/** `throws` が指定コードの VericertsError であることを検証する。 */
function expectThrowsCode(fn: () => unknown, code: ErrorCode): VericertsError {
  let caught: unknown;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(code);
  return caught as VericertsError;
}

/** 指定 kind / `revoked_keys` を持つ TrustChainNode を作る。 */
function node(
  kind: TrustChainNode['kind'],
  revokedKeys?: readonly RevokedKeyDeclaration[],
): TrustChainNode {
  const statement: EntityStatement = {
    iss: 'https://parent.example.eu',
    sub: 'https://child.example.eu',
    iat: T - 3600,
    exp: T + 3600,
    jwks: { keys: [] },
    ...(revokedKeys === undefined ? {} : { revoked_keys: revokedKeys }),
  };
  return { iss: statement.iss, sub: statement.sub, kind, statement };
}

describe('parseRevokedKeys', () => {
  it('正常な宣言配列をそのまま返す', () => {
    const parsed = parseRevokedKeys([
      { kid: 'issuer-1', revoked_at: T, reason: 'key_compromise' },
      { kid: 'issuer-2', revoked_at: 0 },
    ]);
    expect(parsed).toEqual([
      { kid: 'issuer-1', revoked_at: T, reason: 'key_compromise' },
      { kid: 'issuer-2', revoked_at: 0 },
    ]);
  });

  it('未設定（undefined）なら空配列を返す', () => {
    expect(parseRevokedKeys(undefined)).toEqual([]);
  });

  it('空配列はそのまま空配列を返す', () => {
    expect(parseRevokedKeys([])).toEqual([]);
  });

  it('reason 未指定なら reason フィールドを付けない', () => {
    const parsed = parseRevokedKeys([{ kid: 'issuer-1', revoked_at: T }]);
    expect(parsed[0]).toEqual({ kid: 'issuer-1', revoked_at: T });
    expect('reason' in (parsed[0] as object)).toBe(false);
  });

  it('配列でなければ TRUST_CHAIN_INVALID', () => {
    expectThrowsCode(() => parseRevokedKeys({ kid: 'issuer-1' }), ErrorCodes.TRUST_CHAIN_INVALID);
    expectThrowsCode(() => parseRevokedKeys('issuer-1'), ErrorCodes.TRUST_CHAIN_INVALID);
    expectThrowsCode(() => parseRevokedKeys(null), ErrorCodes.TRUST_CHAIN_INVALID);
  });

  it('要素がオブジェクトでなければ TRUST_CHAIN_INVALID', () => {
    expectThrowsCode(() => parseRevokedKeys(['issuer-1']), ErrorCodes.TRUST_CHAIN_INVALID);
    expectThrowsCode(() => parseRevokedKeys([null]), ErrorCodes.TRUST_CHAIN_INVALID);
    expectThrowsCode(() => parseRevokedKeys([[]]), ErrorCodes.TRUST_CHAIN_INVALID);
  });

  it('kid 欠落 / 非文字列 / 空文字なら TRUST_CHAIN_INVALID', () => {
    expectThrowsCode(() => parseRevokedKeys([{ revoked_at: T }]), ErrorCodes.TRUST_CHAIN_INVALID);
    expectThrowsCode(
      () => parseRevokedKeys([{ kid: 1, revoked_at: T }]),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
    expectThrowsCode(
      () => parseRevokedKeys([{ kid: '', revoked_at: T }]),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('revoked_at が非整数 / 負値 / NaN / 欠落なら TRUST_CHAIN_INVALID', () => {
    for (const revokedAt of [T + 0.5, -1, Number.NaN, Number.POSITIVE_INFINITY, '1767225600']) {
      expectThrowsCode(
        () => parseRevokedKeys([{ kid: 'issuer-1', revoked_at: revokedAt }]),
        ErrorCodes.TRUST_CHAIN_INVALID,
      );
    }
    expectThrowsCode(() => parseRevokedKeys([{ kid: 'issuer-1' }]), ErrorCodes.TRUST_CHAIN_INVALID);
  });

  it('reason が文字列でなければ TRUST_CHAIN_INVALID', () => {
    expectThrowsCode(
      () => parseRevokedKeys([{ kid: 'issuer-1', revoked_at: T, reason: 42 }]),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('1 要素でも不正なら配列全体を拒否する（黙って読み飛ばさない）', () => {
    expectThrowsCode(
      () => parseRevokedKeys([{ kid: 'issuer-1', revoked_at: T }, { kid: 'issuer-2' }]),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });
});

describe('findKeyRevocation', () => {
  const revocations: readonly ScopedRevokedKeyDeclaration[] = [
    { sub: SUB, kid: 'issuer-1', revoked_at: T },
  ];

  it('iat < revoked_at なら該当しない（漏洩前の署名は巻き添えにしない）', () => {
    expect(findKeyRevocation(revocations, SUB, 'issuer-1', T - 1)).toBeUndefined();
  });

  it('iat === revoked_at は該当する（境界を含む）', () => {
    expect(findKeyRevocation(revocations, SUB, 'issuer-1', T)).toEqual({
      sub: SUB,
      kid: 'issuer-1',
      revoked_at: T,
    });
  });

  it('iat > revoked_at なら該当する', () => {
    expect(findKeyRevocation(revocations, SUB, 'issuer-1', T + 1)).toEqual({
      sub: SUB,
      kid: 'issuer-1',
      revoked_at: T,
    });
  });

  it('kid が異なれば該当しない', () => {
    expect(findKeyRevocation(revocations, SUB, 'issuer-2', T + 1)).toBeUndefined();
  });

  // 回帰: kid は 1 つの JWKS 内でしか一意でない。sub を条件に含めないと、上位が別エンティティに
  // ついて出した宣言が同名 kid を使う無関係なエンティティの署名まで拒否してしまう。
  it('kid が一致しても sub が異なれば該当しない（別エンティティを巻き込まない）', () => {
    expect(
      findKeyRevocation(revocations, 'https://other.example.eu', 'issuer-1', T + 1),
    ).toBeUndefined();
  });

  it('宣言が無ければ該当しない', () => {
    expect(findKeyRevocation([], SUB, 'issuer-1', T + 1)).toBeUndefined();
  });

  it('同一 kid に複数宣言がある場合は最も早い revoked_at を採用する', () => {
    const multiple: readonly ScopedRevokedKeyDeclaration[] = [
      { sub: SUB, kid: 'issuer-1', revoked_at: T + 1000, reason: 'late' },
      { sub: SUB, kid: 'issuer-1', revoked_at: T, reason: 'early' },
      { sub: SUB, kid: 'issuer-1', revoked_at: T + 500, reason: 'middle' },
    ];
    expect(findKeyRevocation(multiple, SUB, 'issuer-1', T + 2000)?.reason).toBe('early');
  });

  // 回帰: 「最早が勝つ」規則は sub ごとに閉じていなければならない。別エンティティ宛の
  // より早い宣言が同名 kid の判定時刻を前倒ししてはならない。
  it('最早採用は sub ごとに閉じている（他エンティティの早い宣言を混ぜない）', () => {
    const multiple: readonly ScopedRevokedKeyDeclaration[] = [
      { sub: 'https://other.example.eu', kid: 'issuer-1', revoked_at: T - 5000, reason: 'other' },
      { sub: SUB, kid: 'issuer-1', revoked_at: T, reason: 'mine' },
    ];
    expect(findKeyRevocation(multiple, SUB, 'issuer-1', T + 1)?.reason).toBe('mine');
    // 他エンティティの早い宣言に引きずられて T-1 の署名が拒否されないこと。
    expect(findKeyRevocation(multiple, SUB, 'issuer-1', T - 1)).toBeUndefined();
  });

  it('後からの遅い再宣言は既に無効化された署名を復活させない', () => {
    const multiple: readonly ScopedRevokedKeyDeclaration[] = [
      { sub: SUB, kid: 'issuer-1', revoked_at: T },
      { sub: SUB, kid: 'issuer-1', revoked_at: T + 10_000 },
    ];
    // T 以降 T+10000 未満の署名も、最早宣言（T）により拒否され続ける。
    expect(findKeyRevocation(multiple, SUB, 'issuer-1', T + 100)?.revoked_at).toBe(T);
  });
});

describe('collectRevokedKeys', () => {
  it('subordinate-statement ノードの宣言を全て集約する', () => {
    const nodes = [
      node('subordinate-statement', [{ kid: 'a', revoked_at: T }]),
      node('subordinate-statement', [{ kid: 'b', revoked_at: T + 1 }]),
    ];
    expect(collectRevokedKeys(nodes).map((r) => r.kid)).toEqual(['a', 'b']);
  });

  it('entity-configuration ノードの宣言は無視する（自己署名は権威にしない）', () => {
    const nodes = [
      node('entity-configuration', [{ kid: 'self-declared', revoked_at: T }]),
      node('subordinate-statement', [{ kid: 'authoritative', revoked_at: T }]),
    ];
    expect(collectRevokedKeys(nodes).map((r) => r.kid)).toEqual(['authoritative']);
  });

  it('宣言が無ければ空配列を返す', () => {
    expect(
      collectRevokedKeys([node('subordinate-statement'), node('entity-configuration')]),
    ).toEqual([]);
  });

  // 回帰: 平坦化時に sub を捨てると別エンティティの同名 kid と衝突する。
  it('各宣言に宣言元 Statement の sub を紐付ける', () => {
    const collected = collectRevokedKeys([
      node('subordinate-statement', [{ kid: 'a', revoked_at: T }]),
    ]);
    expect(collected).toEqual([{ sub: SUB, kid: 'a', revoked_at: T }]);
  });
});

describe('assertKeyNotRevoked', () => {
  const revocations: readonly ScopedRevokedKeyDeclaration[] = [
    { sub: SUB, kid: 'issuer-1', revoked_at: T, reason: 'key_compromise' },
  ];

  it('該当しなければ何も投げない', () => {
    expect(() => assertKeyNotRevoked(revocations, SUB, 'issuer-1', T - 1)).not.toThrow();
    expect(() => assertKeyNotRevoked(revocations, SUB, 'other', T + 1)).not.toThrow();
  });

  // 回帰: 別エンティティの同名 kid を巻き添えで拒否しない。
  it('sub が異なれば同名 kid でも投げない', () => {
    expect(() =>
      assertKeyNotRevoked(revocations, 'https://other.example.eu', 'issuer-1', T + 1),
    ).not.toThrow();
  });

  it('該当すれば FEDERATION_KEY_REVOKED（5012）を投げる', () => {
    const error = expectThrowsCode(
      () => assertKeyNotRevoked(revocations, SUB, 'issuer-1', T),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
    expect(error.code).toBe('5012');
    expect(error.retriable).toBe(false);
  });

  it('例外に kid・reason を漏らさない', () => {
    const error = expectThrowsCode(
      () => assertKeyNotRevoked(revocations, SUB, 'issuer-1', T + 1),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
    const serialized = `${error.message}${JSON.stringify(error.context ?? {})}`;
    expect(serialized).not.toContain('issuer-1');
    expect(serialized).not.toContain('key_compromise');
  });
});

describe('KEY_REVOCATION_PROPAGATION_MAX_SECONDS', () => {
  it('伝播上限は 600 秒', () => {
    expect(KEY_REVOCATION_PROPAGATION_MAX_SECONDS).toBe(600);
  });
});
