/**
 * createDidWebVh / updateDidWebVh の**入れ子**の own アクセサ再評価耐性テスト。
 *
 * `normalizeLogInput`はトップレベルの own プロパティしか畳んでいなかったため、
 * 入れ子のオブジェクトは**参照ごとコピー**され、その中の own アクセサが生き残っていた。
 *
 * 1. Art.9 走査器（`special-category.ts`）が入れ子を辿る際に 1 回目が評価される。
 * 2. `webvh/codec.ts` の `canonicalize` が SCID 計算・Log entry 搭載で 2 回目以降を評価する。
 *
 * 走査器は各階層の**キー名**でしか Art.9 を判定しないため、入れ子アクセサが
 * **キー集合ごと違うオブジェクト**（1 回目は無害・2 回目に Art.9 属性）を返すと、10601 を
 * 素通りした値が公開・追記専用の DID Log に焼き付く。`normalizeLogInput` が
 * `internal/prototype-safety/deep-snapshot.ts` で入れ子まで畳んでいることを固定する（深い畳みを外すと落ちる）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { DIDDocument } from '../../../did.js';
import { createDidWebVh, updateDidWebVh, type WebVhCreateDocument } from '../../method-webvh.js';
import { generateKey, signEntry } from '../webvh-fixtures.js';

const SPECIAL_CATEGORY = new VericertsError(ErrorCodes.GDPR_SPECIAL_CATEGORY_ON_CHAIN);

/** SCID / versionId を決定的にするための固定 versionTime。 */
const FIXED_TIME = '2026-01-01T00:00:00.000Z';

/** update 版の versionTime。初版（FIXED_TIME）より後でなければ verifyChain が拒否する。 */
const UPDATE_TIME = '2026-01-02T00:00:00.000Z';

/** 1 回目の読み取りで返る無害な値（Art.9 属性名を持たない）。 */
const CLEAN_META = { region: 'jp' } as const;
/** 2 回目以降で返る Art.9 属性（`healthData`）入りの値。 */
const TOXIC_META = { healthData: 'HIV+' } as const;

/** getter の呼び出し回数を数えつつ、回数に応じた値を返す入れ子オブジェクトを作る。 */
function nestedWithCountingAccessor(values: readonly unknown[]): {
  readonly entry: Record<string, unknown>;
  reads: () => number;
} {
  let reads = 0;
  const entry: Record<string, unknown> = {
    id: '#s1',
    type: 'DIDCommMessaging',
    serviceEndpoint: 'https://vericerts.io/v1',
  };
  Object.defineProperty(entry, 'metadata', {
    configurable: true,
    enumerable: true,
    get(): unknown {
      const value = values[Math.min(reads, values.length - 1)];
      reads += 1;
      return value;
    },
  });
  return { entry, reads: () => reads };
}

/** 入れ子アクセサを `service[0].metadata` に持つ DID Document を組み立てる。 */
function documentWithNestedAccessor(values: readonly unknown[]): {
  readonly document: WebVhCreateDocument;
  reads: () => number;
} {
  const { entry, reads } = nestedWithCountingAccessor(values);
  const document = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    verificationMethod: [],
    authentication: [],
    assertionMethod: [],
    service: [entry],
  };
  return { document: document as unknown as WebVhCreateDocument, reads };
}

/** 初版 Log（proof 付き）を作る。 */
function genesis() {
  const key = generateKey();
  const { did, logEntry } = createDidWebVh({
    domain: 'vericerts.io',
    updateKeys: [key.multikey],
    versionTime: FIXED_TIME,
  });
  return { did, key, signedGenesis: signEntry(logEntry, key) };
}

describe('createDidWebVh の入れ子 own アクセサ再評価耐性', () => {
  it('2 回目に Art.9 属性へすり替わる入れ子アクセサでも Log に載らない', () => {
    const { document } = documentWithNestedAccessor([CLEAN_META, TOXIC_META]);

    const { logEntry } = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [generateKey().multikey],
      versionTime: FIXED_TIME,
      document,
    });

    expect(JSON.stringify(logEntry.state)).not.toContain('healthData');
    expect(JSON.stringify(logEntry.state)).toContain('"region":"jp"');
  });

  it('入れ子アクセサは 1 度しか評価されない（SCID 計算と state 搭載で読み直さない）', () => {
    const { document, reads } = documentWithNestedAccessor([CLEAN_META, TOXIC_META]);

    createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [generateKey().multikey],
      versionTime: FIXED_TIME,
      document,
    });

    // 深い畳みが無いと、Art.9 走査 + プレースホルダ entry + 最終 entry で 3 回以上読まれる。
    expect(reads()).toBe(1);
  });

  it('1 回目の読み取りが Art.9 属性を返す入れ子アクセサは 10601 で拒否される', () => {
    const { document } = documentWithNestedAccessor([TOXIC_META, CLEAN_META]);

    expect(() =>
      createDidWebVh({
        domain: 'vericerts.io',
        updateKeys: [generateKey().multikey],
        versionTime: FIXED_TIME,
        document,
      }),
    ).toThrow(SPECIAL_CATEGORY);
  });

  it('SCID / versionId は畳んだ確定値だけから導かれる（別呼び出しと一致する）', () => {
    const key = generateKey();
    const { document } = documentWithNestedAccessor([CLEAN_META, TOXIC_META]);

    const actual = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
      versionTime: FIXED_TIME,
      document,
    });
    // 1 回目の読み取り値を素のデータとして持つ document で組み立てた場合の期待値。
    const expected = createDidWebVh({
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
      versionTime: FIXED_TIME,
      document: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        verificationMethod: [],
        authentication: [],
        assertionMethod: [],
        service: [
          {
            id: '#s1',
            type: 'DIDCommMessaging',
            serviceEndpoint: 'https://vericerts.io/v1',
            metadata: CLEAN_META,
          },
        ],
      } as unknown as WebVhCreateDocument,
    });

    expect(actual.did).toBe(expected.did);
    expect(actual.logEntry).toEqual(expected.logEntry);
  });
});

describe('updateDidWebVh の入れ子 own アクセサ再評価耐性', () => {
  it('2 回目に Art.9 属性へすり替わる入れ子アクセサでも次版 Log に載らない', () => {
    const { did, signedGenesis } = genesis();
    const { entry } = nestedWithCountingAccessor([CLEAN_META, TOXIC_META]);
    const state = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
      service: [entry],
    } as unknown as DIDDocument;

    const v2 = updateDidWebVh({ previousLog: [signedGenesis], versionTime: UPDATE_TIME, state });

    expect(JSON.stringify(v2)).not.toContain('healthData');
    expect(JSON.stringify(v2.state)).toContain('"region":"jp"');
  });

  it('1 回目の読み取りが Art.9 属性を返す入れ子アクセサは 10601 で拒否される', () => {
    const { did, signedGenesis } = genesis();
    const { entry } = nestedWithCountingAccessor([TOXIC_META, CLEAN_META]);
    const state = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
      service: [entry],
    } as unknown as DIDDocument;

    expect(() =>
      updateDidWebVh({ previousLog: [signedGenesis], versionTime: UPDATE_TIME, state }),
    ).toThrow(SPECIAL_CATEGORY);
  });
});
