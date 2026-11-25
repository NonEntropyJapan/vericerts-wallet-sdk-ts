/**
 * createDidWebVh / updateDidWebVh の own アクセサ再評価（TOCTOU）耐性テスト。
 *
 * `ownProperty` は own アクセサを読むたびに再評価する。`updateDidWebVh` は `options.state` を
 * 継続性ガードと Log entry 搭載で 2 度読んでいたため、
 *
 * 1. 1 回目に `previous.state.id` と一致する文書、
 * 2. 2 回目に別 DID / 別鍵の文書
 *
 * を返す `get state()` が **DID 同一性ガードを素通りし**、すり替え済み state がハッシュ連鎖された
 * 追記専用 Log に書き込まれた。state 自身の `get id()` でも同じすり替えが成立する（ガードが読む
 * `id` と `canonicalize` されて `versionId` にハッシュされる `id` が別物になる）。
 *
 * 併せて `createDidWebVh` の SCID 用プレースホルダ entry と最終 entry の 2 度組み立ても
 * 固定する。正規化スナップショット（`identity/normalized-log-input.ts`）を外すと本ファイルの
 * テストは落ちる。
 */

import { describe, expect, it } from 'bun:test';
import {
  defineNonEnumerableProperty,
  defineReadCountingAccessor,
} from '../../../../__tests__/accessor-toctou.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { DIDDocument } from '../../../did.js';
import {
  createDidWebVh,
  updateDidWebVh,
  type WebVhCreateDocument,
  type WebVhUpdateOptions,
} from '../../method-webvh.js';
import { generateKey, signEntry } from '../webvh-fixtures.js';

const INVALID_DID = new VericertsError(ErrorCodes.INVALID_DID);

const SPECIAL_CATEGORY = new VericertsError(ErrorCodes.GDPR_SPECIAL_CATEGORY_ON_CHAIN);

/** SCID / versionId を決定的にするための固定 versionTime。 */
const FIXED_TIME = '2026-01-01T00:00:00.000Z';

/** update 版の versionTime。初版（FIXED_TIME）より後でなければ verifyChain が拒否する。 */
const UPDATE_TIME = '2026-01-02T00:00:00.000Z';

/** すり替え先として使う別 DID。Log に現れてはならない。 */
const ATTACKER_DID = 'did:webvh:zAttackerScid:attacker.example';

/** 1 回目の読み取りで返る service。 */
const CLEAN_SERVICE = [
  { id: '#s1', type: 'DIDCommMessaging', serviceEndpoint: 'https://vericerts.io/v1' },
];

/** 2 回目以降の読み取りで返る service。 */
const SWAPPED_SERVICE = [
  { id: '#s1', type: 'DIDCommMessaging', serviceEndpoint: 'https://attacker.example/v2' },
];

/** 指定 id の最小 state。 */
function stateWith(id: string): DIDDocument {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id,
    verificationMethod: [],
    authentication: [],
    assertionMethod: [],
  };
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

describe('updateDidWebVh の own アクセサ再評価耐性', () => {
  it('options.state の 2 回目の読み取りが別 DID を返してもガード済みの state しか Log に載らない', () => {
    const { did, signedGenesis } = genesis();
    const options = { previousLog: [signedGenesis], versionTime: UPDATE_TIME };
    defineReadCountingAccessor(options, 'state', [stateWith(did), stateWith(ATTACKER_DID)]);

    const v2 = updateDidWebVh(options as unknown as WebVhUpdateOptions);

    expect(v2.state.id).toBe(did);
    expect(JSON.stringify(v2)).not.toContain(ATTACKER_DID);
  });

  it('options.state の 1 回目の読み取りが別 DID なら従来どおり INVALID_DID で拒否される', () => {
    const { did, signedGenesis } = genesis();
    const options = { previousLog: [signedGenesis], versionTime: UPDATE_TIME };
    defineReadCountingAccessor(options, 'state', [stateWith(ATTACKER_DID), stateWith(did)]);

    expect(() => updateDidWebVh(options as unknown as WebVhUpdateOptions)).toThrow(INVALID_DID);
  });

  it('state 自身の get id() が 2 回目に別 DID を返しても versionId は検査済み id から導かれる', () => {
    const { did, signedGenesis } = genesis();
    const state = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
    };
    defineReadCountingAccessor(state, 'id', [did, ATTACKER_DID]);

    const actual = updateDidWebVh({
      previousLog: [signedGenesis],
      versionTime: UPDATE_TIME,
      state: state as unknown as DIDDocument,
    });
    // 検査済み id だけで組み立てた場合の期待値（versionId のハッシュ連鎖まで一致する）。
    const expected = updateDidWebVh({
      previousLog: [signedGenesis],
      versionTime: UPDATE_TIME,
      state: stateWith(did),
    });

    expect(actual.state.id).toBe(did);
    expect(actual).toEqual(expected);
  });

  it('state を省略した JS 呼び出しは従来どおり INVALID_DID で拒否される', () => {
    const { signedGenesis } = genesis();

    expect(() =>
      updateDidWebVh({ previousLog: [signedGenesis] } as unknown as WebVhUpdateOptions),
    ).toThrow(INVALID_DID);
  });
});

describe('createDidWebVh の own アクセサ再評価耐性', () => {
  it('Document のフィールドアクセサが呼び出しごとに別の値を返しても SCID と公開 state が一致する', () => {
    const key = generateKey();
    const base = {
      domain: 'vericerts.io',
      updateKeys: [key.multikey],
      versionTime: FIXED_TIME,
    };
    const document = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
    };
    // 検査 → SCID 用プレースホルダ entry → 最終 entry の 3 度読みで別の値を返させる。
    defineReadCountingAccessor(document, 'service', [
      CLEAN_SERVICE,
      SWAPPED_SERVICE,
      SWAPPED_SERVICE,
    ]);

    const actual = createDidWebVh({
      ...base,
      document: document as unknown as WebVhCreateDocument,
    });
    const expected = createDidWebVh({
      ...base,
      document: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        verificationMethod: [],
        authentication: [],
        assertionMethod: [],
        service: CLEAN_SERVICE,
      } as unknown as WebVhCreateDocument,
    });

    expect(actual).toEqual(expected);
    expect(JSON.stringify(actual.logEntry.state)).not.toContain('attacker.example');
  });
});

describe('正規化スナップショットの走査範囲', () => {
  it('own 非列挙の Art.9 属性を持つ state は updateDidWebVh で 10601 拒否される', () => {
    const { did, signedGenesis } = genesis();
    // Art.9 走査（`Object.getOwnPropertyNames`）は非列挙も見る。スナップショットを
    // spread（own かつ列挙可能）で作ると属性が落ち、ガードが素通りしてしまう。
    const state = defineNonEnumerableProperty(stateWith(did), 'healthData', 'HIV+');

    expect(() =>
      updateDidWebVh({ previousLog: [signedGenesis], versionTime: UPDATE_TIME, state }),
    ).toThrow(SPECIAL_CATEGORY);
  });

  it('own 非列挙の Art.9 属性を持つ document は createDidWebVh で 10601 拒否される', () => {
    const key = generateKey();
    const document = defineNonEnumerableProperty(
      {
        '@context': ['https://www.w3.org/ns/did/v1'],
        verificationMethod: [],
        authentication: [],
        assertionMethod: [],
      } as unknown as WebVhCreateDocument,
      'healthData',
      'HIV+',
    );

    expect(() =>
      createDidWebVh({
        domain: 'vericerts.io',
        updateKeys: [key.multikey],
        versionTime: FIXED_TIME,
        document,
      }),
    ).toThrow(SPECIAL_CATEGORY);
  });

  it('own 非列挙プロパティは canonical 形に載らないが own プロパティとしては保たれる', () => {
    const { did, signedGenesis } = genesis();
    // Art.9 でない任意のキー。元の入力では非列挙なので `canonicalize`（`Object.keys`）にも
    // JSON 化にも現れない。スナップショットが非列挙を列挙可能へ格上げすると、これまで公開
    // されていなかった値が追記専用の DID Log に焼き付いてしまう。
    const state = defineNonEnumerableProperty(stateWith(did), 'internalNote', 'do-not-publish');

    const v2 = updateDidWebVh({ previousLog: [signedGenesis], versionTime: UPDATE_TIME, state });

    expect(JSON.stringify(v2)).not.toContain('do-not-publish');
    // `ownProperty`（`Object.hasOwn`）から見える範囲は元の入力と一致させる。
    expect(Object.hasOwn(v2.state, 'internalNote')).toBe(true);
    expect(Object.keys(v2.state)).not.toContain('internalNote');
    // 非列挙は canonical 形に入らないため versionId も元の state と同じになる。
    const expected = updateDidWebVh({
      previousLog: [signedGenesis],
      versionTime: UPDATE_TIME,
      state: stateWith(did),
    });
    expect(v2.versionId).toBe(expected.versionId);
  });
});
