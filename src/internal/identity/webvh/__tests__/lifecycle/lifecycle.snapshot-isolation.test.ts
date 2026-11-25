/**
 * `createDidWebVh` が返す初版 state の呼び出し間の独立性。
 *
 * `document['@context']` を省略すると `buildGenesisState` がモジュール定数 `DID_WEBVH_CONTEXT` で
 * 補完する。定数の**参照そのもの**を state に載せると既定 `@context` 配列が呼び出し間で共有され、
 * ある呼び出しの戻り値への破壊的変更が次の呼び出しの SCID / `versionId` へ焼き付く。DID Log は
 * 公開・追記専用でハッシュチェーンにより確定するため、載ってしまえば取り消せない。
 */

import { describe, expect, it } from 'bun:test';
import { createDidWebVh } from '../../lifecycle/lifecycle.js';
import { generateKey } from '../webvh-fixtures.js';

/** SCID / versionId を決定的にするための固定 versionTime。 */
const FIXED_TIME = '2026-01-01T00:00:00.000Z';

/** `document['@context']` 未指定時に `buildGenesisState` が補完する既定コンテキスト。 */
const DEFAULT_WEBVH_CONTEXT = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/multikey/v1',
];

describe('createDidWebVh の既定 @context 独立性', () => {
  /** `document` 未指定の生成オプション（既定値補完の経路を通す）。 */
  function defaultOptions(multikey: string) {
    return { domain: 'vericerts.io', updateKeys: [multikey], versionTime: FIXED_TIME };
  }

  it('戻り値 state の @context は呼び出し間で別インスタンスになる', () => {
    const key = generateKey();

    const first = createDidWebVh(defaultOptions(key.multikey));
    const second = createDidWebVh(defaultOptions(key.multikey));

    expect(first.logEntry.state['@context']).toEqual(DEFAULT_WEBVH_CONTEXT);
    expect(first.logEntry.state['@context']).not.toBe(second.logEntry.state['@context']);
  });

  it('先行 DID の戻り値 @context への破壊的変更が後続の DID / SCID へ漏れない', () => {
    const key = generateKey();
    const first = createDidWebVh(defaultOptions(key.multikey));
    // 汚染前の DID / versionId を文字列として控える（配列を共有していても値は影響を受けない）。
    const pristine = createDidWebVh(defaultOptions(key.multikey));
    const pristineDid = pristine.did;
    const pristineVersionId = pristine.logEntry.versionId;

    (first.logEntry.state['@context'] as unknown as string[]).push('https://poison.example');
    const second = createDidWebVh(defaultOptions(key.multikey));

    expect(second.logEntry.state['@context']).toEqual(DEFAULT_WEBVH_CONTEXT);
    expect(second.did).toBe(pristineDid);
    expect(second.logEntry.versionId).toBe(pristineVersionId);
  });
});
