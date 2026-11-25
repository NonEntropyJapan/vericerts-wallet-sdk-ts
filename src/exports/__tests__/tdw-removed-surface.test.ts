/**
 * did:tdw / Trust Envelope の公開 API を削除したことの回帰テスト。
 *
 * did:tdw は公式仕様（DIF didwebvh）では did:webvh の v0.4 以前の旧名であり、本 SDK が独自に
 * 持っていた「Trust Envelope 必須の派生メソッド」は公式に存在しない。実装・export を
 * 削除し、`did:tdw:` は未登録メソッド（2002）になった。誤って export を戻すことを防ぐ。
 */

import { describe, expect, it } from 'bun:test';
import * as sdk from '../../index.js';

describe('公開エクスポート: did:tdw の API は公開されない', () => {
  it.each([
    'MethodTdw',
    'createDidTdw',
    'updateDidTdw',
    'resolveDidTdw',
    'parseTdw',
  ])('%s はメインバレルに存在しない', (name) => {
    expect(name in sdk).toBe(false);
  });
});
