/**
 * OID4VP の response_mode 定数を公開バレルから参照できることを確認する。
 * 内部の提示処理だけをテストすると、利用者が使う RESPONSE_MODE_DIRECT_POST_JWT の公開漏れを検知できない。
 */

import { describe, expect, test } from 'bun:test';
import * as sdk from '../../index.js';

describe('公開エクスポート: OID4VP response_mode 定数', () => {
  test('RESPONSE_MODE_DIRECT_POST が SDK エントリポイントから import できる', () => {
    expect(sdk.RESPONSE_MODE_DIRECT_POST).toBe('direct_post');
  });

  test('RESPONSE_MODE_DIRECT_POST_JWT が SDK エントリポイントから import できる', () => {
    // direct_post と同格の response_mode であるにもかかわらず、公開バレルから欠落していた。
    expect(sdk.RESPONSE_MODE_DIRECT_POST_JWT).toBe('direct_post.jwt');
  });
});
