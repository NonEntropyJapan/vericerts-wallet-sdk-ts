/**
 * Wallet Swap に使うパスフレーズの強度検証。
 *
 * エクスポート時は最小 10 文字かつ zxcvbn のスコア 3 以上を要求する。
 *
 * ライブラリ選定: `zxcvbn-ts`（`@zxcvbn-ts/core` + 辞書パッケージ）を採用する。オリジナルの
 * `zxcvbn` は 2017 年以降メンテナンスが止まっており型定義も別パッケージ頼みだが、`zxcvbn-ts` は
 * TypeScript ネイティブ・ESM 対応で継続的にメンテナンスされている後継実装であり、この SDK の
 * ブラウザ/Node 両対応ビルド（`bun build --target browser` / CJS 出力）と親和性が高い。
 */

import { ZxcvbnFactory } from '@zxcvbn-ts/core';
import * as zxcvbnCommonPackage from '@zxcvbn-ts/language-common';
import * as zxcvbnEnPackage from '@zxcvbn-ts/language-en';

/** パスフレーズに要求する zxcvbn スコアの下限。 */
export const MIN_PASSPHRASE_SCORE = 3;

const zxcvbn = new ZxcvbnFactory({
  dictionary: {
    ...zxcvbnCommonPackage.dictionary,
    ...zxcvbnEnPackage.dictionary,
  },
  graphs: zxcvbnCommonPackage.adjacencyGraphs,
  translations: zxcvbnEnPackage.translations,
});

/**
 * パスフレーズが強度要件（zxcvbn スコア >= {@link MIN_PASSPHRASE_SCORE}）を満たすか判定する。
 *
 * @param passphrase 検証対象のパスフレーズ（平文）。
 * @returns 強度要件を満たせば `true`。
 */
export function isPassphraseStrongEnough(passphrase: string): boolean {
  return zxcvbn.check(passphrase).score >= MIN_PASSPHRASE_SCORE;
}
