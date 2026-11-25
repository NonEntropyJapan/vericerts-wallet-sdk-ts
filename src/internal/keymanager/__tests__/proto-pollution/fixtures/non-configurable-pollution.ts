/**
 * 非 configurable な `Object.prototype` 汚染下での HD 導出の挙動を報告する子プロセス用スクリプト。
 *
 * 非 configurable なプロパティは後から削除もできず、テストプロセス全体を恒久的に汚染してしまう。
 * そのため親のテストからは切り離し、結果だけを JSON で標準出力へ返す。
 */

import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { deriveKeyFromSeed, deriveMasterKey } from '../../../hd.js';

const SEED = Uint8Array.from([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
]);
const PATH = "m/44'/60'/0'/0/0";

// ガードが取り除けない形の汚染を仕込む。
Object.defineProperty(Object.prototype, 'index', { value: 42, configurable: false });

/** 呼び出し結果を「VericertsError のコード」か診断用の文字列へ落とす。 */
function outcomeOf(fn: () => unknown): unknown {
  try {
    fn();
    return 'no-throw';
  } catch (e) {
    return e instanceof VericertsError ? e.code : `raw:${(e as Error).name}`;
  }
}

process.stdout.write(
  JSON.stringify({
    deriveKeyFromSeed: outcomeOf(() => deriveKeyFromSeed(SEED, PATH)),
    deriveMasterKey: outcomeOf(() => deriveMasterKey(SEED)),
    expected: ErrorCodes.DERIVATION_PATH_INVALID,
  }),
);
