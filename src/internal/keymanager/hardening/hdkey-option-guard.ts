/**
 * `@scure/bip32` の `HDKey` 生成を `Object.prototype` 汚染から隔離するガード。
 *
 * ## 背景
 *
 * `@scure/bip32@2.2` の `HDKey` コンストラクタは、渡されたオプションオブジェクトを
 * **プロトタイプ鎖経由**で読む（`Object.hasOwn` で own property に限定していない）:
 *
 * ```js
 * this.depth = opt.depth || 0;
 * this.index = opt.index || 0;
 * this.parentFingerprint = opt.parentFingerprint || 0;
 * if (!this.depth && (this.parentFingerprint || this.index)) throw new Error(...);
 * if (opt.publicKey && opt.privateKey) throw new Error(...);
 * ```
 *
 * 一方 `HDKey.fromMasterSeed` が渡すのは `{ versions, chainCode, privateKey }` という
 * 通常のオブジェクトリテラルであり、`index` / `depth` / `parentFingerprint` / `publicKey` を
 * own property として持たない。したがって `Object.prototype` にこれらのキーが仕込まれていると
 * 継承値が読まれ、**正当な導出パスでもマスター鍵の生成そのものが失敗する**
 * （`HDKey: zero depth with non-zero index/parent fingerprint` 等）。
 * 挙動は fail-closed（誤った鍵を返すのではなく拒否する）だが、HD 鍵導出・ペルソナ作成・
 * Wallet 初期化が全面的に停止するため可用性が失われる。
 *
 * ## この実装方式を選んだ理由
 *
 * 汚染の影響を受けるオブジェクトリテラルは `@scure/bip32` の**内部**で生成されるため、
 * 呼び出し側から own property を注入することも、`Object.create(null)` 由来の
 * プロトタイプなしオプションを渡すこともできない。ライブラリを fork せずに直せる箇所は、
 * 「ライブラリを呼んでいる同期区間だけ `Object.prototype` の該当キーを退避しておく」
 * という一点に限られる。
 *
 * `hmac(sha512, 'Bitcoin seed', seed)` からマスター鍵素材を自前で計算して
 * プロトタイプなしのオプションで `new HDKey()` を呼ぶ案もあるが、
 * BIP-32 の暗号処理をライブラリと二重に実装することになるため採用しない。
 *
 * ## 安全性の前提
 *
 * - `fn` は**同期**でなければならない。グローバル状態を一時的に書き換えるため、
 *   区間内で await すると他のコードが汚染の外れた `Object.prototype` を観測し得る。
 * - 退避したプロパティは記述子ごと `finally` で必ず復元する。`fn` が投げても復元される。
 * - 非 configurable なプロパティは削除できない（strict mode では `delete` が TypeError）。
 *   その場合は触らずに素通しするため、従来どおり fail-closed で失敗する。
 *
 * ## 上流報告
 *
 * 根本原因は本リポジトリではなく `@scure/bip32` 側にあるため、上流へ報告した:
 * https://github.com/paulmillr/scure-bip32/issues/29 。
 *
 * 最新リリース（2.4.0, 2026-09 時点）でも `HDKey` コンストラクタは `opt.depth` /
 * `opt.index` / `opt.parentFingerprint` / `opt.publicKey` / `opt.versions` を
 * `Object.hasOwn` を介さず直接読んでおり、`fromMasterSeed` / `derive` 内部の
 * `new HDKey(opt)` 再構築も同じ形の素のオブジェクトリテラルを渡すため、
 * 依然としてプロトタイプ鎖経由の読み取りに晒される（未修正を実機で再確認済み）。
 * 上流 issue がクローズされ、修正がリリースされたバージョンに `package.json` の
 * `@scure/bip32` を上げるまで、このガードは撤去できない。
 */

import { toBareDescriptor } from '../../prototype-safety/define-data-property.js';
import { nonObjectPrototypeProperty } from '../../prototype-safety/own-property.js';

/**
 * `HDKey` のコンストラクタがプロトタイプ鎖から読み得るオプションキー。
 *
 * `@scure/bip32@2.2` の `HDKeyOpt` の全フィールドを対象にする。内訳:
 *
 * - `index` / `depth` / `parentFingerprint`: `fromMasterSeed` が渡すリテラルに own property が
 *   なく、実際に鍵導出を妨げるキー。
 * - `publicKey` / `privateKey`: 生成経路によって**片方しか own property で渡されない**
 *   （`fromMasterSeed` は `privateKey` のみ、公開鍵ノードは `publicKey` のみ）。
 *   欠けている側が汚染されると `publicKey && privateKey` の同時指定と誤判定されるため必須。
 * - `versions` / `chainCode`: 現行バージョンでは全経路が own property で渡すため実害はないが、
 *   将来 @scure 側が省略に変えたときに静かに壊れないよう防御的に含める。
 */
const HDKEY_OPTION_KEYS: readonly string[] = [
  'versions',
  'depth',
  'index',
  'parentFingerprint',
  'chainCode',
  'publicKey',
  'privateKey',
];

/**
 * `value` が thenable（`then` メソッドを持つ）かを、`Object.prototype` 汚染に惑わされずに判定する。
 *
 * 素朴に `value.then` を読むとプロトタイプ鎖を辿るため、`Object.prototype.then` が関数で
 * 汚染された環境では**正常な `HDKey` インスタンスまで Promise と誤判定**され、
 * 本ガードが `TypeError` を投げて `hd.ts` がそれを 1040 へ正規化してしまう。
 * つまり プロトタイプ汚染による HD 導出の停止を `then` という別のキーで再発させる。
 * `then` は `HDKeyOpt` のキーではないため退避対象にも含められない。
 *
 * そこで `nonObjectPrototypeProperty` で「`then` の記述子を最初に持つオブジェクトが
 * `Object.prototype` 自身なら未指定とみなす」判定を使う。
 * 本物の Promise は `Promise.prototype` に `then` を持つため誤検知しない。
 *
 * @param value 判定対象。
 * @returns `Object.prototype` 由来でない `then` メソッドを持つなら `true`。
 */
function isThenable(value: unknown): boolean {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) {
    return false;
  }
  return typeof nonObjectPrototypeProperty(value as object, 'then') === 'function';
}

/**
 * `Object.prototype` から `HDKey` オプション相当のキーを一時的に取り除いた状態で `fn` を実行する。
 *
 * 退避したプロパティは `fn` の成否にかかわらず、元の記述子のまま復元する。
 *
 * @param fn `@scure/bip32` を呼ぶ**同期**処理。
 * @returns `fn` の戻り値。
 */
export function withoutHDKeyOptionPollution<T>(fn: () => T): T {
  const proto = Object.prototype as unknown as Record<string, unknown>;
  const saved: Array<readonly [string, PropertyDescriptor]> = [];

  for (const key of HDKEY_OPTION_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(proto, key);
    // 未汚染なら何もしない。非 configurable は削除できないため触らない。
    if (descriptor === undefined || descriptor.configurable !== true) {
      continue;
    }
    saved.push([key, descriptor]);
    delete proto[key];
  }

  try {
    const result = fn();
    // 非同期処理を渡されると `finally` の復元が await より先に走り、実際の
    // `@scure/bip32` 呼び出しは汚染下で実行されてしまう。黙って壊れるより落とす。
    if (isThenable(result)) {
      // 誤用で作られた Promise が reject 済み/後で reject されると、誰も待たないまま
      // unhandledRejection としてプロセスを落とし得る。握り潰してから誤用を報告する。
      // `.catch` を持たない素の thenable でも扱えるよう `Promise.resolve` を通す
      // （`Promise.resolve` は thenable に then を繋ぐので元の値も handled になる）。
      // 意図的に捨てる: 報告する失敗は直下の `TypeError`（誤用）で、握り潰す Promise の理由は誤用の副産物。
      void Promise.resolve(result as unknown as PromiseLike<unknown>).catch(() => undefined);
      throw new TypeError('withoutHDKeyOptionPollution: fn must be synchronous');
    }
    return result;
  } finally {
    for (const [key, descriptor] of saved) {
      // 1 キーの復元に失敗しても残りの復元を続ける。ここで例外を投げると
      // `Object.prototype` を削除したまま区間を抜け、汚染どころか
      // 元々あったプロパティを恒久的に壊してしまう。
      try {
        // 退避した記述子もエンジン生成の通常オブジェクトで `Object.prototype` を継承する。
        // そのまま渡すと、区間中に別のコードが `Object.prototype.get` を汚染していた場合に
        // 「データ記述子にアクセサが見える」と解釈されて `defineProperty` が TypeError を
        // 投げ、**復元に失敗する**。`null` プロトタイプの複製へ写してから復元する。
        Object.defineProperty(proto, key, toBareDescriptor(descriptor));
      } catch {
        // 復元不能（`Object.prototype` が凍結された等）。区間外へは漏らさない。
      }
    }
  }
}
