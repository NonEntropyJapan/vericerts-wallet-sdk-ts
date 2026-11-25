/**
 * HD 鍵導出の `Object.prototype` 汚染耐性テスト。
 *
 * `@scure/bip32@2.2` の `HDKey` コンストラクタは、渡されたオプションを
 * `opt.index` / `opt.depth` / `opt.parentFingerprint` / `opt.publicKey` のように
 * **プロトタイプ鎖経由**で読む。`HDKey.fromMasterSeed` が渡すのは
 * `{ versions, chainCode, privateKey }` という通常のオブジェクトリテラルで、
 * `index` 等を own property として持たないため、`Object.prototype` が汚染されていると
 * 継承値を拾って `HDKey: zero depth with non-zero index/parent fingerprint` 等で失敗する。
 *
 * 結果として、正当な導出パスであっても HD 鍵導出が全面的に停止する（可用性の喪失）。
 * 本テストは汚染下でも導出が成功し、かつ**汚染のない状態と同一の鍵素材**が得られることを担保する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { deriveKeyFromSeed, deriveMasterKey } from '../../hd.js';

// BIP-32 test vector 1 のシード。
const SEED = Uint8Array.from([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
]);
const PATH = "m/44'/60'/0'/0/0";

/** `Object.prototype.then` 汚染を再現する props。 */
const THEN_POLLUTION = {
  // biome-ignore lint/suspicious/noThenProperty: 汚染を再現する意図的な then。
  then: () => undefined,
};

/**
 * `HDKey` コンストラクタがプロトタイプ鎖から拾い得るオプションキーと、その汚染値。
 *
 * 前半は `@scure/bip32@2.2` で**実際に 鍵導出失敗を再現する**ケース（修正前は導出が失敗する）。
 * 後半は修正前でも同一性アサーション自体は通る**防御的**ケースで、将来 @scure 側の
 * 読み取りが変わったときに静かに壊れないよう固定する。
 */
const POLLUTION_CASES: ReadonlyArray<readonly [string, unknown]> = [
  // --- 鍵導出失敗を再現するケース ---
  ['index', 42],
  ['index', 7],
  ['index', 'x'],
  ['parentFingerprint', 3],
  ['publicKey', 3],
  // --- 将来の @scure 変更に備えた防御的ケース ---
  // `depth` は例外にならず、汚染値がノードの depth として採用されるだけ。鍵素材自体は
  // 変わらないため以下の同一性アサーションは修正前でも通る（この行は再発防止の固定用）。
  ['depth', 3],
  // 以下は現行版では own property が渡るため素通りする。
  ['privateKey', 3],
  ['chainCode', 3],
  ['versions', { private: 1, public: 2 }],
];

/** 鍵素材を比較しやすい hex 文字列へ落とす。 */
function fingerprintOf(key: {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  chainCode: Uint8Array;
  derivationPath: string;
}): string {
  const hex = (bytes: Uint8Array): string =>
    Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  return [hex(key.privateKey), hex(key.publicKey), hex(key.chainCode), key.derivationPath].join(
    ':',
  );
}

describe('HD 導出の Object.prototype 汚染耐性', () => {
  const cleanDerived = fingerprintOf(deriveKeyFromSeed(SEED, PATH));
  const cleanMaster = fingerprintOf(deriveMasterKey(SEED));

  for (const [key, value] of POLLUTION_CASES) {
    it(`Object.prototype.${key} = ${JSON.stringify(value)} 汚染下でも deriveKeyFromSeed が同一の鍵を返す`, () => {
      const polluted = withPollutedPrototype({ [key]: value }, () =>
        fingerprintOf(deriveKeyFromSeed(SEED, PATH)),
      );
      expect(polluted).toBe(cleanDerived);
    });

    it(`Object.prototype.${key} = ${JSON.stringify(value)} 汚染下でも deriveMasterKey が同一の鍵を返す`, () => {
      const polluted = withPollutedPrototype({ [key]: value }, () =>
        fingerprintOf(deriveMasterKey(SEED)),
      );
      expect(polluted).toBe(cleanMaster);
    });
  }

  it('Object.prototype.then が関数で汚染されても導出が止まらない', () => {
    // ガードの thenable 判定がプロトタイプ鎖から `then` を読むと、正常な `HDKey` を
    // Promise と誤判定して鍵導出失敗を別キーで再発させる。`then` は `HDKeyOpt` のキーではないため
    // 退避対象にもできず、判定側で断つしかない。
    const polluted = withPollutedPrototype(THEN_POLLUTION, () =>
      fingerprintOf(deriveKeyFromSeed(SEED, PATH)),
    );
    expect(polluted).toBe(cleanDerived);
  });

  it('Object.prototype.then 汚染下でも deriveMasterKey が止まらない', () => {
    const polluted = withPollutedPrototype(THEN_POLLUTION, () =>
      fingerprintOf(deriveMasterKey(SEED)),
    );
    expect(polluted).toBe(cleanMaster);
  });

  it('汚染された then は呼び出されない', () => {
    let called = false;
    withPollutedPrototype(
      {
        // biome-ignore lint/suspicious/noThenProperty: 汚染を再現する意図的な then。
        then: () => {
          called = true;
        },
      },
      () => deriveKeyFromSeed(SEED, PATH),
    );
    expect(called).toBe(false);
  });

  it('複数キーを同時に汚染しても同一の鍵を返す', () => {
    const polluted = withPollutedPrototype(
      { index: 42, depth: 3, parentFingerprint: 9, publicKey: 3 },
      () => fingerprintOf(deriveKeyFromSeed(SEED, PATH)),
    );
    expect(polluted).toBe(cleanDerived);
  });

  it('汚染下でも不正パスは DERIVATION_PATH_INVALID(1040) のままである', () => {
    withPollutedPrototype({ index: 42 }, () => {
      expect(() => deriveKeyFromSeed(SEED, 'm/x')).toThrow(VericertsError);
      try {
        deriveKeyFromSeed(SEED, 'm/x');
        throw new Error('unreachable');
      } catch (e) {
        expect((e as VericertsError).code).toBe(ErrorCodes.DERIVATION_PATH_INVALID);
      }
    });
  });

  it('導出後に汚染された記述子をそのまま復元する', () => {
    withPollutedPrototype({ index: 42 }, () => {
      deriveKeyFromSeed(SEED, PATH);
      const descriptor = Object.getOwnPropertyDescriptor(Object.prototype, 'index');
      expect(descriptor).toEqual({
        value: 42,
        writable: true,
        enumerable: false,
        configurable: true,
      });
    });
  });

  it('導出が例外で終わっても汚染された記述子を復元する', () => {
    withPollutedPrototype({ index: 42 }, () => {
      // 範囲外インデックスで `@scure/bip32` 内部の derive を失敗させる。
      expect(() => deriveKeyFromSeed(SEED, 'm/4294967296')).toThrow(VericertsError);
      const descriptor = Object.getOwnPropertyDescriptor(Object.prototype, 'index');
      expect(descriptor?.value).toBe(42);
    });
  });

  it('削除できない非 configurable な汚染は既知の限界として 1040 で fail-closed する', () => {
    // ガードは `delete` できないプロパティには触れない（strict mode で TypeError になるため）。
    // その場合は修正前と同じく導出が失敗するが、生の Error ではなく必ず 1040 へ正規化されること。
    // 非 configurable なプロパティはもう取り除けずテストプロセス全体を汚染するため、
    // 子プロセスに隔離して検証する。
    const fixture = new URL('./fixtures/non-configurable-pollution.ts', import.meta.url).pathname;
    const proc = Bun.spawnSync(['bun', 'run', fixture]);

    expect(proc.stderr.toString()).toBe('');
    expect(proc.exitCode).toBe(0);
    const result = JSON.parse(proc.stdout.toString().trim()) as {
      deriveKeyFromSeed: unknown;
      deriveMasterKey: unknown;
    };
    expect(result.deriveKeyFromSeed).toBe(ErrorCodes.DERIVATION_PATH_INVALID);
    expect(result.deriveMasterKey).toBe(ErrorCodes.DERIVATION_PATH_INVALID);
  });

  it('汚染がない場合は Object.prototype に own property を残さない', () => {
    deriveKeyFromSeed(SEED, PATH);
    for (const key of ['index', 'depth', 'parentFingerprint', 'publicKey', 'privateKey']) {
      expect(Object.hasOwn(Object.prototype, key)).toBe(false);
    }
  });
});
