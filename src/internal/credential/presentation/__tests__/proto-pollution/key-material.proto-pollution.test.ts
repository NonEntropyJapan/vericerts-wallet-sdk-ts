/**
 * `verifyPresentation` の検証鍵解決が、**データ汚染とアクセサ汚染の両方**に対して同一に
 * 振る舞うことの回帰テスト。
 *
 * `key.publicKeyJwk` と `key.verify` は `Object.prototype` から継承した値を使わない。署名を検証できなければ 3010 となる。
 *
 * 塞いでいる欠陥: 汚染除外を `candidate !== Object.prototype.verify` の**同一性比較**で行うと、
 * `Object.defineProperty(Object.prototype, 'verify', { get() { return () => true; } })` の
 * ように **getter が毎回新しい関数を返す汚染**では別インスタンスとなって一致せず、汚染関数が
 * そのまま検証コールバックに採用される（署名検証の完全バイパス）。プロトタイプ鎖を辿って
 * 「記述子を最初に持つオブジェクトが `Object.prototype` なら不採用」とすることで両形式を塞ぐ。
 *
 * 同時に、`publicKeyJwk` を own 限定で読むと `class KmsKey { get publicKeyJwk() {} }` のような
 * **ゲッタで鍵素材を公開するクラス鍵が無言で 3010 拒否される**非対称性も解消されていることを
 * 正常系として固定する。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { issuePresentation } from '../../issue.js';
import { type PresentationVerifierKey, verifyPresentation } from '../../presentation.js';
import { FIXTURES, sampleVp, signerFor } from '../presentation.fixtures.js';

const fx = FIXTURES.ES256;

/** `verify` を**プロトタイプメソッド**として持つ鍵（KMS / HSM をクラスでラップした統合の縮図）。 */
class MethodVerifierKey {
  constructor(private readonly result: boolean) {}

  verify(_digest: Uint8Array, _signature: Uint8Array, _signingInput: Uint8Array): boolean {
    return this.result;
  }
}

/** `publicKeyJwk` を**プロトタイプのアクセサ**として公開する鍵（鍵素材を遅延取得する統合の縮図）。 */
class GetterJwkKey {
  constructor(private readonly material: PublicKeyJwk) {}

  get publicKeyJwk(): PublicKeyJwk {
    return this.material;
  }
}

/** 汚染モード: 同じ汚染値をデータプロパティ / アクセサの 2 形式で仕込む。 */
const POLLUTION_MODES = [
  {
    label: 'データプロパティ汚染',
    run: <T>(props: Readonly<Record<string, () => unknown>>, fn: () => T): T =>
      withPollutedPrototype(
        Object.fromEntries(Object.entries(props).map(([key, make]) => [key, make()])),
        fn,
      ),
  },
  {
    label: 'アクセサ汚染',
    run: <T>(props: Readonly<Record<string, () => unknown>>, fn: () => T): T =>
      withPollutedPrototypeAccessor(props, fn),
  },
] as const;

/** 常に受理してしまう汚染 `verify`。アクセサ形式では呼ばれるたび別インスタンスを返す。 */
const pollutedVerify = (): unknown => (): boolean => true;
/** 別曲線の汚染 JWK。採用されれば正当な `verify` が無視される。 */
const pollutedJwk = (): unknown => FIXTURES.ES256K.jwk;

/** 例外を投げずに送出値を取り出す。 */
function captureError(fn: () => unknown): unknown {
  try {
    fn();
    return undefined;
  } catch (e: unknown) {
    return e;
  }
}

/** 3010（SIG_INVALID）であることを表明する。 */
function expectSigInvalid(error: unknown): void {
  expect(error).toBeInstanceOf(VericertsError);
  expect((error as VericertsError).code).toBe(ErrorCodes.SIG_INVALID);
}

/** 正当な署名を持つ JWT-VP。 */
function validJwt(): string {
  return issuePresentation(sampleVp(), signerFor('ES256'));
}

/** `verifyPresentation` を unbound モードで呼ぶ。 */
function verifyWith(jwt: string, key: unknown): ReturnType<typeof verifyPresentation> {
  return verifyPresentation(jwt, { key: key as PresentationVerifierKey, allowUnbound: true });
}

for (const mode of POLLUTION_MODES) {
  describe(`verifyPresentation: 鍵解決と ${mode.label}`, () => {
    it('不正な key={} は汚染 verify を検証関数に採用しない（3010）', () => {
      const jwt = validJwt();
      const error = mode.run({ verify: pollutedVerify }, () =>
        captureError(() => verifyWith(jwt, {})),
      );
      expectSigInvalid(error);
    });

    it('不正な key={} は汚染 publicKeyJwk を鍵素材に採用しない（3010）', () => {
      const jwt = validJwt();
      const error = mode.run({ publicKeyJwk: pollutedJwk }, () =>
        captureError(() => verifyWith(jwt, {})),
      );
      expectSigInvalid(error);
    });

    it('正常系: own リテラルの publicKeyJwk 鍵は汚染下でも受理される', () => {
      const jwt = validJwt();
      const result = mode.run({ verify: pollutedVerify }, () =>
        verifyWith(jwt, { publicKeyJwk: fx.jwk }),
      );
      expect(result.presentation.holder).toBe('did:example:holder');
    });

    it('正常系: own リテラルの verify 鍵は汚染 JWK に乗っ取られない', () => {
      // 汚染 JWK（別曲線）が採用されると署名検証が失敗して 3010 になる。
      const jwt = validJwt();
      const result = mode.run({ publicKeyJwk: pollutedJwk }, () =>
        verifyWith(jwt, { verify: () => true }),
      );
      expect(result.presentation.holder).toBe('did:example:holder');
    });

    it('正常系: verify をプロトタイプメソッドに持つクラス鍵は汚染下でも受理される', () => {
      const jwt = validJwt();
      const result = mode.run({ publicKeyJwk: pollutedJwk }, () =>
        verifyWith(jwt, new MethodVerifierKey(true)),
      );
      expect(result.presentation.holder).toBe('did:example:holder');
    });

    it('クラス鍵の verify が false を返せば 3010（戻り値が本当に参照されている）', () => {
      const jwt = validJwt();
      const error = mode.run({ verify: pollutedVerify }, () =>
        captureError(() => verifyWith(jwt, new MethodVerifierKey(false))),
      );
      expectSigInvalid(error);
    });

    it('正常系: publicKeyJwk をゲッタで公開するクラス鍵は汚染下でも受理される', () => {
      const jwt = validJwt();
      const result = mode.run({ verify: pollutedVerify }, () =>
        verifyWith(jwt, new GetterJwkKey(fx.jwk)),
      );
      expect(result.presentation.holder).toBe('did:example:holder');
    });

    it('ゲッタ鍵が別曲線の JWK を返せば 3010（ゲッタの戻り値が本当に使われている）', () => {
      const jwt = validJwt();
      const error = mode.run({ verify: pollutedVerify }, () =>
        captureError(() => verifyWith(jwt, new GetterJwkKey(FIXTURES.ES256K.jwk))),
      );
      expectSigInvalid(error);
    });
  });
}

describe('verifyPresentation: 鍵解決の汚染なし基準線', () => {
  it('正常系: ゲッタ鍵・クラスメソッド鍵は汚染のない環境でも受理される', () => {
    const jwt = validJwt();
    expect(verifyWith(jwt, new GetterJwkKey(fx.jwk)).presentation.holder).toBe(
      'did:example:holder',
    );
    expect(verifyWith(jwt, new MethodVerifierKey(true)).presentation.holder).toBe(
      'did:example:holder',
    );
  });

  it('key={} は汚染のない環境でも 3010', () => {
    expectSigInvalid(captureError(() => verifyWith(validJwt(), {})));
  });
});
