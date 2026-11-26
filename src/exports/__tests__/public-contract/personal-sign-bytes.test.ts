/**
 * `personal_sign` のバイト列正規化の公開契約。`@vericerts/vericerts-wallet-sdk/asset` から引いた
 * 公開面だけで、署名・承認前ガード・表示の 3 経路が同じバイト列を読むことを固定する。
 * 内部パス経由では「公開したつもりの面」が通っているかを確かめられないので `../../asset.js` を使う。
 */

import { afterEach, beforeEach, describe, expect, spyOn, test } from 'bun:test';
import { personalSignMessageBytes as personalSignMessageBytesImpl } from '../../../internal/asset/personal-sign-message.js';
import { ErrorCodes } from '../../../internal/errors.js';
import {
  resetExperimentalWarnings,
  SUPPRESS_EXPERIMENTAL_WARNINGS_ENV,
} from '../../../internal/experimental-warning.js';
import {
  assertPersonalSignAllowed,
  personalSignMessageBytes,
  personalSignPayload,
} from '../../asset.js';

// 不可視文字を直書きしないよう、BOM（U+FEFF）は定数で明示する。
const BOM = String.fromCharCode(0xfeff);
const utf8 = (text: string) => new TextEncoder().encode(text);
const segment = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const jws = (header: Record<string, unknown>) =>
  `${segment({ alg: 'ES256K-R', ...header })}.${segment({ iss: 'did:pkh:eip155:1:0xabc' })}`;
const toHex = (text: string) => `0x${Buffer.from(text).toString('hex')}`;

// Issue が指定する 6 入力と期待バイト列（値で固定する）。
const CASES: ReadonlyArray<readonly [string, string, Uint8Array]> = [
  ['空 0x', '0x', new Uint8Array()],
  ['奇数桁', '0xabc', utf8('0xabc')],
  ['大文字 0X は hex と見なさない', '0X68656c6c6f', utf8('0X68656c6c6f')],
  ['BOM 付き hex は BOM を落とさない', '0xefbbbf62', new Uint8Array([0xef, 0xbb, 0xbf, 0x62])],
  ['BOM 付き平文', `${BOM}hello`, new Uint8Array([0xef, 0xbb, 0xbf, ...utf8('hello')])],
  ['不正 UTF-8 の hex', '0xff', new Uint8Array([0xff])],
];

const ALL_INPUTS = [
  ...CASES.map(([, data]) => data),
  'Hello',
  '0x68656c6c6f',
  jws({ kid: 'k' }),
  toHex(jws({ kid: 'k' })),
  jws({ pad: 'A'.repeat(6000) }),
];

const outcome = (run: () => unknown) => {
  try {
    run();
    return 'ok';
  } catch (error) {
    return (error as { code?: number }).code;
  }
};

describe('公開契約: personalSignMessageBytes（@vericerts/vericerts-wallet-sdk/asset）', () => {
  test.each(CASES)('%s', (_name, data, expected) => {
    expect([...personalSignMessageBytes(data)]).toEqual([...expected]);
  });

  test('署名対象は同じバイト列に EIP-191 prefix を付けたものと一致する（署名との同一性）', () => {
    for (const data of ALL_INPUTS.filter(
      (input) => outcome(() => personalSignPayload(input)) === 'ok',
    )) {
      const message = personalSignMessageBytes(data);
      const prefix = utf8(`\x19Ethereum Signed Message:\n${message.length}`);
      expect([...personalSignPayload(data)]).toEqual([...prefix, ...message]);
    }
  });

  test('assertPersonalSignAllowed は personalSignPayload と常に同じ入力を拒否する（承認前ガードとの同一性）', () => {
    for (const data of ALL_INPUTS) {
      expect(outcome(() => assertPersonalSignAllowed(data))).toBe(
        outcome(() => personalSignPayload(data)),
      );
    }
  });

  test('JWS signing-input は素のままでも hex 化しても水増しヘッダでも SIGN_FAILED で拒否する', () => {
    for (const input of [jws({ kid: 'k' }), jws({ pad: 'A'.repeat(6000) })]) {
      for (const data of [input, toHex(input)]) {
        expect(outcome(() => assertPersonalSignAllowed(data))).toBe(ErrorCodes.SIGN_FAILED);
      }
    }
  });

  test('不正 UTF-8 は表示経路のデコードが拒否する（表示との同一性）', () => {
    const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    expect(() => decoder.decode(personalSignMessageBytes('0xff'))).toThrow();
  });

  test('表示経路の UTF-8 デコードは hex 入力でも平文入力と同じ文字列になる（表示との同一性）', () => {
    const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    for (const text of ['hello', `${BOM}hello`, '日本語 🔑']) {
      expect(decoder.decode(personalSignMessageBytes(toHex(text)))).toBe(text);
      expect(decoder.decode(personalSignMessageBytes(text))).toBe(text);
    }
  });
});

describe('公開契約: personalSignMessageBytes のランタイム警告', () => {
  let warn: ReturnType<typeof spyOn<Console, 'warn'>>;
  let savedSuppression: string | undefined;

  beforeEach(() => {
    resetExperimentalWarnings();
    savedSuppression = process.env[SUPPRESS_EXPERIMENTAL_WARNINGS_ENV];
    delete process.env[SUPPRESS_EXPERIMENTAL_WARNINGS_ENV];
    warn = spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    warn.mockRestore();
    resetExperimentalWarnings();
    if (savedSuppression === undefined) delete process.env[SUPPRESS_EXPERIMENTAL_WARNINGS_ENV];
    else process.env[SUPPRESS_EXPERIMENTAL_WARNINGS_ENV] = savedSuppression;
  });

  test('/asset の personalSignMessageBytes は公開呼び出しの初回だけ警告する', () => {
    const data = '0x61';
    const bytes = personalSignMessageBytesImpl(data);
    assertPersonalSignAllowed(data);
    personalSignPayload(data);
    expect(warn).not.toHaveBeenCalled();

    expect(personalSignMessageBytes(data)).toEqual(bytes);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0]?.[0])).toContain(
      '`personalSignMessageBytes` is @experimental',
    );
    expect(personalSignMessageBytes(data)).toEqual(bytes);
    expect(warn).toHaveBeenCalledTimes(1);

    resetExperimentalWarnings();
    warn.mockClear();
    expect(personalSignMessageBytes(data)).toEqual(bytes);
    expect(warn).toHaveBeenCalledTimes(1);
  });

  test('環境変数を読めなくても初回に警告を試み、正規化する', () => {
    const processDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'process');
    if (processDescriptor === undefined) throw new Error('missing test runner process');
    let envReads = 0;
    const restrictedProcess = {
      versions: { node: '24.22.1' },
      get env() {
        envReads += 1;
        throw new Error('environment access denied');
      },
    };
    Object.defineProperty(globalThis, 'process', { configurable: true, value: restrictedProcess });
    let first: Uint8Array;
    let second: Uint8Array;
    try {
      first = personalSignMessageBytes('0x61');
      second = personalSignMessageBytes('b');
    } finally {
      Object.defineProperty(globalThis, 'process', processDescriptor);
    }
    expect([...first]).toEqual([0x61]);
    expect([...second]).toEqual([0x62]);
    expect(envReads).toBe(1);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0]?.[0])).toContain(
      '`personalSignMessageBytes` is @experimental',
    );
  });

  test('警告の出力に失敗しても正規化し、警告を再試行しない', () => {
    warn.mockImplementation(() => {
      throw new Error('warning output failed');
    });

    expect([...personalSignMessageBytes('0x61')]).toEqual([0x61]);
    expect([...personalSignMessageBytes('b')]).toEqual([0x62]);
    expect(warn).toHaveBeenCalledTimes(1);
  });

  test('警告出力の失敗後も、正規化そのものの例外は伝播する', () => {
    warn.mockImplementation(() => {
      throw new Error('warning output failed');
    });
    const invalid = Symbol() as unknown as string;
    expect(() => personalSignMessageBytesImpl(invalid)).toThrow(TypeError);
    expect(() => personalSignMessageBytes(invalid)).toThrow(TypeError);
  });

  test('process が無い、または警告の共有記録を作れない環境でも正規化は動く', () => {
    const processDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'process');
    if (processDescriptor === undefined) throw new Error('missing test runner process');

    const nodeVersions = { node: '24.22.1' };
    const marker = Symbol.for('vericerts-wallet-sdk:experimental-warning:personalSignMessageBytes');
    let getterCalls = 0;
    const hosts = [
      undefined,
      { versions: {} },
      Object.freeze({ versions: nodeVersions }),
      {
        versions: nodeVersions,
        get [marker]() {
          getterCalls += 1;
          return true;
        },
      },
    ];
    for (const host of hosts) {
      resetExperimentalWarnings();
      warn.mockClear();
      const originalMarker = host && Object.getOwnPropertyDescriptor(host, marker);
      Object.defineProperty(globalThis, 'process', { configurable: true, value: host });
      let first: Uint8Array;
      let second: Uint8Array;
      try {
        first = personalSignMessageBytes('0x61');
        second = personalSignMessageBytes('b');
      } finally {
        Object.defineProperty(globalThis, 'process', processDescriptor);
      }

      expect([...first]).toEqual([0x61]);
      expect([...second]).toEqual([0x62]);
      expect(warn).toHaveBeenCalledTimes(1);
      expect(host && Object.getOwnPropertyDescriptor(host, marker)).toEqual(originalMarker);
    }
    expect(getterCalls).toBe(0);
  });
});
