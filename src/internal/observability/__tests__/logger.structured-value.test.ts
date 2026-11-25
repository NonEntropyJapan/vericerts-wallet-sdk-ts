/**
 * ログ属性の値から JWT / SD-JWT / COSE を検出し、ヘッダーを残してペイロードを
 * `[REDACTED]` に置き換えることを検証する。
 *
 * 検証内容:
 * 1. キー名規則に当たらない属性でも、値が JWT / SD-JWT / COSE なら payload が落ちる。
 * 2. 誤検知しない（バージョン文字列・ドメイン名・非 COSE のバイト列などは素通し）。
 * 3. どんな入力でも例外を投げない（マスキングは強制ポリシーであり失敗が許されない）。
 * 4. キー名規則が当たる属性の結果は従来どおり（値規則が上書きしない）。
 *
 * `logger.test.ts` は キー名規則を担当し、本ファイルは値規則を担当する
 * （1 ファイルの行数上限を超えないための分割）。
 */

import { describe, expect, it } from 'bun:test';
import { base64nopad, base64urlnopad, hex } from '@scure/base';
import type { LogAttributes, Logger } from '../logger.js';
import { createLogger, maskLogAttributes } from '../logger.js';

/** テキストを padding なし base64url へ（JOSE の各セグメントの表記）。 */
function segment(text: string): string {
  return base64urlnopad.encode(new TextEncoder().encode(text));
}

const JWT_HEADER = segment('{"alg":"ES256","typ":"JWT"}');
const JWT = `${JWT_HEADER}.${segment('{"iss":"did:key:z6Mk"}')}.${segment('signature-bytes')}`;
const REDACTED_JWT = `${JWT_HEADER}.[REDACTED]`;
const DISCLOSURE = segment('["salt","given_name","Alice"]');
const KB_JWT = `${segment('{"typ":"kb+jwt"}')}.${segment('{"aud":"rp"}')}.${segment('kb-sig')}`;

/** 複数のバイト列を連結する。 */
function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** CBOR byte string（長さ 24 以上は additional information 24 の 2 バイト head になる）。 */
function cborByteString(payload: Uint8Array): Uint8Array {
  const head =
    payload.length <= 23
      ? Uint8Array.of(0x40 | payload.length)
      : Uint8Array.of(0x58, payload.length);
  return concat(head, payload);
}

/**
 * COSE_Sign1 相当の 4 要素 CBOR 配列を組み立てる。
 * `84`（array(4)）/ `43 a10126`（protected `{1:-7}`）/ `a0`（unprotected `{}`）/ payload / `4199`（署名）。
 */
function coseSign1(payload: Uint8Array): Uint8Array {
  return concat(
    Uint8Array.of(0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0),
    cborByteString(payload),
    Uint8Array.of(0x41, 0x99),
  );
}

/** 差し替え後の payload（`[REDACTED]` の UTF-8 バイト列）。 */
const REDACTED_PAYLOAD = new TextEncoder().encode('[REDACTED]');

/** base64 で `+` / `/`、base64url で `-` / `_` が現れる payload（基数判定を一意にするため）。 */
const SIGN_SENSITIVE_PAYLOAD = Uint8Array.of(0xff, 0xef, 0xbe);

/** 呼び出しを 1 件だけ記録するロガーを注入した SDK 内部用ロガー。 */
function setup(): { log: Logger; attrs: () => LogAttributes } {
  const logs: (LogAttributes | undefined)[] = [];
  const sink: Logger = {
    debug: () => {},
    info: (_message: string, attrs?: LogAttributes) => {
      logs.push(attrs);
    },
    warn: () => {},
    error: () => {},
    child: () => sink,
  };
  return {
    log: createLogger(sink),
    attrs: () => {
      expect(logs.length).toBe(1);
      return logs[0] as LogAttributes;
    },
  };
}

describe('JWT / SD-JWT / COSE 値の構造検出', () => {
  it('キー名規則に当たらない属性でも JWT なら payload を落とす', () => {
    const { log, attrs } = setup();

    log.info('m', { token: JWT });

    expect(attrs()).toEqual({ token: REDACTED_JWT });
  });

  it('ネストしたオブジェクト・配列要素の JWT も落とす', () => {
    const { log, attrs } = setup();

    log.info('m', { request: { assertion: JWT }, batch: [JWT, 'plain'] });

    expect(attrs()).toEqual({
      request: { assertion: REDACTED_JWT },
      batch: [REDACTED_JWT, 'plain'],
    });
  });

  it('SD-JWT（末尾 `~`・KB-JWT なし）は issuer JWT の header だけ残す', () => {
    const { log, attrs } = setup();

    log.info('m', { token: `${JWT}~${DISCLOSURE}~${DISCLOSURE}~` });

    expect(attrs()).toEqual({ token: REDACTED_JWT });
  });

  it('SD-JWT（KB-JWT あり）も issuer JWT の header だけ残す', () => {
    const { log, attrs } = setup();

    log.info('m', { token: `${JWT}~${DISCLOSURE}~${KB_JWT}` });

    expect(attrs()).toEqual({ token: REDACTED_JWT });
  });

  it('hex の COSE は payload だけが差し替わり header と署名は元のまま', () => {
    const { log, attrs } = setup();

    log.info('m', { token: hex.encode(coseSign1(Uint8Array.of(0x01, 0x02, 0x03))) });

    expect(attrs()).toEqual({ token: hex.encode(coseSign1(REDACTED_PAYLOAD)) });
  });

  it('24 バイト以上の payload（2 バイト head）でも差し替えられる', () => {
    const { log, attrs } = setup();
    const payload = new Uint8Array(24).fill(0x2a);

    log.info('m', { token: hex.encode(coseSign1(payload)) });

    expect(attrs()).toEqual({ token: hex.encode(coseSign1(REDACTED_PAYLOAD)) });
  });

  it('base64 の COSE は base64 のまま返る', () => {
    const { log, attrs } = setup();
    const encoded = base64nopad.encode(coseSign1(SIGN_SENSITIVE_PAYLOAD));

    expect(encoded).toContain('/');
    log.info('m', { token: encoded });

    expect(attrs()).toEqual({ token: base64nopad.encode(coseSign1(REDACTED_PAYLOAD)) });
  });

  it('base64url の COSE は base64url のまま返る', () => {
    const { log, attrs } = setup();
    const encoded = base64urlnopad.encode(coseSign1(SIGN_SENSITIVE_PAYLOAD));

    expect(encoded).toContain('_');
    log.info('m', { token: encoded });

    expect(attrs()).toEqual({ token: base64urlnopad.encode(coseSign1(REDACTED_PAYLOAD)) });
  });

  it('detached payload（CBOR `null`）の COSE は落とす中身がないので触らない', () => {
    const detached = '8443a10126a0f64199';

    expect(maskLogAttributes({ token: detached })).toEqual({ token: detached });
  });

  it('unprotected header を深く入れ子にした COSE も payload が漏れず値ごと [REDACTED] になる（fail-closed）', () => {
    // `84` / protected `40` / unprotected `{0: [[[…]]]}`（入れ子 N 段）/ payload / 署名。
    const secret = Uint8Array.of(0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03);
    for (const depth of [100, 5000, 200000]) {
      const cose = concat(
        Uint8Array.of(0x84, 0x40, 0xa1, 0x00),
        new Uint8Array(depth).fill(0x81),
        Uint8Array.of(0x80),
        cborByteString(secret),
        Uint8Array.of(0x41, 0x99),
      );
      const encoded = hex.encode(cose);

      const masked = maskLogAttributes({ token: encoded }) as { token: string };

      expect(masked.token).toBe('[REDACTED]');
      expect(masked.token).not.toContain(hex.encode(secret));
    }
  });

  it('許容深さ内の入れ子を持つ COSE は payload だけが差し替わる', () => {
    const secret = Uint8Array.of(0xde, 0xad, 0xbe, 0xef);
    const cose = (payload: Uint8Array): Uint8Array =>
      concat(
        Uint8Array.of(0x84, 0x40, 0xa1, 0x00),
        new Uint8Array(10).fill(0x81),
        Uint8Array.of(0x80),
        cborByteString(payload),
        Uint8Array.of(0x41, 0x99),
      );

    expect(maskLogAttributes({ token: hex.encode(cose(secret)) })).toEqual({
      token: hex.encode(cose(REDACTED_PAYLOAD)),
    });
  });
});

describe('値の構造検出の誤検知防止', () => {
  const untouched: readonly [string, string][] = [
    ['バージョン文字列', '1.20.3'],
    ['ドメイン風の文字列', 'sdk.internal.example'],
    ['数字だけの 3 セグメント', '12.34.56'],
    ['header が JSON にならない 3 セグメント', 'aGVsbG8.aGVsbG8.aGVsbG8'],
    ['先頭が JWT でない `~` 区切り', 'not-a-jwt~abc~def'],
    ['奇数長の hex', 'abcde'],
    ['4 要素でない CBOR 配列', '83010203'],
    ['payload が bstr でも null でもない CBOR 配列', '8443a10126a0014199'],
    ['空文字列', ''],
    ['ドットだけ', '.'],
    ['チルダだけ', '~'],
  ];

  for (const [label, value] of untouched) {
    it(`${label}はマスクしない`, () => {
      expect(maskLogAttributes({ token: value })).toEqual({ token: value });
    });
  }

  it('キー名規則が当たる属性は従来どおり値ごと [REDACTED] になる', () => {
    const { log, attrs } = setup();

    log.info('m', { credentialSubject: JWT, portrait: JWT, userMnemonic: JWT });

    expect(attrs()).toEqual({ credentialSubject: '[REDACTED]', portrait: '[REDACTED]' });
  });
});

describe('値の構造検出は例外を投げない', () => {
  const adversarial: readonly string[] = [
    // 長さだけ巨大を名乗る byte string（本体が足りない）。
    '845affffffff',
    // 8 バイト引数で安全整数を超える長さを名乗る配列。
    '9bffffffffffffffff',
    // 極端に深い入れ子（スタック不足になっても外へ例外を出さない）。
    `84${'81'.repeat(50000)}`,
    // 途中で切れた JWT。
    `${JWT_HEADER}.`,
    `${JWT_HEADER}.${JWT_HEADER}`,
    // `~` だけが並ぶ SD-JWT もどき。
    '~~~~',
    // padding だけ / 記号混在。
    '====',
    'aa==bb',
  ];

  for (const value of adversarial) {
    it(`不正な候補文字列でも落ちない: ${value.slice(0, 24)}`, () => {
      const log = createLogger(undefined);

      expect(() => {
        log.info('m', { token: value });
      }).not.toThrow();
    });
  }
});

describe('maskLogAttributes（値の構造検出）', () => {
  it('入力オブジェクトを書き換えず新しいオブジェクトを返す', () => {
    const input: LogAttributes = { token: JWT, nested: { token: JWT } };

    const masked = maskLogAttributes(input);

    expect(masked).toEqual({ token: REDACTED_JWT, nested: { token: REDACTED_JWT } });
    expect(input).toEqual({ token: JWT, nested: { token: JWT } });
  });
});
