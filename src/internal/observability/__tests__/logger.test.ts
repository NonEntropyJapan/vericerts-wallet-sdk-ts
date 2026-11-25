/**
 * `createLogger` / `maskLogAttributes` の単位テスト。
 *
 * 検証内容:
 * 1. 未注入時（`createLogger(undefined)`）は no-op として例外なく呼べる。
 * 2. PII マスキングが、注入されたロガーへ渡る**前に**強制適用される
 *    （削除 / `[REDACTED]` / `sha256` 先頭 8 桁 / 素通しの 4 経路と、ネストへの再帰）。
 * 3. `child(bindings)` の束縛が出力時にマージされ、衝突時は呼び出し側属性が勝つ。
 */

import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import type { LogAttributes, Logger } from '../logger.js';
import { createLogger, maskLogAttributes } from '../logger.js';

/** 記録したログ 1 件。 */
interface RecordedLog {
  readonly level: 'debug' | 'info' | 'warn' | 'error';
  readonly message: string;
  readonly attrs: LogAttributes | undefined;
}

/** 呼び出しを配列に貯めるだけのロガー（注入先の代役）。 */
function recordingLogger(): { sink: Logger; logs: RecordedLog[] } {
  const logs: RecordedLog[] = [];
  const record =
    (level: RecordedLog['level']) =>
    (message: string, attrs?: LogAttributes): void => {
      logs.push({ level, message, attrs });
    };
  const sink: Logger = {
    debug: record('debug'),
    info: record('info'),
    warn: record('warn'),
    error: record('error'),
    // ラッパ側が束縛をマージするため、注入先の `child` は呼ばれない。
    child: () => sink,
  };
  return { sink, logs };
}

/** 記録用ロガーを注入した SDK 内部用ロガーを組み立てる。 */
function setup(): { log: Logger; logs: RecordedLog[] } {
  const { sink, logs } = recordingLogger();
  return { log: createLogger(sink), logs };
}

/** テスト対象と独立に期待値（`sha256` hex 先頭 8 桁）を計算する。 */
function expectedHash(value: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(value))).slice(0, 8);
}

/** 1 件だけ記録されている前提でその属性を取り出す。 */
function onlyAttrs(logs: readonly RecordedLog[]): LogAttributes {
  expect(logs.length).toBe(1);
  const attrs = logs[0]?.attrs;
  expect(attrs).toBeDefined();
  return attrs as LogAttributes;
}

describe('createLogger（未注入時の no-op）', () => {
  it('4 レベルと child 経由の出力がいずれも例外を投げない', () => {
    const log = createLogger(undefined);

    expect(() => {
      log.debug('d', { a: 1 });
      log.info('i');
      log.warn('w', { mnemonic: 'secret' });
      log.error('e', { error_code: '2002' });
      log.child({ component: 'sdk.did' }).info('nested', { operation: 'did.resolve' });
    }).not.toThrow();
  });
});

describe('createLogger（注入時の PII マスキング）', () => {
  it('*mnemonic* / *privateKey* / *pin* を含むキーはキーごと落とす', () => {
    const { log, logs } = setup();

    log.info('m', {
      userMnemonic: 'abandon abandon',
      walletPrivateKey: '0xdead',
      pinCode: '1234',
      component: 'sdk.did',
    });

    expect(onlyAttrs(logs)).toEqual({ component: 'sdk.did' });
  });

  it('credentialSubject を含むキーは [REDACTED] にする（中身へは踏み込まない）', () => {
    const { log, logs } = setup();

    log.info('m', {
      credentialSubject: { name: 'Alice' },
      vcCredentialSubjectSnapshot: { name: 'Bob' },
    });

    expect(onlyAttrs(logs)).toEqual({
      credentialSubject: '[REDACTED]',
      vcCredentialSubjectSnapshot: '[REDACTED]',
    });
  });

  it('portrait / document_number は [REDACTED] にする', () => {
    const { log, logs } = setup();

    log.info('m', { portrait: 'base64...', document_number: 'P1234567' });

    expect(onlyAttrs(logs)).toEqual({ portrait: '[REDACTED]', document_number: '[REDACTED]' });
  });

  it('email / phone / address / ssn は sha256 の先頭 8 桁にする', () => {
    const { log, logs } = setup();

    log.info('m', {
      email: 'alice@example.com',
      phone: '+81-90-0000-0000',
      address: '0xabc',
      ssn: '123-45-6789',
    });

    expect(onlyAttrs(logs)).toEqual({
      email: expectedHash('alice@example.com'),
      phone: expectedHash('+81-90-0000-0000'),
      address: expectedHash('0xabc'),
      ssn: expectedHash('123-45-6789'),
    });
  });

  it('ハッシュ対象キーの値が文字列でなければ [REDACTED] にする', () => {
    const { log, logs } = setup();

    log.info('m', { email: { primary: 'alice@example.com' }, phone: 42 });

    expect(onlyAttrs(logs)).toEqual({ email: '[REDACTED]', phone: '[REDACTED]' });
  });

  it('対象外のキーはそのまま素通しする', () => {
    const { log, logs } = setup();

    log.info('m', { duration_ms: 12, component: 'sdk.did', ok: true, none: null });

    expect(onlyAttrs(logs)).toEqual({
      duration_ms: 12,
      component: 'sdk.did',
      ok: true,
      none: null,
    });
  });

  it('ネストしたオブジェクト・配列の中まで再帰的にマスクする', () => {
    const { log, logs } = setup();

    log.info('m', {
      user: { mnemonic: 'secret', keep: 1 },
      entries: [{ pin: '1234', email: 'alice@example.com' }, { keep: 2 }],
    });

    expect(onlyAttrs(logs)).toEqual({
      user: { keep: 1 },
      entries: [{ email: expectedHash('alice@example.com') }, { keep: 2 }],
    });
  });

  it('属性が空になる場合は undefined を渡す（空オブジェクトは渡さない）', () => {
    const { log, logs } = setup();

    log.warn('m', { mnemonic: 'secret' });

    expect(logs.length).toBe(1);
    expect(logs[0]?.attrs).toBeUndefined();
  });

  it('メッセージとレベルはそのまま注入先へ渡る（info/warn/error は DEBUG 環境変数の影響を受けない）', () => {
    const { log, logs } = setup();

    log.info('i');
    log.warn('w');
    log.error('e');

    expect(logs.map((entry) => [entry.level, entry.message])).toEqual([
      ['info', 'i'],
      ['warn', 'w'],
      ['error', 'e'],
    ]);
  });

  it('ラップせず注入先を直接呼ぶとマスキングされない（検知能力の裏付け）', () => {
    const { sink, logs } = recordingLogger();

    sink.info('m', { mnemonic: 'secret' });

    expect(onlyAttrs(logs)).toEqual({ mnemonic: 'secret' });
  });
});

describe('Logger.child の束縛マージ', () => {
  it('束縛と呼び出し側属性が 1 つのオブジェクトにマージされる', () => {
    const { log, logs } = setup();

    log.child({ component: 'sdk.did' }).info('did.resolve', { operation: 'did.resolve' });

    expect(onlyAttrs(logs)).toEqual({ component: 'sdk.did', operation: 'did.resolve' });
  });

  it('2 段目の child は 1 段目の束縛に重ねる', () => {
    const { log, logs } = setup();

    log.child({ component: 'sdk.did' }).child({ operation: 'did.resolve' }).info('did.resolve');

    expect(onlyAttrs(logs)).toEqual({ component: 'sdk.did', operation: 'did.resolve' });
  });

  it('キー衝突時は呼び出し側の属性が束縛に勝つ', () => {
    const { log, logs } = setup();

    log.child({ component: 'sdk.did' }).info('m', { component: 'sdk.vc' });

    expect(onlyAttrs(logs)).toEqual({ component: 'sdk.vc' });
  });

  it('child は元のロガーの束縛を書き換えない', () => {
    const { log, logs } = setup();
    const parent = log.child({ component: 'sdk.did' });

    parent.child({ operation: 'did.resolve' });
    parent.info('m');

    expect(onlyAttrs(logs)).toEqual({ component: 'sdk.did' });
  });

  it('束縛もマスキングの対象になる', () => {
    const { log, logs } = setup();

    log.child({ pin: '1234', component: 'sdk.did' }).info('m');

    expect(onlyAttrs(logs)).toEqual({ component: 'sdk.did' });
  });
});

describe('Logger.debug の DEBUG=vericerts:* 名前空間フィルタ', () => {
  const ORIGINAL_DEBUG = process.env.DEBUG;

  beforeEach(() => {
    delete process.env.DEBUG;
  });

  afterEach(() => {
    if (ORIGINAL_DEBUG === undefined) {
      delete process.env.DEBUG;
    } else {
      process.env.DEBUG = ORIGINAL_DEBUG;
    }
  });

  it('DEBUG 未設定なら component 未束縛でも出力しない（本番既定 Off）', () => {
    const { log, logs } = setup();

    log.debug('d');

    expect(logs).toEqual([]);
  });

  it('DEBUG=vericerts:* なら component 未束縛でも出力する', () => {
    process.env.DEBUG = 'vericerts:*';
    const { log, logs } = setup();

    log.debug('d');

    expect(logs.map((entry) => [entry.level, entry.message])).toEqual([['debug', 'd']]);
  });

  it('DEBUG=vericerts:did:* なら component: "sdk.did" の debug ログを出力する', () => {
    process.env.DEBUG = 'vericerts:did:*';
    const { log, logs } = setup();

    log.child({ component: 'sdk.did' }).debug('did.resolve');

    expect(logs.map((entry) => [entry.level, entry.message])).toEqual([['debug', 'did.resolve']]);
  });

  it('DEBUG=vericerts:did:* では component: "sdk.vc" の debug ログは出力しない', () => {
    process.env.DEBUG = 'vericerts:did:*';
    const { log, logs } = setup();

    log.child({ component: 'sdk.vc' }).debug('vc.verify');

    expect(logs).toEqual([]);
  });

  it('debug ログでも PII マスキングは適用される', () => {
    process.env.DEBUG = 'vericerts:*';
    const { log, logs } = setup();

    log.debug('d', { mnemonic: 'secret', component: 'sdk.did' });

    expect(onlyAttrs(logs)).toEqual({ component: 'sdk.did' });
  });
});

describe('maskLogAttributes', () => {
  it('入力オブジェクトを書き換えず新しいオブジェクトを返す', () => {
    const input: LogAttributes = { mnemonic: 'secret', keep: 1 };

    const masked = maskLogAttributes(input);

    expect(masked).toEqual({ keep: 1 });
    expect(input).toEqual({ mnemonic: 'secret', keep: 1 });
  });

  it('キー判定は大文字小文字を区別しない', () => {
    expect(maskLogAttributes({ MNEMONIC: 'x', Email: 'alice@example.com', PORTRAIT: 'y' })).toEqual(
      {
        Email: expectedHash('alice@example.com'),
        PORTRAIT: '[REDACTED]',
      },
    );
  });

  it('プロトタイプ由来のキーは拾わない', () => {
    const polluted = Object.create({ mnemonic: 'inherited', leaked: 'inherited' }) as LogAttributes;
    polluted.keep = 1;

    expect(maskLogAttributes(polluted)).toEqual({ keep: 1 });
  });
});
