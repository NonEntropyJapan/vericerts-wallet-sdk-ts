/**
 * Wallet ファサードの DID メソッド配線（統合）テスト。
 *
 * createWallet が標準で登録する DID メソッド（key/web/jwk/peer/jwt/pkh/ethr/webvh/ipid/plc）を
 * Resolver に登録していることを、resolveDID のディスパッチ挙動から検証する。
 *
 * 判定方法: 登録済みメソッドに不正な識別子を渡すと、当該メソッドが処理して
 * INVALID_DID（2001）等で reject する（METHOD_NOT_SUPPORTED=2002 にはならない）。
 * 一方、未登録メソッドは Resolver が 2002 で reject する。これにより「登録されているか」を
 * ネットワーク非依存（オフライン解決可能な jwk/peer/jwt/pkh）で確認する。
 */

import { describe, expect, it } from 'bun:test';
import { VericertsError } from '../../../internal/errors.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import type { WalletOptions } from '../../options.js';
import { findLog, recordingLogger } from '../metrics/logger.fixtures.js';
import { findSpan, recordingTracer } from '../metrics/tracer.fixtures.js';

async function setup(options: Omit<WalletOptions, 'storage'> = {}) {
  return createWallet({ storage: new MemoryStorage(), ...options });
}

/** resolveDID を呼び、VericertsError の code を返す（成功した場合は null）。 */
async function resolveErrorCode(
  did: string,
  options: Omit<WalletOptions, 'storage'> = {},
): Promise<string | null> {
  const wallet = await setup(options);
  try {
    await wallet.resolveDID(did);
    return null;
  } catch (error) {
    if (error instanceof VericertsError) {
      return error.code;
    }
    throw error;
  }
}

describe('Wallet.resolveDID メソッド配線', () => {
  // オフライン解決可能なメソッドは、不正識別子で当該メソッドに到達し 2002 以外で reject する
  // （= Resolver に登録済み）。
  it.each([
    'jwk',
    'peer',
    'jwt',
    'pkh',
    'ethr',
    // did:ipid は解決にネットワークを要するが、不正識別子は parseDidIpid が 2001 で弾くため
    // ネットワークに出ずに「登録済み（2002 にならない）」を確認できる。
    'ipid',
    // did:plc は固定ホスト（plc.directory）で解決するため常に登録される。不正識別子は 2001。
    'plc',
  ])('did:%s は登録済みで、未対応(2002)にはならない', async (m) => {
    const code = await resolveErrorCode(`did:${m}:!!!invalid`);
    expect(code).not.toBeNull();
    expect(code).not.toBe('2002');
  });

  // did:ebsi は解決先ノードが設定値のため、`didNodeUrls.ebsi` を渡したときだけ登録される。
  it('did:ebsi は didNodeUrls.ebsi を指定したときだけ登録される', async () => {
    expect(await resolveErrorCode('did:ebsi:!!!invalid')).toBe('2002');
    expect(
      await resolveErrorCode('did:ebsi:!!!invalid', {
        didNodeUrls: { ebsi: 'https://api.example' },
      }),
    ).toBe('2001');
  });

  it('did:ion は didNodeUrls.ion を指定したときだけ登録される', async () => {
    expect(await resolveErrorCode('did:ion:!!!invalid')).toBe('2002');
    expect(
      await resolveErrorCode('did:ion:!!!invalid', { didNodeUrls: { ion: 'https://ion.example' } }),
    ).toBe('2001');
  });

  it('did:cheqd は didNodeUrls.cheqd を指定したときだけ登録される', async () => {
    expect(await resolveErrorCode('did:cheqd:!!!invalid')).toBe('2002');
    expect(
      await resolveErrorCode('did:cheqd:!!!invalid', {
        didNodeUrls: { cheqd: 'https://resolver.cheqd.example' },
      }),
    ).toBe('2001');
  });

  it('未登録メソッドは METHOD_NOT_SUPPORTED(2002)', async () => {
    expect(await resolveErrorCode('did:unknownmethod:xyz')).toBe('2002');
  });

  it('did:tdw は未登録メソッドとして METHOD_NOT_SUPPORTED(2002)', async () => {
    expect(await resolveErrorCode('did:tdw:QmScid:example.com')).toBe('2002');
  });

  it('DID 形式不正は INVALID_DID(2001)', async () => {
    expect(await resolveErrorCode('not-a-did')).toBe('2001');
  });
});

// BIP-39 公式オールゼロ・エントロピーのニーモニック（passphrase なし）。
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

describe('Wallet.resolveDID のログ配線', () => {
  it('解決成功で info(did.resolve) を出す（component/operation/did_method/duration_ms 付き）', async () => {
    const { logger, logs } = recordingLogger();
    const wallet = await createWallet({ storage: new MemoryStorage(), logger });
    await wallet.importMnemonic(TEST_MNEMONIC);
    const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
    const { id: did } = await wallet.createDID('key', { keyID: keyPair.id });

    await wallet.resolveDID(did);

    const attrs = findLog(logs, 'info', 'did.resolve')?.attrs;
    expect(attrs?.component).toBe('sdk.did');
    expect(attrs?.operation).toBe('did.resolve');
    expect(attrs?.did_method).toBe('key');
    expect(typeof attrs?.duration_ms).toBe('number');
    expect(findLog(logs, 'error', 'did.resolve')).toBeUndefined();
  });

  it('解決失敗で error(did.resolve) を出し、元の例外はそのまま呼び出し側へ届く', async () => {
    const { logger, logs } = recordingLogger();
    const wallet = await createWallet({ storage: new MemoryStorage(), logger });

    let caught: unknown;
    try {
      await wallet.resolveDID('did:unknownmethod:xyz');
    } catch (error) {
      caught = error;
    }

    // ログは観測に徹し、例外を握り潰さない・差し替えない。
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe('2002');
    const attrs = findLog(logs, 'error', 'did.resolve')?.attrs;
    expect(attrs?.component).toBe('sdk.did');
    expect(attrs?.operation).toBe('did.resolve');
    expect(attrs?.did_method).toBe('unknownmethod');
    expect(attrs?.error_code).toBe('2002');
    expect(findLog(logs, 'info', 'did.resolve')).toBeUndefined();
  });

  it('DID 形式不正では did_method を付けない（推測しない）', async () => {
    const { logger, logs } = recordingLogger();
    const wallet = await createWallet({ storage: new MemoryStorage(), logger });

    await expect(wallet.resolveDID('not-a-did')).rejects.toBeInstanceOf(VericertsError);

    const attrs = findLog(logs, 'error', 'did.resolve')?.attrs;
    expect(attrs).toBeDefined();
    expect(attrs?.did_method).toBeUndefined();
    expect(attrs?.error_code).toBe('2001');
  });

  it('logger 未注入でも resolveDID の挙動は変わらない（no-op）', async () => {
    expect(await resolveErrorCode('did:unknownmethod:xyz')).toBe('2002');
  });
});

describe('Wallet.resolveDID のトレース配線', () => {
  it('解決成功で did.resolve Span に did.method / did.result=success / ok を積んで閉じる', async () => {
    const { tracer, spans } = recordingTracer();
    const wallet = await createWallet({ storage: new MemoryStorage(), tracer });
    await wallet.importMnemonic(TEST_MNEMONIC);
    const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
    const { id: did } = await wallet.createDID('key', { keyID: keyPair.id });

    await wallet.resolveDID(did);

    const span = findSpan(spans, 'did.resolve');
    expect(span?.attributes['did.method']).toBe('key');
    expect(span?.attributes['did.result']).toBe('success');
    expect(span?.status).toEqual({ status: 'ok', description: undefined });
    expect(span?.exceptions).toEqual([]);
    expect(span?.ended).toBe(true);
    // `did.cache_hit` は Resolver にキャッシュ機構が無いため載せない。
    expect(span?.attributes['did.cache_hit']).toBeUndefined();
  });

  it('解決失敗で recordException / did.result=failure / error(コード) を積んで閉じる', async () => {
    const { tracer, spans } = recordingTracer();
    const wallet = await createWallet({ storage: new MemoryStorage(), tracer });

    await expect(wallet.resolveDID('did:unknownmethod:xyz')).rejects.toBeInstanceOf(VericertsError);

    const span = findSpan(spans, 'did.resolve');
    expect(span?.attributes['did.method']).toBe('unknownmethod');
    expect(span?.attributes['did.result']).toBe('failure');
    // description は VericertsError の code のみ（例外 message は秘密を含み得るため載せない）。
    expect(span?.status).toEqual({ status: 'error', description: '2002' });
    expect(span?.exceptions[0]).toBeInstanceOf(VericertsError);
    expect(span?.ended).toBe(true);
  });

  it('DID 形式不正では did.method を付けない（推測しない）', async () => {
    const { tracer, spans } = recordingTracer();
    const wallet = await createWallet({ storage: new MemoryStorage(), tracer });

    await expect(wallet.resolveDID('not-a-did')).rejects.toBeInstanceOf(VericertsError);

    const span = findSpan(spans, 'did.resolve');
    expect(span).toBeDefined();
    expect(span?.attributes['did.method']).toBeUndefined();
    expect(span?.attributes['did.result']).toBe('failure');
  });

  it('tracer 未注入でも resolveDID の挙動は変わらない（no-op）', async () => {
    expect(await resolveErrorCode('did:unknownmethod:xyz')).toBe('2002');
  });
});
