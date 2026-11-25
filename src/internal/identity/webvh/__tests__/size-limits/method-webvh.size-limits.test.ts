/**
 * did:webvh の DID Log 検証量の上限。
 *
 * 1 MiB 未満の `did.jsonl` に「許可鍵を名乗るが署名が不正な」proof を 1,500 個以上並べ state を約 520 KB にすると、
 * proof ごとに payload 全体を SHA-512 に掛けて `resolveDidWebVh` が約 11.5 秒停止した。実時間ではなく
 * 決定的なカウンタ（Ed25519 検証の呼び出し回数・例外の種別）で pin する。
 */

import { afterEach, describe, expect, it, spyOn } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import * as ed25519Module from '../../../../keymanager/ed25519.js';
import { multibaseBase58Decode, multibaseBase58Encode } from '../../../multibase.js';
import { nextVersionTime, parseDidLog, type WebVhLogEntry, type WebVhProof } from '../../codec.js';
import {
  MAX_LOG_ENTRIES,
  MAX_LOG_ENTRY_CHARS,
  MAX_PROOFS_PER_ENTRY,
  SIGNATURE_BUDGET_SLACK,
} from '../../limits.js';
import { resolveDidWebVh } from '../../method-webvh.js';
import { verifyChain } from '../../verify.js';
import {
  forgeAppendEntry,
  generateKey,
  mockFetchOnce,
  restoreFetch,
  signEntry,
  type TestKey,
  toJsonl,
} from '../webvh-fixtures.js';
import { forgeGenesisWithPadding } from './forge-genesis.js';

afterEach(() => {
  restoreFetch();
});

const SCID_DOMAIN = 'vericerts.io';

/** 署名済み初版エントリ（state に `padding` 文字ぶんの service を載せられる）。 */
function signedGenesis(keys: readonly TestKey[], padding = 0) {
  const [signer] = keys;
  const { did, logEntry } = forgeGenesisWithPadding(keys, padding, SCID_DOMAIN);
  const signed = signEntry(logEntry, signer as TestKey);
  return { did, signed, scid: did.split(':')[2] as string };
}

/** 署名の S 部を 1 ビット壊した proof（鍵・位置束縛は正規なので、件数上限が無ければ必ず署名検証まで進む）。 */
function corrupted(proof: WebVhProof): WebVhProof {
  const signature = multibaseBase58Decode(proof.proofValue).slice();
  (signature as Uint8Array)[32] = ((signature as Uint8Array)[32] as number) ^ 1;
  return { ...proof, proofValue: multibaseBase58Encode(signature) };
}

function withProofs(entry: WebVhLogEntry, proofs: readonly WebVhProof[]): WebVhLogEntry {
  return { ...entry, proof: proofs };
}

function expectOversized(fn: () => unknown): void {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(VericertsError);
    expect((err as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    expect((err as VericertsError).context).toMatchObject({ reason: 'did_log_too_large' });
    return;
  }
  throw new Error('should have thrown');
}

describe('verifyEntryProof: proof 件数・payload サイズの上限', () => {
  it('proof が上限を 1 個超えるエントリは、署名を 1 回も検証せず拒否する', () => {
    const key = generateKey();
    const { did, signed, scid } = signedGenesis([key]);
    const good = (signed.proof as readonly WebVhProof[])[0] as WebVhProof;
    const spy = spyOn(ed25519Module, 'verifyEd25519');
    try {
      const over = Array.from({ length: MAX_PROOFS_PER_ENTRY + 1 }, () => corrupted(good));
      expectOversized(() => verifyChain([withProofs(signed, over)], did, scid));
      // 末尾に有効な proof があっても、上限超過は先に拒否される。
      expectOversized(() => verifyChain([withProofs(signed, [...over, good])], did, scid));
      expect(spy).toHaveBeenCalledTimes(0);
    } finally {
      spy.mockRestore();
    }
  });

  it('同一鍵の proof は 1 つしか検証しない（上限ちょうどの不正 proof でも検証は 1 回）', () => {
    const key = generateKey();
    const { did, signed, scid } = signedGenesis([key]);
    const good = (signed.proof as readonly WebVhProof[])[0] as WebVhProof;
    const spy = spyOn(ed25519Module, 'verifyEd25519');
    try {
      const atLimit = Array.from({ length: MAX_PROOFS_PER_ENTRY }, () => corrupted(good));
      expect(() => verifyChain([withProofs(signed, atLimit)], did, scid)).toThrow(
        new VericertsError(ErrorCodes.INVALID_DID),
      );
      expect(spy).toHaveBeenCalledTimes(1);
    } finally {
      spy.mockRestore();
    }
  });

  it('payload が上限を超えるエントリは、署名を 1 回も検証せず拒否する', () => {
    const key = generateKey();
    const { did, signed, scid } = signedGenesis([key], MAX_LOG_ENTRY_CHARS);
    const spy = spyOn(ed25519Module, 'verifyEd25519');
    try {
      expectOversized(() => verifyChain([signed], did, scid));
      expect(spy).toHaveBeenCalledTimes(0);
    } finally {
      spy.mockRestore();
    }
  });

  it('異なる許可鍵の複数 proof は従来どおり成立する（鍵ごとに 1 回、有効なものが 1 つあればよい）', () => {
    const keyA = generateKey();
    const keyB = generateKey();
    const { did, scid, signed: entry } = signedGenesis([keyA, keyB]);
    // 同じ payload・versionId を keyB でも署名する（proof は署名対象に含まれない）。
    const proofB = (signEntry(entry, keyB).proof as readonly WebVhProof[])[0] as WebVhProof;
    const proofA = (entry.proof as readonly WebVhProof[])[0] as WebVhProof;
    const spy = spyOn(ed25519Module, 'verifyEd25519');
    try {
      expect(() =>
        verifyChain([withProofs(entry, [corrupted(proofA), proofB])], did, scid),
      ).not.toThrow();
      expect(spy).toHaveBeenCalledTimes(2);
    } finally {
      spy.mockRestore();
    }
  });
});

describe('verifyChain / parseDidLog: エントリ数・1 行の長さの上限', () => {
  it('エントリ数が上限を超える配列は、検証（ハッシュ・署名）を始めず拒否する', () => {
    const spy = spyOn(ed25519Module, 'verifyEd25519');
    try {
      const entries = Array.from({ length: MAX_LOG_ENTRIES + 1 }, () => undefined);
      expectOversized(() => verifyChain(entries as never, 'did:webvh:x:y', 'x'));
      expect(spy).toHaveBeenCalledTimes(0);
    } finally {
      spy.mockRestore();
    }
  });

  it('parseDidLog はエントリ数超過を JSON パース前に拒否する', () => {
    // 各行は不正 JSON。件数上限が無ければ「JSON 不正」（reason なし）の 2001 になる。
    expectOversized(() =>
      parseDidLog(Array.from({ length: MAX_LOG_ENTRIES + 1 }, () => '{').join('\n')),
    );
  });

  it('parseDidLog は 1 行の長さ超過を JSON パース前に拒否する', () => {
    expectOversized(() => parseDidLog(`{${'x'.repeat(MAX_LOG_ENTRY_CHARS)}`));
  });

  it('parseDidLog は proof 件数超過のエントリを拒否する', () => {
    const key = generateKey();
    const { signed } = signedGenesis([key]);
    const good = (signed.proof as readonly WebVhProof[])[0] as WebVhProof;
    const over = Array.from({ length: MAX_PROOFS_PER_ENTRY + 1 }, () => good);
    expectOversized(() => parseDidLog(toJsonl([withProofs(signed, over)])));
    expect(parseDidLog(toJsonl([signed]))).toHaveLength(1);
  });
});

describe('resolveDidWebVh: 巨大 state ＋ 大量の不正 proof', () => {
  it('1 MiB 未満の did.jsonl は署名検証を 1 回も走らせず 2001 で拒否する', async () => {
    const key = generateKey();
    const { did, signed } = signedGenesis([key], 520_000);
    const good = (signed.proof as readonly WebVhProof[])[0] as WebVhProof;
    const proofs = [...Array.from({ length: 1300 }, () => corrupted(good)), good];
    const text = JSON.stringify(withProofs(signed, proofs));
    expect(text.length).toBeLessThan(1_048_576);
    mockFetchOnce(text);
    const spy = spyOn(ed25519Module, 'verifyEd25519');
    try {
      await expect(resolveDidWebVh(did)).rejects.toMatchObject({
        code: ErrorCodes.INVALID_DID,
        context: { reason: 'did_log_too_large' },
      });
      expect(spy).toHaveBeenCalledTimes(0);
    } finally {
      spy.mockRestore();
    }
  });

  it('通常規模の署名済み did:webvh は従来どおり解決できる', async () => {
    const key = generateKey();
    const { did, signed } = signedGenesis([key], 2_000);
    mockFetchOnce(toJsonl([signed]));
    expect((await resolveDidWebVh(did)).id).toBe(did);
  });
});

/** 全エントリに「許可鍵を名乗る不正 proof を 7 個 + 正規 1 個」を置いた、署名済みログ。 */
function buildLog(entryCount: number, keys: readonly TestKey[], badProofsPerEntry: number) {
  const genesis = signedGenesis(keys);
  const sign = (entry: WebVhLogEntry): WebVhLogEntry => {
    const bad = keys
      .slice(0, badProofsPerEntry)
      .map((k) => corrupted((signEntry(entry, k).proof as readonly WebVhProof[])[0] as WebVhProof));
    const good = (
      signEntry(entry, keys[keys.length - 1] as TestKey).proof as readonly WebVhProof[]
    )[0];
    return withProofs(entry, [...bad, good as WebVhProof]);
  };
  const log: WebVhLogEntry[] = [sign(genesis.signed)];
  while (log.length < entryCount) {
    const previous = log[log.length - 1] as WebVhLogEntry;
    const next = forgeAppendEntry(log, genesis.signed.state, nextVersionTime(previous.versionTime));
    log.push(sign(next));
  }
  return { did: genesis.did, scid: genesis.scid, log };
}

describe('verifyChain: ログ全体の署名検証回数の予算', () => {
  it('全エントリに不正 proof を並べたログは、エントリ数 + 余剰を超える署名検証を実行せず拒否する', () => {
    const keys = Array.from({ length: MAX_PROOFS_PER_ENTRY }, () => generateKey());
    const entryCount = 40;
    const { did, scid, log } = buildLog(entryCount, keys, MAX_PROOFS_PER_ENTRY - 1);
    const spy = spyOn(ed25519Module, 'verifyEd25519');
    try {
      expectOversized(() => verifyChain(log, did, scid));
      // 1 エントリ 8 検証なら 320 回走る。予算（40 + 8 = 48）で打ち切られる。
      expect(spy).toHaveBeenCalledTimes(entryCount + SIGNATURE_BUDGET_SLACK);
    } finally {
      spy.mockRestore();
    }
  });

  it('1 エントリ 1 proof の正規ログは従来どおり成立し、検証はエントリ数ちょうど', () => {
    const keys = [generateKey()];
    const entryCount = 20;
    const { did, scid, log } = buildLog(entryCount, keys, 0);
    const spy = spyOn(ed25519Module, 'verifyEd25519');
    try {
      expect(() => verifyChain(log, did, scid)).not.toThrow();
      expect(spy).toHaveBeenCalledTimes(entryCount);
    } finally {
      spy.mockRestore();
    }
  });

  it('不正 proof が少数エントリに限られる場合は余剰の範囲で成立する', () => {
    const keys = Array.from({ length: 2 }, () => generateKey());
    const { did, scid, log } = buildLog(3, keys, 1);
    // 各エントリ: 不正 1 + 正規 1 = 2 検証 → 計 6 <= 3 + 8。
    expect(() => verifyChain(log, did, scid)).not.toThrow();
  });
});
