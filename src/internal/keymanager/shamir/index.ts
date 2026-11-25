/**
 * SLIP-0039 Shamir 秘密分散のバックアップ・復旧。
 *
 * `KeyManager` から呼ばれる薄いオーケストレーション層。GF(256) 補間（gf256.ts）・
 * Feistel 暗号化（cipher.ts）・ニーモニック変換（share.ts / wordlist.ts）・RS1024
 * チェックサム（rs1024.ts）を組み合わせ、K1（BIP-39 ニーモニックのエントロピー）を
 * 単一グループ（groupThreshold=1, groupCount=1）の T-of-N シェアへ分割・復元する
 * （spec: 「single-level T-of-N scheme」は GT=1, G=1 で表現する構成が SHOULD 推奨）。
 *
 * 本 SDK の公開 API はパスフレーズを扱わない（常に空文字列。SLIP-0039 の Passphrase 節の
 * 「省略時は空文字列」に従う）。BIP-39 パスフレーズ（"25 番目の語"）付きでインポートされた
 * ニーモニックへの対応は `KeyManager.createShamirShares` が事前ガードで拒否する
 * （本モジュールはパスフレーズの有無を検知できないため、上位層の責務）。
 *
 * **言語の保持（重要）**: BIP-39 のシードはニーモニック文字列そのものを PBKDF2 に渡すため、
 * 同じエントロピーでも言語が違えば別のシード＝別のウォレットになる。SLIP-0039 の master secret
 * は生エントロピーのみでは言語を保持できないため、先頭 2 バイト（1 バイトの言語コード + 1 バイトの
 * パディング、エントロピー長の偶数制約を保つため）に言語タグを付与してから分割し、復元時に
 * 剥がして同一言語で `entropyToMnemonic` する。これにより master secret 長は BIP-39 標準の
 * 16/32 バイトではなく 18/34 バイトになる（SLIP-0039 仕様上は「16bit の倍数かつ 128bit 以上」を
 * 満たせば任意長を許容するため準拠内だが、汎用 SLIP-0039 ツールでの見た目は標準と異なる）。
 *
 * セキュリティ上の注意: エントロピー・EMS・言語タグ付き payload 等の
 * 秘密バイト列は使用後に `fill(0)` で消去する。例外メッセージに秘密を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import {
  entropyToMnemonic,
  type MnemonicLanguage,
  mnemonicToEntropy,
  resolveMnemonicLanguage,
} from '../mnemonic.js';
import { decryptMasterSecret, encryptMasterSecret } from './cipher.js';
import { recoverSecret, splitSecret } from './shamir-core.js';
import { decodeRecoverableShares, type Share, shareToMnemonic } from './share.js';

/** 拡張可能バックアップフラグ（SLIP-0039）。新規作成シェアは常に 1（SHOULD）。 */
const EXTENDABLE = true;
/** PBKDF2 反復指数。反復回数 = 10000 << e（spec 既定の e=1）。 */
const DEFAULT_ITERATION_EXPONENT = 1;
/**
 * 復旧時に受理する PBKDF2 反復指数の上限。
 *
 * 指数は 4bit（0〜15）でシェア文字列に載り、チェックサムは公開アルゴリズムなので、1 語書き換えるだけで
 * `10000 << e` 回の同期 PBKDF2 を強要できる（e=15 で約 8 分）。この SDK が生成するシェアは常に
 * {@link DEFAULT_ITERATION_EXPONENT}。外部ツールが強めの値（SLIP-0039 の想定は小さな指数）で
 * 作ったシェアも受けられるよう、既定の 8 倍（実測で 1 秒未満）までを許す。
 */
const MAX_ACCEPTED_ITERATION_EXPONENT = 4;
const EMPTY_PASSPHRASE = new Uint8Array(0);
const MIN_THRESHOLD = 2;
const MAX_SHARE_COUNT = 16;

/**
 * 言語タグの固定エンコード表（wire format）。**追加のみ許可・既存インデックスの再割当禁止**
 * （既発行シェアの復元に必要）。`mnemonic.ts` の `MnemonicLanguage` 10 言語すべてを含む。
 */
const LANGUAGE_CODES: readonly MnemonicLanguage[] = [
  'en',
  'ja',
  'ko',
  'zh-CN',
  'zh-TW',
  'es',
  'fr',
  'it',
  'cs',
  'pt',
];
/** 言語タグの長さ（バイト）。1 バイトの言語コード + 1 バイトのパディング（偶数長制約のため）。 */
const LANGUAGE_TAG_LENGTH = 2;
/** 言語を 2 バイトのタグへエンコードする（[言語コード index, 0x00]）。 */
function encodeLanguageTag(language: MnemonicLanguage): Uint8Array {
  const index = LANGUAGE_CODES.indexOf(language);
  if (index < 0) {
    // LANGUAGE_CODES は MnemonicLanguage の全列挙のため到達しない防御。
    throw new Error('SLIP-0039: unknown mnemonic language');
  }
  return new Uint8Array([index, 0]);
}

/** 2 バイトの言語タグを言語へデコードする。 */
function decodeLanguageTag(tag: Uint8Array): MnemonicLanguage {
  const index = tag[0];
  const language = index === undefined ? undefined : LANGUAGE_CODES[index];
  if (language === undefined) {
    throw new Error('SLIP-0039: invalid language tag');
  }
  return language;
}

function randomIdentifier(): number {
  const bytes = crypto.getRandomValues(new Uint8Array(2));
  const value = ((bytes[0] ?? 0) << 8) | (bytes[1] ?? 0);
  // spec: id は 15bit。上位 1bit を落として範囲に収める。
  return value & 0x7fff;
}

function assertValidThresholdTotal(threshold: number, total: number): void {
  const valid =
    Number.isInteger(threshold) &&
    Number.isInteger(total) &&
    threshold >= MIN_THRESHOLD &&
    threshold <= total &&
    total <= MAX_SHARE_COUNT;
  if (!valid) {
    throw new VericertsError(ErrorCodes.SHAMIR_INVALID_PARAMS);
  }
}

/**
 * ニーモニックの BIP-39 エントロピーを SLIP-0039 の `threshold`-of-`total` シェアへ分割する。
 *
 * @throws `threshold` / `total` が `2 <= threshold <= total <= 16` を満たさない場合（code `1015`）、
 *         SLIP-0039 エンコードに失敗した場合（code `1011`）。
 */
export function createShares(
  mnemonic: string,
  threshold: number,
  total: number,
): { shares: string[] } {
  assertValidThresholdTotal(threshold, total);

  let entropy: Uint8Array | undefined;
  let payload: Uint8Array | undefined;
  // EMS はパスフレーズ空の本 SDK では実質 K1 相当の秘密なので、`entropy` / `payload` と同じく
  // 使用後に消す（`recoverMnemonic` 側も同様に消している）。
  let encryptedMasterSecret: Uint8Array | undefined;
  try {
    const language = resolveMnemonicLanguage(mnemonic);
    entropy = mnemonicToEntropy(mnemonic, language);
    // 先頭に言語タグを付与してから分割する（言語を保持しないと復元時に別ウォレットになる）。
    const languageTag = encodeLanguageTag(language);
    payload = new Uint8Array(languageTag.length + entropy.length);
    payload.set(languageTag, 0);
    payload.set(entropy, languageTag.length);

    const identifier = randomIdentifier();
    encryptedMasterSecret = encryptMasterSecret(
      payload,
      EMPTY_PASSPHRASE,
      DEFAULT_ITERATION_EXPONENT,
      identifier,
      EXTENDABLE,
    );
    const rawShares = splitSecret(threshold, total, encryptedMasterSecret);
    const shares = rawShares.map((raw) =>
      shareToMnemonic({
        identifier,
        extendable: EXTENDABLE,
        iterationExponent: DEFAULT_ITERATION_EXPONENT,
        groupIndex: 0,
        groupThreshold: 1,
        groupCount: 1,
        index: raw.x,
        memberThreshold: threshold,
        value: raw.data,
      }),
    );
    return { shares };
  } catch (cause) {
    if (cause instanceof VericertsError) {
      throw cause;
    }
    throw new VericertsError(ErrorCodes.SHAMIR_ENCODE_FAILED);
  } finally {
    entropy?.fill(0);
    payload?.fill(0);
    encryptedMasterSecret?.fill(0);
  }
}

export type RecoverSharesResult =
  | { readonly status: 'success'; readonly mnemonic: string }
  | { readonly status: 'insufficient_shares' }
  | { readonly status: 'invalid_share' };

function shareGroupParamsMatch(a: Share, b: Share): boolean {
  return (
    a.identifier === b.identifier &&
    a.extendable === b.extendable &&
    a.iterationExponent === b.iterationExponent &&
    a.groupThreshold === b.groupThreshold &&
    a.groupCount === b.groupCount &&
    a.memberThreshold === b.memberThreshold
  );
}

/**
 * SLIP-0039 シェアから元のニーモニックを再構成する。
 *
 * 単一グループ（groupThreshold=1, groupCount=1）構成のみをサポートする
 * （`createShares` が常にこの構成で生成するため）。
 */
export function recoverMnemonic(shareMnemonics: readonly string[]): RecoverSharesResult {
  if (shareMnemonics.length === 0) {
    return { status: 'insufficient_shares' };
  }
  const decodedShares = decodeRecoverableShares(
    shareMnemonics,
    MAX_SHARE_COUNT,
    MAX_ACCEPTED_ITERATION_EXPONENT,
  );
  if (decodedShares === undefined) {
    return { status: 'invalid_share' };
  }

  const [first] = decodedShares;
  if (first === undefined) {
    // shareMnemonics が空でない限り到達しない（map で同じ長さの配列を生成しているため）。
    return { status: 'insufficient_shares' };
  }
  if (!decodedShares.every((share) => shareGroupParamsMatch(first, share))) {
    return { status: 'invalid_share' };
  }
  if (first.groupThreshold !== 1 || first.groupCount !== 1) {
    // 本 API（single-level T-of-N）が生成しない構成。マルチグループ復旧は未サポート。
    return { status: 'invalid_share' };
  }

  // 同じ member index のシェアを 2 枚渡された場合、Map の後勝ちで黙って 1 枚に畳むと、
  // 「閾値枚数を集めたのに復元できない」がダイジェスト不一致としてしか現れず、利用者には
  // 原因が伝わらない（同じシェアの重複か、別分割由来の混在かを区別できない）。明示的に弾く。
  const uniqueByIndex = new Map(decodedShares.map((share) => [share.index, share]));
  if (uniqueByIndex.size !== decodedShares.length) {
    return { status: 'invalid_share' };
  }
  if (uniqueByIndex.size < first.memberThreshold) {
    return { status: 'insufficient_shares' };
  }

  const rawShares = [...uniqueByIndex.values()]
    .slice(0, first.memberThreshold)
    .map((share) => ({ x: share.index, data: share.value }));

  let encryptedMasterSecret: Uint8Array;
  try {
    encryptedMasterSecret = recoverSecret(first.memberThreshold, rawShares);
  } catch {
    return { status: 'invalid_share' };
  }

  let payload: Uint8Array | undefined;
  let entropy: Uint8Array | undefined;
  try {
    payload = decryptMasterSecret(
      encryptedMasterSecret,
      EMPTY_PASSPHRASE,
      first.iterationExponent,
      first.identifier,
      first.extendable,
    );
    if (payload.length <= LANGUAGE_TAG_LENGTH) {
      return { status: 'invalid_share' };
    }
    // 分割時に付与した言語タグを剥がし、同一言語で BIP-39 ニーモニックを再構成する
    // （言語がずれると同じエントロピーでも別のシード＝別のウォレットになるため）。
    const language = decodeLanguageTag(payload.slice(0, LANGUAGE_TAG_LENGTH));
    entropy = payload.slice(LANGUAGE_TAG_LENGTH);
    const mnemonic = entropyToMnemonic(entropy, language);
    return { status: 'success', mnemonic };
  } catch {
    return { status: 'invalid_share' };
  } finally {
    encryptedMasterSecret.fill(0);
    payload?.fill(0);
    entropy?.fill(0);
  }
}

/** `KeyManager.createShamirShares` の結果。 */
export interface ShamirSharesResult {
  /** 各シェアは SLIP-0039 ワードリスト空白区切り。 */
  readonly shares: string[];
  /** SLIP-0039 のグループ閾値。本 SDK は単一グループ構成のみのため常に 1。 */
  readonly groupThreshold: number;
  /** SLIP-0039 のグループ数。本 SDK は単一グループ構成のみのため常に 1。 */
  readonly groupCount: number;
  /** シェア生成時刻（unix timestamp、ミリ秒）。 */
  readonly createdAt: number;
}

/** `KeyManager.recoverFromShamirShares` の結果。 */
export interface ShamirRecoveryResult {
  /**
   * `insufficient_shares`（code `1012` 相当）/ `invalid_share`
   * （グループ不一致 code `1013` / チェックサム不正 code `1014` 相当）はいずれも
   * 例外ではなく本フィールドで表現する（Response 型が失敗状態を包含するため）。
   */
  readonly status: 'success' | 'insufficient_shares' | 'invalid_share';
  /** 復旧成功時刻（unix timestamp、ミリ秒）。`status !== 'success'` の場合は undefined。 */
  readonly recoveredAt?: number;
}

/**
 * `KeyManager.createShamirShares` の実体。
 *
 * アンロックゲート（`exportMnemonic` と同じ 1005 / 1042）は呼び出し側の `KeyManager` が
 * `vault.export()` で通したうえで、その結果を `mnemonic` として渡す。
 */
export function createSharesResult(
  mnemonic: string,
  threshold: number,
  total: number,
): ShamirSharesResult {
  const { shares } = createShares(mnemonic, threshold, total);
  return { shares, groupThreshold: 1, groupCount: 1, createdAt: Date.now() };
}

/**
 * `KeyManager.recoverFromShamirShares` の実体。成功時は再構成したニーモニックを
 * `importMnemonic` へ渡し、本インスタンスのアクティブなマスターシードへ再投入する。
 */
export async function recoverSharesInto(
  shareMnemonics: readonly string[],
  importMnemonic: (mnemonic: string) => Promise<void>,
): Promise<ShamirRecoveryResult> {
  const result = recoverMnemonic(shareMnemonics);
  if (result.status !== 'success') {
    return { status: result.status };
  }
  await importMnemonic(result.mnemonic);
  return { status: 'success', recoveredAt: Date.now() };
}
