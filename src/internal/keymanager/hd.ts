/**
 * BIP-32 / BIP-44 階層的決定性（HD）鍵導出の純粋関数モジュール。
 *
 * `@scure/bip32` の `HDKey` と `@scure/bip39` の `mnemonicToSeedSync` をラップし、
 * シード生成と任意の導出パスからの鍵導出を提供する。
 *
 * 本モジュールは BIP-32 / BIP-44 の HD 派生のみを担当する。
 * `KeyManager` は、ここで返す `DerivedKey` からアドレスを算出し、鍵 ID とアルゴリズムを付けて
 * `KeyPair` を組み立てる。`DerivedKey` 自体は address / id / algorithm を持たない。
 *
 * セキュリティ上の注意:
 * - seed / privateKey / chainCode などの秘密情報は、例外メッセージやログに一切含めない。導出パス文字列もメッセージに含めない。
 * - エラーは `VericertsError` を投げる。メッセージは秘密を含まない
 *   静的な日本語で、code により分岐できる。
 */

import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync } from '@scure/bip39';
import { ErrorCodes, VericertsError } from '../errors.js';
import { withoutHDKeyOptionPollution } from './hardening/hdkey-option-guard.js';
import type { MnemonicLanguage } from './mnemonic.js';
import { assertValidMnemonic } from './mnemonic.js';

/**
 * HD 導出で得られた鍵素材。
 *
 * BIP-32 層の生データのみを保持する。アドレス・ID・アルゴリズムなどの
 * 上位概念は含めない（後続 KeyManager Issue が組み立てる）。
 */
export interface DerivedKey {
  /** 秘密鍵（32 バイト）。 */
  readonly privateKey: Uint8Array;
  /** 公開鍵（圧縮形式・33 バイト）。 */
  readonly publicKey: Uint8Array;
  /** チェーンコード（32 バイト）。 */
  readonly chainCode: Uint8Array;
  /** この鍵を導出した BIP-32 パス（例: `m`, `m/44'/60'/0'/0/0`）。 */
  readonly derivationPath: string;
}

/**
 * BIP-32 導出パスの構文を緩く検証する正規表現。
 * `m` 単体、または `m/` に続くインデックス（任意で hardened を表す `'`）の繰り返しを許可する。
 * 厳密な範囲・カーブ検証は `@scure/bip32` の `derive` に委ねる。
 */
const DERIVATION_PATH_PATTERN = /^m(\/\d+'?)*$/;

/**
 * `HDKey` を `DerivedKey` へ変換する。
 *
 * `privateKey` / `publicKey` / `chainCode` はいずれも null になり得る
 * （`noUncheckedIndexedAccess` / strict 下で必須ガード）。いずれかが欠ける場合は
 * 公開鍵のみ等の不完全なノードであり、本 SDK の HD 派生用途では不正パス扱いとする。
 *
 * @param hd 変換対象の HDKey ノード。
 * @param path このノードを導出したパス。
 * @returns 完全な `DerivedKey`。
 * @throws いずれかの鍵素材が欠ける場合（VericertsError、code `1040`）。
 */
function toDerivedKey(hd: HDKey, path: string): DerivedKey {
  const { privateKey, publicKey, chainCode } = hd;
  if (privateKey === null || publicKey === null || chainCode === null) {
    // 秘密情報・パス文字列はメッセージに含めない。
    throw new VericertsError(ErrorCodes.DERIVATION_PATH_INVALID);
  }
  return { privateKey, publicKey, chainCode, derivationPath: path };
}

/**
 * ニーモニックから BIP-39 シード（64 バイト）を導出する。
 *
 * まず `assertValidMnemonic` でニーモニックを検証し、その後
 * `@scure/bip39` の `mnemonicToSeedSync` で同期的にシードを生成する。
 *
 * @param mnemonic 変換対象のニーモニック。
 * @param passphrase 任意のパスフレーズ（BIP-39 の "25 番目の語"）。省略時は空文字。
 *   BIP-39 仕様上パスフレーズに内容上の制約はなく、本関数でも検証せず
 *   そのまま PBKDF2 のソルトとして `@scure/bip39` に委譲する（任意のバイト列を許容）。
 * @param language ニーモニックの言語。省略時は自動判定。
 * @returns 64 バイト（512bit）のシード。
 * @throws ニーモニックが不正な場合（VericertsError、code `1001`）。
 */
export function mnemonicToSeed(
  mnemonic: string,
  passphrase?: string,
  language?: MnemonicLanguage,
): Uint8Array {
  assertValidMnemonic(mnemonic, language);
  return mnemonicToSeedSync(mnemonic, passphrase ?? '');
}

/**
 * シードからマスター鍵（パス `m`）を導出する。
 *
 * `HDKey` の生成は `withoutHDKeyOptionPollution` で包む。`@scure/bip32` が
 * オプションをプロトタイプ鎖経由で読むため、包まないと `Object.prototype` 汚染下で
 * 正当なシードでも生成が失敗する。
 *
 * @param seed BIP-39 シード（バイト列）。
 * @returns マスター鍵の `DerivedKey`（`derivationPath` は `m`）。
 * @throws シードが不正、または鍵素材が欠ける場合（VericertsError、code `1040`）。
 */
export function deriveMasterKey(seed: Uint8Array): DerivedKey {
  let master: HDKey;
  try {
    master = withoutHDKeyOptionPollution(() => HDKey.fromMasterSeed(seed));
  } catch {
    // @scure のシード長違反等を本 SDK のコードへ正規化する。削除できない
    // プロトタイプ汚染（非 configurable）が残っている場合もここへ落ちる。
    // @scure 例外メッセージにシード長が含まれるため cause は渡さない。
    throw new VericertsError(ErrorCodes.DERIVATION_PATH_INVALID);
  }
  return toDerivedKey(master, 'm');
}

/**
 * シードと BIP-32 パスから鍵を導出する。hardened / non-hardened の両方に対応する。
 *
 * パスは前段で正規表現により緩く検証し、構文違反は `DERIVATION_PATH_INVALID` とする。
 * `@scure/bip32` の `derive` 内部での失敗（範囲外インデックス等）も同コードへ正規化する。
 * 導出そのものは `withoutHDKeyOptionPollution` で包み、`Object.prototype` 汚染に
 * 起因する偽の失敗を防ぐ。ただし防げるのは**削除できる（configurable な）汚染**に
 * 限る。非 configurable な汚染は退避できないため、従来どおり `DERIVATION_PATH_INVALID`
 * で fail-closed する。
 *
 * @param seed BIP-39 シード（バイト列）。
 * @param path BIP-32 導出パス（例: `m/44'/60'/0'/0/0`）。
 * @returns 導出された `DerivedKey`。
 * @throws パスが不正、または鍵素材が欠ける場合（VericertsError、code `1040`）。
 */
export function deriveKeyFromSeed(seed: Uint8Array, path: string): DerivedKey {
  if (!DERIVATION_PATH_PATTERN.test(path)) {
    // 秘密情報・パス文字列はメッセージに含めない。
    throw new VericertsError(ErrorCodes.DERIVATION_PATH_INVALID);
  }
  let derived: HDKey;
  try {
    // `@scure/bip32` はオプションをプロトタイプ鎖経由で読むため、`Object.prototype`
    // 汚染下でも正当なパスが導出できるようガードで包む。
    derived = withoutHDKeyOptionPollution(() => HDKey.fromMasterSeed(seed).derive(path));
  } catch {
    // @scure の範囲外インデックス・カーブ不正等を本 SDK のコードへ正規化する。
    // @scure 例外メッセージに seed 由来の秘密が含まれ得るため cause は渡さない。
    throw new VericertsError(ErrorCodes.DERIVATION_PATH_INVALID);
  }
  return toDerivedKey(derived, path);
}

/**
 * ニーモニックと BIP-32 パスから鍵を導出する（`mnemonicToSeed` → `deriveKeyFromSeed` の糖衣）。
 *
 * @param mnemonic 変換対象のニーモニック。
 * @param path BIP-32 導出パス。
 * @param passphrase 任意のパスフレーズ。省略時は空文字。
 * @param language ニーモニックの言語。省略時は自動判定。
 * @returns 導出された `DerivedKey`。
 * @throws ニーモニックが不正な場合（VericertsError、code `1001`）、
 *         パスが不正な場合（VericertsError、code `1040`）。
 */
export function deriveKeyFromMnemonic(
  mnemonic: string,
  path: string,
  passphrase?: string,
  language?: MnemonicLanguage,
): DerivedKey {
  const seed = mnemonicToSeed(mnemonic, passphrase, language);
  return deriveKeyFromSeed(seed, path);
}

/**
 * Ethereum（BIP-44 coin type 60）の標準導出パスを組み立てる。
 *
 * 形式は `m/44'/60'/{account}'/0/{index}`（外部チェーン固定）。
 *
 * @param account アカウント番号（非負整数）。
 * @param index アドレスインデックス（非負整数）。
 * @returns BIP-44 導出パス文字列。
 * @throws `account` / `index` が非負整数でない場合（VericertsError、code `1040`）。
 */
export function ethereumPath(account: number, index: number): string {
  if (!isNonNegativeInteger(account) || !isNonNegativeInteger(index)) {
    throw new VericertsError(ErrorCodes.DERIVATION_PATH_INVALID);
  }
  return `m/44'/60'/${account}'/0/${index}`;
}

/** 値が非負整数（0 以上の安全な整数）かを判定する。 */
function isNonNegativeInteger(value: number): boolean {
  return Number.isInteger(value) && value >= 0;
}
