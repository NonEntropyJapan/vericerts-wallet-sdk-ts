/**
 * BIP-44 Ethereum 導出（既知ニーモニック）の決定性検証と `ethereumPath` の検証。
 *
 * 既知ニーモニック `abandon ... about`（passphrase 空）→ seed → `m/44'/60'/0'/0/0` の
 * privateKey / publicKey が固定値に一致することを確認する。
 *
 * 期待値の根拠: 本リポジトリの実装（`@scure/bip32` ベース）で一度算出し固定値化した。
 * この既知ニーモニック + `m/44'/60'/0'/0/0` は MetaMask / ethers / Trezor 等で広く
 * 公開・再現されている標準テストアカウントであり、ethers の
 * `HDNodeWallet.fromPhrase(mnemonic).privateKey` が
 * `0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727` を返すことと一致する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { deriveKeyFromMnemonic, ethereumPath } from '../../hd.js';

/** `fn` を実行し、捕捉した例外を返す（未throw なら undefined）。 */
function captureError(fn: () => unknown): unknown {
  try {
    fn();
  } catch (error) {
    return error;
  }
  return undefined;
}

/** バイト列を hex 文字列へ変換する（テスト専用ヘルパ）。 */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

const KNOWN_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// ethers HDNodeWallet.fromPhrase(KNOWN_MNEMONIC) とクロスチェック済みの固定値。
const EXPECTED_PRIVATE_KEY_HEX = '1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727';
const EXPECTED_PUBLIC_KEY_HEX =
  '0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299';

describe('deriveKeyFromMnemonic (BIP-44 Ethereum, known mnemonic)', () => {
  it("derives the canonical key for m/44'/60'/0'/0/0", () => {
    const key = deriveKeyFromMnemonic(KNOWN_MNEMONIC, "m/44'/60'/0'/0/0");
    expect(toHex(key.privateKey)).toBe(EXPECTED_PRIVATE_KEY_HEX);
    expect(toHex(key.publicKey)).toBe(EXPECTED_PUBLIC_KEY_HEX);
    expect(key.derivationPath).toBe("m/44'/60'/0'/0/0");
  });

  it('uses an empty passphrase by default (explicit empty matches default)', () => {
    const withoutPassphrase = deriveKeyFromMnemonic(KNOWN_MNEMONIC, "m/44'/60'/0'/0/0");
    const withEmptyPassphrase = deriveKeyFromMnemonic(KNOWN_MNEMONIC, "m/44'/60'/0'/0/0", '');
    expect(toHex(withEmptyPassphrase.privateKey)).toBe(toHex(withoutPassphrase.privateKey));
  });

  it('produces a different key with a non-empty passphrase', () => {
    const withoutPassphrase = deriveKeyFromMnemonic(KNOWN_MNEMONIC, "m/44'/60'/0'/0/0");
    const withPassphrase = deriveKeyFromMnemonic(KNOWN_MNEMONIC, "m/44'/60'/0'/0/0", 'secret');
    expect(toHex(withPassphrase.privateKey)).not.toBe(toHex(withoutPassphrase.privateKey));
  });
});

describe('ethereumPath', () => {
  it('builds the standard BIP-44 Ethereum path', () => {
    expect(ethereumPath(0, 0)).toBe("m/44'/60'/0'/0/0");
    expect(ethereumPath(2, 5)).toBe("m/44'/60'/2'/0/5");
  });

  it('throws DERIVATION_PATH_INVALID (code 1040) for negative account or index', () => {
    for (const error of [
      captureError(() => ethereumPath(-1, 0)),
      captureError(() => ethereumPath(0, -1)),
    ]) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe(ErrorCodes.DERIVATION_PATH_INVALID);
    }
  });

  it('throws DERIVATION_PATH_INVALID (code 1040) for non-integer account or index', () => {
    for (const error of [
      captureError(() => ethereumPath(1.5, 0)),
      captureError(() => ethereumPath(0, Number.NaN)),
    ]) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe(ErrorCodes.DERIVATION_PATH_INVALID);
    }
  });
});
