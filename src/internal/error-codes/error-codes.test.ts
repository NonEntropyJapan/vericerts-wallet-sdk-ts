import { describe, expect, test } from 'bun:test';
import { ErrorCodes } from '../errors.js';
import { ACCOUNT_PROTOCOL_ERROR_CODES } from './account-protocol.js';
import { CREDENTIAL_ERROR_CODES } from './credential.js';
import { DIDCOMM_ERROR_CODES } from './didcomm.js';
import { KEY_DID_ERROR_CODES } from './key-did.js';
import { STORAGE_ERROR_CODES } from './storage.js';
import { TRUST_EUDI_ERROR_CODES } from './trust-eudi.js';

// ErrorCodes 本体の振る舞い（コード値・SSOT 整合）は errors.test.ts が担う。ここでは
// ドメイン別分割そのものが持ち込むリスク（結合時の取りこぼし）だけを対象にする。
describe('ErrorCodes のドメイン別分割（error-codes/*.ts）の結合整合', () => {
  // ErrorCodes はドメイン別の部分定数をスプレッド結合して構築する。結合ではキーが重複すると
  // 後勝ちで静かに潰れるため、ドメイン間のキー重複といずれかのドメインの取り込み漏れを回帰検知する。
  const PARTS = [
    KEY_DID_ERROR_CODES,
    CREDENTIAL_ERROR_CODES,
    ACCOUNT_PROTOCOL_ERROR_CODES,
    TRUST_EUDI_ERROR_CODES,
    STORAGE_ERROR_CODES,
    DIDCOMM_ERROR_CODES,
  ] as const;

  test('部分定数のキー数の総和が ErrorCodes のキー数と一致する（ドメイン間のキー重複なし）', () => {
    const total = PARTS.reduce((sum, part) => sum + Object.keys(part).length, 0);
    expect(total).toBe(Object.keys(ErrorCodes).length);
  });

  test('部分定数のエントリの和集合が ErrorCodes と完全一致する（取り込み漏れなし）', () => {
    const merged = Object.fromEntries(PARTS.flatMap((part) => Object.entries(part)));
    expect(merged).toEqual(ErrorCodes);
  });

  test('コード値に重複がない', () => {
    const values = Object.values(ErrorCodes);
    expect(new Set(values).size).toBe(values.length);
  });

  test('ErrorCodes は readonly（コンパイル時検証）', () => {
    // 関数は参照するだけで実行しない（実行すると ErrorCodes を実際に書き換えてしまう）。
    // スプレッド結合で readonly が落ちると @ts-expect-error が未使用になり `tsc --noEmit` が失敗する。
    const assertReadonly = (): void => {
      // 値は現行と同一にし、型不一致ではなく readonly 違反だけがエラー要因になるようにする。
      // @ts-expect-error ErrorCodes は as const で readonly のためプロパティへの再代入は不可。
      ErrorCodes.INVALID_MNEMONIC = '1001';
    };
    expect(typeof assertReadonly).toBe('function');
    expect(ErrorCodes.INVALID_MNEMONIC).toBe('1001');
  });
});
