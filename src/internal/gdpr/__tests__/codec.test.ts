/**
 * `gdpr/codec.ts` の decode 失敗時のエラーコード正規化の単体テスト。
 *
 * 破損レコードの正規化先はレコード種別で分かれる（codec.ts のモジュール doc）。
 * - `DashboardLogEntry`（GDPR 監査ログのレコード。VC ではない）→ `STORAGE_RECORD_CORRUPTED`(6005)
 * - `CredentialRecord`（VC 本体のレコード）→ `VC_NOT_FOUND`(3070)（従来どおり）
 *
 * `CredentialRecord` の全フィールドの encode/decode ラウンドトリップは、本ディレクトリの行数上限
 * （linterly `max_lines_per_directory`）を避けるため `credential-record/codec-round-trip.test.ts`
 * に分けている。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { decodeCredentialRecord, decodeDashboardLogEntry } from '../codec.js';

/** 文字列を storage 上のバイト列（UTF-8）として渡す。 */
const bytesOf = (text: string): Uint8Array => new TextEncoder().encode(text);

/** JSON としては読めるが必須フィールドを欠くレコード（型ガードで弾かれる形）。 */
const MISSING_FIELDS = bytesOf(JSON.stringify({ id: 'record-1' }));

/** `decode` を実行し、投げられた `VericertsError` を返す（投げなければテストを失敗させる）。 */
function thrownError(decode: () => unknown): VericertsError {
  try {
    decode();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    return e as VericertsError;
  }
  throw new Error('VericertsError が投げられませんでした');
}

describe('decodeDashboardLogEntry の破損時エラーコード', () => {
  it('JSON パースできないバイト列は STORAGE_RECORD_CORRUPTED(6005) を投げる', () => {
    const error = thrownError(() => decodeDashboardLogEntry(bytesOf('{ not json')));

    expect(error.code).toBe(ErrorCodes.STORAGE_RECORD_CORRUPTED);
    // 流用元の VC 専用コード（3070）に戻っていないことまで見る（回帰検知）。
    expect(error.code).toBe('6005');
    expect(error.category).toBe('storage');
  });

  it('必須フィールドを欠くレコードも STORAGE_RECORD_CORRUPTED(6005) を投げる', () => {
    const error = thrownError(() => decodeDashboardLogEntry(MISSING_FIELDS));

    expect(error.code).toBe(ErrorCodes.STORAGE_RECORD_CORRUPTED);
  });
});

describe('decodeCredentialRecord の破損時エラーコードは VC_NOT_FOUND(3070) のまま', () => {
  // VC レコードの破損は「その VC が見つからない」のと同義に扱う設計判断（codec.ts の JSDoc）。
  // 以前は DashboardLogEntry 側だけを 6005 へ移したため、こちら側の退行を回帰検知する。
  it('JSON パースできないバイト列は VC_NOT_FOUND(3070) を投げる', () => {
    const error = thrownError(() => decodeCredentialRecord(bytesOf('{ not json')));

    expect(error.code).toBe(ErrorCodes.VC_NOT_FOUND);
    expect(error.code).toBe('3070');
  });

  it('必須フィールドを欠くレコードも VC_NOT_FOUND(3070) を投げる', () => {
    const error = thrownError(() => decodeCredentialRecord(MISSING_FIELDS));

    expect(error.code).toBe(ErrorCodes.VC_NOT_FOUND);
  });
});
