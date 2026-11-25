/**
 * OID4VP Authorization Request からの Transaction Data 抽出。
 *
 * OID4VP の `transaction_data` は base64url でエンコードされた JSON オブジェクトの配列。本モジュールは
 * 受領した生の base64url 文字列配列を検証・デコードし、`TransactionDataEntry[]` へ正規化する。
 * `encoded`（生 base64url）はそのまま保持し、`transaction_data_hashes` 計算（`hashes.ts`）の入力とする。
 *
 * スコープ外: Authorization Request 全体のパース（`auth/request.ts` の責務）。本モジュールは
 * パース済み Request から取り出した `transaction_data` 配列を受け取る純粋関数に留める。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` に Transaction Data 本文（金額・相手方等）を含めない。
 */

import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import { TRANSACTION_DATA_HASH_ALG, type TransactionDataEntry } from './types.js';

/** base64url 文字列を UTF-8 JSON としてデコードする。失敗は 8030 へ正規化する。 */
function decodeBase64urlJson(encoded: string): Record<string, unknown> {
  let text: string;
  try {
    text = new TextDecoder().decode(base64urlnopad.decode(encoded));
  } catch {
    // 本文を漏らさないため cause は握りつぶす。
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'transaction_data_decode_failed' },
    });
  }
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(text);
  } catch {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'transaction_data_decode_failed' },
    });
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'transaction_data_shape_invalid' },
    });
  }
  return parsed as Record<string, unknown>;
}

/** 非空文字列配列であることを検証して返す。不正は 8030。 */
function requireStringArray(value: unknown, reason: string): readonly string[] {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some((v) => typeof v !== 'string' || v.length === 0)
  ) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, { context: { reason } });
  }
  return value as string[];
}

/**
 * `transaction_data_hashes_alg` を検証・正規化する。
 *
 * 省略時は `['sha-256']`。指定時は非空文字列配列を要求し、本 SDK が対応する `sha-256` を
 * 含まないアルゴリズムセットは未対応として拒否する。
 */
function normalizeHashAlgorithms(raw: unknown): readonly string[] {
  if (raw === undefined) {
    return [TRANSACTION_DATA_HASH_ALG];
  }
  const algs = requireStringArray(raw, 'transaction_data_hashes_alg_invalid');
  if (!algs.includes(TRANSACTION_DATA_HASH_ALG)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'transaction_data_hashes_alg_unsupported' },
    });
  }
  return algs;
}

/**
 * 1 件の base64url Transaction Data を `TransactionDataEntry` へ正規化する。
 *
 * @throws `type` / `credential_ids` 欠落・不正、デコード失敗、未対応アルゴリズム時（8030）。
 */
function extractOne(encoded: string): TransactionDataEntry {
  if (typeof encoded !== 'string' || encoded.length === 0) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'transaction_data_empty' },
    });
  }
  const claims = decodeBase64urlJson(encoded);

  const { type } = claims;
  if (typeof type !== 'string' || type.length === 0) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'transaction_data_type_invalid' },
    });
  }
  const credentialIds = requireStringArray(
    claims.credential_ids,
    'transaction_data_credential_ids_invalid',
  );
  const hashAlgorithms = normalizeHashAlgorithms(claims.transaction_data_hashes_alg);

  return { type, credentialIds, hashAlgorithms, claims, encoded };
}

/**
 * OID4VP Authorization Request の `transaction_data` 配列を抽出・正規化する。
 *
 * `transaction_data` は base64url エンコードされた JSON オブジェクトの配列。各要素をデコードし、
 * `type` / `credential_ids` の必須検証と `transaction_data_hashes_alg` の正規化を行う。
 * 空配列や `undefined` は「Transaction Data 要求なし」として空配列を返す。
 *
 * @param transactionData Authorization Request 上の生 base64url 文字列配列（または未指定）。
 * @returns 正規化された `TransactionDataEntry[]`（要求なしなら空配列）。
 * @throws 配列でない / 要素が不正 / デコード失敗 / 未対応アルゴリズム時（VericertsError、code `8030`）。
 */
export function extractTransactionData(
  transactionData: readonly string[] | undefined,
): readonly TransactionDataEntry[] {
  if (transactionData === undefined) {
    return [];
  }
  if (!Array.isArray(transactionData)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'transaction_data_not_array' },
    });
  }
  return transactionData.map(extractOne);
}
