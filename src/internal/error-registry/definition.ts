/**
 * ERROR_REGISTRY エントリの共通型定義。
 *
 * ドメイン別の定義ファイル（`key-did.ts` / `credential.ts` / `account-protocol.ts` /
 * `trust-eudi.ts`）と集約ファイル（`../error-registry.ts`）から共有する。
 */

import type { ErrorCode } from '../errors.js';

/**
 * レジストリ 1 エントリの定義。`category` は エラーの分類名、
 * `message` は秘密を含まない静的な日本語。
 */
export interface ErrorDefinition {
  readonly category: string;
  readonly retriable: boolean;
  readonly message: string;
}

/**
 * ドメイン別の部分レジストリの型。全ドメインを結合すると `Record<ErrorCode, ErrorDefinition>`
 * となる（各コードは errors.ts の `ErrorCode` union のいずれか）。
 */
export type ErrorRegistryPart = Partial<Record<ErrorCode, ErrorDefinition>>;
