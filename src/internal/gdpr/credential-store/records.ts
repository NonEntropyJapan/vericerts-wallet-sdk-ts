/**
 * `CredentialStore` が扱う VC レコードの永続化プリミティブ（storage ポート・キー体系・読み書き）。
 *
 * GDPR の権利処理（訂正・処理制限・同意撤回・削除）は `store.ts` の `CredentialStore` が担い、本
 * モジュールは「どのキーに・どの符号化で置くか」だけを持つ。storage ポートをここに閉じることで、
 * 権利処理側は `Storage`（storage.ts）の実体を知らずに済む。
 */

import { decodeCredentialRecord, encodeCredentialRecord } from '../codec.js';
import type { CredentialRecord } from '../types.js';

/** storage 上で VC レコードを保存するキーの prefix（`matchCredentials` の候補列挙でも使うため export）。 */
export const CREDENTIAL_KEY_PREFIX = 'credential/';

/**
 * 永続化バックエンドへの最小依存。`Storage`（storage.ts）を構造的に満たす。循環 import を避けるため
 * `Storage` を直接 import せず、必要なメソッドのみを構造型として要求する（`persona/persona.ts` の構造的 Storage 依存と同パターン）。
 */
export interface CredentialStorage {
  get(key: string): Promise<Uint8Array | null>;
  set(key: string, value: Uint8Array): Promise<void>;
  delete(key: string): Promise<void>;
  list(prefix: string): Promise<string[]>;
}

/** VC ID から storage キーを組み立てる。 */
export function recordKey(id: string): string {
  return `${CREDENTIAL_KEY_PREFIX}${id}`;
}

/**
 * 保存済み VC レコードを読む。未存在なら `null`。
 *
 * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `3070`）。
 */
export async function readRecord(
  storage: CredentialStorage,
  vcId: string,
): Promise<CredentialRecord | null> {
  const stored = await storage.get(recordKey(vcId));
  return stored === null ? null : decodeCredentialRecord(stored);
}

/** VC レコードを書き込む（新規・更新とも `record.id` から導いた同一キーへ上書きする）。 */
export function writeRecord(storage: CredentialStorage, record: CredentialRecord): Promise<void> {
  return storage.set(recordKey(record.id), encodeCredentialRecord(record));
}
