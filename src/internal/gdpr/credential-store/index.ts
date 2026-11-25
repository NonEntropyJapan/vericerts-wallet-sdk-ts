/**
 * GDPR 対象 VC レコードのストア。実装は責務ごとに `store.ts`（権利処理）と
 * `records.ts`（永続化プリミティブ）へ分かれており、本モジュールは公開面をまとめる。
 */

export { CredentialStore } from './store.js';
