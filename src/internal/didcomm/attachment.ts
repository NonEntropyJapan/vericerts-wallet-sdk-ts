import { ownProperty } from '../prototype-safety/own-property.js';
import type { DIDCommAttachment, DIDCommPlaintextMessage } from './types.js';

/**
 * メッセージの添付のうち、`data.base64` を own で持つ最初のものの `data.base64` を返す（無ければ `undefined`）。
 *
 * `attachments` / 各 `data` / `base64` は**すべて own 限定**で読む。`data` は型では必須だが実体は受信メッセージ（JSON）で、
 * 省略した添付が `Object.prototype.data`（`{ base64: <攻撃者の JWT> }`）を拾うと、取り出した JWT-VC / JWT-VP が攻撃者の値に
 * なる。非オブジェクトの要素・`data` は添付として扱わず読み飛ばす（生 `TypeError` を漏らさない）。
 */
export function firstBase64Attachment(message: DIDCommPlaintextMessage): unknown {
  const attachments = ownProperty<readonly DIDCommAttachment[]>(message, 'attachments') ?? [];
  for (const entry of attachments) {
    if (typeof entry !== 'object' || entry === null) {
      continue;
    }
    const data = ownProperty<unknown>(entry, 'data');
    if (typeof data !== 'object' || data === null) {
      continue;
    }
    const encoded = ownProperty<unknown>(data, 'base64');
    if (encoded !== undefined) {
      return encoded;
    }
  }
  return undefined;
}
