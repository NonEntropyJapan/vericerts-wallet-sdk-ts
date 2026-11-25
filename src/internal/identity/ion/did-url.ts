/**
 * Sidetree の DID Document の相対 DID URL を絶対化する。
 *
 * Sidetree は文書鍵・サービスの `id` と検証関係の参照を `#<id>` の相対 DID URL で返す。署名検証側は
 * `kid`（`<did>#<fragment>`）と検証メソッドの `id` を完全一致で突き合わせるため、`#` 始まりの値に
 * 文書の `id` を前置して絶対 DID URL にそろえる。それ以外の値（絶対 DID URL など）は変えない。
 * 配列でない・オブジェクトでない要素は形状検査（`assertNetworkDidDocumentShape`）が先に拒否している前提で、
 * ここでは触らない。省略された必須の 3 配列（`verificationMethod` / `authentication` / `assertionMethod`）は
 * 空配列で埋める（Sidetree は空の項目を省略する）。
 */

import { ownProperty } from '../../prototype-safety/own-property.js';
import type { DIDDocument, VerificationMethod } from '../did.js';
import { RELATIONSHIP_KEYS } from '../did-document-read.js';

function absolutize(id: unknown, did: string): unknown {
  return typeof id === 'string' && id.startsWith('#') ? `${did}${id}` : id;
}

/** `id` を絶対化した浅いコピー（`id` を持たない・オブジェクトでない値はそのまま）。 */
function withAbsoluteId<T>(entry: T, did: string): T {
  if (typeof entry !== 'object' || entry === null) {
    return entry;
  }
  return { __proto__: null, ...entry, id: absolutize(ownProperty<unknown>(entry, 'id'), did) };
}

/**
 * 文書の相対 DID URL を `did` 基準で絶対化した DID Document を返す（入力は変更しない）。
 *
 * @param document 形状検査済みの DID Document。
 * @param did 文書の `id`（検証済み）。
 */
export function absolutizeDidUrls(document: DIDDocument, did: string): DIDDocument {
  // パース境界で除いたプロトタイプをコピー時に戻さず、欠落値と継承アクセサを分離する。
  const out: Record<string, unknown> = { __proto__: null, ...document };
  for (const key of ['verificationMethod', 'authentication', 'assertionMethod'] as const) {
    out[key] ??= [];
  }
  const methods = ownProperty<readonly VerificationMethod[]>(document, 'verificationMethod');
  if (methods !== undefined) {
    out.verificationMethod = methods.map((vm) => withAbsoluteId(vm, did));
  }
  for (const key of RELATIONSHIP_KEYS) {
    const entries = ownProperty<readonly (string | VerificationMethod)[]>(document, key);
    if (entries !== undefined) {
      out[key] = entries.map((entry) =>
        typeof entry === 'string' ? absolutize(entry, did) : withAbsoluteId(entry, did),
      );
    }
  }
  const services = ownProperty<readonly unknown[]>(document, 'service');
  if (services !== undefined) {
    out.service = services.map((service) => withAbsoluteId(service, did));
  }
  return out as unknown as DIDDocument;
}
