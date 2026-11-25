/**
 * did:peer numalgo 4 のエンコード・デコード（短縮ハッシュ + 長形式）。
 *
 * DIF の peer-did-method-spec に従う。
 *
 * 長形式: `did:peer:4<hash>:<encoded-document>`。
 * - `encoded-document` = multibase(base58btc, multicodec(json) || utf8(compact-JSON))。
 * - `hash` = multibase(base58btc, multihash(sha2-256, utf8(encoded-document)))。
 * 短縮形（`did:peer:4<hash>` のみ）は長形式が無いと解決できない。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` に DID 文字列・ドキュメント内容などの入力データを含めない。
 * - `@scure/base` / JSON パース由来の例外は cause を渡さず `VericertsError`（code `2001`）へ正規化する。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import type { DIDDocument } from '../did.js';
import { MAX_PEER4_ENCODED_DOCUMENT_LENGTH } from '../did-format.js';
import {
  encodeMulticodecVarint,
  multibaseBase58Decode,
  multibaseBase58Encode,
} from '../multibase.js';

/** `did:peer:` メソッドプレフィックス（numalgo 付き短縮形組み立て用）。 */
const DID_PEER_PREFIX = 'did:peer:';

/** Multicodec `json`（0x0200）。エンコード済みドキュメントの prefix。 */
const MULTICODEC_JSON = 0x0200;

/** Multihash `sha2-256` のコード（0x12）。 */
const MULTIHASH_SHA2_256 = 0x12;

/** sha2-256 ダイジェスト長（32 バイト）。 */
const SHA2_256_LENGTH = 32;

/**
 * numalgo 4 の長形式本体（numalgo 直後）`<hash>:<encoded-document>` を組み立てる。
 *
 * @param document DID Document 本体。
 * @returns `<hash>:<encoded-document>` 文字列。
 */
export function encodeNumalgo4(document: Record<string, unknown>): string {
  const encodedDocument = encodeDocument(document);
  return `${encodeHash(encodedDocument)}:${encodedDocument}`;
}

/** エンコード済みドキュメント文字列を生成する（multibase(base58btc, multicodec(json) || utf8)）。 */
function encodeDocument(document: Record<string, unknown>): string {
  const jsonBytes = new TextEncoder().encode(JSON.stringify(document));
  const prefix = encodeMulticodecVarint(MULTICODEC_JSON);
  const payload = new Uint8Array(prefix.length + jsonBytes.length);
  payload.set(prefix, 0);
  payload.set(jsonBytes, prefix.length);
  return multibaseBase58Encode(payload);
}

/** 短縮ハッシュ文字列を生成する（multibase(base58btc, 0x12 || 0x20 || sha256(encoded-document)))。 */
function encodeHash(encodedDocument: string): string {
  const digest = sha256(new TextEncoder().encode(encodedDocument));
  const multihash = new Uint8Array(2 + digest.length);
  multihash[0] = MULTIHASH_SHA2_256;
  multihash[1] = SHA2_256_LENGTH;
  multihash.set(digest, 2);
  return multibaseBase58Encode(multihash);
}

/**
 * numalgo 4 の長形式本体（numalgo 直後）を解決する（ハッシュ検証 + ドキュメントデコード）。
 *
 * @param did 完全な DID 文字列（解決対象、長形式）。
 * @param rest numalgo 直後の文字列（`<hash>:<encoded-document>`）。
 * @returns DID Document。
 * @throws 形式不正・ハッシュ不一致・ドキュメントデコード失敗の場合（VericertsError、code `2001`）。
 */
export function resolveNumalgo4(did: string, rest: string): DIDDocument {
  const separator = rest.indexOf(':');
  if (separator < 0) {
    // 短縮形（hash のみ）は長形式が無いと解決不可（peer-did-method-spec）。
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const hash = rest.slice(0, separator);
  const encodedDocument = rest.slice(separator + 1);
  if (
    hash.length === 0 ||
    encodedDocument.length === 0 ||
    encodedDocument.length > MAX_PEER4_ENCODED_DOCUMENT_LENGTH
  ) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  // ハッシュ整合性を検証する。
  if (encodeHash(encodedDocument) !== hash) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const document = decodeDocument(encodedDocument);
  const shortForm = `${DID_PEER_PREFIX}4${hash}`;
  return finalizeDocument(document, did, shortForm);
}

/** エンコード済みドキュメント文字列を JSON オブジェクトへデコードする。 */
function decodeDocument(encodedDocument: string): Record<string, unknown> {
  const decoded = multibaseBase58Decode(encodedDocument, MAX_PEER4_ENCODED_DOCUMENT_LENGTH);
  const prefix = encodeMulticodecVarint(MULTICODEC_JSON);
  if (decoded.length <= prefix.length) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  for (let i = 0; i < prefix.length; i++) {
    if (decoded[i] !== prefix[i]) {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
  }
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(new TextDecoder().decode(decoded.subarray(prefix.length)));
  } catch {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  return parsed as Record<string, unknown>;
}

/**
 * デコードしたドキュメントに解決時の最終調整を施す。
 *
 * - `id` を解決対象 DID（長形式）に設定する。
 * - `alsoKnownAs` に短縮形 DID を追加する。
 * - 必須フィールド（@context / verificationMethod / authentication / assertionMethod）を検証する。
 *
 * @param document デコード済みドキュメント。
 * @param did 解決対象 DID（長形式）。
 * @param shortForm 短縮形 DID。
 * @returns DID Document。
 * @throws 必須フィールドが欠落・不正な場合（VericertsError、code `2001`）。
 */
function finalizeDocument(
  document: Record<string, unknown>,
  did: string,
  shortForm: string,
): DIDDocument {
  const required = [
    document['@context'],
    document.verificationMethod,
    document.authentication,
    document.assertionMethod,
  ];
  if (!required.every((field) => Array.isArray(field))) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const existingAka = document.alsoKnownAs;
  const alsoKnownAs = Array.isArray(existingAka)
    ? [...(existingAka as unknown[]), shortForm]
    : [shortForm];
  return { ...document, id: did, alsoKnownAs } as unknown as DIDDocument;
}
