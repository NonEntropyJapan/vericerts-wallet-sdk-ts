/**
 * DID Document の書き出し。ネットワークへの書き込みは一切しない（ファイル内容の文字列を返すだけ）。
 *
 * - {@link buildDidCoreDocument}: 公開鍵 JWK から W3C DID Core の DID Document（JSON）を作る。検証メソッドは
 *   `JsonWebKey2020`（did:jwk と同じ型・コンテキスト）で、`authentication` / `assertionMethod`（既定。
 *   `capabilityInvocation` / `capabilityDelegation` も付ける）に載せる。did:web・did:webvh・did:ion・did:cheqd・
 *   did:ebsi・did:ipid など、メソッド固有の公開手段（ファイル配置・ログ・Sidetree・チェーン Tx・IPNS）を
 *   取る DID に対して、**DID Core の文書そのもの**だけを提供する。メソッド固有の成果物（webvh のログ証明、
 *   Sidetree 操作要求、チェーン Tx など）は作らない。
 * - {@link didWebDocumentLocation}: did:web の `did.json` の配置先（did:web 仕様 §3.2 / §3.3 の変換規則）。
 *   `did:web:example.com` → `https://example.com/.well-known/did.json`、
 *   `did:web:example.com:users:alice` → `https://example.com/users/alice/did.json`。
 * - {@link buildDidWebDocument}: did:web `did.json` の内容（上記 2 つの組み合わせ）。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { DIDDocument, PublicKeyJwk, VerificationMethod } from '../../identity/did.js';
import { didWebToUrl } from '../../identity/web/method-web.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { algForPublicKeyJwk } from './public-key-jwk.js';

/** 書き出す検証メソッドの type（did:jwk と同じ。公開鍵は `publicKeyJwk`）。 */
const VERIFICATION_METHOD_TYPE = 'JsonWebKey2020';

/** JSON-LD コンテキスト（did:jwk の DID Document と同じ）。 */
const DID_CORE_CONTEXT: readonly string[] = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/suites/jws-2020/v1',
];

/** `buildDidCoreDocument` の入力。 */
export interface DidCoreDocumentInput {
  /** 文書の `id`（DID）。 */
  readonly did: string;
  /** 公開する公開鍵 JWK（秘密鍵 `d` を含んではならない）。 */
  readonly publicKeyJwk: PublicKeyJwk;
  /** 検証メソッドの fragment（`#` を除く）。省略時は `key-1`。 */
  readonly fragment?: string;
  /** DID Core の `controller`。省略時は出力しない（DID 自身が controller）。 */
  readonly controller?: string;
}

/**
 * 公開鍵 JWK から DID Core の DID Document（JSON オブジェクト）を作る。
 *
 * @throws 秘密鍵パラメータ（`d`）を含む・未対応の鍵種の場合（VericertsError、code `1003` / `1030`）。
 */
export function buildDidCoreDocument(input: DidCoreDocumentInput): DIDDocument {
  if (Object.hasOwn(input.publicKeyJwk, 'd')) {
    throw new VericertsError(ErrorCodes.INVALID_PRIVATE_KEY);
  }
  algForPublicKeyJwk(input.publicKeyJwk);
  const fragment = ownProperty<string>(input, 'fragment') ?? 'key-1';
  const controller = ownProperty<string>(input, 'controller');
  const id = `${input.did}#${fragment}`;
  const method: VerificationMethod = {
    id,
    type: VERIFICATION_METHOD_TYPE,
    controller: input.did,
    publicKeyJwk: input.publicKeyJwk,
  };
  return {
    '@context': DID_CORE_CONTEXT,
    id: input.did,
    ...(controller !== undefined ? { controller } : {}),
    verificationMethod: [method],
    authentication: [id],
    assertionMethod: [id],
    capabilityInvocation: [id],
    capabilityDelegation: [id],
  };
}

/** DID Document を配置用の JSON 文字列（2 スペースインデント・末尾改行）にする。 */
export function serializeDidDocument(document: DIDDocument): string {
  return `${JSON.stringify(document, null, 2)}\n`;
}

/** did:web の `did.json` の配置先。 */
export interface DidWebLocation {
  /** 取得に使われる HTTPS URL（`didWebToUrl` と同じ）。 */
  readonly url: string;
  /** ホスト名（ポート付き）。 */
  readonly host: string;
  /** ドキュメントルートからの相対パス（`.well-known/did.json` または `<path>/did.json`）。 */
  readonly path: string;
}

/**
 * did:web の DID から `did.json` の配置先を求める。
 *
 * @throws did:web として不正な場合（VericertsError、code `2001`）。
 */
export function didWebDocumentLocation(did: string): DidWebLocation {
  const url = new URL(didWebToUrl(did));
  return { url: url.href, host: url.host, path: url.pathname.slice(1) };
}

/** did:web の `did.json`（配置先と内容）。 */
export interface DidWebExport extends DidWebLocation {
  /** `did.json` の内容（JSON 文字列）。 */
  readonly content: string;
  /** 同じ内容の DID Document オブジェクト。 */
  readonly document: DIDDocument;
}

/**
 * did:web の `did.json` を作る（配置先と内容を返すだけ。書き込みはしない）。
 *
 * 公開したあと、`importPersonaFromDid` で取り込めば DID Document の鍵と保持鍵の一致が確認される。
 *
 * @throws did:web として不正（`2001`）、秘密鍵を含む（`1003`）、未対応の鍵種（`1030`）。
 */
export function buildDidWebDocument(input: DidCoreDocumentInput): DidWebExport {
  const location = didWebDocumentLocation(input.did);
  const document = buildDidCoreDocument(input);
  return { ...location, document, content: serializeDidDocument(document) };
}
