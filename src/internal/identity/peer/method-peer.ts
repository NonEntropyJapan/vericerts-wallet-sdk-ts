/**
 * did:peer メソッド実装（P2P / DIDComm v2 向けレジストリ不要 DID）。
 *
 * peer-did-method-spec（DIF）の numalgo 0 / 2 / 4 に対応する。
 *
 * numalgo 別の DID 形式:
 * - 0: `did:peer:0<multibase(inception-key)>`（inception key のみ、did:key 相当）。
 * - 2: `did:peer:2.V<key>.E<key>.S<base64url(service)>` の連結（→ numalgo2.ts）。
 * - 4: `did:peer:4<hash>:<encoded-document>` の長形式（→ numalgo4.ts）。
 *
 * did:peer は更新非対応（新しい DID を生成する）。
 *
 * 本ファイルは numalgo 0・ディスパッチ・`MethodPeer` クラス・鍵符号化ヘルパを担う。
 * numalgo 2 / 4 の詳細は分割ファイルに委譲する（300 行上限のため）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・鍵バイト・サービス内容などの入力データを含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { CreateOptions, DIDDocument, DIDMethod, Service, UpdateOptions } from '../did.js';
import {
  encodeMulticodecVarint,
  multibaseBase58Decode,
  multibaseBase58Encode,
} from '../multibase.js';
import { encodeNumalgo2Elements, resolveNumalgo2 } from './numalgo2.js';
import { encodeNumalgo4, resolveNumalgo4 } from './numalgo4.js';

/** `did:peer:` メソッドプレフィックス。 */
const DID_PEER_PREFIX = 'did:peer:';

/**
 * numalgo 0 の DID を生成する（inception key のみ、did:key 相当）。
 *
 * @param inceptionKeyMultibase multibase(base58btc) 表現の inception 公開鍵（`z...`）。
 * @returns `did:peer:0<multibase>` 形式の DID 文字列。
 * @throws multibase 形式が不正な場合（VericertsError、code `2001`）。
 */
export function createDidPeer0(inceptionKeyMultibase: string): string {
  // multibase として妥当か（z + base58btc）を検証する。鍵バイトはメッセージに含めない。
  multibaseBase58Decode(inceptionKeyMultibase);
  return `${DID_PEER_PREFIX}0${inceptionKeyMultibase}`;
}

/**
 * numalgo 2 の DID を生成する。
 *
 * @param opts 鍵要素（V / E）とサービス（S）。
 * @returns `did:peer:2.V...E...S...` 形式の DID 文字列。
 * @throws 鍵 multibase 不正・署名鍵未指定の場合（VericertsError、code `2001`）。
 */
export function createDidPeer2(opts: {
  /** 署名鍵（multibase base58btc、`z...`）。少なくとも 1 つ必要。 */
  readonly verificationKeys: readonly string[];
  /** 暗号鍵（multibase base58btc、`z...`）。省略可。 */
  readonly keyAgreementKeys?: readonly string[];
  /** サービス（DIDComm v2 等）。省略可。 */
  readonly services?: readonly Service[];
}): string {
  const elements = encodeNumalgo2Elements(
    // 任意キー・サービスの省略時に `Object.prototype` 汚染値が DID に混入しないよう own 限定で読む。
    ownProperty<readonly string[]>(opts, 'verificationKeys') ?? [],
    ownProperty<readonly string[]>(opts, 'keyAgreementKeys') ?? [],
    ownProperty<readonly Service[]>(opts, 'services') ?? [],
  );
  return `${DID_PEER_PREFIX}2${elements}`;
}

/**
 * numalgo 4 の長形式 DID を生成する。
 *
 * @param document DID Document 本体（`id` は付与しない / されていてもエンコード対象に含む）。
 * @returns `did:peer:4<hash>:<encoded-document>` 形式の DID 文字列。
 */
export function createDidPeer4(document: Record<string, unknown>): string {
  return `${DID_PEER_PREFIX}4${encodeNumalgo4(document)}`;
}

/**
 * did:peer 文字列を DID Document に解決する。
 *
 * numalgo（プレフィックス直後の 1 文字）で分岐する。
 *
 * @param did did:peer 文字列。
 * @returns DID Document。
 * @throws プレフィックス不正・未対応 numalgo・要素不正の場合（VericertsError、code `2001`）。
 */
export function resolveDidPeer(did: string): DIDDocument {
  if (!did.startsWith(DID_PEER_PREFIX)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const body = did.slice(DID_PEER_PREFIX.length);
  const numalgo = body[0];
  const rest = body.slice(1);
  switch (numalgo) {
    case '0':
      return resolveNumalgo0(did, rest);
    case '2':
      return resolveNumalgo2(did, rest);
    case '4':
      return resolveNumalgo4(did, rest);
    default:
      throw new VericertsError(ErrorCodes.INVALID_DID);
  }
}

/**
 * numalgo 0 を解決する（inception key のみ）。
 *
 * @param did 完全な DID 文字列。
 * @param keyMultibase inception 鍵の multibase 表現（`z...`）。
 * @returns DID Document。
 * @throws multibase 不正・空の場合（VericertsError、code `2001`）。
 */
function resolveNumalgo0(did: string, keyMultibase: string): DIDDocument {
  if (keyMultibase.length === 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  // multibase として妥当か検証する（鍵バイトはメッセージに含めない）。
  multibaseBase58Decode(keyMultibase);
  const methodId = `${did}#${keyMultibase}`;
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    verificationMethod: [
      { id: methodId, type: 'Multikey', controller: did, publicKeyMultibase: keyMultibase },
    ],
    authentication: [methodId],
    assertionMethod: [methodId],
  };
}

/**
 * did:peer メソッドプラグイン（numalgo 0 / 2 / 4）。
 *
 * `create` は numalgo 2 を生成する。
 * 生成では `opts.publicKey` を `keyType` に応じた multibase 鍵に変換して `.V` 要素にする。
 * did:peer は更新非対応のため `update` / `deactivate` は `METHOD_NOT_SUPPORTED`（code `2002`）。
 */
export class MethodPeer implements DIDMethod {
  /** メソッド名（`'peer'`）。 */
  method(): string {
    return 'peer';
  }

  /**
   * 公開鍵から did:peer numalgo 2 の DID Document を生成して解決済みドキュメントを返す。
   *
   * `opts.publicKey` を did:key 同様の multicodec varint || raw で multibase 化し、
   * 署名鍵（`.V`）として numalgo 2 DID を構築・解決する。
   */
  async create(opts: CreateOptions): Promise<DIDDocument> {
    const keyMultibase = encodePublicKeyMultibase(opts.keyType, opts.publicKey);
    const did = createDidPeer2({ verificationKeys: [keyMultibase] });
    return resolveDidPeer(did);
  }

  /** did:peer 文字列（numalgo 0 / 2 / 4）を DID Document に解決する。 */
  async resolve(did: string): Promise<DIDDocument> {
    return resolveDidPeer(did);
  }

  /** did:peer は更新非対応（新しい DID を生成する。code `2002`）。 */
  async update(_did: string, _opts: UpdateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** did:peer は無効化非対応（ピア間合意で破棄。code `2002`）。 */
  async deactivate(_did: string): Promise<void> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }
}

/** 鍵タイプ → Multicodec コード / 公開鍵長（did:key と同一の対応）。 */
const PUBLIC_KEY_CODECS: Record<string, { codec: number; length: number }> = {
  Ed25519: { codec: 0xed, length: 32 },
  secp256k1: { codec: 0xe7, length: 33 },
  'P-256': { codec: 0x1200, length: 33 },
};

/**
 * raw 公開鍵を did:key 同様の multibase(base58btc, multicodec || raw) へ符号化する。
 *
 * @param keyType 公開鍵の鍵タイプ。
 * @param publicKey raw 公開鍵バイト列。
 * @returns multibase 文字列（`z...`）。
 * @throws 未対応鍵タイプ・公開鍵長不一致の場合（VericertsError、code `2001`）。
 */
export function encodePublicKeyMultibase(keyType: string, publicKey: Uint8Array): string {
  const spec = PUBLIC_KEY_CODECS[keyType];
  if (spec === undefined || publicKey.length !== spec.length) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const prefix = encodeMulticodecVarint(spec.codec);
  const payload = new Uint8Array(prefix.length + publicKey.length);
  payload.set(prefix, 0);
  payload.set(publicKey, prefix.length);
  return multibaseBase58Encode(payload);
}
