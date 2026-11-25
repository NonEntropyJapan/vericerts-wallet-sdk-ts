/**
 * did:key メソッド実装（公開鍵ベース DID）。
 *
 * did:key はネットワーク通信不要で、公開鍵から DID と DID Document をローカル生成する:
 *   `did:key:<multibase(base58btc, multicodec_prefix || raw_public_key_bytes)>`
 *
 * 対応鍵タイプ（P-256 は本実装の拡張）:
 *
 * | 鍵タイプ  | Multicodec | 公開鍵長 | VerificationMethod type             |
 * | --------- | ---------- | -------- | ----------------------------------- |
 * | Ed25519   | `0xed01`   | raw 32B  | `Ed25519VerificationKey2020`        |
 * | secp256k1 | `0xe701`   | 圧縮 33B | `EcdsaSecp256k1VerificationKey2019` |
 * | P-256     | `0x1200`   | 圧縮 33B | `Multikey`                          |
 *
 * did:key は不変のため `update` / `deactivate` は非対応（code `2002`）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・公開鍵バイトを含めない。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import type { CreateOptions, DIDDocument, DIDMethod, DidKeyType, UpdateOptions } from './did.js';
import {
  encodeMulticodecVarint,
  multibaseBase58Decode,
  multibaseBase58Encode,
} from './multibase.js';

/** 鍵タイプごとの did:key パラメータ（Multicodec / 公開鍵長 / VerificationMethod type）。 */
interface KeyTypeSpec {
  /** Multicodec コード（unsigned LEB128 varint でエンコードして prefix にする）。 */
  readonly codec: number;
  /** 期待する raw 公開鍵長（バイト）。 */
  readonly publicKeyLength: number;
  /** VerificationMethod の type。 */
  readonly verificationMethodType: string;
}

/**
 * 鍵タイプ → did:key パラメータの対応表。
 *
 * `codec` は Multicodec の数値コード。unsigned LEB128 varint へエンコードすると
 * 次の multicodec プレフィックスバイト列になる:
 * - Ed25519: 0xed → [0xed, 0x01]
 * - secp256k1: 0xe7 → [0xe7, 0x01]
 * - P-256: 0x1200 → [0x80, 0x24]
 */
const KEY_TYPE_SPECS: Record<DidKeyType, KeyTypeSpec> = {
  Ed25519: {
    codec: 0xed,
    publicKeyLength: 32,
    verificationMethodType: 'Ed25519VerificationKey2020',
  },
  secp256k1: {
    codec: 0xe7,
    publicKeyLength: 33,
    verificationMethodType: 'EcdsaSecp256k1VerificationKey2019',
  },
  'P-256': {
    codec: 0x1200,
    publicKeyLength: 33,
    verificationMethodType: 'Multikey',
  },
};

/** `did:key:` メソッドプレフィックス。 */
const DID_KEY_PREFIX = 'did:key:';

/**
 * 鍵タイプごとの canonical Multicodec varint prefix（再エンコード照合用）。
 *
 * `encodeMulticodecVarint` で生成した既知 codec の prefix をそのまま保持する。
 * resolve 時はデコード列の先頭がこのいずれかと「完全一致」する場合のみ採用し、
 * 非 canonical varint（継続ビットの誤用）・未知 codec・長さ不一致を弾く。
 */
const CANONICAL_PREFIXES: ReadonlyArray<readonly [Uint8Array, DidKeyType]> = (
  Object.keys(KEY_TYPE_SPECS) as DidKeyType[]
).map((keyType) => [encodeMulticodecVarint(KEY_TYPE_SPECS[keyType].codec), keyType]);

/**
 * 与えられた DID Document 部品から、DID Document を組み立てる。
 *
 * @param did DID 文字列（`did:key:<keyId>`）。
 * @param keyId multibase 部分（`z...`）。
 * @param verificationMethodType VerificationMethod の type。
 * @returns DID Document。
 */
function buildDidDocument(did: string, keyId: string, verificationMethodType: string): DIDDocument {
  const methodId = `${did}#${keyId}`;
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    verificationMethod: [
      {
        id: methodId,
        type: verificationMethodType,
        controller: did,
        publicKeyMultibase: keyId,
      },
    ],
    authentication: [methodId],
    assertionMethod: [methodId],
  };
}

/**
 * 公開鍵から did:key の DID Document を生成する。
 *
 * @param keyType 公開鍵の鍵タイプ。
 * @param publicKey raw 公開鍵バイト列（鍵タイプに応じた長さ）。
 * @returns DID Document。
 * @throws 未対応の鍵タイプ・公開鍵長不一致の場合（VericertsError、code `2001`）。
 */
export function createDidKey(keyType: DidKeyType, publicKey: Uint8Array): DIDDocument {
  const spec = KEY_TYPE_SPECS[keyType];
  if (spec === undefined) {
    // 型外の鍵タイプ（実行時に不正な値が渡された場合）は DID 形式不正に正規化する。
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  if (publicKey.length !== spec.publicKeyLength) {
    // 公開鍵バイトはメッセージに含めない。
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const prefix = encodeMulticodecVarint(spec.codec);
  const payload = new Uint8Array(prefix.length + publicKey.length);
  payload.set(prefix, 0);
  payload.set(publicKey, prefix.length);
  const keyId = multibaseBase58Encode(payload);
  const did = `${DID_KEY_PREFIX}${keyId}`;
  return buildDidDocument(did, keyId, spec.verificationMethodType);
}

/**
 * did:key 文字列を鍵タイプと raw 公開鍵に分解する（`resolveDidKey` と同じ検査）。
 *
 * DID Document を必要とせず鍵だけを取り出したい呼び出し側（did:plc の `rotationKeys` 等、`did:key`
 * 表記で鍵を持つ他メソッド）用。曲線上の点としての妥当性は検査しない（長さと multicodec のみ）。
 *
 * @param did did:key 文字列（`did:key:z...`）。
 * @returns 鍵タイプと raw 公開鍵（Ed25519=32B、secp256k1 / P-256=圧縮 33B）。
 * @throws プレフィックス不正・base58 不正・未知 multicodec・公開鍵長不一致・空 identifier の場合
 *         （VericertsError、code `2001`）。
 */
export function parseDidKey(did: string): { keyType: DidKeyType; publicKey: Uint8Array } {
  if (!did.startsWith(DID_KEY_PREFIX)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const keyId = did.slice(DID_KEY_PREFIX.length);
  if (keyId.length === 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const decoded = multibaseBase58Decode(keyId);
  const { keyType, prefixLength } = decodeMulticodecKeyType(decoded);
  const publicKey = decoded.subarray(prefixLength);
  if (publicKey.length !== KEY_TYPE_SPECS[keyType].publicKeyLength) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  return { keyType, publicKey };
}

/**
 * did:key 文字列を DID Document に解決する。
 *
 * 手順:
 * 1. `did:key:` プレフィックスを除去。
 * 2. multibase(base58btc) デコード。
 * 3. Multicodec プレフィックスから鍵タイプを判定。
 * 4. 公開鍵長を検証し、DID Document を構築。
 *
 * @param did did:key 文字列（`did:key:z...`）。
 * @returns DID Document。
 * @throws プレフィックス不正・base58 不正・未知 multicodec・公開鍵長不一致・空 identifier の
 *         場合（VericertsError、code `2001`）。
 */
export function resolveDidKey(did: string): DIDDocument {
  const { keyType } = parseDidKey(did);
  return buildDidDocument(
    did,
    did.slice(DID_KEY_PREFIX.length),
    KEY_TYPE_SPECS[keyType].verificationMethodType,
  );
}

/**
 * デコード済みペイロード先頭の Multicodec varint から鍵タイプを判定する。
 *
 * 既知 3 codec（Ed25519 / secp256k1 / P-256）を `encodeMulticodecVarint` で
 * 再エンコードした canonical prefix のいずれかと、デコード列の先頭が「完全一致」する
 * 場合のみその鍵タイプを採用する。一致しなければ DID 形式不正（code `2001`）。
 *
 * canonical 再エンコード照合により、非 canonical varint（継続ビットの誤用、
 * 例 `[0xed, 0x81, ...]`）・未知 codec・長さ不一致を確実に弾く。
 *
 * @param decoded multibase デコード済みバイト列（`prefix || publicKey`）。
 * @returns 判定した鍵タイプと prefix のバイト長。
 * @throws prefix が既知 canonical のいずれにも一致しない場合（VericertsError、code `2001`）。
 */
function decodeMulticodecKeyType(decoded: Uint8Array): {
  keyType: DidKeyType;
  prefixLength: number;
} {
  for (const [prefix, keyType] of CANONICAL_PREFIXES) {
    if (hasPrefix(decoded, prefix)) {
      return { keyType, prefixLength: prefix.length };
    }
  }
  throw new VericertsError(ErrorCodes.INVALID_DID);
}

/** `bytes` の先頭が `prefix` と完全一致するか。 */
function hasPrefix(bytes: Uint8Array, prefix: Uint8Array): boolean {
  if (bytes.length < prefix.length) {
    return false;
  }
  for (let i = 0; i < prefix.length; i++) {
    if (bytes[i] !== prefix[i]) {
      return false;
    }
  }
  return true;
}

/**
 * did:key メソッドプラグイン。
 *
 * `create` / `resolve` を提供する。did:key は不変のため `update` / `deactivate` は
 * 非対応で、`METHOD_NOT_SUPPORTED`（code `2002`）を投げる。
 */
export class MethodKey implements DIDMethod {
  /** メソッド名（`'key'`）。 */
  method(): string {
    return 'key';
  }

  /** 公開鍵から DID Document を生成する。 */
  async create(opts: CreateOptions): Promise<DIDDocument> {
    return createDidKey(opts.keyType, opts.publicKey);
  }

  /** did:key 文字列を DID Document に解決する。 */
  async resolve(did: string): Promise<DIDDocument> {
    return resolveDidKey(did);
  }

  /** did:key は不変のため更新非対応（code `2002`）。 */
  async update(_did: string, _opts: UpdateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** did:key は不変のため無効化非対応（code `2002`）。 */
  async deactivate(_did: string): Promise<void> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }
}
