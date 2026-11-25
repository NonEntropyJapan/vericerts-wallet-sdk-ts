/**
 * did:ipid の CID と取得コンテンツの照合。
 *
 * `did:ipid:<CID>` は「CID が指す内容そのもの」を DID Document とするイミュータブル DID である。
 * Gateway は運営者を信頼するしかない第三者なので、返ってきたバイト列が CID と一致するかを
 * 呼び出し側で確かめなければ、悪意ある / 侵害された Gateway が任意の CID に対して任意の検証鍵を
 * 含む Document を返せる（コンテンツアドレスの保証が「Gateway を信頼する」に退化する）。
 *
 * **検証できる CID の範囲。** `GET <gateway>/ipfs/<CID>` が返すのはファイルの中身であって
 * ブロックそのものではない。中身のハッシュが CID のダイジェストと一致する（= 中身だけで照合できる）
 * のは、単一ブロックの raw leaf（CIDv1・codec `raw`(0x55)・`sha2-256`）に限られる。SDK の `create`
 * が使う `POST /api/v0/add?cid-version=1` は DID Document のような 256 KiB 未満のファイルでこの形の
 * CID を返す。dag-pb（UnixFS ラッパ / チャンク分割）等は中身から CID を再計算できず、Gateway の主張を
 * 検証する手段が無いので **fail-closed で拒否する**（`unsupported`）。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base58, hex } from '@scure/base';
import { decodeMultibase, MAX_CONTENT_HASH_TEXT_LENGTH } from '../content-hash/digest-codec.js';
import { decodeMultihash } from '../content-hash/multihash.js';

/** CID バージョン 1 のバージョンバイト。 */
const CID_VERSION_1 = 0x01;
/** multicodec `raw`（バイト列そのものがブロック）。1 バイトの varint。 */
const CODEC_RAW = 0x55;
/** multicodec `libp2p-key`（IPNS 名 = libp2p 公開鍵の CIDv1 表現）。1 バイトの varint。 */
const CODEC_LIBP2P_KEY = 0x72;
/** multihash `identity`（公開鍵そのものを埋め込む libp2p PeerID の `12D3Koo...` 形式）。 */
const MULTIHASH_IDENTITY = 0x00;
/** multihash `sha2-256` のコード。 */
const MULTIHASH_SHA2_256 = 0x12;
/** `sha2-256` ダイジェスト長（バイト）。 */
const SHA2_256_LENGTH = 32;

/** multibase `base36`（小文字）のプレフィックス。`@scure/base` に無いため本モジュールで復号する。 */
const BASE36_PREFIX = 'k';

/** base36（小文字）本体を BigInt 経由でバイト列へ戻す。正準形（先頭 `0` 無し）以外は拒否する。 */
function decodeBase36(body: string): Uint8Array | undefined {
  if (!/^[1-9a-z][0-9a-z]*$/.test(body)) {
    return undefined;
  }
  let value = 0n;
  for (const char of body) {
    value = value * 36n + BigInt(Number.parseInt(char, 36));
  }
  const text = value.toString(16);
  return hex.decode(text.length % 2 === 0 ? text : `0${text}`);
}

/**
 * did:ipid の method-specific id を CID / PeerID のバイト列へ復号する。
 *
 * - 先頭が `Qm` / `1` の識別子は multibase プレフィックス無しの base58btc（CIDv0 `Qm...` 46 文字、
 *   libp2p PeerID `12D3Koo...`）。`Q` / `1` は multibase のプレフィックス文字ではないので曖昧さは無い。
 * - それ以外は multibase（`b` base32 / `k` base36 / `f` / `z` ...）の CIDv1。
 *
 * @returns 復号したバイト列（CIDv0 / PeerID は multihash、CIDv1 は `<version><codec><multihash>`）。
 *   復号できない・長さ上限超過なら `undefined`。
 */
export function decodeIpidIdentifierBytes(identifier: string): Uint8Array | undefined {
  if (identifier.length > MAX_CONTENT_HASH_TEXT_LENGTH) {
    return undefined;
  }
  if (identifier.startsWith('Qm') || identifier.startsWith('1')) {
    try {
      return base58.decode(identifier);
    } catch {
      return undefined;
    }
  }
  if (identifier.startsWith(BASE36_PREFIX)) {
    const bytes = decodeBase36(identifier.slice(1));
    return bytes !== undefined && bytes[0] === CID_VERSION_1 ? bytes : undefined;
  }
  return decodeMultibase(identifier);
}

/**
 * 識別子を実際に復号して IPNS 名か CID かを分類する。先頭文字ヒューリスティックは使わない。
 *
 * - IPNS 名: CIDv1 で codec が `libp2p-key`（0x72）、または multihash `identity` の PeerID（`12D3Koo...`）。
 * - CID: 上記以外の CIDv1（`raw` / `dag-pb` 等）と CIDv0（`Qm...`。sha2-256 multihash）。
 *   base36（`k...`）や CIDv0 でも CID は取得本文のハッシュ照合の対象になる。
 *
 * 旧 RSA 鍵の IPNS 名（`Qm...`）は CIDv0 と同形で区別できない。**CID 側（本文照合、照合不能なら拒否）
 * に倒す**（Gateway の応答を無検証で受理しない fail-closed）。
 *
 * @returns `ipns` / `cid`。CID としても PeerID としても復号できなければ `undefined`。
 */
export function classifyIpidIdentifier(identifier: string): 'cid' | 'ipns' | undefined {
  const bytes = decodeIpidIdentifierBytes(identifier);
  if (bytes === undefined) {
    return undefined;
  }
  if (bytes[0] === CID_VERSION_1) {
    return bytes[1] === CODEC_LIBP2P_KEY ? 'ipns' : 'cid';
  }
  const multihash = decodeMultihash(bytes);
  if (multihash === undefined) {
    return undefined;
  }
  if (multihash.code === MULTIHASH_IDENTITY) {
    return 'ipns';
  }
  return multihash.code === MULTIHASH_SHA2_256 && multihash.digest.length === SHA2_256_LENGTH
    ? 'cid'
    : undefined;
}

/** CID と取得コンテンツの照合結果。 */
export type CidVerification = 'match' | 'mismatch' | 'unsupported';

/**
 * 取得コンテンツが CID のダイジェストと一致するか検証する。
 *
 * @param cid multibase 文字列の CID（`did:ipid:` の method-specific id）。
 * @param content Gateway から取得したバイト列。
 * @returns 一致なら `match`、ダイジェスト不一致なら `mismatch`、中身だけでは照合できない CID
 *   （CIDv0 / dag-pb / `sha2-256` 以外 / デコード不能）なら `unsupported`。
 */
export function verifyRawCidContent(cid: string, content: Uint8Array): CidVerification {
  const bytes = decodeIpidIdentifierBytes(cid);
  if (bytes === undefined || bytes[0] !== CID_VERSION_1 || bytes[1] !== CODEC_RAW) {
    return 'unsupported';
  }
  const multihash = decodeMultihash(bytes.subarray(2));
  if (
    multihash === undefined ||
    multihash.code !== MULTIHASH_SHA2_256 ||
    multihash.digest.length !== SHA2_256_LENGTH
  ) {
    return 'unsupported';
  }
  const actual = sha256(content);
  return multihash.digest.every((byte, index) => byte === actual[index]) ? 'match' : 'mismatch';
}
