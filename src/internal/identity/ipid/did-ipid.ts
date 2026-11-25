/**
 * did:ipid の DID 文字列パースと識別子分類。
 *
 * did:ipid は IPFS/IPNS ベースの分散 DID。識別子（method-specific id）は次の 2 種:
 * - イミュータブル: `did:ipid:<CIDv1>`（特定バージョンを指す不変ポインタ）
 * - 可変: `did:ipid:<ipns-name>`（IPNS による可変ポインタ）
 *
 * CID と IPNS 名（libp2p-key）は文字種が重なるため、先頭文字では判別しない。識別子を実際に
 * 復号し、CIDv1 の multicodec が `libp2p-key`（0x72）または multihash `identity` の PeerID なら IPNS 名、
 * それ以外（`raw` / `dag-pb` の CIDv1・CIDv0）は CID として扱う（{@link classifyIpidIdentifier}）。
 * CID は取得本文のハッシュを照合するため、base36（`k...`）や CIDv0（`Qm...`）表記でも
 * 照合が迂回されない。CID としても PeerID としても復号できない識別子は拒否する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・識別子を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { classifyIpidIdentifier } from './cid.js';

/** `did:ipid:` メソッドプレフィックス。 */
export const DID_IPID_PREFIX = 'did:ipid:';

/** 識別子の分類。 */
export type IpidIdKind = 'cid' | 'ipns';

/** パース済みの did:ipid 識別子。 */
export interface ParsedIpid {
  /** method-specific id（CIDv1 または IPNS 名）。 */
  readonly identifier: string;
  /** 識別子の分類（取得経路 `/ipfs/` か `/ipns/` の振り分けに使う）。 */
  readonly kind: IpidIdKind;
}

/**
 * method-specific id が multibase 文字（英数字）のみで構成されるか判定する。
 *
 * `/`・`:`・`#`・空白などは Gateway パス偽装（path traversal）になり得るため拒否する。
 * `create` が IPFS API から得た CID 連結時にも本検証を通して `resolve` 経路と一貫させる。
 *
 * @param identifier method-specific id。
 * @returns 英数字のみなら `true`。
 */
export function isValidIpidIdentifier(identifier: string): boolean {
  return identifier.length > 0 && /^[A-Za-z0-9]+$/.test(identifier);
}

/**
 * did:ipid 文字列をパースして識別子と分類を返す。
 *
 * @param did did:ipid 文字列（`did:ipid:<CIDv1>` または `did:ipid:<ipns-name>`）。
 * @returns 識別子と分類。
 * @throws プレフィックス不正・識別子空・不正文字を含む場合、CID / PeerID として復号できない場合
 *         （VericertsError、code `2001`）。
 */
export function parseDidIpid(did: string): ParsedIpid {
  if (!did.startsWith(DID_IPID_PREFIX)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const identifier = did.slice(DID_IPID_PREFIX.length);
  // multibase 文字（英数字）のみを許容する。空・`/`・`:`・`#`・空白などは経路偽装になり得るため拒否。
  if (!isValidIpidIdentifier(identifier)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  // 識別子を復号して分類する（先頭文字ヒューリスティックは CIDv1 base36 / CIDv0 の検証迂回になる）。
  const kind = classifyIpidIdentifier(identifier);
  if (kind === undefined) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  return { identifier, kind };
}
