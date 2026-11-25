/**
 * Token Status List の運用で使う値・オプション・永続化状態の型定義。
 *
 * IETF draft-ietf-oauth-status-list 準拠。
 *
 * 実装（`StatusListManager`）から型と定数を分離し、Issuer 側（発行・失効）と Verifier 側
 * （評価・キャッシュ）の双方が循環 import なしに参照できるようにする。
 *
 * ## `idx` の二重割当を避ける設計
 *
 * `StatusListManager.allocate` は**単調増加カーソル（`nextIndex`）**からインデックスを払い出し、
 * 解放（再利用）を一切行わない。失効済みエントリのインデックスを他の VC へ再利用すると、古い VC の
 * 失効状態が新しい VC に漏れる（あるいは失効が取り消される）ため、再利用は安全上も禁止する。
 *
 * カーソルはプロセスメモリ上にしか無いので、Issuer Service を再起動すると 0 に戻り**同じ `idx` を
 * 二重に払い出す**。これを避けるため、運用側は次を守る:
 *
 * 1. VC 発行のたびに `snapshot()`（`StatusListSnapshot`）を永続化し、起動時に `restore()` で
 *    復元する。`nextIndex` はスナップショットに含まれるので、復元すれば払い出しが続きから再開する。
 * 2. 1 本の Status List（1 つの `uri`）に対する `allocate` は**単一の書き込み主体に直列化**する。
 *    複数プロセス / 複数レプリカから同時に払い出す場合は、`uri` 単位の排他ロック（DB 行ロック等）を
 *    取ってから `allocate` → スナップショット永続化までを 1 トランザクションで行う。
 * 3. 払い出した `idx` は、VC 発行が失敗しても**欠番のまま捨てる**（巻き戻して再利用しない）。
 *
 * purpose（revocation / suspension）ごとに別 URI・別インスタンスで運用する。
 */

import type { StatusReference } from '../credential/sdjwt/sdjwt.js';
import type { StatusBits } from './bitstring.js';

/** Status List の用途。 */
export type StatusPurpose = 'revocation' | 'suspension';

/** 有効（未失効・未停止）を表すビット値。 */
export const STATUS_VALUE_VALID = 0;

/** 失効 / 一時停止を表すビット値（bits=1 の場合）。 */
export const STATUS_VALUE_SET = 1;

/** `StatusListManager` 生成オプション。 */
export interface StatusListManagerOptions {
  /** Status List Token の参照先 URI（VC の `status.status_list.uri`）。 */
  readonly uri: string;
  /** Issuer 識別子（Token の `iss`）。 */
  readonly issuer: string;
  /** 収容するエントリ数（容量）。 */
  readonly size: number;
  /** エントリあたりのビット数（既定 1）。 */
  readonly bits?: StatusBits;
  /** このリストの用途（既定 `revocation`）。用途ごとに別リストで運用する。 */
  readonly purpose?: StatusPurpose;
}

/** `allocateEntry` の戻り値（確保したインデックスと VC へ埋め込む `status` 参照）。 */
export interface AllocatedStatusEntry {
  /** 確保したビットインデックス（0 始まり）。 */
  readonly idx: number;
  /** VC の `status` クレームへそのまま埋め込める参照。 */
  readonly status: StatusReference;
}

/**
 * 永続化用の Status List 状態（JSON 直列化可能）。
 *
 * `lst` は Status List Token と同じ `base64url(zlib(bitstring))` 形式なので、DB へそのまま保存でき、
 * 配信中の Token と同じ値を再利用できる。`nextIndex` を必ず一緒に保存することが二重割当の防止条件。
 */
export interface StatusListSnapshot {
  /** Status List URI。 */
  readonly uri: string;
  /** Issuer 識別子。 */
  readonly issuer: string;
  /** 収容エントリ数（容量）。 */
  readonly size: number;
  /** エントリあたりのビット数。 */
  readonly bits: StatusBits;
  /** リストの用途。 */
  readonly purpose: StatusPurpose;
  /** 次に払い出すインデックス（二重割当を避けるために必ず一緒に永続化する）。 */
  readonly nextIndex: number;
  /** ビット列本体（`base64url(zlib(bitstring))`）。 */
  readonly lst: string;
}
