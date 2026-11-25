/**
 * VP 内包 VC の文字列が COSE_Sign1（`vc+cose`）の外形を持つかの判定。
 *
 * `vc+cose` は未実装なので、本モジュールは**検証を一切行わず**、
 * 「JWT-VC / SD-JWT VC として読もうとしてはいけない入力」を見分けるためだけに使う。判定結果は
 * 診断コードの選択にのみ効く（未対応構造なら `VC_SCHEMA_INVALID`（3002）、署名不成立と読める
 * `SIG_INVALID`（3010）は使わない）。
 *
 * 方針:
 * - 外形だけを見る。COSE の中身（protected header / payload / signature）は一切解釈しない。
 * - どの経路でも例外を投げず、判断がつかない入力は必ず `false` に倒す。`false` は既存の
 *   JWT / SD-JWT 経路への素通しを意味し、壊れた文字列は従来どおり 3010 に落ちる（挙動を
 *   変えるのは「COSE_Sign1 だと確信できた入力」だけ）。
 */

import { base64urlnopad } from '@scure/base';
import { CBOR_MAJOR, type CborHeader, readCborHeader } from '../../../cbor.js';

/** COSE_Sign1 に登録された CBOR タグ番号（RFC 9052 §2 / IANA CBOR Tags）。 */
const COSE_SIGN1_TAG = 18;

/** COSE_* は常に 4 要素の CBOR 配列（RFC 9052 §2）。 */
const COSE_ELEMENT_COUNT = 4;

/**
 * 文字列が base64url（padding なし）の COSE_Sign1 に見えるかを判定する。
 *
 * 受理するのは「4 要素の CBOR 配列」そのもの、またはそれをタグ 18 で包んだもの
 * （`d2 84 ...`）の 2 形。どちらでもない・デコードできない場合は `false`。
 *
 * @param entry `verifiableCredential` の要素（文字列のもの）。
 * @returns COSE_Sign1 の外形を持つなら `true`。
 */
export function looksLikeCoseSign1(entry: string): boolean {
  // JWT は `.`、SD-JWT は `~` で区切る。COSE_Sign1 の base64url にはどちらも現れないので、
  // 先に弾いて既存フォーマットの入力を確実に素通しさせる。
  if (entry.includes('.') || entry.includes('~')) {
    return false;
  }
  const bytes = decodeBase64Url(entry);
  if (bytes === undefined) {
    return false;
  }
  const head = readCborHeader(bytes, 0);
  if (head === undefined) {
    return false;
  }
  if (head.majorType === CBOR_MAJOR.tag) {
    return head.value === COSE_SIGN1_TAG && isCoseArray(readCborHeader(bytes, head.headerLen));
  }
  return isCoseArray(head);
}

/** base64url（padding なし）としてバイト列に戻す。デコードできなければ `undefined`。 */
function decodeBase64Url(entry: string): Uint8Array | undefined {
  try {
    return base64urlnopad.decode(entry);
  } catch {
    return undefined;
  }
}

/** CBOR head が COSE_* の本体（4 要素配列）か。 */
function isCoseArray(head: CborHeader | undefined): boolean {
  return (
    head !== undefined && head.majorType === CBOR_MAJOR.array && head.value === COSE_ELEMENT_COUNT
  );
}
