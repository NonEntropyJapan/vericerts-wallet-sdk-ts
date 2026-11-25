/**
 * content-addressed DID のサブパスから contentHash を抽出する。
 *
 * Artifact DID の例は `did:web:acme.example.com:artifacts:sha256-ab12…`。
 * Verifier はここから抽出した hash と実コンテンツの hash を照合する。
 *
 * 抽出規則は曖昧さを排するため「method-specific-id の**最終**セグメントが contentHash」と
 * 固定する。途中のセグメントを探索的に拾うと、攻撃者が任意位置に一致する hash を埋め込んで
 * 検証を通す余地が生まれるため採用しない（fail-closed）。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { type ParsedContentHash, parseContentHash } from './notation.js';

/** DID URL のパラメータ部（path / query / fragment）の開始文字。 */
const DID_URL_DELIMITERS = ['/', '?', '#'];

/**
 * DID URL から DID 本体（`did:<method>:<method-specific-id>`）を切り出す。
 *
 * @param didUrl DID または DID URL。
 * @returns DID 本体。
 */
function stripDidUrlParts(didUrl: string): string {
  let end = didUrl.length;
  for (const delimiter of DID_URL_DELIMITERS) {
    const index = didUrl.indexOf(delimiter);
    if (index >= 0 && index < end) {
      end = index;
    }
  }
  return didUrl.slice(0, end);
}

/**
 * content-addressed DID の最終サブパスセグメントから contentHash を抽出・正規化する。
 *
 * DID URL（path / query / fragment 付き）を渡した場合はそれらを取り除いてから解釈する。
 *
 * @param didUrl content-addressed DID または DID URL。
 * @returns 正規化済み contentHash。
 * @throws DID 形式が不正な場合（VericertsError、code `2001`）。
 * @throws 最終セグメントが contentHash 表記でない場合（VericertsError、code `2016`）。
 * @throws 未対応アルゴリズムの場合（VericertsError、code `1030`）。
 */
export function extractDidContentHash(didUrl: string): ParsedContentHash {
  if (typeof didUrl !== 'string') {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const did = stripDidUrlParts(didUrl);
  const segments = did.split(':');
  // `did` / `<method>` / `<method-specific-id>` の最低 3 セグメントが必要。
  if (segments[0] !== 'did' || segments.length < 4) {
    // サブパスを持たない DID（`did:web:example.com` など）も content-addressed ではない。
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const method = segments[1];
  if (method === undefined || method.length === 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const last = segments[segments.length - 1];
  if (last === undefined || last.length === 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  return parseContentHash(last);
}
