/**
 * leaf 証明書の共通パース・有効期間・失効検査（`jar-trust-evaluation.ts` から分割した実体。
 * Linterly 300 行/ファイル上限）。
 *
 * TSL 層は `verifyRpAccessCertificate` が有効期間・失効（`revokedSerials` / `now`）を内部で検査する。
 * OIDF 層（`jar-trust-oidf.ts`）・ARF 層（`jar-trust-arf.ts`）は x5c 先頭証明書そのものの有効期間・
 * 失効を検査していなかった（`trustAnchors: []` + `federationTrustAnchor` / `arfTrustAnchor` の
 * 場合、失効済み・期限切れの証明書がそのまま受理され得た）。本モジュールはその検査を両層で
 * 共通化するための小さなヘルパーを提供する。
 */

import type { LayerStatus } from '../../trust/arf/index.js';
import {
  type ParsedRpAccessCertificate,
  parseRpAccessCertificate,
} from '../../trust/rp-access/index.js';

/**
 * leaf 証明書をパースし、失敗時は `undefined` を返す（例外を外へ出さない）。OIDF / ARF 層が
 * 有効期間・失効検査と identity binding に必要なフィールド（`base.spki` / `base.notBefore` /
 * `base.notAfter` / `serialHex` / `identity.origin`）をまとめて得るために使う。
 */
export function tryParseRpAccessCertificate(
  leafDer: Uint8Array,
): ParsedRpAccessCertificate | undefined {
  try {
    return parseRpAccessCertificate(leafDer);
  } catch {
    return undefined;
  }
}

/**
 * leaf 証明書の有効期間・失効を検査する（TSL 層専用だった検査を OIDF / ARF 層にも共通化）。
 * `revokedSerials` 省略時は失効**未確認**として検査をスキップする
 * （`verifyRpAccessCertificate` の `revocationStatus` と同じ「未確認を確認済みと主張しない」
 * 規約）。`now` 省略時は現在時刻を使う（有効期間検査は revocation と異なり常時行う）。
 *
 * @returns 証明書が無効なら `'revoked'` / `'not-found'`、問題なければ `undefined`。
 */
export function certValidityStatus(
  parsed: ParsedRpAccessCertificate,
  revokedSerials: ReadonlySet<string> | undefined,
  now: number | undefined,
): LayerStatus | undefined {
  if (revokedSerials?.has(parsed.serialHex)) {
    return 'revoked';
  }
  const effectiveNow = now ?? Math.floor(Date.now() / 1000);
  // 時刻が非有限（NaN 等）だと比較が常に false になり期限切れ証明書を通す。`!(nb <= now <= na)` で fail-closed。
  if (!(effectiveNow >= parsed.base.notBefore && effectiveNow <= parsed.base.notAfter)) {
    return 'not-found';
  }
  return undefined;
}
