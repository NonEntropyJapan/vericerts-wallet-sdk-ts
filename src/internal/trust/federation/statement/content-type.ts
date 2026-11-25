/**
 * Entity Statement 応答の Content-Type 検査（Entity Configuration / Subordinate Statement 共通）。
 *
 * 仕様 SoT: OpenID Federation 1.0 §9（Entity Configuration）・§8（Fetch）。
 *
 * `entity-configuration.ts` と `subordinate.ts` は同じ Entity Statement を同じ `fetchFn` seam から
 * 取り、同じ `decodeAndVerifyStatement` へ渡す双子の経路である。どちらも `Accept` で受け入れる型を
 * 宣言する以上、応答の Content-Type 検査も両方で同じでなければならない。片方だけに置くと、硬化が
 * 一方に取り残される。宣言と検査を 1 か所に置いて同期を機械的に保証する。
 *
 * media type の照合そのものは共有ヘルパー（`internal/http/body-limit.ts`）が持つ。本モジュールが
 * 持つのは**このプロファイル固有の逸脱**（ヘッダ欠落の許容）だけであり、共有ヘルパーと同名の述語で
 * それを覆い隠さないよう関数名を変えてある。
 */

import { isAllowedContentType } from '../../../http/body-limit.js';

/** Entity Statement の Content-Type（OpenID Federation 1.0 §9）。`Accept` の値でもある。 */
export const FEDERATION_CONTENT_TYPES: ReadonlyArray<string> = [
  'application/entity-statement+jwt',
  'application/jwt',
];

/**
 * Content-Type が Entity Statement JWT として許容されるか判定する（パラメータ部を除いて比較）。
 *
 * **ヘッダ欠落（`null`）を許容する点が他の取得経路と異なる。** OpenID Federation の一部実装は
 * Content-Type を省くため受け入れる必要があり、本文は JWT 署名で真正性を検証するため、宣言の欠落を
 * もって拒否する必要がない。この逸脱は共有ヘルパーの `allowMissing` に明示して渡す（既定は拒否で、
 * did:web / did:ipid / did:webvh / OID4VCI Offer の各経路は既定のままである）。
 *
 * @param contentType 応答の `content-type` ヘッダ値（欠落時は `null`）。
 * @returns 許容される場合 `true`。
 */
export function isAllowedEntityStatementContentType(contentType: string | null): boolean {
  return isAllowedContentType(contentType, FEDERATION_CONTENT_TYPES, { allowMissing: true });
}
