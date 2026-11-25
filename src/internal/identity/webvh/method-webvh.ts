/**
 * did:webvh メソッド実装（did:web + 更新履歴の検証）。
 *
 * did:webvh は did:web の HTTPS インフラを活かしつつ、鍵ローテーション履歴を
 * ハッシュチェーンで検証可能にした派生メソッドである。
 *
 *   `did:webvh:{scid}:{domain}[:{path}]`
 *
 * - `scid`: Self-Certifying Identifier（初版 state のハッシュ由来、multibase base58btc）。
 * - `domain`: `example.com` / `example.com%3A8443`（ポートは URI エンコード）。
 * - `path`: `users:alice` 等の任意パス（`:` 区切り、URL では `/`）。
 *
 * Issuer は `https://{domain}/.well-known/did.jsonl`（path 付きは `/{path}/did.jsonl`）に
 * DID Log（JSON Lines）を公開する。
 *
 * 解決フロー: JSONL を fetch → 初版 scid の self-certifying 検証 →
 * versionId ハッシュチェーン検証 → proof チェーン検証（Ed25519 / updateKeys）→
 * versionId 指定 or 最新版の state を返す → `deactivated` なら失効扱い。
 *
 * 正規化・multihash・DID 構文/URL/Log パースは `./codec.ts`（DID 構文/URL は `./did-url.ts`）、
 * 検証アルゴリズムは `./verify.ts`、生成・更新 API は `./lifecycle.ts` に分割している
 * （1 ファイル 300 行以下のため）。例外メッセージ・`context` に DID 文字列・URL・Log 本文・
 * 鍵バイトを含めない。
 *
 * did:webvh の生成・更新・失効は新しい行を JSONL に append する運用であり、`DIDMethod` の
 * `create` / `update` / `deactivate` では必要情報（domain / updateKeys / previousLog 等）を
 * 表現できないため非対応（code `2002`）。生成・更新・失効は専用 API（`createDidWebVh` /
 * `updateDidWebVh`）を用いる。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { CreateOptions, DIDDocument, DIDMethod, UpdateOptions } from '../did.js';
import type { ResolutionWorkBudget } from '../resolution-budget.js';
import { resolveDidWebVh, resolveDidWebVhWithMetadata, type WebVhResolution } from './resolve.js';

export {
  canonicalize,
  type ParsedWebVh,
  parseDidLog,
  parseWebVh,
  updateKeyHash,
  type WebVhLogEntry,
  type WebVhParameters,
  type WebVhProof,
  webVhLogUrl,
} from './codec.js';
export {
  createDidWebVh,
  type WebVhCreateDocument,
  type WebVhCreateOptions,
  type WebVhCreateResult,
} from './lifecycle/lifecycle.js';
export { updateDidWebVh, type WebVhUpdateOptions } from './lifecycle/lifecycle-update.js';
export {
  createWebVhAttemptLedger,
  resolveDidWebVh,
  resolveDidWebVhHooked,
  resolveDidWebVhWithMetadata,
  type WebVhAttemptLedger,
  type WebVhDidMetadata,
  type WebVhResolution,
  type WebVhResolveHooks,
  type WebVhResolveOptions,
  type WebVhWitnessMetadata,
} from './resolve.js';
export { type VerifiedLog, verifyChain } from './verify.js';
export { parseWitnessFile, type WebVhWitnessFileItem } from './witness/file.js';
export {
  assertWebVhCandidateVerifies,
  collectWebVhWitnessProofs,
  createWebVhWitnessProof,
  type WebVhCollectWitnessProofsOptions,
  type WebVhSignFn,
  type WebVhWitnessApprover,
  type WebVhWitnessProofSigner,
  type WebVhWitnessRequest,
} from './witness/sign.js';

/**
 * did:webvh メソッドプラグイン。`resolve` は DID Log の検証付き解決を行う。生成・更新・失効は
 * `CreateOptions` / `UpdateOptions` で表現できないため非対応（code `2002`）。専用 API
 * （`createDidWebVh` / `updateDidWebVh`）を用いる。
 */
export class MethodWebVh implements DIDMethod {
  /** メソッド名（`'webvh'`）。 */
  method(): string {
    return 'webvh';
  }

  /** 生成は専用 API `createDidWebVh` を使用すること（code `2002`）。 */
  async create(_opts: CreateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** did:webvh 文字列を DID Log の検証付きで解決する。 */
  async resolve(did: string, scope?: ResolutionWorkBudget): Promise<DIDDocument> {
    return resolveDidWebVh(did, undefined, scope);
  }

  /** DID Document に加えて解決メタデータ（`scid` / `portable` / `deactivated` / `ttl` / `witness` / `watchers` など）を返す。 */
  async resolveWithMetadata(did: string, scope?: ResolutionWorkBudget): Promise<WebVhResolution> {
    return resolveDidWebVhWithMetadata(did, undefined, scope);
  }

  /** 更新は専用 API `updateDidWebVh` を使用すること（code `2002`）。 */
  async update(_did: string, _opts: UpdateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** 失効は専用 API `updateDidWebVh`（`deactivated: true`）を使用すること（code `2002`）。 */
  async deactivate(_did: string): Promise<void> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }
}
