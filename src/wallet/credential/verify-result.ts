/**
 * 高レベル Verifier API（判別共用体 Result 型）の実装。
 *
 * 2 層構成のうち**上の層**。低レベル primitive（`verifyCredentialWith` /
 * `resolvePresentationEnvelope`）は fail-closed のまま一切いじらず、その例外を
 * `VerificationIssue` へ写して Result 型に畳む。
 *
 * **握り潰さない**: `catch` するのは `VericertsError`（= 検証の不成立として SDK が定義した失敗）
 * だけで、それ以外の例外はそのまま再送出する。想定外の失敗まで `valid: false` に丸めると、
 * 不具合が「正常な検証失敗」に紛れて表に出なくなる。
 *
 * **top-level `valid` は認可判定**: VP は「envelope が正当」かつ「内包 VC が 1 件以上あり全件有効」
 * のときだけ `valid: true` になる。部分成功（envelope は正当だが内包 VC の一部が invalid）と
 * 内包 VC ゼロは `valid: false` / `presentationValid: true` として返し、診断は
 * `credentialResults` / `errors` を読ませる。
 */

import type {
  CredentialVerificationResult,
  EmbeddedCredentialVerificationFields,
  EmbeddedCredentialVerificationResult,
  PresentationVerificationResult,
  ValidEmbeddedCredentialVerificationResult,
  VerificationIssue,
  VerificationResult,
  VerifiedPresentationEnvelope,
} from '../../internal/credential/index.js';
import {
  verificationIssueFromCode,
  verificationIssueFromVericertsError,
} from '../../internal/credential/index.js';
// 内包 VC を検証しない内部経路の型のためバレルには出していない（実体から取る）。
import type { VerifiedPresentationClaims } from '../../internal/credential/presentation/presentation.js';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../internal/errors.js';
import type { Resolver } from '../../internal/identity/resolver.js';
import type { Logger } from '../../internal/observability/logger.js';
import type { Metrics } from '../../internal/observability/metrics.js';
import type { Tracer } from '../../internal/observability/tracer.js';
import { ownProperty } from '../../internal/prototype-safety/own-property.js';
import { attachCredentialResults } from '../presentation/index.js';
import { verifyCredentialWith } from './ops.js';
import { resolvePresentationEnvelope } from './presentation-envelope.js';
import type {
  VerifyCredentialFacadeOptions,
  VerifyPresentationFacadeOptions,
} from './verify-api.js';

/** VP envelope の検証結果を公開型へ写す（内包 VC には触れない）。 */
function toEnvelope(
  claims: Pick<VerifiedPresentationClaims, 'header' | 'payload' | 'asserted'>,
): VerifiedPresentationEnvelope {
  // `asserted` は構造検証時に一度だけ読まれた own 値。VP オブジェクトを読み直さない（TOCTOU 回避）。
  return {
    header: claims.header,
    payload: claims.payload,
    presentation: claims.asserted.vp,
    holderDID: claims.asserted.holder,
  };
}

/** 内包 VC 1 件の低レベル結果（`VerificationResult`）を高レベルの判別共用体へ写す。 */
function toEmbeddedResult(result: VerificationResult): EmbeddedCredentialVerificationResult {
  const fields: EmbeddedCredentialVerificationFields = {
    issuerDID: result.issuerDID,
    isExpired: result.isExpired,
    isRevoked: result.isRevoked,
    isSuspended: result.isSuspended,
    isTrustedIssuer: result.isTrustedIssuer,
    schemaValid: result.schemaValid,
    format: result.format,
  };
  if (result.valid) {
    return { ...fields, valid: true, warnings: [] };
  }
  // `errors` は**成功時にキー自体を持たない**任意プロパティなので own 限定で読む。鎖読みすると
  // `Object.prototype.errors` の汚染値を「当該 VC の失敗理由」として報告してしまう（拒否は拒否の
  // ままだが、攻撃者が選んだコードを診断結果に載せられる）。
  const codes = ownProperty<readonly ErrorCode[]>(result, 'errors');
  // `valid: false` なのに理由が 1 件も無い結果は作らせない。空の `errors` は呼び出し側から
  // 「失敗理由が無い ＝ 失敗していない」と読み違えられ得るため、理由不明の拒否は 3010 に寄せる。
  const resolved: readonly ErrorCode[] =
    codes !== undefined && codes.length > 0 ? codes : [ErrorCodes.SIG_INVALID];
  return { ...fields, valid: false, errors: resolved.map(verificationIssueFromCode) };
}

/** `valid: true` の枝かを判定する（`every` で配列ごと絞り込むための述語）。 */
function isValidEmbedded(
  result: EmbeddedCredentialVerificationResult,
): result is ValidEmbeddedCredentialVerificationResult {
  return result.valid;
}

/**
 * 失敗した内包 VC の理由をコード重複なく集める。
 *
 * 内包 VC が 1 件も無い VP は「失敗した VC」が存在しないため理由が空になる。`valid: false` の枝が
 * 理由ゼロで返ると呼び出し側に異常のシグナルが一つも残らないので、`3002`（提示すべき VC を 1 件も
 * 含まない VP 構造）を明示的に返す（下位層の `errors` と同じコード）。
 */
function collectIssues(
  results: readonly EmbeddedCredentialVerificationResult[],
): VerificationIssue[] {
  if (results.length === 0) {
    return [verificationIssueFromCode(ErrorCodes.VC_SCHEMA_INVALID)];
  }
  const seen = new Set<ErrorCode>();
  const issues: VerificationIssue[] = [];
  for (const result of results) {
    if (result.valid) {
      continue;
    }
    for (const issue of result.errors) {
      if (!seen.has(issue.code)) {
        seen.add(issue.code);
        issues.push(issue);
      }
    }
  }
  return issues;
}

/**
 * JWT-VP の envelope だけを検証する低レベル primitive（`verifyPresentationEnvelopeStrict` の実体）。
 *
 * 内包 VC は検証しない。失敗は従来どおり例外（fail-closed）。
 */
export async function verifyPresentationEnvelopeStrictWith(
  resolver: Resolver,
  jwt: string,
  metrics: Metrics,
  opts?: VerifyPresentationFacadeOptions,
): Promise<VerifiedPresentationEnvelope> {
  const envelope = await resolvePresentationEnvelope(resolver, jwt, metrics, opts);
  return toEnvelope(envelope.claims);
}

/**
 * JWT-VC を検証し、判別共用体の結果を返す（`verifyCredential`（高レベル）の実体）。
 *
 * 計装（ログ / メトリクス / Span）は `verifyCredentialWith` が従来どおり記録する。失敗を Result へ
 * 畳むのはその**後**なので、`valid: false` で返るケースも `vc.verify` の failure として計測される。
 */
export async function verifyCredentialResultWith(
  resolver: Resolver,
  jwt: string,
  logger: Logger,
  metrics: Metrics,
  tracer: Tracer,
  opts?: VerifyCredentialFacadeOptions,
): Promise<CredentialVerificationResult> {
  try {
    const data = await verifyCredentialWith(resolver, jwt, logger, metrics, tracer, opts);
    return { valid: true, data, warnings: [] };
  } catch (error) {
    if (!(error instanceof VericertsError)) {
      // 検証の不成立ではない（プログラミングエラー等）。Result へ丸めず伝播させる。
      throw error;
    }
    return { valid: false, errors: [verificationIssueFromVericertsError(error)] };
  }
}

/**
 * JWT-VP を envelope + 内包 VC まで検証し、判別共用体の結果を返す（`verifyPresentation`（高レベル）の実体）。
 *
 * envelope の失敗だけを `presentationValid: false` として捕捉する（内包 VC 検証の段で想定外の例外が
 * 出た場合は envelope の失敗として報告せず、そのまま伝播させる）。top-level `valid` は
 * 「envelope 正当 **かつ** 全内包 VC が有効」を**この場で計算する**（下位層の `valid` を鵜呑みに
 * しない。判定の SSOT を 1 箇所に置くため）。
 */
export async function verifyPresentationResultWith(
  resolver: Resolver,
  jwt: string,
  metrics: Metrics,
  opts?: VerifyPresentationFacadeOptions,
): Promise<PresentationVerificationResult> {
  let envelope: Awaited<ReturnType<typeof resolvePresentationEnvelope>>;
  try {
    envelope = await resolvePresentationEnvelope(resolver, jwt, metrics, opts);
  } catch (error) {
    if (!(error instanceof VericertsError)) {
      throw error;
    }
    // envelope が不成立なら内包 VC は評価していない（未検証の VP が指す DID を解決しないため）。
    return {
      valid: false,
      presentationValid: false,
      credentialResults: [],
      errors: [verificationIssueFromVericertsError(error)],
    };
  }
  const verified = await attachCredentialResults(
    resolver,
    envelope.claims,
    envelope.opts,
    envelope.nowSeconds,
    envelope.binding,
  );
  const data = toEnvelope(envelope.claims);
  const credentialResults = verified.credentialResults.map(toEmbeddedResult);
  // `length > 0` を先に見る。`every([])` は空真なので、内包 VC ゼロの VP が envelope 検証だけで
  // `valid: true` になり、「提示者がある DID を保有している」以外を何も証明しない提示で RP が認可
  // してしまう。下位層（`buildPresentationVerificationFields`）でも同じ判定を
  // するが、ここは判定の SSOT として独立に計算する方針なので両方に置く。
  if (credentialResults.length > 0 && credentialResults.every(isValidEmbedded)) {
    return {
      valid: true,
      data,
      holderDID: data.holderDID,
      credentialResults,
      warnings: [],
    };
  }
  // envelope は正当（例外が出ていない）だが内包 VC が無い / 不正がある。認可は deny に倒す。
  return {
    valid: false,
    holderDID: data.holderDID,
    presentationValid: true,
    credentialResults,
    errors: collectIssues(credentialResults),
  };
}
