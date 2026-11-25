/**
 * Wallet ファサードの VC / VP / SD-JWT 発行・検証の実処理。
 *
 * `WalletImpl`（`wallet.ts`）から credential プリミティブ（issue.ts / verify.ts / presentation.ts /
 * sdjwt.ts）と keymanager 署名・DID 解決を組み合わせる詳細を分離し、ファサード本体を薄く保つ。各関数は
 * 委譲に徹し、状態は持たない（`WalletImpl` から keymanager / resolver を受け取る）。
 *
 * 検証系は JWT / SD-JWT の発行者・提示者 DID を `resolveIssuerVerifierKey` / `resolveSdJwtIssuerKey`
 * （`setup.ts`）で解決してから検証する。発行系は keymanager の鍵を非公開のまま署名する。
 *
 * JWT-VP の検証は本ファイルには無い。envelope の検証は `presentation-envelope.ts`、内包 VC まで
 * 含めた高レベル Verifier API は `verify-result.ts` が担う。
 */

import { snapshotNonceContext } from '../../internal/auth/nonce/context-snapshot.js';
import { verifySdJwtWithReplayGuard } from '../../internal/auth/nonce/index.js';
import {
  type CreateSdJwtOptions,
  createSdJwt,
  type IssueCredentialOptions,
  type IssuePresentationOptions,
  issueCredential,
  issuePresentation,
  type VerifiableCredential,
  type VerifiablePresentation,
  type VerifiedCredential,
  type VerifiedSdJwt,
  verifyCredential,
  verifySdJwt,
} from '../../internal/credential/index.js';
import { ErrorCodes, VericertsError } from '../../internal/errors.js';
import type { DidResolverLike } from '../../internal/identity/bounded-resolver.js';
import type { Resolver } from '../../internal/identity/resolver.js';
import type { KeyManager } from '../../internal/keymanager/keymanager.js';
import { errorLogAttributes, type Logger } from '../../internal/observability/logger.js';
import { MetricNames, type Metrics } from '../../internal/observability/metrics.js';
import { safeEmit } from '../../internal/observability/safe-emit.js';
import {
  hashAttributeValue,
  type Span,
  type Tracer,
  traceSpan,
} from '../../internal/observability/tracer.js';
import { ownProperty } from '../../internal/prototype-safety/own-property.js';
import { resolveIssuerVerifierKey, resolveSdJwtIssuerKey } from '../issuer-key.js';
import type { VerifyCredentialFacadeOptions, VerifySdJwtFacadeOptions } from './api.js';
import { recordNonceReplayIfDetected } from './observability.js';
import { assertReplayInputsComplete } from './replay-opt-in.js';

/** VC に keymanager 内の鍵で署名し、JWT-VC を返す（未登録鍵 1004 は rejected Promise に正規化）。 */
export async function issueCredentialWith(
  keymanager: KeyManager,
  vc: VerifiableCredential,
  keyID: string,
  opts?: IssueCredentialOptions,
): Promise<string> {
  const signer = keymanager.getCredentialSigner(keyID);
  return issueCredential(vc, signer, opts);
}

/**
 * JWT-VC を検証する（`iss` を解決して検証鍵を組み立ててから署名・時刻を検証）。
 *
 * 成否とレイテンシを `vc.verify` としてログ・メトリクス・Span に記録する。
 * `logger` / `metrics` / `tracer` はいずれも必須引数で、未注入時も
 * `createLogger` / `createMetrics` / `createTracer` が均したものが渡る（任意引数にすると呼び出し側
 * ごとに「計装を配線し忘れた経路」が静かに生まれる）。JWT 本文はログにも Span にも載せない。
 *
 * `vc.status_check` は載せない。本関数はステータスリストによる失効確認を行わない
 * 経路であり、検査していない項目の結果を書けないためである。
 */
export async function verifyCredentialWith(
  resolver: DidResolverLike,
  jwt: string,
  logger: Logger,
  metrics: Metrics,
  tracer: Tracer,
  opts?: VerifyCredentialFacadeOptions,
): Promise<VerifiedCredential> {
  const log = logger.child({ component: 'sdk.vc', operation: 'vc.verify' });
  return traceSpan(tracer, 'vc.verify', 'vc.result', async (span) => {
    span.setAttribute('vc.format', 'jwt');
    const startedAt = Date.now();
    try {
      const verified = await verifyCredentialClaims(resolver, jwt, opts);
      setIssuerAttribute(span, verified);
      // 実測は 1 回だけ取り、ログ（ミリ秒）とメトリクス（秒）で同じ値を使う。
      const durationMs = Date.now() - startedAt;
      // 検証は成功済み。テレメトリ sink の失敗で成功結果を reject に変えない（safeEmit）。
      safeEmit(() => log.info('vc.verify', { vc_format: 'jwt', duration_ms: durationMs }));
      // 成功に失敗理由は無いが、`reason` は検証回数の必須ラベルなので固定値で埋める（ラベル集合が
      // 成否で変わると Prometheus 側で同一メトリクスの系列として扱えなくなる）。
      safeEmit(() => recordVerifyMetrics(metrics, 'success', 'none', durationMs));
      return verified;
    } catch (error) {
      const durationMs = Date.now() - startedAt;
      // ログ属性とメトリクスの `reason` は同じ抽出結果を使う（2 回呼ぶと両者がずれる余地が残る）。
      const errorAttrs = errorLogAttributes(error);
      // テレメトリの失敗で元のエラー（VericertsError のコード）を置換しない。
      safeEmit(() =>
        log.error('vc.verify', { vc_format: 'jwt', duration_ms: durationMs, ...errorAttrs }),
      );
      const errorCode = errorAttrs.error_code;
      // `VericertsError` 以外はコードを持たないためログでは属性を省く。
      // メトリクスはラベルを省けないため、推測せず `unknown` という明示の 1 系列へ寄せる。
      safeEmit(() =>
        recordVerifyMetrics(
          metrics,
          'failure',
          typeof errorCode === 'string' ? errorCode : 'unknown',
          durationMs,
        ),
      );
      throw error;
    }
  });
}

/**
 * 検証済み VC の発行者を `vc.issuer` として Span に載せる。
 *
 * 生の DID は入れずハッシュの先頭 16 桁に限定する。`iss` は own プロパティに限って読む
 * （`Object.prototype` の汚染値を「発行者」として集計に混ぜない）。文字列でない・
 * 存在しない場合は推測せず属性ごと落とす。
 */
function setIssuerAttribute(span: Span, verified: VerifiedCredential): void {
  const issuer = ownProperty<unknown>(verified.payload, 'iss');
  if (typeof issuer === 'string') {
    span.setAttribute('vc.issuer', hashAttributeValue(issuer));
  }
}

/** JWT-VC の検証回数と所要時間（秒）を記録する。 */
function recordVerifyMetrics(
  metrics: Metrics,
  result: 'success' | 'failure',
  reason: string,
  durationMs: number,
): void {
  metrics.counter(MetricNames.VC_VERIFY_TOTAL, { format: 'jwt', result, reason }).inc();
  metrics
    .histogram(MetricNames.VC_VERIFY_DURATION_SECONDS, { format: 'jwt' })
    .observe(durationMs / 1000);
}

/** `verifyCredentialWith` の検証本体（計装を挟まない素の経路）。 */
async function verifyCredentialClaims(
  resolver: DidResolverLike,
  jwt: string,
  opts?: VerifyCredentialFacadeOptions,
): Promise<VerifiedCredential> {
  const key = await resolveIssuerVerifierKey(resolver, jwt);
  // 任意プロパティは自身のプロパティに限って読む。`opts?.x` はプロトタイプ鎖を
  // 辿るため、ここで継承値を新しいオブジェクトリテラルへ詰め直すと **own プロパティに化けて**
  // `verifyCredential` 側の own 限定読み取りを無意味にする。`nowSeconds` の汚染値は
  // exp 超過の失効済み JWT-VC を受理させ、`issuerTrust` の汚染値は FC-11 の鍵無効化突合を
  // 攻撃者の宣言へ差し替える。
  const o: object = opts ?? {};
  const nowSeconds = ownProperty<number>(o, 'nowSeconds');
  const clockSkewSeconds = ownProperty<number>(o, 'clockSkewSeconds');
  const issuerTrust = ownProperty<VerifyCredentialFacadeOptions['issuerTrust']>(o, 'issuerTrust');
  return verifyCredential(jwt, {
    key,
    ...(nowSeconds !== undefined ? { nowSeconds } : {}),
    ...(clockSkewSeconds !== undefined ? { clockSkewSeconds } : {}),
    // FC-11: Trust Chain が渡されていれば鍵無効化宣言の突合を委譲する。
    ...(issuerTrust !== undefined ? { issuerTrust } : {}),
  });
}

/** VP に keymanager 内の鍵で署名し、JWT-VP を返す（未登録鍵 1004 は rejected Promise に正規化）。 */
export async function issuePresentationWith(
  keymanager: KeyManager,
  vp: VerifiablePresentation,
  keyID: string,
  opts?: IssuePresentationOptions,
): Promise<string> {
  const signer = keymanager.getCredentialSigner(keyID);
  return issuePresentation(vp, signer, opts);
}

/** SD-JWT VC を発行する（Issuer 署名鍵は keymanager 内に保持したまま使う）。 */
export async function issueSdJwtWith(
  keymanager: KeyManager,
  keyID: string,
  opts: CreateSdJwtOptions,
): Promise<string> {
  const signer = keymanager.getCredentialSigner(keyID);
  return createSdJwt(signer, opts);
}

/**
 * SD-JWT VC を検証する（Issuer-signed JWT の `iss` を解決して Issuer 鍵を組み立ててから検証）。
 *
 * `nonceStore` と `nonceContext` が揃っている場合は seen-nonces cache による replay 検知経路を
 * 通す。この経路では `nonce` が必須で、未指定なら 4013 を投げる。
 * 両方とも指定しない呼び出しだけが replay 検知なしの通常検証になり、**片方だけの指定は拒否する**
 * （`nonceStore` のみ 4012 / `nonceContext` のみ 4010）。
 */
export async function verifySdJwtWith(
  resolver: Resolver,
  sdJwt: string,
  metrics: Metrics,
  opts?: VerifySdJwtFacadeOptions,
): Promise<VerifiedSdJwt> {
  const issuerKey = await resolveSdJwtIssuerKey(resolver, sdJwt);
  // 分割代入はプロトタイプ鎖を辿るため、`nonceStore` / `nonceContext` を渡していない正当な
  // 呼び出しでも汚染値で replay 検知が攻撃者提供のストアへ委譲される。
  // `...opts` のスプレッドは自身の列挙可能プロパティだけを写すので継承値は載らない。
  const o: object = opts ?? {};
  const nonceStore = ownProperty<NonNullable<VerifySdJwtFacadeOptions['nonceStore']>>(
    o,
    'nonceStore',
  );
  const nonceContext = ownProperty<NonNullable<VerifySdJwtFacadeOptions['nonceContext']>>(
    o,
    'nonceContext',
  );
  // 片方だけの指定は replay 検知を求めた意図の取りこぼしなので、通常検証へ落とさず拒否する。
  assertReplayInputsComplete(nonceStore, nonceContext);
  if (nonceStore !== undefined && nonceContext !== undefined) {
    const nonce = ownProperty<string>(o, 'nonce');
    if (nonce === undefined) {
      throw new VericertsError(ErrorCodes.NONCE_MALFORMED);
    }
    // 元の `nonceContext` はここで一度だけ読む。
    // ガードにもメトリクス計装にもこのスナップショットを渡し、計装が元オブジェクトの `flow` を
    // 読み直して 4010 を握りつぶしたり別 flow で集計したりしないようにする。
    const snapshot = snapshotNonceContext(nonceContext);
    try {
      return await verifySdJwtWithReplayGuard(sdJwt, {
        ...opts,
        issuerKey,
        nonce,
        nonceStore,
        nonceContext: snapshot,
      });
    } catch (error) {
      recordNonceReplayIfDetected(metrics, snapshot.flow, error);
      throw error;
    }
  }
  return verifySdJwt(sdJwt, { ...opts, issuerKey });
}
