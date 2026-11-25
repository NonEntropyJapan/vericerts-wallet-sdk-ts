/**
 * JWT-VP の **envelope 部分だけ**の検証（`ops.ts` から切り出し）。
 *
 * 「envelope」= VP 署名・時刻（exp/nbf）・Verifier バインド（aud/nonce）・replay 検知までで、
 * **内包 VC（`vp.verifiableCredential`）は検証しない**範囲。2 層構成では、
 * 低レベル primitive（`verifyPresentationEnvelopeStrict`）が返すのがちょうどこの範囲であり、
 * 高レベル `verifyPresentation` / 従来の `verifyPresentationWith` はこの結果に
 * `attachCredentialResults`（内包 VC 検証）を重ねて組み立てる。
 *
 * 切り出しは**純粋な抽出**で、判定・順序・fail-closed の挙動は `ops.ts` にあった時点と同一。
 */

import { snapshotNonceContext } from '../../internal/auth/nonce/context-snapshot.js';
// バレル（`nonce/index.js`）ではなく実体から取る。`verifyPresentationWithReplayGuardClaims` は
// 内包 VC を検証しない内部経路で、公開 API ではないためバレルには出していない。
import { verifyPresentationWithReplayGuardClaims } from '../../internal/auth/nonce/vp-guard.js';
// `verifyPresentationClaims` も内包 VC を検証しない内部経路のためバレルには出していない。
import type { VerifiedPresentationClaims } from '../../internal/credential/presentation/presentation.js';
import { verifyPresentationClaims } from '../../internal/credential/presentation/presentation.js';
import { ErrorCodes, VericertsError } from '../../internal/errors.js';
import type { Resolver } from '../../internal/identity/resolver.js';
import type { Metrics } from '../../internal/observability/metrics.js';
import { ownProperty } from '../../internal/prototype-safety/own-property.js';
import { resolveIssuerVerifierKey } from '../issuer-key.js';
import type { PresentationBinding } from '../presentation/index.js';
import { recordNonceReplayIfDetected } from './observability.js';
import { assertReplayInputsComplete } from './replay-opt-in.js';
import type { VerifyPresentationFacadeOptions } from './verify-api.js';

/** envelope 検証の結果と、内包 VC 検証へ引き継ぐ値。 */
export interface ResolvedPresentationEnvelope {
  /** VP レベルの検証を終えた中間結果（内包 VC は未検証）。 */
  readonly claims: Pick<VerifiedPresentationClaims, 'header' | 'payload' | 'asserted'>;
  /** 時刻評価に用いた基準時刻（内包 VC も同じ値で評価させる）。 */
  readonly nowSeconds: number;
  /** 内包 SD-JWT VC の KB-JWT 検証へ中継する実効 audience / nonce。 */
  readonly binding: PresentationBinding;
  /**
   * 内包 VC 検証へ渡すオプション（`opts ?? {}`）。
   *
   * 呼び出し側で `opts ?? {}` を作り直すと、`opts` が `undefined` の呼び出しで**別の**空オブジェクトが
   * できる。挙動は変わらないが、読み取り対象を 1 つに固定しておく方が「どのオブジェクトを own 限定で
   * 読んだか」が追いやすいため、本関数が使ったものをそのまま返す。
   */
  readonly opts: object;
}

/**
 * JWT-VP の envelope を検証する（`iss`（提示者 DID）を解決して検証鍵を組み立て、署名・時刻・
 * aud/nonce を検証する）。**内包 VC は検証しない。**
 *
 * `nonceStore` と `nonceContext` が揃っている場合は seen-nonces cache による replay 検知経路を
 * 通す。両方とも指定しない呼び出しだけが replay 検知なしの通常検証で、
 * **片方だけの指定は拒否する**（`nonceStore` のみ 4012 / `nonceContext` のみ 4010）。
 * ガードは `expectedNonce` / `allowUnbound` を受け取らない（自身で制御する）ため、`...opts` を
 * そのまま流さず、`expectedNonce` は唯一の nonce 入力である `nonce` へ明示的にマップする。
 */
export async function resolvePresentationEnvelope(
  resolver: Resolver,
  jwt: string,
  metrics: Metrics,
  opts?: VerifyPresentationFacadeOptions,
): Promise<ResolvedPresentationEnvelope> {
  // VP の署名は holder の本人認証なので `authentication` で鍵を解決する。`assertionMethod` 専用の
  // 委任鍵（did:ethr `veriKey` 等）で署名した VP を holder として受理しない。内包 VC の発行者鍵は別経路。
  const key = await resolveIssuerVerifierKey(resolver, jwt, 'authentication');
  // 任意プロパティは自身のプロパティに限って読む。分割代入・`opts?.x` は
  // プロトタイプ鎖を辿るため、`nonceStore` / `nonceContext` を**渡していない**正当な呼び出しでも
  // 汚染値が揃って replay 検知が攻撃者提供のストアへ委譲される（seen-nonce の記録先が攻撃者側に
  // なるため、再提示が「初回」と判定される）。時刻・スキュー・窓の各オプションも同じ経路で
  // 継承値が有効期限・リプレイ窓の評価を緩めるため、同じ読み方に揃える。
  const o: object = opts ?? {};
  const nonceStore = ownProperty<NonNullable<VerifyPresentationFacadeOptions['nonceStore']>>(
    o,
    'nonceStore',
  );
  const nonceContext = ownProperty<NonNullable<VerifyPresentationFacadeOptions['nonceContext']>>(
    o,
    'nonceContext',
  );
  const expectedNonce = ownProperty<string>(o, 'expectedNonce');
  const expectedAudience = ownProperty<string>(o, 'expectedAudience');
  const nowSeconds = ownProperty<number>(o, 'nowSeconds');
  const clockSkewSeconds = ownProperty<number>(o, 'clockSkewSeconds');
  // 片方だけの指定は replay 検知を求めた意図の取りこぼしなので、通常検証へ落とさず拒否する。
  assertReplayInputsComplete(nonceStore, nonceContext);
  if (nonceStore !== undefined && nonceContext !== undefined) {
    if (expectedNonce === undefined) {
      throw new VericertsError(ErrorCodes.NONCE_MALFORMED);
    }
    const replayWindowSeconds = ownProperty<number>(o, 'replayWindowSeconds');
    const nonceTtlMs = ownProperty<number>(o, 'nonceTtlMs');
    // 元の `nonceContext` はここで一度だけ読む。
    // ガードにもメトリクス計装にもこのスナップショットを渡し、計装が元オブジェクトの `flow` を
    // 読み直して 4010 を握りつぶしたり別 flow で集計したりしないようにする。
    const snapshot = snapshotNonceContext(nonceContext);
    let guarded: Awaited<ReturnType<typeof verifyPresentationWithReplayGuardClaims>>;
    try {
      guarded = await verifyPresentationWithReplayGuardClaims(jwt, {
        key,
        nonce: expectedNonce,
        nonceStore,
        nonceContext: snapshot,
        ...(expectedAudience !== undefined ? { expectedAudience } : {}),
        ...(nowSeconds !== undefined ? { nowSeconds } : {}),
        ...(clockSkewSeconds !== undefined ? { clockSkewSeconds } : {}),
        ...(replayWindowSeconds !== undefined ? { replayWindowSeconds } : {}),
        ...(nonceTtlMs !== undefined ? { nonceTtlMs } : {}),
      });
    } catch (error) {
      recordNonceReplayIfDetected(metrics, snapshot.flow, error);
      throw error;
    }
    // 内包 SD-JWT VC の KB-JWT へ中継する audience は、**replay guard が解決した実効値**を使う
    // この経路では `expectedAudience` が任意で、照合対象は `nonceContext` の
    // 束縛値だからである。guard は実測 `aud` を束縛値と照合済みで、それを `guarded.audience` と
    // して返す。ガードは内包 VC を検証しない内部経路（`...Claims`）なので、内包 VC の暗号検証と
    // 発行者鍵の解決はこの 1 パスだけで済む（公開ラッパを呼ぶと捨てる 1 パスが余計に走る）。
    return {
      claims: guarded,
      nowSeconds: guarded.nowSeconds,
      binding: { audience: guarded.audience, nonce: guarded.nonce },
      opts: o,
    };
  }
  const allowUnbound = ownProperty<boolean>(o, 'allowUnbound');
  // 内包 VC を検証しない内部経路を使う。ファサードは発行者鍵を DID 解決で補完してから
  // `attachCredentialResults` で組み立てるため、プリミティブに組み立てさせるとその 1 パスが
  // まるごと捨てられる（同じ VC を 2 回検証することになる）。
  const verified = verifyPresentationClaims(jwt, {
    key,
    expectedAudience,
    expectedNonce,
    ...(nowSeconds !== undefined ? { nowSeconds } : {}),
    ...(clockSkewSeconds !== undefined ? { clockSkewSeconds } : {}),
    ...(allowUnbound !== undefined ? { allowUnbound } : {}),
  });
  // 実効バインド値は呼び出し側の期待値そのもの（束縛モードでは payload と一致確認済み）。
  return {
    claims: verified,
    nowSeconds: verified.nowSeconds,
    binding: { audience: expectedAudience, nonce: expectedNonce },
    opts: o,
  };
}
