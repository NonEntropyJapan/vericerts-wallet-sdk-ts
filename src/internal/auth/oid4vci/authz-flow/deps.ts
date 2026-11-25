/**
 * Authorization Code Flow の呼び出し側入力（`AuthorizationCodeFlowDeps`）の読み取りと検証。
 *
 * `receive.ts` の「AS / Issuer と何を話すか」から「呼び出し側から何を受け取ったか」を分離する。
 * 呼び出し側が渡すオブジェクトは `JSON.parse` を通らないため、`parse-json.ts` のパース境界での
 * プロトタイプ除去が**一切効かない**（`own-property.ts`「本ヘルパーが効かない範囲」）。したがって
 * 読み取り時点の判定が唯一の防御線であり、その判定をこの 1 か所へ集約する。
 * 併せて「1 回だけ読んで以降はローカルだけを使う」ことで、own アクセサ付きのオブジェクトを
 * 渡されたときに検査した値と実際に使う値が食い違う（TOCTOU）余地を無くす。
 *
 * 方針・記法は `eudi/issuance/deps.ts`と同一である。
 */

import type { CredentialSigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { FetchLike } from '../../../fetch-di.js';
import type { CorrelationContext } from '../../../observability/correlation.js';
import { isCorrelationContext } from '../../../observability/correlation.js';
import { isNonBlankString } from '../../../prototype-safety/non-empty-string.js';
import {
  hasExplicitNonCallableProperty,
  nonObjectPrototypeProperty,
  ownProperty,
} from '../../../prototype-safety/own-property.js';
import type { DpopProofFactory } from '../oid4vci-credential-dpop.js';
import type { AuthorizationCodeFlowDeps, AuthorizationRedirect } from './types.js';

/** `deps` から読み出した、フローが実際に使う値の組。関数はレシーバを束ね直してある。 */
export interface ResolvedFlowDeps {
  /** JWT Proof の署名鍵。 */
  readonly signer: CredentialSigner;
  /** Holder DID（JWT Proof の `iss`）。 */
  readonly holderDid: string;
  /** 検証鍵 ID（JWT Proof の `kid`）。 */
  readonly keyId: string;
  /** 認可 URL を開いて `code` / `state` / `iss` を受領する関数（`iss` は必須。欠落・不一致は Token Request 前に拒否）。 */
  readonly authorize: (authorizationUrl: string) => Promise<AuthorizationRedirect>;
  /** HTTP 差し替えシーム（未注入なら `undefined`）。 */
  readonly fetchImpl: FetchLike | undefined;
  /** `htu` ごとの DPoP proof 生成（未指定なら `undefined`）。 */
  readonly createDpopProof: DpopProofFactory | undefined;
  /** フロー全体で共有する相関 ID（未指定なら `undefined`）。 */
  readonly correlationContext: CorrelationContext | undefined;
}

/** 依存不正は `TOKEN_REQUEST_FAILED`（8010）へ寄せる（PAR から先へ 1 歩も進めないため）。 */
function depsFailure(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED, { context: { reason } });
}

/**
 * 相関 ID を own 限定で読む。純データなので `ownProperty` を使う。
 *
 * 形が壊れた値は他の不正な依存と同じく 8010 で弾く（下流のプリミティブは黙って落とすが、
 * ここは呼び出し側の入力を検証する境界であり、実装ミスを気付けるようにする）。
 */
function optionalCorrelationContext(deps: object): CorrelationContext | undefined {
  const value = ownProperty<unknown>(deps, 'correlationContext');
  if (value === undefined) {
    return undefined;
  }
  if (!isCorrelationContext(value)) {
    throw depsFailure('invalid_flow_deps');
  }
  return value;
}

/**
 * `AuthorizationCodeFlowDeps` を 1 回だけ読み出して検証する。
 *
 * `signer` / `authorize` / `fetchImpl` / `createDpopProof` は class の prototype メソッドとして
 * 提供されるのが正当な DI のため `nonObjectPrototypeProperty`（own 限定にすると正当なクラス
 * ベース実装が「未指定」に化け、注入したブラウザ起動や証明書ピンニング付き fetch が無言で
 * 差し替わる）、純データの `holderDid` / `keyId` / `correlationContext` は `ownProperty` で読む。
 *
 * 関数値は取り出し元 `deps` をレシーバに束ね直して返す（裸で呼ぶと、インスタンス状態に
 * Custom Tab のハンドルや署名鍵を持つクラスベース実装が `this` を失って壊れる。`fetch-di.ts`
 * と同じ規則）。
 *
 * `authorize` は**必須**である。未指定を「認可をスキップする」と解釈すると、ユーザーの同意も
 * 認可コードも無いまま Token Request へ進む経路が生まれるため fail-closed に落とす。
 *
 * @param deps 呼び出し側から渡された依存。
 * @returns 検証済みの依存。
 * @throws 必須依存の欠落・型不正の場合（VericertsError、code `8010`）。
 */
export function resolveFlowDeps(deps: AuthorizationCodeFlowDeps): ResolvedFlowDeps {
  const signer = nonObjectPrototypeProperty<CredentialSigner>(deps, 'signer');
  const holderDid = ownProperty<unknown>(deps, 'holderDid');
  const keyId = ownProperty<unknown>(deps, 'keyId');
  if (
    typeof signer !== 'object' ||
    signer === null ||
    !isNonBlankString(holderDid) ||
    !isNonBlankString(keyId) ||
    hasExplicitNonCallableProperty(signer, 'sign')
  ) {
    throw depsFailure('invalid_flow_deps');
  }
  const authorizeFn = nonObjectPrototypeProperty<unknown>(deps, 'authorize');
  if (typeof authorizeFn !== 'function') {
    throw depsFailure('missing_authorize');
  }
  const authorize = (authorizationUrl: string): Promise<AuthorizationRedirect> =>
    (
      authorizeFn as (
        this: AuthorizationCodeFlowDeps,
        url: string,
      ) => Promise<AuthorizationRedirect>
    ).call(deps, authorizationUrl);

  const dpopFn = nonObjectPrototypeProperty<unknown>(deps, 'createDpopProof');
  // 可変長引数のまま中継する（Credential Endpoint 用の第 2 引数 `ctx.accessToken` を落とすと
  // `ath` を載せられない）。
  const createDpopProof: DpopProofFactory | undefined =
    typeof dpopFn === 'function'
      ? (...args) => (dpopFn as DpopProofFactory).call(deps, ...args)
      : undefined;

  return {
    signer,
    holderDid,
    keyId,
    authorize,
    fetchImpl: nonObjectPrototypeProperty<FetchLike>(deps, 'fetchImpl'),
    createDpopProof,
    correlationContext: optionalCorrelationContext(deps),
  };
}
