/**
 * ファサード `receiveCredential` の依存の読み取りと検証。
 *
 * 呼び出し側が渡すオブジェクトは `JSON.parse` を通らないため、`parse-json.ts` のパース境界での
 * プロトタイプ除去が**一切効かない**（`own-property.ts`「本ヘルパーが効かない範囲」）。したがって
 * 読み取り時点の判定が唯一の防御線であり、その判定をこの 1 か所へ集約する。併せて
 * 「1 回だけ読んで以降はローカルだけを使う」ことで、own アクセサ付きのオブジェクトを渡された
 * ときに検査した値と実際に使う値が食い違う（TOCTOU）余地を無くす。
 *
 * 方針・記法は `authz-flow/deps.ts`と `eudi/issuance/deps.ts`に揃える。
 */

import type { CredentialSigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { FetchLike } from '../../../fetch-di.js';
import type { CorrelationContext } from '../../../observability/correlation.js';
import { isCorrelationContext } from '../../../observability/correlation.js';
import { isNonBlankString } from '../../../prototype-safety/non-empty-string.js';
import {
  hasExplicitNonCallableProperty,
  isObjectPrototypeProperty,
  nonObjectPrototypeProperty,
  ownProperty,
} from '../../../prototype-safety/own-property.js';
import { FORMAT_SD_JWT_VC_DC } from '../../matcher.js';
import type { AuthorizationRedirect } from '../authz-flow/types.js';
import { readFinalCredentialRequest } from '../credential-wire/request-body.js';
import type { DpopProofFactory } from '../oid4vci-credential-dpop.js';
import type { ReceiveCredentialDeps } from './types.js';

/** 読み出し済みの依存。関数値はレシーバを束ね直してある。 */
export interface ResolvedReceiveDeps {
  readonly signer: CredentialSigner;
  readonly holderDid: string;
  readonly keyId: string;
  readonly authorize: ((authorizationUrl: string) => Promise<AuthorizationRedirect>) | undefined;
  readonly txCode: string | undefined;
  readonly clientAssertion: string | undefined;
  readonly clientAssertionType: string | undefined;
  readonly clientId: string | undefined;
  readonly redirectUri: string | undefined;
  readonly format: string;
  /** `credentialRequestVersion: '1.0'` のとき `true`（`credential_configuration_id` 形で送る）。 */
  readonly finalCredentialRequest: boolean;
  readonly createDpopProof: DpopProofFactory | undefined;
  readonly verifyReceived: ((raw: string) => void | Promise<void>) | undefined;
  readonly fetchImpl: FetchLike | undefined;
  readonly correlationContext: CorrelationContext | undefined;
}

/** 依存不正は `TOKEN_REQUEST_FAILED`（8010）へ寄せる（Offer から先へ 1 歩も進めないため）。 */
export function facadeFailure(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED, { context: { reason } });
}

/**
 * `ReceiveCredentialDeps` の**全キー**（`Object.prototype` 汚染の拒否対象）。
 *
 * `satisfies` が余計なキー（型に無いキー）を、{@link MissingReceiveDepsKey} が漏れたキーをコンパイル時に
 * 弾く。`ReceiveCredentialDeps` にキーを足すと、ここへ足すまで `tsc` が落ちる。
 */
export const RECEIVE_DEPS_KEYS = [
  // `Wallet` が解決する値（`Wallet.receiveCredential` は `opts` では読まず、常に自分の値で上書きする）。
  'signer',
  'holderDid',
  'keyId',
  // 関数 DI。
  'authorize',
  'createDpopProof',
  'verifyReceived',
  'fetchImpl',
  // 純データ。
  'txCode',
  'clientAssertion',
  'clientAssertionType',
  'clientId',
  'redirectUri',
  'format',
  'credentialRequestVersion',
  'correlationContext',
] as const satisfies readonly (keyof ReceiveCredentialDeps)[];

/** `RECEIVE_DEPS_KEYS` に載っていない `ReceiveCredentialDeps` のキー。常に `never` でなければならない。 */
type MissingReceiveDepsKey = Exclude<
  keyof ReceiveCredentialDeps,
  (typeof RECEIVE_DEPS_KEYS)[number]
>;
/** `MissingReceiveDepsKey` が空でない（= キーの載せ忘れ）と、この制約 `T extends never` が型エラーになる。 */
export type AssertAllReceiveDepsKeysListed<T extends never = MissingReceiveDepsKey> = T;

/**
 * DI キーが `Object.prototype` 由来（データ汚染・アクセサ汚染）なら `8010` / `invalid_receive_deps` で拒否する
 * （以前は未指定扱いで黙って捨てていた）。
 *
 * 汚染を黙って捨てると、利用者は自分が渡していない値の存在に気づけない。ファサードと `Wallet.receiveCredential`
 * の両方が同じ規則（**15 キー全て**を、副作用・通信の**前**に拒否）を使うよう、判定をこの 1 か所に置く。
 * `signer` / `holderDid` / `keyId` を含めるのは、規則を 1 本に保ち、読み方が将来変わっても汚染が素通りしないため。
 * `deps` 自身またはそのクラスのプロトタイプが同じキーを持つなら、それが優先され拒否しない。
 *
 * @throws 汚染されたキーがある場合（VericertsError、code `8010`）。
 */
export function rejectPollutedReceiveDeps(deps: object | undefined): void {
  const source = deps ?? {};
  for (const key of RECEIVE_DEPS_KEYS) {
    if (isObjectPrototypeProperty(source, key)) {
      throw facadeFailure('invalid_receive_deps');
    }
  }
}

/** 任意の純データ文字列メンバを own 限定で読む。空文字・非文字列は不正として落とす。 */
function optionalString(deps: object, key: string): string | undefined {
  const value = ownProperty<unknown>(deps, key);
  if (value === undefined) {
    return undefined;
  }
  if (!isNonBlankString(value)) {
    throw facadeFailure('invalid_receive_deps');
  }
  return value;
}

/**
 * 相関 ID を own 限定で読む。純データなので `ownProperty` を使う。
 *
 * 形が壊れた値は `optionalString` と同じく `invalid_receive_deps`（8010）で弾く（下流の
 * プリミティブは黙って落とすが、ここは呼び出し側の入力を検証する境界である）。
 */
function optionalCorrelationContext(deps: object): CorrelationContext | undefined {
  const value = ownProperty<unknown>(deps, 'correlationContext');
  if (value === undefined) {
    return undefined;
  }
  if (!isCorrelationContext(value)) {
    throw facadeFailure('invalid_receive_deps');
  }
  return value;
}

/**
 * 任意の関数値メンバを読み、取り出し元 `deps` をレシーバに束ね直して返す。
 *
 * `nonObjectPrototypeProperty` を使うのは、これらが `class Deps { authorize() {…} }` のように
 * **プロトタイプメソッドとして実装されるのが正当**な DI だからである（`own-property.ts`
 * 「どちらのヘルパーを使うか」）。own 限定で読むと正当なクラスベース実装が「未指定」に化け、
 * 注入したブラウザ起動・DPoP proof 生成・署名検証が**無言でスキップ**される（fail-open）。
 * 裸で呼ぶとインスタンス状態（Custom Tab のハンドル・署名鍵）を持つ実装が `this` を失って壊れる。
 */
function optionalFunction(deps: object, key: string): ((...args: never[]) => unknown) | undefined {
  const fn = nonObjectPrototypeProperty<unknown>(deps, key);
  if (fn === undefined) {
    return undefined;
  }
  if (typeof fn !== 'function') {
    throw facadeFailure('invalid_receive_deps');
  }
  return (...args: never[]): unknown =>
    (fn as (this: object, ...a: never[]) => unknown).call(deps, ...args);
}

/**
 * `ReceiveCredentialDeps` を 1 回だけ読み出して検証する。
 *
 * `signer` は class インスタンスであり得るため `nonObjectPrototypeProperty`、純データの
 * `holderDid` / `keyId` / 各種文字列 / `correlationContext` は `ownProperty` で読む。grant 種別ごとの必須依存
 * （`authorize` / `clientId` / `redirectUri`）はここでは検査せず、grant を判別した後に
 * `receive.ts` が検査する（pre-authorized_code の Offer にそれらを要求しないため）。
 *
 * @param deps 呼び出し側から渡された依存。
 * @returns 検証済みの依存。`format` は未指定なら SD-JWT VC（`dc+sd-jwt`）。
 * @throws 必須依存の欠落・型不正、または `Object.prototype` 由来の汚染がある場合（VericertsError、code `8010`）。
 */
export function resolveReceiveCredentialDeps(deps: ReceiveCredentialDeps): ResolvedReceiveDeps {
  rejectPollutedReceiveDeps(deps);
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
    throw facadeFailure('invalid_receive_deps');
  }
  return {
    signer,
    holderDid,
    keyId,
    authorize: optionalFunction(deps, 'authorize') as ResolvedReceiveDeps['authorize'],
    txCode: optionalString(deps, 'txCode'),
    clientAssertion: optionalString(deps, 'clientAssertion'),
    clientAssertionType: optionalString(deps, 'clientAssertionType'),
    clientId: optionalString(deps, 'clientId'),
    redirectUri: optionalString(deps, 'redirectUri'),
    format: optionalString(deps, 'format') ?? FORMAT_SD_JWT_VC_DC,
    finalCredentialRequest: readFinalCredentialRequest(deps, () =>
      facadeFailure('invalid_receive_deps'),
    ),
    createDpopProof: optionalFunction(
      deps,
      'createDpopProof',
    ) as ResolvedReceiveDeps['createDpopProof'],
    verifyReceived: optionalFunction(
      deps,
      'verifyReceived',
    ) as ResolvedReceiveDeps['verifyReceived'],
    fetchImpl: nonObjectPrototypeProperty<FetchLike>(deps, 'fetchImpl'),
    correlationContext: optionalCorrelationContext(deps),
  };
}
