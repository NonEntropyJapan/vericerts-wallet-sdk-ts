/**
 * 受領フローの呼び出し側入力（`ReceiveDeps`）の読み取りと検証。
 *
 * `receive.ts` の「発行者と何を話すか」から「呼び出し側から何を受け取ったか」を分離する。
 * 呼び出し側が渡すオブジェクトは `JSON.parse` を通らないため、`parse-json.ts` のパース境界での
 * プロトタイプ除去が**一切効かない**（`own-property.ts` /「本ヘルパーが効かない範囲」）。
 * したがって読み取り時点の判定が唯一の防御線であり、その判定をこの 1 か所へ集約する。
 *
 * 併せて「1 回だけ読んで以降はローカルだけを使う」ことで、own アクセサ付きのオブジェクトを
 * 渡されたときに検査した値と実際に使う値が食い違う（TOCTOU）余地を無くす。
 */

import type { CredentialSigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { ClientAttestation } from '../../../eudi/wua/types.js';
import type { FetchLike } from '../../../fetch-di.js';
import { bindInjectedFetch } from '../../../http/bind-fetch.js';
import type { Metrics } from '../../../observability/metrics.js';
import { isNonBlankString } from '../../../prototype-safety/non-empty-string.js';
import {
  hasExplicitNonCallableProperty,
  nonObjectPrototypeProperty,
  ownProperty,
} from '../../../prototype-safety/own-property.js';
import { readFinalCredentialRequest } from '../../oid4vci/credential-wire/request-body.js';
import type { ReceiveDeps } from './types.js';

/** `deps` から読み出した、受領フローが実際に使う値の組。 */
export interface ResolvedDeps {
  /** JWT Proof の署名鍵。 */
  readonly signer: CredentialSigner;
  /** Holder DID（JWT Proof の `iss`）。 */
  readonly holderDid: string;
  /** 検証鍵 ID（JWT Proof の `kid`）。 */
  readonly keyId: string;
  /** HTTP 差し替えシーム（未注入なら `undefined`）。 */
  readonly fetchImpl: FetchLike | undefined;
  /**
   * Token Request へ添付する `client_assertion` の組み立て関数（未指定なら `undefined`）。
   * 取り出し元 `deps` をレシーバに束ね直してあるので、そのまま呼んでよい。
   */
  readonly buildClientAttestation: ((aud: string, nonce: string) => ClientAttestation) | undefined;
  /** `vericerts_oid4vci_token_duration_seconds` の記録先（未注入なら `undefined`）。 */
  readonly metrics: Metrics | undefined;
  /** `credentialRequestVersion: '1.0'` のとき `true`（`credential_configuration_id` 形で送る）。 */
  readonly finalCredentialRequest: boolean;
}

/**
 * `ReceiveDeps` を 1 回だけ読み出して検証する。
 *
 * `signer` / `fetchImpl` / `buildClientAttestation` は class の prototype メソッド・アクセサとして
 * 提供されるのが正当な DI のため `nonObjectPrototypeProperty`（own 限定にすると正当なクラスベース
 * 実装が「未指定」に化け、注入した fetch が無言でグローバル `fetch` に差し替わる）、純データの
 * `holderDid` / `keyId` は `ownProperty` で読む（`own-property.ts`「どちらのヘルパーを使うか」）。
 *
 * 欠落・型不正は `as` で下流へ流さず、この時点で fail-closed に拒否する。特に `keyId` は
 * **署名済み** JWT Proof の `kid` に載って検証側の鍵解決を誘導するため、汚染値が入り込む経路を
 * 残さない。エラーは `CREDENTIAL_REQUEST_FAILED`（8020）へ寄せる（受領そのものが成立しないため。
 * 新しいコードは作らない）。
 *
 * @param deps 呼び出し側から渡された依存。
 * @returns 検証済みの依存。
 * @throws 必須依存の欠落・型不正の場合（VericertsError、code `8020`）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export function resolveReceiveDeps(deps: ReceiveDeps): ResolvedDeps {
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
    throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED, {
      context: { reason: 'invalid_receive_deps' },
    });
  }
  // 関数値は「取り出し元をレシーバに束ね直して呼ぶ」（`fetch-di.ts` と同じ規則）。
  // 裸で呼ぶと、インスタンス状態に WUA を持つクラスベースの組み立て実装が `this` を失って壊れる。
  const build = nonObjectPrototypeProperty<unknown>(deps, 'buildClientAttestation');
  const buildClientAttestation =
    typeof build === 'function'
      ? (aud: string, nonce: string): ClientAttestation =>
          (build as (this: ReceiveDeps, aud: string, nonce: string) => ClientAttestation).call(
            deps,
            aud,
            nonce,
          )
      : undefined;
  return {
    signer,
    holderDid,
    keyId,
    fetchImpl: bindInjectedFetch(deps, 'fetchImpl'),
    buildClientAttestation,
    metrics: nonObjectPrototypeProperty<Metrics>(deps, 'metrics'),
    finalCredentialRequest: readFinalCredentialRequest(
      deps,
      () =>
        new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED, {
          context: { reason: 'invalid_receive_deps' },
        }),
    ),
  };
}
