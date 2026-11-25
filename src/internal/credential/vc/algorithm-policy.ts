/**
 * JWT-VC の署名アルゴリズムに対する検証ポリシー。
 *
 * `verify.ts` から分離してファイル行数上限（linterly）を抑える。ステータスの一元管理そのものは
 * 横断ヘルパー `crypto-registry.ts` が持ち、本モジュールは JWT-VC の `alg` 値をそのレジストリ ID
 * （`algorithm@version`）へ写像し、ステータスに応じた Verifier ポリシーを適用する薄い層である。
 */

import { type AlgorithmStatus, getAlgorithmStatus } from '../../crypto-registry.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { CredentialSignerAlg } from './jws.js';

/**
 * JWT-VC の `alg`（`ES256` / `ES256K` / `EdDSA`）→ 暗号アジリティレジストリの ID
 * （`algorithm@version`）。レジストリ側の最新バージョンに対応させる。
 */
const CREDENTIAL_ALG_REGISTRY_ID: Record<CredentialSignerAlg, string> = {
  ES256: 'ES256@1.0',
  ES256K: 'ES256K@1.0',
  'ES256K-R': 'ES256K-R@1.0',
  EdDSA: 'EdDSA-Ed25519@1.0',
};

/**
 * 暗号アジリティレジストリのステータスに Verifier ポリシーを適用する。
 *
 * | ステータス                            | 挙動                                                             |
 * | -------------------------------------- | ------------------------------------------------------------------ |
 * | `recommended` / `acceptable`           | 通常検証（`false` を返す）                                        |
 * | `deprecated` / `sunset`                | 検証は継続し、警告フラグとして `true` を返す                       |
 * | `prohibited`                           | 署名検証より前に fail-closed で拒否する（`VericertsError` 3019）   |
 * | それ以外（未登録 `undefined` を含む）  | 通常検証（`false`）。サポート対象の署名アルゴリズムはすべてレジストリに登録済みのため、実際にはここへ到達しない |
 *
 * `prohibited` を署名検証（暗号処理）より前に判定するのは `alg=none` と同じ早期拒否の考え方で、
 * 失敗するはずの署名検証に暗号処理コストを払わないためである。
 *
 * @param status 対象アルゴリズムの暗号アジリティレジストリ上のステータス（未登録なら `undefined`）。
 * @returns `algorithmDeprecated` に載せるべき警告フラグ。
 * @throws ステータスが `prohibited` の場合（VericertsError、code `3019`）。
 */
export function applyAlgorithmStatusPolicy(status: AlgorithmStatus | undefined): boolean {
  if (status === 'prohibited') {
    throw new VericertsError(ErrorCodes.VERIFY_ALGO_PROHIBITED);
  }
  return status === 'deprecated' || status === 'sunset';
}

/**
 * JWT-VC の `alg` に対する検証ポリシーを解決する。
 *
 * `verify.ts` の `verifyCredential` が呼ぶ唯一の入口。レジストリ ID への写像
 * （`CREDENTIAL_ALG_REGISTRY_ID`）とステータス参照（`getAlgorithmStatus`）を隠蔽し、
 * 呼び出し側は `CredentialAlg` だけを渡せばよい。
 *
 * @param alg 検証済みの JWT-VC 署名アルゴリズム。
 * @returns `algorithmDeprecated` に載せるべき警告フラグ。
 * @throws アルゴリズムが `prohibited` 段階の場合（VericertsError、code `3019`）。
 */
export function resolveCredentialAlgorithmDeprecation(alg: CredentialSignerAlg): boolean {
  return applyAlgorithmStatusPolicy(getAlgorithmStatus(CREDENTIAL_ALG_REGISTRY_ID[alg]));
}
