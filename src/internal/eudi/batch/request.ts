/**
 * Batch Credential Request の組み立て。
 *
 * 単一の OID4VCI セッションで複数の短命 VC をバッチ発行するため、各短命鍵ペアの
 * proof JWT を配列にまとめ、`{ proofs: { jwt: [...] } }` を作る。
 *
 * 本モジュールは組み立て（純粋変換）のみを担い、proof JWT の署名や送信は行わない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { BatchCredentialRequest, BatchProof } from './types.js';

/**
 * Batch Credential Request を組み立てる。
 *
 * @param vct    発行対象の VC Type URI（例: `urn:eudi:pid:1`）。空文字は不可。
 * @param proofs 短命鍵ペアごとの proof。1 件以上必須。各 proof は `proofType='jwt'`。
 * @returns `{ vct, proofs: { jwt: [...] } }` 形式のリクエストボディ。
 * @throws {VericertsError} vct が空、proofs が空、proof の種別が jwt でない、
 *   もしくは jwt が空文字の場合（いずれも code `8020` CREDENTIAL_REQUEST_FAILED。
 *   個別の理由は `context.reason`、該当 proof の位置は `context.index` で識別する）。
 *
 * proof の順序は入力順を保持する（Issuer は同順で `credentials` 配列を返す）。
 */
export function buildBatchCredentialRequest(
  vct: string,
  proofs: readonly BatchProof[],
): BatchCredentialRequest {
  if (typeof vct !== 'string' || vct.length === 0) {
    throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED, {
      context: { reason: 'missing_vct' },
    });
  }
  if (proofs.length === 0) {
    throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED, {
      context: { reason: 'empty_proofs' },
    });
  }

  const jwts: string[] = [];
  for (const [index, proof] of proofs.entries()) {
    if (proof.proofType !== 'jwt') {
      throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED, {
        context: { reason: 'invalid_proof_type', index },
      });
    }
    if (typeof proof.jwt !== 'string' || proof.jwt.length === 0) {
      throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED, {
        context: { reason: 'empty_jwt', index },
      });
    }
    jwts.push(proof.jwt);
  }

  return {
    vct,
    proofs: { jwt: jwts },
  };
}
