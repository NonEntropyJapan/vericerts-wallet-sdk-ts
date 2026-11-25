/**
 * OID4VP `transaction_data` を提示（KB-JWT）へ束縛するための入力解決。
 *
 * 仕様 SoT: OpenID4VP §8.4 / HAIP（Wallet は `transaction_data` を要求されたとき、提示する各クレデンシャルの
 * KB-JWT に `transaction_data_hashes` / `transaction_data_hashes_alg` を含める）。
 *
 * 従来は同意画面で `transaction_data` を見せて承認させても、署名する KB-JWT にはそのハッシュを載せなかった
 * （承認した取引内容と署名対象が結び付かない）。本モジュールは要求の `transaction_data` を抽出して
 * クレデンシャルごとの対象へ割り当て、`addKeyBindingWithTransactionData` に渡す入力を決める。
 * **束縛できない要求は署名せず fail-closed で拒否する**（同意画面に出して束縛しない状態を残さない）:
 *
 * - SD-JWT VC 以外の提示形式（JWT-VP）は KB-JWT を持たず、ハッシュを載せる場所が無い → 拒否（8035）
 * - どの DCQL クレデンシャル要件（`credentials[].id`）の提示かを決められない → 拒否（8035）
 *   （入力の `credentialQueryId` 指定、または DCQL が要件 1 件のみのときその `id`）
 * - 提示するどのクレデンシャルにも紐付かない `transaction_data`（`credential_ids` 不一致）が残る → 拒否（8035）
 * - `type` / `credential_ids` 欠落・不正、未対応の `transaction_data_hashes_alg` → `extractTransactionData` が 8030
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { extractTransactionData } from '../../eudi/transaction-data/extract.js';
import type { TransactionDataEntry } from '../../eudi/transaction-data/types.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { DcqlQuery } from '../dcql/dcql.js';
import type { PresentationRequest } from '../request.js';

/** 提示失敗（8035、再試行不可）。理由は固定識別子のみ（`transaction_data` 本文を載せない）。 */
export function transactionDataBindingFailure(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.PRESENTATION_SUBMIT_FAILED, { context: { reason } });
}

/** 要求が `transaction_data` を持つか（持たなければ従来どおりの提示）。 */
export function hasTransactionData(request: PresentationRequest): boolean {
  const raw = ownProperty<readonly string[]>(request, 'transactionData');
  return raw !== undefined && raw.length > 0;
}

/** 1 件の提示入力がどの DCQL クレデンシャル要件に対応するか（`id`）を決める。決められなければ `undefined`。 */
function resolveCredentialQueryId(
  request: PresentationRequest,
  explicitId: string | undefined,
): string | undefined {
  if (explicitId !== undefined) {
    return explicitId;
  }
  const credentials = ownProperty<DcqlQuery>(request, 'dcqlQuery')?.credentials;
  return credentials !== undefined && credentials.length === 1 ? credentials[0]?.id : undefined;
}

/**
 * 提示入力ごとに、KB-JWT へ束縛する Transaction Data（要求順）を決める。要求に `transaction_data` が無ければ
 * 全入力が空（従来どおりの KB-JWT）。
 *
 * @param request パース済み Authorization Request。
 * @param inputs `buildVPToken` の提示入力（`credentialQueryId` のみを own 限定で読む）。
 * @param isSdJwt 入力が SD-JWT VC 形式かの判定（`oid4vp.ts` の型述語）。
 * @returns 入力と同じ順序の、各提示に束縛する Transaction Data。
 * @throws 束縛できない場合（VericertsError、code `8035`）、`transaction_data` 不正（code `8030`）。
 */
export function resolveTransactionDataBindings(
  request: PresentationRequest,
  inputs: readonly object[],
  isSdJwt: (input: object) => boolean,
): readonly (readonly TransactionDataEntry[])[] {
  if (!hasTransactionData(request)) {
    return inputs.map(() => []);
  }
  const entries = extractTransactionData(
    ownProperty<readonly string[]>(request, 'transactionData'),
  );
  const bound = new Set<TransactionDataEntry>();
  const bindings = inputs.map((input) => {
    if (!isSdJwt(input)) {
      throw transactionDataBindingFailure('transaction_data_unsupported_format');
    }
    const queryId = resolveCredentialQueryId(
      request,
      ownProperty<string>(input, 'credentialQueryId'),
    );
    if (queryId === undefined) {
      throw transactionDataBindingFailure('transaction_data_credential_unresolved');
    }
    const relevant = entries.filter((entry) => entry.credentialIds.includes(queryId));
    for (const entry of relevant) {
      bound.add(entry);
    }
    return relevant;
  });
  // どの提示にも束縛されない取引は、利用者が同意しても署名対象に入らない。黙って落とさず拒否する。
  if (entries.some((entry) => !bound.has(entry))) {
    throw transactionDataBindingFailure('transaction_data_credential_ids_unmatched');
  }
  return bindings;
}

/**
 * 呼び出し側（同意 UI）が利用者に見せて同意を取った `transaction_data`（生 base64url 文字列配列）と、
 * 署名対象になる要求の `transaction_data` が**完全に同一**であることを確かめる。
 *
 * 同意後に `request_uri` の応答が差し替わっても、承認した取引と別の取引へ署名しない。
 * 順序・件数・文字列のいずれが違っても不一致（ハッシュは生文字列に対して計算されるため）。
 *
 * @throws 不一致の場合（VericertsError、code `10402`）。
 */
export function assertConsentedTransactionData(
  request: PresentationRequest,
  consented: readonly string[],
): void {
  const actual = ownProperty<readonly string[]>(request, 'transactionData') ?? [];
  if (actual.length !== consented.length || actual.some((value, i) => value !== consented[i])) {
    throw new VericertsError(ErrorCodes.TRANSACTION_DATA_HASH_MISMATCH, {
      context: { reason: 'transaction_data_consent_mismatch' },
    });
  }
}
