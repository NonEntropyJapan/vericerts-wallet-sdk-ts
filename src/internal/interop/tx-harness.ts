/**
 * HAIP SD-JWT VC と Transaction Data 提示を検証する相互運用ハーネス。
 *
 * KB-JWT に `transaction_data_hashes` を含めて署名する。
 *
 * HAIP プロファイルの OID4VP 提示で、Verifier が Transaction Data（例: payment）への同意を
 * 要求する場合のフロー。`runInteropPair` の Present 段階を Transaction Data 付き KB-JWT
 * （`addKeyBindingWithTransactionData`）へ差し替え、Verifier が `transaction_data_hashes` を
 * 突き合わせられる形で提示する。抽出（`extractTransactionData`）→ ハッシュ計算 → KB-JWT 格納 →
 * 検証の一貫性を相互運用境界で確認する。
 */

import type { CreateSdJwtOptions } from '../credential/sdjwt/sdjwt.js';
import { createSdJwt, selectDisclosures } from '../credential/sdjwt/sdjwt.js';
import type { VerifiedSdJwt } from '../credential/sdjwt/verify.js';
import { verifySdJwt } from '../credential/sdjwt/verify.js';
import type { CredentialSigner } from '../credential/vc/signer.js';
import { extractTransactionData } from '../eudi/transaction-data/extract.js';
import { addKeyBindingWithTransactionData } from '../eudi/transaction-data/hashes.js';
import type { TransactionDataEntry } from '../eudi/transaction-data/types.js';
import type { PublicKeyJwk } from '../identity/did.js';
import { nonObjectPrototypeProperty, ownProperty } from '../prototype-safety/own-property.js';

/** Transaction Data 付きペアフローの入力。 */
export interface InteropTxPairInput {
  /** Issuer 署名器。 */
  readonly issuer: CredentialSigner;
  /** Issuer 検証鍵。 */
  readonly issuerKey: PublicKeyJwk;
  /** Holder 署名器（cnf に対応）。 */
  readonly holder: CredentialSigner;
  /** SD-JWT VC 発行入力（fixtures）。 */
  readonly credential: CreateSdJwtOptions;
  /** 提示要求クレーム名。 */
  readonly requestedClaims: readonly string[];
  /** Verifier 発行の nonce。 */
  readonly nonce: string;
  /** Verifier 識別子（audience / client_id）。 */
  readonly audience: string;
  /** OID4VP Authorization Request の `transaction_data`（生 base64url 文字列配列）。 */
  readonly transactionData: readonly string[];
  /** KB-JWT の iat（決定性）。 */
  readonly iatSeconds: number;
  /**
   * 検証時の現在時刻（エポック秒）。既定は `iatSeconds`。
   * 時刻クレーム評価は wall-clock に依存させず、フィクスチャの時刻軸で決定的に行う。
   */
  readonly nowSeconds?: number;
}

/** Transaction Data 付きペアフローの結果。 */
export interface InteropTxPairResult {
  /** 抽出・正規化された Transaction Data。 */
  readonly extracted: readonly TransactionDataEntry[];
  /** 提示した SD-JWT VC（選択開示 + Transaction Data 付き KB-JWT）。 */
  readonly presented: string;
  /** Verifier の検証結果。 */
  readonly verified: VerifiedSdJwt;
}

/**
 * HAIP SD-JWT VC + Transaction Data の提示フローを 1 サイクル実行する。
 *
 * Offer/Receive は `runInteropPair` と同一だが、Present 段階で Transaction Data を抽出し、
 * その `transaction_data_hashes` を KB-JWT に格納して署名する。Verifier は SD-JWT VC を検証する
 * （`transaction_data_hashes` 自体の Verifier 側突合は issuer/verifier ドメインの責務のため、
 * ここでは KB-JWT 署名・cnf・nonce / aud の一貫性まで確認する）。
 *
 * @param input 各ロールの鍵・提示要求・Transaction Data。
 * @returns 抽出結果・提示 SD-JWT VC・検証結果。
 * @throws 抽出・提示・検証いずれかの失敗時（VericertsError をそのまま伝播）。
 */
export function runInteropTxPair(input: InteropTxPairInput): InteropTxPairResult {
  // 任意プロパティは自身のプロパティに限って読む。継承値を新しいオブジェクト
  // リテラルへ詰め直すと own プロパティに化け、下流（`createSdJwt` / `verifySdJwt` /
  // `addKeyBinding`）の own 限定読み取りが無効化される。本ハーネスは `exports/interop.ts` から
  // 公開されており、署名対象の `nonce` / `aud` / `iat` と検証の基準時刻に汚染値が入り得る。
  const iatSeconds = ownProperty<number>(input, 'iatSeconds');
  const nonce = ownProperty<string>(input, 'nonce') as string;
  const audience = ownProperty<string>(input, 'audience') as string;
  // 検証鍵も同関数内で読み方を揃える（nonce / audience / iatSeconds は own 化済み）。
  // クラスインスタンスであり得るため `Object.prototype` 由来だけを弾く。
  const issuerKey = nonObjectPrototypeProperty<PublicKeyJwk>(input, 'issuerKey') as PublicKeyJwk;
  const nowSeconds = ownProperty<number>(input, 'nowSeconds') ?? iatSeconds;
  // 必須フィールドも同じ規律で読む。型上は必須だが、型の無い JS から渡し忘れると
  // 継承値がそのまま発行入力・提示要求・同意対象の取引・署名器になる。`credential` は
  // `{ ...credential }` で own プロパティへ化けるため攻撃者の `vct` / `claims` が**正規の Issuer
  // 鍵で署名されて発行**され、`transactionData` は Holder が**同意していない取引**の
  // `transaction_data_hashes` を署名済み KB-JWT に載せる。純データは own 限定で読む。
  const credential = ownProperty<CreateSdJwtOptions>(input, 'credential') as CreateSdJwtOptions;
  const requestedClaims = ownProperty<readonly string[]>(
    input,
    'requestedClaims',
  ) as readonly string[];
  const transactionData = ownProperty<readonly string[]>(
    input,
    'transactionData',
  ) as readonly string[];
  // 署名器は `class Signer { sign() {} }` のようにプロトタイプメソッドで実装され得るため、
  // own 限定では正当なクラスインスタンスを「未指定」と誤判定する。`Object.prototype` 由来だけを弾く。
  const issuer = nonObjectPrototypeProperty<CredentialSigner>(input, 'issuer') as CredentialSigner;
  const holder = nonObjectPrototypeProperty<CredentialSigner>(input, 'holder') as CredentialSigner;
  // 発行時刻を検証側の基準時刻に合わせる（`iat` が `nowSeconds` より未来だと 4014 になるため）。
  const issued = createSdJwt(issuer, {
    ...credential,
    ...(nowSeconds !== undefined ? { nowSeconds } : {}),
  });
  // Receive 検証（Issuer 署名・vct）。
  verifySdJwt(issued, {
    issuerKey,
    expectedVct: credential.vct,
    nowSeconds,
  });

  const extracted = extractTransactionData(transactionData);
  const disclosed = selectDisclosures(issued, requestedClaims);
  const presented = addKeyBindingWithTransactionData(disclosed, holder, {
    nonce,
    audience,
    transactionData: extracted,
    ...(iatSeconds !== undefined ? { iatSeconds } : {}),
  });

  const verified = verifySdJwt(presented, {
    issuerKey,
    expectedVct: credential.vct,
    audience,
    nonce,
    requireKeyBinding: true,
    nowSeconds,
  });

  return { extracted, presented, verified };
}
