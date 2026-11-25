/**
 * Transaction Data の KB-JWT hashes 計算と KB-JWT への格納。
 *
 * OID4VP（draft-ietf-oauth-transaction-data / OpenID4VP §8.4）では、Holder は提示する
 * Transaction Data の base64url 文字列そのものに対する SHA-256 を base64url でエンコードし、
 * KB-JWT payload の `transaction_data_hashes`（配列）に格納する。`transaction_data_hashes_alg`
 * にはアルゴリズム識別子を格納する。これにより Verifier は同意された Transaction Data と署名の
 * 結び付きを検証できる。
 *
 * KB-JWT の基本構造（`nonce` / `aud` / `iat` / `sd_hash`）は `credential/sdjwt` の `addKeyBinding`
 * と同一だが、`transaction_data_hashes` / `transaction_data_hashes_alg` を追加する点が異なる。
 * `sd_hash` は KB-JWT を除いた提示部（末尾 `~` まで）の SHA-256（`addKeyBinding` と同一計算）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` に Transaction Data 本文・鍵素材・JWT を含めない。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { base64urlText } from '../../base64url.js';
import { assertBindingValue } from '../../credential/sdjwt/key-binding.js';
import { buildJwsHeader, type CredentialSigner } from '../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { isEpochSeconds } from '../../primitives/option-guard.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { TRANSACTION_DATA_HASH_ALG, type TransactionDataEntry } from './types.js';

/** ハッシュ関数（バイト列 → digest バイト列）。 */
type HashFunction = (input: Uint8Array) => Uint8Array;

/**
 * 対応する `transaction_data_hashes_alg` → ハッシュ関数の対応表。本 SDK は `sha-256` のみ対応。
 *
 * プロトタイプを持たないオブジェクト（`Object.create(null)`）として構築する。引く鍵は Verifier の
 * Authorization Request や受領 KB-JWT の `transaction_data_hashes_alg` 由来＝攻撃者が自由に指定
 * できる値であり、通常のオブジェクトリテラルだと `"constructor"` / `"toString"` / `"valueOf"` が
 * `Object.prototype` のプロパティにヒットする。ヒットするのは関数などの非 undefined 値なので
 * 「表に無ければ拒否」という fail-closed の判定をすり抜け、未対応アルゴリズムが受理されうる。
 * プロトタイプを断つことで、未知アルゴリズムが構造的に `undefined` ＝拒否へ落ちる
 * （`credential/format-negotiation/types.ts` の `PRIVACY_TIER` と同じ定石）。
 */
const TRANSACTION_DATA_HASH_FUNCTIONS: Readonly<Record<string, HashFunction | undefined>> =
  Object.assign(Object.create(null) as Record<string, HashFunction | undefined>, {
    [TRANSACTION_DATA_HASH_ALG]: sha256,
  });

/**
 * 指定アルゴリズムで Transaction Data 群の `transaction_data_hashes` を計算する。
 *
 * 各要素の生 base64url 文字列（`encoded`）そのものを入力として digest を取り、base64url で
 * エンコードした配列を返す。入力順を保持する（Verifier は要求順と突き合わせる）。
 *
 * 未対応アルゴリズムは fail-closed で拒否する（既定の `sha-256` へフォールバックしない）。
 *
 * @param entries 抽出済み Transaction Data（`extractTransactionData` の戻り値）。
 * @param alg ハッシュアルゴリズム識別子（`transaction_data_hashes_alg`）。
 * @returns 各要素の base64url digest 配列（入力順）。
 * @throws 未対応アルゴリズムの場合（VericertsError、code `10402`）。
 */
export function computeTransactionDataHashesWithAlg(
  entries: readonly TransactionDataEntry[],
  alg: string,
): readonly string[] {
  const digest = TRANSACTION_DATA_HASH_FUNCTIONS[alg];
  if (digest === undefined) {
    throw new VericertsError(ErrorCodes.TRANSACTION_DATA_HASH_MISMATCH, {
      context: { reason: 'transaction_data_hashes_alg_unsupported' },
    });
  }
  return entries.map((entry) =>
    base64urlnopad.encode(digest(new TextEncoder().encode(entry.encoded))),
  );
}

/**
 * Transaction Data 群の `transaction_data_hashes` を計算する。
 *
 * 各要素の生 base64url 文字列（`encoded`）そのものを入力として SHA-256 を取り、base64url で
 * エンコードした配列を返す。入力順を保持する（Verifier は要求順と突き合わせる）。
 *
 * @param entries 抽出済み Transaction Data（`extractTransactionData` の戻り値）。
 * @returns 各要素の base64url SHA-256 ハッシュ配列（入力順）。
 */
export function computeTransactionDataHashes(
  entries: readonly TransactionDataEntry[],
): readonly string[] {
  return computeTransactionDataHashesWithAlg(entries, TRANSACTION_DATA_HASH_ALG);
}

/** `addKeyBindingWithTransactionData` の入力。 */
export interface TransactionDataKeyBindingOptions {
  /** Verifier 発行の nonce。 */
  readonly nonce: string;
  /** Verifier 識別子（audience / client_id）。 */
  readonly audience: string;
  /** 同意された Transaction Data（`extractTransactionData` の戻り値）。 */
  readonly transactionData: readonly TransactionDataEntry[];
  /**
   * UI で表示・同意された内容に対応する期待ハッシュ（`computeTransactionDataHashes` 相当）。
   * 指定時は KB-JWT へ格納するハッシュと厳密一致を検査し、不一致なら同意改ざんとして拒否する
   * （10402 TRANSACTION_DATA_HASH_MISMATCH）。UI と KB-JWT の乖離検知に用いる。
   */
  readonly expectedHashes?: readonly string[];
  /** 発行時刻（エポック秒）。既定は現在時刻。テストの決定性のため注入可能。 */
  readonly iatSeconds?: number;
}

/** `expectedHashes` 指定時、KB-JWT へ格納するハッシュと厳密一致を検査する（不一致は 10402）。 */
function assertHashesMatchConsent(
  computed: readonly string[],
  expected: readonly string[] | undefined,
): void {
  if (expected === undefined) {
    return;
  }
  const mismatch =
    computed.length !== expected.length || computed.some((h, i) => h !== expected[i]);
  if (mismatch) {
    throw new VericertsError(ErrorCodes.TRANSACTION_DATA_HASH_MISMATCH);
  }
}

/**
 * SD-JWT 提示部に `transaction_data_hashes` 付き Key Binding JWT を付与する。
 *
 * Holder が `signer`（`cnf.jwk` に対応する鍵）で KB-JWT（`typ:'kb+jwt'`）を署名し、提示部末尾に
 * 連結する。KB-JWT payload は `{ nonce, aud, iat, sd_hash, transaction_data_hashes,
 * transaction_data_hashes_alg }`。`sd_hash` は KB-JWT を除いた提示部（末尾 `~` まで）の SHA-256。
 *
 * `opts.expectedHashes` 指定時は、UI で表示・同意された内容のハッシュと格納するハッシュの厳密一致を
 * 検査し、不一致なら同意改ざんとして拒否する（code `10402`）。
 *
 * @param sdJwt 提示部 SD-JWT（KB-JWT なし、末尾 `~`）。
 * @param signer Holder の署名鍵（`cnf.jwk` に対応）。`kid` 設定時は KB-JWT ヘッダへ伝播する。
 * @param opts nonce / audience / transactionData / expectedHashes / iat。
 * @returns KB-JWT を連結した SD-JWT 文字列。
 * @throws 入力 SD-JWT に既に KB-JWT が含まれる / Transaction Data が空の場合（VericertsError、code `3010`）、
 *         `nonce` / `audience` が空・未指定・非文字列の場合（code `3012`。`addKeyBinding` と同じ判定）、
 *         `expectedHashes` と不一致の場合（code `10402`）。
 */
export function addKeyBindingWithTransactionData(
  sdJwt: string,
  signer: CredentialSigner,
  opts: TransactionDataKeyBindingOptions,
): string {
  // `nonce` / `audience` は型上必須だが、型の無い JS から渡し忘れると `undefined` がクレームごと落ち、
  // `nonce` も `aud` も持たない KB-JWT に Holder 鍵で署名してしまう（リプレイ・Verifier 束縛が成立しない）。
  // 通常版 `addKeyBinding` と同じ判定（3012）を共有し、own 限定で読む。
  const nonce = ownProperty<string>(opts, 'nonce');
  const audience = ownProperty<string>(opts, 'audience');
  assertBindingValue(nonce);
  assertBindingValue(audience);
  if (!sdJwt.endsWith('~')) {
    // 既に KB-JWT が付与されている（末尾が `~` でない）提示部には再付与しない。
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  if (opts.transactionData.length === 0) {
    // Transaction Data なしで本関数を呼ぶのは誤用（通常の addKeyBinding を使う）。
    throw new VericertsError(ErrorCodes.SIG_INVALID, {
      context: { reason: 'transaction_data_empty' },
    });
  }
  const transactionDataHashes = computeTransactionDataHashes(opts.transactionData);
  assertHashesMatchConsent(
    transactionDataHashes,
    ownProperty<readonly string[]>(opts, 'expectedHashes'),
  );

  const sdHash = base64urlnopad.encode(sha256(new TextEncoder().encode(sdJwt)));
  // ヘッダは発行系・`addKeyBinding` と同じ組み立てを共有し、`signer.kid` を伝播する。
  // `kid` 未設定時は従来どおり `{"alg":...,"typ":"kb+jwt"}` と完全に一致する（後方互換）。
  const header = buildJwsHeader(signer, 'kb+jwt');
  const iat = ownProperty<number>(opts, 'iatSeconds') ?? Math.floor(Date.now() / 1000);
  // 非有限・負値・文字列の `iat` は署名済み KB-JWT に `null` 等で載り、鮮度判定が成立しない。
  if (!isEpochSeconds(iat)) {
    throw new VericertsError(ErrorCodes.SIG_INVALID, { context: { reason: 'iat_invalid' } });
  }
  const payload = {
    nonce,
    aud: audience,
    // 任意プロパティは自身のプロパティに限って読む。この payload はそのまま
    // 署名されるため、`iatSeconds` を省略した正当な生成でも継承値が **署名済み KB-JWT の
    // `iat`** になり、KB-JWT の鮮度判定を攻撃者が選んだ時刻に固定できる。
    iat,
    sd_hash: sdHash,
    transaction_data_hashes: transactionDataHashes,
    transaction_data_hashes_alg: TRANSACTION_DATA_HASH_ALG,
  };
  const headerSeg = base64urlText(JSON.stringify(header));
  const payloadSeg = base64urlText(JSON.stringify(payload));
  const signingInput = `${headerSeg}.${payloadSeg}`;
  const signature = signer.sign(new TextEncoder().encode(signingInput));
  const kbJwt = `${signingInput}.${base64urlnopad.encode(signature)}`;
  return `${sdJwt}${kbJwt}`;
}
