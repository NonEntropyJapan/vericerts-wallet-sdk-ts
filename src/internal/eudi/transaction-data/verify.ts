/**
 * 受領 KB-JWT の `transaction_data_hashes` と要求 Transaction Data の突合。
 *
 * OID4VP（draft-ietf-oauth-transaction-data / OpenID4VP §8.4）では、Verifier は Authorization
 * Request で要求した `transaction_data` から期待ハッシュ列を再計算し、受領した提示の KB-JWT
 * payload に格納された `transaction_data_hashes` と**要求順のまま**突き合わせる。本モジュールは
 * その突合を任意の OID4VP Verifier / Gateway が再実装せずに済むよう汎用 helper として提供する
 * （特定ドメインの語彙は一切持ち込まない）。
 *
 * セキュリティ上の注意:
 * - ハッシュ比較は `timingSafeEqualString` による定数時間比較で行い、**最初に相違したハッシュの
 *   位置**が実行時間から漏れないよう早期 return しない。要素数自体は
 *   走査回数に影響するため隠れないが、これは Verifier 自身が持つ非秘密の値（要求 Transaction Data
 *   件数・受領ハッシュ件数）であり秘密の漏洩ではない。
 * - 未対応 / 解釈不能なハッシュアルゴリズムは fail-closed で拒否し、既定 `sha-256` へフォール
 *   バックしない。加えて、採用するアルゴリズムは要求側 Transaction Data が宣言した集合
 *   （`TransactionDataEntry.hashAlgorithms`）に制約する（受領 KB-JWT 由来の値を単独で信頼しない）。
 * - 例外メッセージ・`context` に Transaction Data 本文・KB-JWT 本文・ハッシュ値を含めない。
 * 判別用の短い `reason` トークンのみを載せる。
 */

import { parseSdJwt } from '../../credential/sdjwt/sdjwt.js';
import { decodeCompactJws } from '../../credential/vc/jws.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { timingSafeEqualString } from '../../timing-safe.js';
import { computeTransactionDataHashesWithAlg } from './hashes.js';
import { TRANSACTION_DATA_HASH_ALG, type TransactionDataEntry } from './types.js';

/** `verifyTransactionDataHashes` の入力。 */
export interface VerifyTransactionDataHashesOptions {
  /**
   * Verifier が Authorization Request で要求した Transaction Data
   * （`extractTransactionData` で正規化済み）。**順序が意味を持つ**: ハッシュはこの順で
   * KB-JWT に並んでいなければならない。
   */
  readonly requested: readonly TransactionDataEntry[];
  /** 受領した提示（KB-JWT を連結済みの SD-JWT 文字列）。 */
  readonly presentation: string;
}

/** 突合失敗を 10402 として送出する（本文を漏らさないため短い `reason` のみ載せる）。 */
function hashMismatch(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.TRANSACTION_DATA_HASH_MISMATCH, { context: { reason } });
}

/**
 * KB-JWT payload の `transaction_data_hashes_alg` を解決する。
 *
 * `undefined`（クレーム不在）は OID4VP が定める**既定値** `sha-256` を意味する（フォールバックでは
 * なく仕様上の既定）。本 SDK の `addKeyBindingWithTransactionData` は常に本クレームを書き出すため、
 * 不在は他実装の提示でのみ発生する。値が存在する場合は非空文字列かつ対応表に載っていることを
 * 要求し、そうでなければ fail-closed で拒否する（未対応値を既定へ倒さない）。
 *
 * 戻り値は**受領した（未検証の）KB-JWT 由来＝攻撃者が指定しうる値**のままである。本関数だけでは
 * 「本 SDK が計算できるアルゴリズムか」しか担保しないため、呼び出し側は続けて
 * `assertAlgRequested` で要求側（Authorization Request）が宣言した集合に制約すること。
 */
function resolveHashAlg(raw: unknown): string {
  if (raw === undefined) {
    return TRANSACTION_DATA_HASH_ALG;
  }
  if (typeof raw !== 'string' || raw.length === 0) {
    throw hashMismatch('transaction_data_hashes_alg_unsupported');
  }
  return raw;
}

/**
 * 解決したアルゴリズムが要求側（Authorization Request）で宣言されているか検査する。
 *
 * `transaction_data_hashes_alg` は**受領した未検証の KB-JWT** 由来であり、Holder（＝攻撃者に
 * なりうる）が自由に指定できる。信頼できるのは Verifier 自身が発行した Authorization Request の
 * 側だけなので、そこで各 Transaction Data が宣言した `hashAlgorithms` を許容集合として使い、
 * **全要素が宣言しているアルゴリズム**のみを受理する（OID4VP §8.4 はこの制約を Verifier に課す）。
 *
 * この検査が無いと、実際に使うアルゴリズムを選ぶのは Holder 側になる。これは構造的に JWT の
 * alg confusion と同じで、将来より弱いアルゴリズムを対応表へ追加した途端に攻撃者がそちらへ
 * 自由にダウングレードできてしまう。宣言に無ければ fail-closed で拒否する。
 */
function assertAlgRequested(requested: readonly TransactionDataEntry[], alg: string): void {
  if (!requested.every((entry) => entry.hashAlgorithms.includes(alg))) {
    throw hashMismatch('transaction_data_hashes_alg_unsupported');
  }
}

/** KB-JWT payload の `transaction_data_hashes` を非空文字列配列として検証する。 */
function requireReceivedHashes(raw: unknown): readonly string[] {
  if (
    !Array.isArray(raw) ||
    raw.length === 0 ||
    raw.some((h) => typeof h !== 'string' || h.length === 0)
  ) {
    throw hashMismatch('transaction_data_hashes_invalid');
  }
  return raw as readonly string[];
}

/**
 * 2 つのハッシュ列を定数時間で index ごとに比較する。
 *
 * 早期 return せず `max(a.length, b.length)` 回走査し、長さの差も同じ不一致フラグへ畳み込む。
 * これにより**最初に相違したハッシュの位置**が実行時間から漏れない。一方で要素数そのものは走査
 * 回数に影響するため隠れないが、ここで扱う件数は Verifier 自身が持つ非秘密の値（要求 Transaction
 * Data の件数・受領ハッシュの件数）であり、秘密の漏洩には当たらない。
 * index 対応での比較なので、値の不一致・件数の不一致・**順序の入れ替わり**をまとめて検知する。
 */
function hashesEqualConstantTime(a: readonly string[], b: readonly string[]): boolean {
  let equal = a.length === b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) {
    // 不足分は空文字列として比較する（長さの差は上で既にフラグへ畳み込み済み）。
    equal = timingSafeEqualString(a[i] ?? '', b[i] ?? '') && equal;
  }
  return equal;
}

/**
 * 受領した提示の KB-JWT `transaction_data_hashes` を要求 Transaction Data と突合する
 * （Verifier・Gateway 側）。
 *
 * `opts.requested` から期待ハッシュ列を再計算し、`opts.presentation` の KB-JWT payload に
 * 格納された `transaction_data_hashes` と index 対応で定数時間比較する。値の相違・件数の相違・
 * 順序の入れ替わりのいずれも不一致として拒否する。
 *
 * **セキュリティ（重要）**: 本関数が検証するのは「要求 Transaction Data と KB-JWT が運ぶハッシュの
 * 結び付き」**のみ**である。KB-JWT の**署名・`cnf`・`sd_hash`・`nonce`・`aud` は一切検証しない**。
 * 攻撃者は任意のハッシュを載せた未署名の KB-JWT を自作できるため、本関数単独では何も証明しない。
 * Verifier は同じ提示に対して必ず `verifySdJwt`（`requireKeyBinding` 付き）も実行し、**両方が
 * 成功した場合にのみ**提示を受理すること。
 *
 * **ハッシュアルゴリズムの制約**: `transaction_data_hashes_alg` は**受領した未検証の KB-JWT**
 * から読むため攻撃者が指定しうる値であり、それ単独では信頼しない。信頼できるのは Authorization
 * Request 側（`opts.requested[].hashAlgorithms`）で、そこで**全要素が宣言している**アルゴリズム
 * でなければ fail-closed で拒否する（OID4VP §8.4 はこの制約を Verifier に課す）。この制約が無いと
 * 使用アルゴリズムを選ぶのは Holder 側になり、構造的に JWT の alg confusion と同じ問題となる
 * （将来より弱いアルゴリズムを対応表へ追加すると、攻撃者が自由にそちらを選べてしまう）。
 *
 * @param opts 要求 Transaction Data（順序が意味を持つ）と受領した提示。
 * @returns 突合が成立した場合は何も返さない。
 * @throws 要求が空 / KB-JWT 不在 / KB-JWT デコード不能 / 未対応アルゴリズム /
 *         `transaction_data_hashes` 不正 / ハッシュ不一致の場合
 *         （VericertsError、code `10402`。判別は `context.reason`）。
 *         提示自体の構造不正は `parseSdJwt` の契約どおり code `3010` がそのまま伝播する。
 */
export function verifyTransactionDataHashes(opts: VerifyTransactionDataHashesOptions): void {
  if (opts.requested.length === 0) {
    // 「何も要求していない」呼び出しを暗黙に成功させると、束縛の無い提示を検証済みとして
    // 扱えてしまうため、誤用として拒否する。
    throw hashMismatch('transaction_data_absent');
  }

  // 構造不正（3010）は既存契約のためそのまま伝播させる。
  const keyBinding = ownProperty<string>(parseSdJwt(opts.presentation), 'keyBinding');
  if (keyBinding === undefined) {
    throw hashMismatch('key_binding_missing');
  }

  let payload: Record<string, unknown>;
  try {
    payload = decodeCompactJws(keyBinding).payload;
  } catch {
    // KB-JWT 本文を漏らさないため cause は握りつぶす。
    throw hashMismatch('key_binding_undecodable');
  }

  const alg = resolveHashAlg(payload.transaction_data_hashes_alg);
  // 受領 KB-JWT 由来の alg は、信頼できる要求側の宣言集合に制約してから使う。
  assertAlgRequested(opts.requested, alg);
  const received = requireReceivedHashes(payload.transaction_data_hashes);
  // 未対応アルゴリズムはここで 10402 `transaction_data_hashes_alg_unsupported` になる。
  const expected = computeTransactionDataHashesWithAlg(opts.requested, alg);

  if (!hashesEqualConstantTime(expected, received)) {
    throw hashMismatch('transaction_data_hashes_mismatch');
  }
}
