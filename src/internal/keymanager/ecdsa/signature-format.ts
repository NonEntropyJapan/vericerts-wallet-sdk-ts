/**
 * ECDSA 署名エンコーディングの正準性ルールと形式変換（secp256k1 / P-256）。
 *
 * `../signer.ts` の検証関数（`verifyP256` / `verifySecp256k1`）が「どのエンコーディングを受理するか」
 * を一箇所に集約する。同一メッセージ・同一鍵に対して**有効な署名バイト列がただ一つに定まる**こと
 * （正準性）を検証側で強制するのが本モジュールの責務。
 *
 * ## なぜ正準性を強制するか
 *
 * ECDSA 署名は同じ `(r, s)` を複数のバイト列で表現でき、さらに `s` と `n - s` はどちらも同一鍵・
 * 同一 digest に対して数学的に有効になる。検証側がこれらを無差別に受理すると、**同一のヘッダ・
 * クレームに対して有効な JWS 文字列が無数に成立**する（署名の可鍛性 / malleability）。秘密鍵なしに
 * 署名を偽造できるわけではないが、JWS 文字列そのものを重複判定キー・キャッシュキーに使う呼び出し側
 * では、末尾 1 バイトを変えるだけでリプレイ検出を回避できてしまう。
 *
 * RFC 7515 §3.1 / RFC 7518 §3.4 は ECDSA の JWS 署名を、曲線位数のオクテット長へ左ゼロ埋めした
 * `R || S` の**固定長**（P-256 / secp256k1 とも 32 バイト × 2 = 64 バイト）と定めており、DER 形式や
 * recovery バイト付き 65 バイト形式は JWS としては非準拠である。したがって検証の既定は
 * `'p1363'`（厳密 64 バイト）とし、DER / recovered を必要とする非 JWS 用途だけが明示的に opt-in する。
 *
 * ## low-S と相互運用性
 *
 * `@noble/curves` の `verify()` は既定で low-S（`s <= n/2`）を強制する。これは上記 malleability 対策
 * として正しい既定だが、AWS KMS / PKCS#11 トークン等の HSM や第三者 Issuer は high-S の ECDSA 署名を
 * **仕様上正当に**返し得るため、既定のままだと正当な第三者発行 credential を一切検証できない。
 * そこで検証側には `allowHighS` の opt-in を用意し（このプリミティブの既定は low-S 強制のまま。JWS 検証経路は
 * `ALG_SPECS` 経由で ES256 の high-S を既定受理する）、発行側には `normalizeLowS` を提供して
 * 「発行時に揃える / 検証時に緩める」を呼び出し側が選べるようにする。
 *
 * セキュリティ上の注意:
 * - 署名バイト列・digest・鍵 material を例外メッセージや `context` に一切含めない。
 *   `@noble` 由来の例外はメッセージに入力が含まれ得るため `cause` を渡さない。
 */

import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ErrorCodes, VericertsError } from '../../errors.js';

/** 対応する ECDSA 曲線。 */
export type EcdsaCurve = 'secp256k1' | 'p256';

/** IEEE P1363（raw）署名の長さ（`r(32) || s(32)`）。 */
export const P1363_LENGTH = 64;

/** recovery バイト付き署名の長さ（`r(32) || s(32) || recovery(1)`）。 */
export const RECOVERED_LENGTH = 65;

/** ECDSA で扱う digest の固定長（32 バイト = 256bit ハッシュ）。secp256k1 / P-256 の signer で共有する。 */
export const DIGEST_LENGTH = 32;

/**
 * digest が 32 バイトであることを検証する。長さ不正は署名演算失敗（1020）に正規化する。
 *
 * `./secp256k1-signer.ts` / `./p256-signer.ts` の sign / recoverPublicKey が共有する前提検証。
 *
 * @param digest 検証対象のダイジェスト。
 * @throws digest が 32 バイトでない場合（VericertsError、code `1020`）。
 */
export function assertDigest(digest: Uint8Array): void {
  if (digest.length !== DIGEST_LENGTH) {
    // 入力データはメッセージに含めない。
    throw new VericertsError(ErrorCodes.SIGN_FAILED);
  }
}

/**
 * 受理する署名エンコーディング。
 *
 * - `'p1363'`: RFC 7515 §3.1 準拠の**厳密 64 バイト**固定長 `r || s`。JWS の唯一の正準形式。
 * - `'der'`: ASN.1 DER。`@noble` の DER パーサは非最小長・余剰バイトを拒否するため正準。
 * - `'recovered'`: `r || s || recovery(1)` の 65 バイト（secp256k1 の Ethereum 互換形式）。
 *   recovery バイトが実際にその公開鍵を復元する値であることまで検証して初めて正準になる。
 */
export type EcdsaSignatureEncoding = 'p1363' | 'der' | 'recovered';

/** ECDSA 署名検証の共通オプション。 */
interface EcdsaVerifyOptionsBase {
  /**
   * high-S 署名（`s > n/2`）を受理するか。既定 `false`（low-S 強制 = malleability 対策）。
   *
   * KMS / HSM や第三者 Issuer が返す high-S 署名は仕様上正当なため、相互運用が必要な検証経路のみ
   * `true` を指定する。`true` にすると同一 `(r, s)` に対し `s` と `n - s` の 2 通りが有効になるため、
   * **署名バイト列を重複判定キーに使う経路では指定してはならない**。
   */
  readonly allowHighS?: boolean;
}

/** `verifyP256` のオプション。P-256 は recovery 付き形式を扱わない。 */
export interface VerifyP256Options extends EcdsaVerifyOptionsBase {
  /** 受理する署名エンコーディング。既定 `'p1363'`（厳密 64 バイト）。 */
  readonly encoding?: Exclude<EcdsaSignatureEncoding, 'recovered'>;
}

/** `verifySecp256k1` のオプション。 */
export interface VerifySecp256k1Options extends EcdsaVerifyOptionsBase {
  /** 受理する署名エンコーディング。既定 `'p1363'`（厳密 64 バイト）。 */
  readonly encoding?: EcdsaSignatureEncoding;
}

/**
 * `curve` から対応する `@noble` の ECDSA 実装を選択する。
 *
 * @param curve 曲線名。
 * @returns 対応する `@noble` の ECDSA オブジェクト。
 * @throws 型外の曲線値の場合（VericertsError、code `1030`）。
 */
export function selectCurve(curve: EcdsaCurve): typeof secp256k1 {
  switch (curve) {
    case 'secp256k1':
      return secp256k1;
    case 'p256':
      return p256;
    default:
      // 型外の値（実行時に不正な curve が渡された場合）は未対応アルゴリズムに正規化する。
      throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
  }
}

/**
 * 64B raw 署名の `s` を low-S（`s <= n/2`）へ正規化する。
 *
 * AWS KMS / PKCS#11 トークン等の外部署名サービスは high-S の ECDSA 署名を正当に返し得るが、
 * SDK の検証経路は既定で low-S を強制するため、そのまま JWS へ載せると自身の `verifyCredential` /
 * `verifySdJwt` が `SIGNATURE_INVALID`（3010）で弾いてしまう。high-S の場合は `s` を `n - s` に
 * 置き換える（ECDSA では両者とも同一鍵・同一 digest に対して有効な署名）。
 *
 * 既に low-S の署名は入力バイト列をそのまま返す（冪等）。
 *
 * @param raw 64 バイトの raw 署名（`r(32) || s(32)`）。
 * @param curve 署名の曲線。
 * @returns low-S 正規化済みの 64 バイト raw 署名。
 * @throws 型外の曲線値の場合（VericertsError、code `1030`）、
 *         署名のパース・再構築に失敗した場合（VericertsError、code `1020`）。
 */
export function normalizeLowS(raw: Uint8Array, curve: EcdsaCurve): Uint8Array {
  const ec = selectCurve(curve);
  try {
    const sig = ec.Signature.fromBytes(raw, 'compact');
    if (!sig.hasHighS()) {
      return raw;
    }
    return new ec.Signature(sig.r, ec.Point.Fn.ORDER - sig.s).toBytes('compact');
  } catch {
    // @noble 由来の例外メッセージに署名バイト列が含まれ得るため cause は渡さない。
    throw new VericertsError(ErrorCodes.SIGN_FAILED);
  }
}

/**
 * 65 バイトの recovered 署名の recovery バイトが、与えられた公開鍵を実際に復元することを検証する。
 *
 * 長さ 65 だけを見て先頭 64 バイトへ切り詰める実装では、**末尾 1 バイトに何を入れても検証が通る**
 * （256 通りの有効な署名バイト列が成立する）。recovery バイトを実際に使って公開鍵を復元し、与えられた
 * 公開鍵と一致することまで確認して初めて表現が一意に定まる。
 *
 * 本関数は構造上 **secp256k1 専用**であり（`r || s || v` は Ethereum 互換形式）、曲線を引数に取らず
 * `secp256k1` 固定で復元する。他曲線が `'recovered'` を指定する経路は呼び出し元
 * （`verifyEcdsaCanonical`）でランタイム拒否するため、ここへは到達しない。
 *
 * @param digest 検証対象のダイジェスト（32 バイト）。
 * @param signature 65 バイトの recovered 署名。
 * @param publicKey 期待する公開鍵（圧縮 33 バイト / 非圧縮 65 バイト）。
 * @returns recovery バイトが当該公開鍵を復元するなら `true`。
 */
function recoveryByteMatches(
  digest: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  const recovery = signature[P1363_LENGTH];
  // recovery id は 0 / 1 のみ（secp256k1 では r >= n となる 2 / 3 は実質発生しない）。
  if (recovery !== 0 && recovery !== 1) {
    return false;
  }
  try {
    const compact = signature.subarray(0, P1363_LENGTH);
    const recoveredPoint = secp256k1.Signature.fromBytes(compact, 'compact')
      .addRecoveryBit(recovery)
      .recoverPublicKey(digest);
    // 圧縮形式へ揃えて比較する（呼び出し側は圧縮 / 非圧縮どちらも渡し得る）。
    const expected = secp256k1.Point.fromBytes(publicKey).toBytes(true);
    const actual = recoveredPoint.toBytes(true);
    if (actual.length !== expected.length) {
      return false;
    }
    return actual.every((byte, index) => byte === expected[index]);
  } catch {
    // 復元不能・公開鍵の形式不正はいずれも検証失敗として扱う。
    return false;
  }
}

/**
 * 指定エンコーディングの正準性を強制したうえで ECDSA 署名を検証する。
 *
 * `../signer.ts` の `verifyP256` / `verifySecp256k1` の共通実装。エンコーディングごとに以下を強制する:
 *
 * - `'p1363'`: 長さが**厳密に** 64 バイト。65 バイトへの末尾付加・DER 再エンコードは拒否する。
 * - `'der'`: `@noble` の DER パーサに委ねる（非最小長・余剰バイトを拒否するため正準）。
 * - `'recovered'`: 長さが厳密に 65 バイトかつ recovery バイトが当該公開鍵を復元する。
 *
 * `'recovered'` は **secp256k1 専用**である（Ethereum 互換の `r || s || v` 形式であり、`recoveryByteMatches`
 * も secp256k1 上で公開鍵を復元する）。P-256 は型（`VerifyP256Options`）で `'recovered'` を除外している
 * が、型検査を迂回した JS 呼び出しがここへ到達し得るため、曲線が secp256k1 でない場合は `selectCurve` と
 * 同じ防御的方針でランタイムでも拒否する（fail-closed = `false`）。
 *
 * @param ec 対象曲線の `@noble` ECDSA 実装。
 * @param digest 検証対象のダイジェスト（32 バイト検証済み）。
 * @param signature 署名バイト列。
 * @param publicKey 公開鍵（圧縮 33 バイト / 非圧縮 65 バイト）。
 * @param encoding 受理するエンコーディング。
 * @param allowHighS high-S を受理するか。
 * @returns 署名が有効かつ指定エンコーディングとして正準なら `true`。
 */
export function verifyEcdsaCanonical(
  ec: typeof secp256k1,
  digest: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
  encoding: EcdsaSignatureEncoding,
  allowHighS: boolean,
): boolean {
  // lowS:false は「s と n-s の両方を受理する」= 可鍛性を許す設定。既定は low-S 強制のまま。
  const options = { prehash: false, lowS: !allowHighS } as const;
  try {
    if (encoding === 'der') {
      return ec.verify(signature, digest, publicKey, { ...options, format: 'der' });
    }
    if (encoding === 'recovered') {
      // recovered は secp256k1 専用。型を迂回した他曲線の指定は fail-closed で拒否する。
      if (ec !== secp256k1 || signature.length !== RECOVERED_LENGTH) {
        return false;
      }
      // 先頭 64B の署名としての有効性と、recovery バイトの正しさを両方要求する。
      const compact = signature.subarray(0, P1363_LENGTH);
      if (!ec.verify(compact, digest, publicKey, { ...options, format: 'compact' })) {
        return false;
      }
      return recoveryByteMatches(digest, signature, publicKey);
    }
    // 'p1363': RFC 7515 §3.1 の固定長。長さが 1 バイトでも違えば拒否する。
    if (signature.length !== P1363_LENGTH) {
      return false;
    }
    return ec.verify(signature, digest, publicKey, { ...options, format: 'compact' });
  } catch {
    // 不正な署名・公開鍵フォーマット等は検証失敗（false）として扱う。
    return false;
  }
}

/**
 * DER 形式の署名を IEEE P1363（raw・64 バイト）へ変換する。
 *
 * **`s` の low-S 正規化は行わない**（形式変換のみ）。high-S の DER 署名を渡すと high-S のまま
 * 64 バイト raw が返る。JWS へ載せる前に low-S へ揃えたい場合は、戻り値を `normalizeLowS` へ通すこと。
 * 変換と正規化を分けているのは、`p1363ToDer` との往復で入力バイト列が保存されることを保証するため
 * （正規化を暗黙に挟むと `derToP1363(p1363ToDer(x)) !== x` になり得る）。
 *
 * @param der DER エンコードされた署名。
 * @param curve 署名の曲線。
 * @returns 64 バイトの P1363 署名（`r(32) || s(32)`）。`s` は入力のまま（正規化なし）。
 * @throws 型外の曲線値の場合（VericertsError、code `1030`）、
 *         DER が不正な場合（VericertsError、code `1020`）。
 */
export function derToP1363(der: Uint8Array, curve: EcdsaCurve): Uint8Array {
  const ec = selectCurve(curve);
  try {
    return ec.Signature.fromBytes(der, 'der').toBytes('compact');
  } catch {
    // @noble の ASN.1 パースエラーを署名演算失敗に正規化する（cause は渡さない）。
    throw new VericertsError(ErrorCodes.SIGN_FAILED);
  }
}

/**
 * IEEE P1363（raw・64 バイト）の署名を DER 形式へ変換する。
 *
 * **`s` の low-S 正規化は行わない**（形式変換のみ）。high-S の raw 署名を渡すと high-S のまま
 * DER が返る。正規化が必要な場合は入力を `normalizeLowS` へ通してから呼ぶこと。
 *
 * @param raw 64 バイトの P1363 署名（`r(32) || s(32)`）。
 * @param curve 署名の曲線。
 * @returns DER エンコードされた署名。`s` は入力のまま（正規化なし）。
 * @throws 型外の曲線値の場合（VericertsError、code `1030`）、
 *         raw が不正な場合（VericertsError、code `1020`）。
 */
export function p1363ToDer(raw: Uint8Array, curve: EcdsaCurve): Uint8Array {
  const ec = selectCurve(curve);
  try {
    return ec.Signature.fromBytes(raw, 'compact').toBytes('der');
  } catch {
    // @noble のパースエラーを署名演算失敗に正規化する（cause は渡さない）。
    throw new VericertsError(ErrorCodes.SIGN_FAILED);
  }
}
