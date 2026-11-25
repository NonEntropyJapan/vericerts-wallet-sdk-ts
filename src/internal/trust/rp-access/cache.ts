/**
 * RP Cert 判定結果の TTL キャッシュ（trust/rp-access）。
 *
 * 同じ証明書チェーン・Trust Anchor・失効情報で繰り返す検査の結果を再利用する。
 *
 * **`verifyRpAccessCertificate`（`verify.ts`）自体は変更しない。** 同関数は要求属性
 * （`requestedClaims`）ごとに purpose / category の権限判定も兼ねており、呼び出しごとに結果が
 * 変わり得る汎用 API である。キャッシュを埋め込むと「別の要求属性での判定結果」を配ってしまう
 * fail-open を招く。本モジュールがキャッシュする対象は、要求属性に依存しない部分
 * ——Trust Anchor へのチェーン到達 + 失効チェック——だけを呼ぶ経路（`auth/jar/jar-signature.ts` の
 * `requireTrustedSigner`。常に `requestedClaims: []` で呼ぶため、この 2 点だけが判定の全体になる）
 * に限定して使う。
 *
 * **キャッシュキーの構成。** `src/internal/credential/chain/verify.ts` の `cacheKeyFor` が
 * 明文化している原則と同じで、判定結果を左右する入力をすべてキーに含めないと、鮮度の異なる
 * 呼び出しに前回の結果を配ってしまう（fail-open）。本キャッシュのキーは 4 点:
 *
 * 1. リーフ証明書 DER 全体の SHA-256（シリアル番号は CA ごとの採番で、`x5c` は Verifier が
 *    選べるため、同一シリアルの偽造証明書が正規の判定にヒット / 汚染できてしまう）
 * 2. 中間証明書（`intermediatesDer`）列全体の SHA-256（各 DER は長さ接頭辞付き。チェーン結果は中間にも依存する）
 * 3. Trust Anchor 集合の指紋（`granted` フラグ + `certDer` から算出）
 * 4. 失効集合（`revokedSerials`）の指紋
 *
 * (4) を含めるのは、失効集合は Trust Anchor 集合とは独立に更新され得る失効情報源だからである。
 * 含めないと、後から失効と判明した証明書の `revokedSerials` を新しく渡しても、TTL 内は
 * 古い `valid:true` にヒットし続けてしまう。
 *
 * **TTL は証明書の有効期間を超えない。** 有効期間はキーに含まれない（基準時刻に依存する）
 * ので、格納時に「成功は使った全証明書の最小 `notAfter` まで、失敗は `notBefore` まで」へ TTL を
 * 頭打ちにする（`storeRpCertJudgment`）。読み取りは同じ基準時刻で行うため、期限を過ぎた基準時刻では
 * ヒットせず再検証（有効期間検査）される。
 *
 * **TTL 内の判定は「確認済み」ではなく「確認したことにする」。** 30 分〜1 時間のキャッシュ窓の間、
 * 実際の失効がキャッシュに反映されるのは次回のキー変化（`revokedSerials` の更新）または TTL 失効
 * まで遅延する。証明書自体の有効期間はキャッシュ期限を制限する。
 *
 * 結果はメモリ上に保持する。
 *
 * セキュリティ上の注意:
 * - キャッシュキーには証明書 DER のハッシュ値のみを使い、DER 本体・DN・鍵素材はキーにも
 *   ログにも含めない。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { createTtlCache, systemNowSeconds, type TtlCache } from '../../cache/index.js';
import type { QtspServiceCertificate } from '../etsi-tsl/tsl.js';

/**
 * RP Cert 判定結果キャッシュの TTL（秒、45 分）。
 */
export const RP_CERT_JUDGMENT_CACHE_TTL_SECONDS = 45 * 60;

/** `revokedSerials` が渡されなかった（未確認）ことを表す sentinel。空集合とは区別する。 */
const REVOKED_SERIALS_UNCONFIGURED = 'unconfigured';

/**
 * RP Cert 判定キャッシュが保持するキー長（文字数）の総量上限。キーは固定長ダイジェスト
 * （約 260 文字）なので通常は件数上限が先に効く。長いキーが渡されても総量で保持量を抑える防御。
 */
export const RP_CERT_JUDGMENT_CACHE_MAX_TOTAL_KEY_LENGTH = 1024 * 1024;

/** バイト列を安定した短い識別子にする（`@noble/hashes` の sha256 を使う既存パターン）。 */
function stableDigestHex(input: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(input)));
}

/**
 * 証明書 DER 列の指紋。**列全体を 1 つの固定長 SHA-256（64 hex）にまとめる**。
 * 各 DER を `長さ(4 バイト BE) + 本体` の順に流し込むので、境界のずらし（`[AB, C]` と `[A, BC]`）で
 * 衝突させられず、順序もチェーン判定に効くため保持する。キー長が x5c の枚数・長さに比例しない
 * （以前は各 DER の hex を連結しており、極小証明書を大量に並べた JAR 1 件で数 MB のキーになった）。
 */
function fingerprintCertificates(certsDer: readonly Uint8Array[]): string {
  const hash = sha256.create();
  const length = new Uint8Array(4);
  const view = new DataView(length.buffer);
  for (const der of certsDer) {
    view.setUint32(0, der.length);
    hash.update(length);
    hash.update(der);
  }
  return bytesToHex(hash.digest());
}

/**
 * Trust Anchor 集合の指紋を算出する。
 *
 * 各アンカーの `granted` フラグと `certDer` を安定ソートして連結し、ハッシュ化する。並び順に
 * 依存させないため、連結前にソートする（呼び出し側が同じ集合を異なる順序で渡してもキャッシュが
 * 別エントリに分裂しないようにするため）。
 */
function fingerprintTrustAnchors(anchors: readonly QtspServiceCertificate[]): string {
  const parts = anchors
    .map((anchor) => `${anchor.granted ? '1' : '0'}:${bytesToHex(anchor.certDer)}`)
    .sort();
  return stableDigestHex(parts.join('\0'));
}

/**
 * 失効集合（`revokedSerials`）の指紋を算出する。
 *
 * `undefined`（失効情報源が無い＝未確認）と空集合（確認したが失効なし）は判定結果を左右し得る
 * 別状態なので、区別できる sentinel を使う。
 */
function fingerprintRevokedSerials(revokedSerials: ReadonlySet<string> | undefined): string {
  if (revokedSerials === undefined) {
    return REVOKED_SERIALS_UNCONFIGURED;
  }
  return stableDigestHex([...revokedSerials].sort().join('\0'));
}

/**
 * RP Cert 判定結果キャッシュのキーを組み立てる。
 *
 * @param leafDer 判定対象のリーフ証明書（DER 全体を SHA-256 でキーに反映する）。
 * @param intermediatesDer 判定に使った中間証明書（DER）。
 * @param trustAnchors 判定に使った Trust Anchor 集合。
 * @param revokedSerials 判定に使った失効集合（未指定なら未確認）。
 * @returns キャッシュキー文字列。
 */
export function rpCertJudgmentCacheKey(
  leafDer: Uint8Array,
  intermediatesDer: readonly Uint8Array[],
  trustAnchors: readonly QtspServiceCertificate[],
  revokedSerials: ReadonlySet<string> | undefined,
): string {
  return [
    bytesToHex(sha256(leafDer)),
    fingerprintCertificates(intermediatesDer),
    fingerprintTrustAnchors(trustAnchors),
    fingerprintRevokedSerials(revokedSerials),
  ].join('\0');
}

/**
 * RP Cert 判定結果（成功/失敗）用の TTL キャッシュを生成する。
 *
 * TTL は `RP_CERT_JUDGMENT_CACHE_TTL_SECONDS`（45 分）が上限で、格納時に証明書の有効期間で
 * さらに頭打ちにされる（`storeRpCertJudgment`）。
 *
 * @param nowSeconds 時計（エポック秒）。未指定なら実時計。
 * @param maxEntries 保持する最大エントリ数（省略時はキャッシュ層の既定）。
 * @returns 判定結果（`boolean`）用 TTL キャッシュ。
 */
export function createRpCertJudgmentCache(
  nowSeconds: () => number = systemNowSeconds,
  maxEntries?: number,
): TtlCache<boolean> {
  const maxTtlSeconds = RP_CERT_JUDGMENT_CACHE_TTL_SECONDS;
  const maxTotalWeight = RP_CERT_JUDGMENT_CACHE_MAX_TOTAL_KEY_LENGTH;
  return createTtlCache<boolean>(
    maxEntries === undefined
      ? { maxTtlSeconds, nowSeconds, maxTotalWeight }
      : { maxTtlSeconds, nowSeconds, maxEntries, maxTotalWeight },
  );
}

/**
 * キーに対応する RP Cert 判定結果を取得する。
 *
 * @param cache 参照元キャッシュ（`createRpCertJudgmentCache` で生成）。
 * @param key `rpCertJudgmentCacheKey` で組み立てたキー。
 * @param nowSeconds 現在時刻（エポック秒）。未指定なら実時計。
 * @returns TTL 内の判定結果。未格納・TTL 切れなら `undefined`（呼び出し側は再検証すること）。
 */
export function readRpCertJudgment(
  cache: TtlCache<boolean>,
  key: string,
  nowSeconds: number = systemNowSeconds(),
): boolean | undefined {
  const entry = cache.get(key, nowSeconds);
  return entry !== undefined && !entry.expired ? entry.value : undefined;
}

/**
 * RP Cert 判定結果をキャッシュへ格納する。
 *
 * 成功と失敗のいずれにも既定 TTL を使う。呼び出し側は証明書の有効期間に合わせて `maxTtlSeconds` で制限する:
 * 成功は使った全証明書の最小 `notAfter` まで、失敗（`notBefore` 前など）は有効になる時刻まで。
 * 境界を無視すると、期限切れ後も最大 45 分は `true` が、有効化後も `false` が配られる。
 *
 * @param cache 格納先キャッシュ（`createRpCertJudgmentCache` で生成）。
 * @param key `rpCertJudgmentCacheKey` で組み立てたキー。
 * @param valid 判定結果。
 * @param nowSeconds 現在時刻（エポック秒）。未指定なら実時計。
 * @param maxTtlSeconds 既定 TTL をさらに頭打ちにする上限（秒）。0 以下（境界を過ぎている）や
 *   NaN なら格納しない。
 */
export function storeRpCertJudgment(
  cache: TtlCache<boolean>,
  key: string,
  valid: boolean,
  nowSeconds: number = systemNowSeconds(),
  maxTtlSeconds: number = RP_CERT_JUDGMENT_CACHE_TTL_SECONDS,
): void {
  // TtlCache は整数 TTL のみ受け付ける。`now` が小数秒だと `notAfter - now` も小数になるため、切り捨てて
  // 保守側（早めに失効）へ倒す。`Infinity`（頭打ち無し）は既定 TTL が勝つ。
  const ttlSeconds = Math.floor(Math.min(RP_CERT_JUDGMENT_CACHE_TTL_SECONDS, maxTtlSeconds));
  // `!(ttl > 0)` は NaN も弾く（境界が不明なものを記憶しない）。
  if (!(ttlSeconds > 0)) {
    return;
  }
  // キー長を重みに計上する。キーは固定長ダイジェストだが、キー長の総量でも保持量を抑える。
  cache.set(key, valid, ttlSeconds, nowSeconds, key.length);
}
