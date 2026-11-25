/**
 * ARF 層（ARF Trust Anchor Catalogue）の Trust Anchor 判定（`jar-trust-evaluation.ts` から
 * 分割した実体。Linterly 300 行/ファイル上限）。
 *
 * `loadArfTrustAnchor`（trust/arf）で取得・署名検証済みの `ArfTrustAnchorSet` を受け取り、x5c
 * 先頭証明書の SPKI（subjectPublicKeyInfo）が Catalogue エントリの `spki` と一致し、かつその
 * エントリの `id` が x5c 先頭証明書の SubjectAltName origin（渡されていれば `expectedClientId`
 * の origin も）と一致することを確かめる。
 *
 * SPKI 一致だけで受理すると、ARF Catalogue に登録済みの任意エンティティが自己署名証明書の SAN
 * を偽装するだけで任意の RP になりすませる。`entry.id` ↔ origin の一致に加え、エントリの
 * `role` が `relying-party`であることも要求する。ARF Catalogue は元々
 * `wallet-provider` / `issuer` / `attestation-provider` の Registry で RP 相当の role を
 * 持たなかったため、従来は既存 3 role を暫定的に許容していたが、`relying-party` role の
 * 新設によりその暫定運用を終了し、role 自体でも絞り込む。`wallet-provider` /
 * `issuer` / `attestation-provider` として登録されたエンティティは、SPKI・origin が一致しても
 * ARF 層の Trust Anchor としては採用しない（Wallet Provider / Issuer が Verifier のふりをする
 * ことを防ぐ）。
 */

import { parseIsoDateTimeMs } from '../../cache/iso-datetime.js';
import { comparableOrigin } from '../../https-url.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { isObject } from '../../trust/arf/catalogue.js';
import type { ArfTrustAnchorSet, LayerStatus } from '../../trust/arf/index.js';
import { derEquals } from '../../trust/etsi-tsl/index.js';
import { certValidityStatus, tryParseRpAccessCertificate } from './jar-trust-cert-status.js';

/**
 * ARF 層の `LayerStatus`。leaf 証明書の有効期間・失効を検査したうえで、SPKI・origin 双方が
 * 一致する Catalogue エントリがあるかを確かめる（モジュール冒頭コメント参照）。
 */
export function arfLayerStatus(
  leafDer: Uint8Array,
  arfSet: ArfTrustAnchorSet,
  expectedClientId: string | undefined,
  revokedSerials: ReadonlySet<string> | undefined,
  now: number | undefined,
): LayerStatus {
  // 集合の鮮度は使用時にも評価する。ロード時（`loadArfTrustAnchor`）にしか見ないと、プロセス内で
  // 保持された集合が `nextUpdate` を過ぎても、Catalogue から登録解除された RP を受理し続ける。
  // 解釈不能な値・期限切れは fail-closed（`error`）。`nextUpdate` を持たない集合は期限なし。
  const nextUpdate = ownProperty<unknown>(arfSet, 'nextUpdate');
  if (nextUpdate !== undefined) {
    const nowMs = (now ?? Math.floor(Date.now() / 1000)) * 1000;
    if (!(nowMs < parseIsoDateTimeMs(nextUpdate))) {
      return 'error';
    }
  }
  const parsed = tryParseRpAccessCertificate(leafDer);
  if (parsed === undefined) {
    return 'not-found';
  }
  const validity = certValidityStatus(parsed, revokedSerials, now);
  if (validity !== undefined) {
    return validity;
  }
  // SAN が無い / 不透明 origin（`did:` 等）の場合は `entry.id` と結び付ける相手が無いため、
  // SPKI が一致していても「起点未確認」とする。
  const sanOrigin = comparableOrigin(parsed.identity.origin);
  if (sanOrigin === undefined) {
    return 'not-found';
  }
  const expectedOrigin =
    expectedClientId === undefined ? undefined : comparableOrigin(expectedClientId);
  // `arfSet.entries` は own 限定で読む。鎖読みだと、`entries` を持たない
  // `ArfTrustAnchorSet` でも `Object.prototype.entries` の汚染値が「登録エントリ集合」に化ける。
  const entries = ownProperty<readonly unknown[]>(arfSet, 'entries');
  const matches =
    Array.isArray(entries) &&
    entries.some((entry) => arfEntryMatches(entry, parsed.base.spki, sanOrigin, expectedOrigin));
  return matches ? 'pass' : 'not-found';
}

/** ARF 層の Trust Anchor として採用するエントリの role。 */
const RELYING_PARTY_ROLE = 'relying-party';

/**
 * ARF Catalogue エントリが leaf 証明書の SPKI・origin・role の全てに一致するか（
 * role も照合する）。`entry` は `null` / 非オブジェクト
 * の場合があり得る（`entries` 配列に混じっていても静的型検査は通らない実行時データ）ため、まず
 * `isObject` で弾いてから読む。通れば `entry.spki` / `entry.id` / `entry.role` を own 限定で読む
 * （鎖読みだと各プロパティを持たないエントリが `Object.prototype` の汚染値を掴み、比較が素通りし
 * 得る）。
 */
function arfEntryMatches(
  entry: unknown,
  leafSpki: Uint8Array,
  sanOrigin: string,
  expectedOrigin: string | undefined,
): boolean {
  if (!isObject(entry)) {
    return false;
  }
  // role が `relying-party` のエントリのみを ARF 層の Trust Anchor として採用する。
  // `wallet-provider` / `issuer` / `attestation-provider` は SPKI・origin が一致しても不採用とし、
  // 他ロールで登録されたエンティティが RP になりすますことを防ぐ。
  if (ownProperty<unknown>(entry, 'role') !== RELYING_PARTY_ROLE) {
    return false;
  }
  const spki = ownProperty<Uint8Array>(entry, 'spki');
  if (!(spki instanceof Uint8Array) || !derEquals(spki, leafSpki)) {
    return false;
  }
  const id = ownProperty<unknown>(entry, 'id');
  if (typeof id !== 'string' || id.length === 0) {
    return false;
  }
  const entryOrigin = comparableOrigin(id);
  if (entryOrigin === undefined || entryOrigin !== sanOrigin) {
    return false;
  }
  return expectedOrigin === undefined || entryOrigin === expectedOrigin;
}
