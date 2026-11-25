/**
 * RP 別 Pseudonym の「破棄済み」フラグ永続化（GDPR Art.7(3) の同意撤回）。
 *
 * `PersonaManager.discardPseudonym` / `isPseudonymDiscarded` の実装本体をここへ切り出す（`persona.ts`
 * の行数を抑えるため。ロジック自体はクラスメソッドと同一）。
 *
 * Pseudonym（`eudi/pseudonym` モジュール）は `masterSeed` + `rpIdentifier` から HKDF-SHA256 で毎回
 * 決定的に導出され、Wallet はそれ自体を永続化しない。そのため本モジュールは鍵の無効化・再生成などの
 * 暗号操作を一切行わず（`derive.ts` の HKDF 派生ロジックには触れない）、「破棄済み」フラグを storage へ
 * 永続化するデータモデル操作のみを行う。`derivePseudonym` / `presentPseudonym` /
 * `issuePseudonymAttestation` は同期・純関数でこのフラグを読まない（同一シード・同一 RP なら撤回後も
 * 同一 `sub`）。そのため提示・発行の**呼び出し側が事前に** `assertPseudonymNotDiscardedIn`
 * （`PersonaManager.assertPseudonymNotDiscarded`）を呼び、破棄済みなら fail-closed で拒否する責務を負う。
 * 拡張の `eudi_authenticatePseudonym` ハンドラがその呼び出し側である。
 *
 * `rpIdentifier` は `canonicalizeRpIdentifier`（`internal/rp-identifier.ts`）で正規化してから保存するため、
 * 大文字小文字・URL 表記揺れが異なっても同一 RP は同一キーに解決される。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { canonicalizeRpIdentifier } from '../rp-identifier.js';

/** storage 上で「破棄済み」とマークした Pseudonym の RP 識別子を保存するキーの prefix。 */
const PSEUDONYM_DISCARD_KEY_PREFIX = 'pseudonym-discarded/';

/** 本モジュールが要求する最小限の storage 依存。 */
interface PseudonymDiscardStorage {
  get(key: string): Promise<Uint8Array | null>;
  set(key: string, value: Uint8Array): Promise<void>;
}

/** 破棄マーカーの列挙（{@link listDiscardedPseudonymsIn}）が要求する storage 依存。 */
interface PseudonymDiscardListStorage extends PseudonymDiscardStorage {
  list(prefix: string): Promise<string[]>;
}

/** 破棄済みの Pseudonym 1 件（{@link listDiscardedPseudonymsIn}）。 */
export interface DiscardedPseudonym {
  /** `canonicalizeRpIdentifier` の結果（破棄マーカーのキーの `pseudonym-discarded/` より後ろ）。 */
  rpId: string;
  /** 破棄日時（エポックミリ秒）。マーカー本文が読めない（形が違う・壊れている）ときは `null`。 */
  discardedAt: number | null;
}

/** 正規化済み RP 識別子から Pseudonym 破棄フラグの storage キーを組み立てる。 */
function pseudonymDiscardKey(rpId: string): string {
  return `${PSEUDONYM_DISCARD_KEY_PREFIX}${rpId}`;
}

/**
 * 指定 RP 向けの Pseudonym を「破棄済み」としてマークする。
 *
 * @param storage 永続化先。
 * @param rpIdentifier 破棄対象の RP 識別子（正規化前）。
 * @param now 現在時刻（エポックミリ秒）取得関数。
 * @throws RP 識別子が不正な場合（VericertsError、code `10201`）。
 */
export async function markPseudonymDiscarded(
  storage: PseudonymDiscardStorage,
  rpIdentifier: string,
  now: () => number,
): Promise<void> {
  const rpId = canonicalizeRpIdentifier(rpIdentifier);
  const marker = { rpId, discardedAt: now() };
  await storage.set(pseudonymDiscardKey(rpId), new TextEncoder().encode(JSON.stringify(marker)));
}

/**
 * 指定 RP 向けの Pseudonym が `markPseudonymDiscarded` で破棄済みとしてマークされているかを返す。
 *
 * @param storage 照会先。
 * @param rpIdentifier 照会対象の RP 識別子（正規化前）。
 * @returns 破棄済みなら `true`。
 * @throws RP 識別子が不正な場合（VericertsError、code `10201`）。
 */
export async function isPseudonymDiscardedIn(
  storage: PseudonymDiscardStorage,
  rpIdentifier: string,
): Promise<boolean> {
  const rpId = canonicalizeRpIdentifier(rpIdentifier);
  return (await storage.get(pseudonymDiscardKey(rpId))) !== null;
}

/**
 * 指定 RP 向けの Pseudonym が破棄済みなら拒否する。Pseudonym での SIOP ログイン・
 * Attestation 発行の**直前**に呼ぶ。同意撤回（`revokeConsent` + `rpIdentifier`）後に、同じ RP へ
 * 同一 `sub` のまま提示が続くことを防ぐ。
 *
 * @param storage 照会先。
 * @param rpIdentifier 提示先 RP 識別子（正規化前。`isPseudonymDiscardedIn` と同じ正規化で照合する）。
 * @throws 破棄済みの場合（VericertsError、code `10603`、`reason: 'pseudonym_discarded'`）、
 *         RP 識別子が不正な場合（code `10201`）。
 */
export async function assertPseudonymNotDiscardedIn(
  storage: PseudonymDiscardStorage,
  rpIdentifier: string,
): Promise<void> {
  if (await isPseudonymDiscardedIn(storage, rpIdentifier)) {
    throw new VericertsError(ErrorCodes.GDPR_CONSENT_NOT_FOUND, {
      context: { reason: 'pseudonym_discarded' },
    });
  }
}

/** マーカー本文（`{ rpId, discardedAt }`）から破棄日時を読む。読めなければ `null`（マーカーの存在自体は有効）。 */
function readDiscardedAt(raw: Uint8Array | null): number | null {
  if (raw === null) return null;
  try {
    const marker: unknown = JSON.parse(new TextDecoder().decode(raw));
    if (typeof marker !== 'object' || marker === null) return null;
    const discardedAt = ownProperty<unknown>(marker, 'discardedAt');
    return typeof discardedAt === 'number' && Number.isFinite(discardedAt) ? discardedAt : null;
  } catch {
    return null;
  }
}

/**
 * 破棄済みの Pseudonym（`markPseudonymDiscarded` が書いた破棄マーカー）を一覧で返す。
 *
 * GDPR の同意撤回（`revokeConsent` + `rpIdentifier`）を行った RP の一覧に当たる。`isPseudonymDiscardedIn` は 1 件ずつの照会しか
 * できず、別の記録（撤回の記録など）を持たない呼び出し側は、破棄済みの RP を知る手段が無かった。
 *
 * - 並びは破棄日時の昇順（古い順）。日時が読めないマーカー（`discardedAt: null`）は最も古い扱いで先頭に置く。同じ日時は
 *   storage の列挙順（キーの昇順）を保つ。
 * - 次のキーは返さない。(a) `rpId` が `canonicalizeRpIdentifier` の正規形でないもの・RP 識別子として不正なもの（`isPseudonymDiscardedIn` の
 *   照会は正規化したキーだけを引くので、どの RP の破棄済み判定にも当たらない）。(b) `<prefix>://` で終わる、識別子の中身が空のもの。
 *   従来の実装が `origin:https://a.example` などを `origin://` へ潰して残したキー `pseudonym-discarded/origin://` がこれに当たる。
 *   `canonicalizeRpIdentifier('origin://')` は `'origin://'` のままで (a) では除けず、`isPseudonymDiscardedIn('origin://')` も真になるが、
 *   特定の RP の撤回ではなく旧版の artefact なので、「撤回済みの提示先」の一覧には載せない（載せると `origin://` が撤回済みに見える）。
 * - マーカー本文は `isPseudonymDiscardedIn` と同じく「キーがあるか」が正で、本文が読めなくても破棄済みとして返す（`discardedAt: null`）。
 *
 * @param storage 照会先。
 */
export async function listDiscardedPseudonymsIn(
  storage: PseudonymDiscardListStorage,
): Promise<DiscardedPseudonym[]> {
  const discarded: DiscardedPseudonym[] = [];
  for (const key of await storage.list(PSEUDONYM_DISCARD_KEY_PREFIX)) {
    const rpId = key.slice(PSEUDONYM_DISCARD_KEY_PREFIX.length);
    if (rpId.endsWith('://')) continue;
    try {
      if (canonicalizeRpIdentifier(rpId) !== rpId) continue;
    } catch {
      continue;
    }
    discarded.push({ rpId, discardedAt: readDiscardedAt(await storage.get(key)) });
  }
  // `Array.prototype.sort` は安定ソート。`null`（読めない日時）は -Infinity として先頭へ寄せる。
  return discarded.sort((a, b) => (a.discardedAt ?? -Infinity) - (b.discardedAt ?? -Infinity));
}
