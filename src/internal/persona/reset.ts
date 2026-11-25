/**
 * seed 差し替え時に旧ウォレットの seed 由来ペルソナ状態を消す。
 *
 * ペルソナの DID は旧 seed から導出した did:key で、`derivationPath` も旧 seed の導出位置を指す。
 * seed だけを差し替えると、保存済みの旧 DID を名乗りつつ新 seed の鍵で署名する不整合なペルソナが
 * アクティブのまま残る。Extension の `SEED_REPLACEMENT_CLEANUP_KEYS`（ペルソナ・委任先 DID 等の掃除）と
 * 同じ方針で、SDK 側もペルソナ本体とアクティブ指定を消す。`credential/` / `dashboard-log/` は旧ウォレットの
 * 監査・VC 本体であり、本関数では扱わない。
 *
 * **Pseudonym 破棄マーカー（`pseudonym-discarded/`）は消さない。** キーは
 * `pseudonym-discarded/<rpId>` で RP 単位であり、seed を含まない。GDPR の同意撤回
 * （`revokeConsent` → `discardPseudonym`）の記録であって、seed 由来の状態ではない。
 *
 * 消すと、パスフレーズの打ち間違いのような**取り消せるはずの操作**で同意撤回が巻き戻る。`importMnemonic`
 * には上書きガードが無く、間違えた直後に正しいニーモニックで入れ直してもマーカーは戻らない。撤回した RP
 * 向けの Pseudonym（seed + RP から決定的に導出される）が再び提示可能になる。
 *
 * 逆に残した場合の害は「別ウォレットでも同じ RP への Pseudonym を拒む」だけで、拒否側（fail-closed）に
 * しか倒れない。不可逆な権利の喪失と、過剰な拒否とでは重みが違う。
 */

import type { Storage } from '../storage-port.js';

/** seed 由来のペルソナ状態を保持する storage キーの prefix（`persona/active` は `persona/` 配下）。 */
const SEED_BOUND_PERSONA_PREFIXES = ['persona/'] as const;

/**
 * 旧 seed 由来のペルソナ状態（ペルソナ・アクティブ指定）を全て削除する。Pseudonym 破棄マーカーは
 * seed に紐づかない同意撤回の記録なので消さない（モジュールの docblock 参照）。
 *
 * @param storage 削除先 storage。
 */
export async function clearSeedBoundPersonaState(
  storage: Pick<Storage, 'list' | 'delete'>,
): Promise<void> {
  for (const prefix of SEED_BOUND_PERSONA_PREFIXES) {
    for (const key of await storage.list(prefix)) {
      await storage.delete(key);
    }
  }
}
