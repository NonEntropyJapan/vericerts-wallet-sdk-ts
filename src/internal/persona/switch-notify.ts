/**
 * アクティブペルソナ切替リスナへの通知（`PersonaManager.setActivePersona` から呼ばれる）。
 *
 * リスナの例外が他のリスナ通知や呼び出し元の永続化結果へ波及しないよう、各リスナの呼び出しは独立して行い、
 * 同期例外と（Promise を返すリスナの）拒否はここで握りつぶす（永続化は既に完了している）。失敗の記録は
 * リスナ側の責務（ここは unhandled rejection を防ぐ最終防衛線）。
 */

import type { PersonaMetadata, PersonaSwitchListener } from './types.js';

/**
 * 登録済みの切替リスナへ、切替後のメタデータを同期的に通知する。
 *
 * @param listeners 登録済みリスナ。
 * @param persona 切替後にアクティブになったペルソナのメタデータ。
 */
export function notifySwitchListeners(
  listeners: ReadonlySet<PersonaSwitchListener>,
  persona: PersonaMetadata,
): void {
  for (const listener of listeners) {
    try {
      const returned: unknown = listener(persona);
      if (returned instanceof Promise) {
        returned.catch(() => {
          // 非同期リスナの拒否も切替処理の成否に影響させない。
        });
      }
    } catch {
      // リスナ側の例外は切替処理の成否に影響させない。
    }
  }
}
