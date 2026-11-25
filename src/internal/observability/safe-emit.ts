/**
 * テレメトリ出力（logger / metrics）を本処理から切り離すための best-effort ラッパ。
 *
 * DI された logger / metrics sink が例外を投げても、本処理の成功結果や元のエラー（`VericertsError` の
 * コード）を置換してはならない（観測性の失敗が業務結果を変えない。`wallet/aa/facade.ts` の監査ログ
 * best-effort と同方針）。sink の失敗はここで握り潰し、再帰的な障害を避けるためさらに記録はしない。
 */
export function safeEmit(emit: () => void): void {
  try {
    emit();
  } catch {
    // テレメトリ sink の障害は本処理へ伝播させない。
  }
}
