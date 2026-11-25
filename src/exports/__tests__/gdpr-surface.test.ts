/**
 * GdprApi の公開メソッドが使う ConsentScope / LogFilter 型の公開エクスポート面の回帰テスト
 *
 * 公開 API では `revokeConsent(scope: ConsentScope)` /
 * `purgeDashboardLog(filter?: LogFilter)` / `exportDashboardLog(filter?: LogFilter)` の
 * パラメータ型として ConsentScope/LogFilter（`internal/gdpr/types.ts`）を規定する。内部バレル
 * （`src/internal/gdpr/index.ts`）は両方を型エクスポートする一方、公開バレル
 * （`src/exports/gdpr.ts`）はエクスポートリストから欠落しており、SDK 利用者がこれらの型を
 * 公開エントリポイント（`src/index.ts`）から参照できなかった。
 *
 * 型のみの欠落は実行時には現れない（`bun test` の transpile は型注釈を消去するため、単に
 * `import type` するだけでは fail-first にならない）。そのため本テストは型を実際の関数シグネチャの
 * 引数位置で使用し、`bun run typecheck`（`tsc --noEmit`、`__tests__` 配下も対象）が
 * `TS2305: Module '"../../index.js"' has no exported member 'ConsentScope'` 等で検知できる形にする。
 */

import { describe, expect, test } from 'bun:test';
import type { ConsentScope, LogFilter } from '../../index.js';

// 公開バレルから型として import できることを tsc（bun run typecheck）に検査させるための
// 具体的な使用箇所。値としても組み立てて実行時にフィールドを検証する。
function buildConsentScope(scope: ConsentScope): ConsentScope {
  return scope;
}

function buildLogFilter(filter: LogFilter): LogFilter {
  return filter;
}

describe('公開エクスポート: GdprApi パラメータ型 ConsentScope/LogFilter', () => {
  test('ConsentScope が SDK エントリポイントから型として import できる', () => {
    const scope = buildConsentScope({
      rpIdentifier: 'https://rp.example',
      purpose: 'age-verification',
    });
    expect(scope.rpIdentifier).toBe('https://rp.example');
    expect(scope.purpose).toBe('age-verification');
  });

  test('LogFilter が SDK エントリポイントから型として import できる', () => {
    const filter = buildLogFilter({
      types: ['consentRevoked'],
      rpIdentifier: 'https://rp.example',
    });
    expect(filter.types).toEqual(['consentRevoked']);
    expect(filter.rpIdentifier).toBe('https://rp.example');
  });
});
