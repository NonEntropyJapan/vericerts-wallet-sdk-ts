/**
 * ベンダリングした did:webvh 公式テストベクタ（`didwebvh-test-suite/`）の読み込み。出典・固定したコミットは
 * `didwebvh-test-suite/README.md`。
 */

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, 'didwebvh-test-suite', 'vectors');

/** 複製した実装別の出力。 */
export const IMPLEMENTATIONS = ['ts', 'python', 'rust', 'java'] as const;

/** 解決結果（`resolutionResult.json`）の形（必要な部分だけ）。 */
export interface ExpectedResolution {
  readonly didDocument: (Record<string, unknown> & { id: string }) | null;
  readonly didDocumentMetadata: Record<string, unknown>;
  readonly didResolutionMetadata?: { readonly error?: string };
}

/** 1 つの（シナリオ, 実装）の入力と期待値。 */
export interface VectorCase {
  readonly scenario: string;
  readonly implementation: string;
  readonly negative: boolean;
  readonly logText: string;
  readonly witnessText: string | undefined;
  readonly expected: ExpectedResolution | undefined;
  /** `script.yaml` の `resolve-did` が列挙する DID（DID だけを検査する負のベクタ）。 */
  readonly dids: readonly string[];
}

function read(path: string): string | undefined {
  return existsSync(path) ? readFileSync(path, 'utf8') : undefined;
}

/** シナリオ名の一覧。 */
export function scenarios(): string[] {
  return readdirSync(ROOT, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
}

/** 全ベクタ（ログのあるもの）を読む。 */
export function loadCases(): VectorCase[] {
  const cases: VectorCase[] = [];
  for (const scenario of scenarios()) {
    const script = read(join(ROOT, scenario, 'script.yaml')) ?? '';
    const negative = /^negative:\s*true/m.test(script);
    for (const implementation of IMPLEMENTATIONS) {
      const dir = join(ROOT, scenario, implementation);
      const logText = read(join(dir, 'did.jsonl'));
      // ログが空のベクタ（DID の文字列だけを検査する負のベクタ）は `didOnlyVectors` が扱う。
      if (logText === undefined || logText.trim() === '') {
        continue;
      }
      const result = read(join(dir, 'resolutionResult.json'));
      cases.push({
        scenario,
        implementation,
        negative,
        logText,
        witnessText: read(join(dir, 'did-witness.json')),
        expected: result === undefined ? undefined : (JSON.parse(result) as ExpectedResolution),
        dids: [],
      });
    }
  }
  return cases;
}

/** `resolve-did` の DID だけを持つ負のベクタ（ログなし）の DID 一覧。 */
export function didOnlyVectors(): { scenario: string; dids: string[] }[] {
  const result: { scenario: string; dids: string[] }[] = [];
  for (const scenario of scenarios()) {
    if (!scenario.startsWith('negative-')) {
      continue;
    }
    const script = read(join(ROOT, scenario, 'script.yaml')) ?? '';
    const dids = [...script.matchAll(/^\s*did:\s*"([^"]+)"/gm)].map((m) => m[1] as string);
    if (dids.length > 0) {
      result.push({ scenario, dids });
    }
  }
  return result;
}
