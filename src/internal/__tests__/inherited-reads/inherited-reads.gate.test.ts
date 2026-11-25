/**
 * 継承読みゲート（`scan.ts` の規則）の実リポジトリ適用と、検出器自身の検出力テスト。
 *
 * 実リポジトリに違反が出たら、修正は `ownProperty` / `nonObjectPrototypeProperty`（`internal/prototype-safety/own-property.ts`）で
 * 読むこと。allowlist での逃げは用意しない（正当な例外は `Object.hasOwn(opts, 'k') ? opts.k : …` の形で表せる）。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import ts from 'typescript';
import { HEAVY_INPUT_TIMEOUT_MS } from '../heavy-input-timeout.js';
import { ALLOWED_READS, applyAllowlist } from './allowlist.js';
import { findInheritedReads } from './scan.js';
import { SCAN_TIMEOUT_MS, scanSource } from './scan-source.js';

setDefaultTimeout(HEAVY_INPUT_TIMEOUT_MS);

const SDK_ROOT = resolve(import.meta.dir, '../../../..');

/** 公開 API の入口（package.json の `exports` の `types` = `dist/<name>.d.ts` に対応する `src/<name>.ts`）。 */
function publicEntries(): string[] {
  const manifest = JSON.parse(readFileSync(join(SDK_ROOT, 'package.json'), 'utf8')) as {
    exports: Record<string, string | { types?: string | { import: string } }>;
  };
  const entries = Object.values(manifest.exports)
    .map((target) => {
      if (typeof target === 'string') return undefined;
      return typeof target.types === 'string' ? target.types : target.types?.import;
    })
    .filter((types): types is string => types !== undefined)
    .map((types) => types.replace(/^\.\/dist\//, 'src/').replace(/\.d\.ts$/, '.ts'));
  if (entries.length < 3) throw new Error(`公開 API の入口を解決できない: ${entries.join(', ')}`);
  return entries;
}

describe('継承読みゲート', () => {
  it(
    'sdk/src に、外部入力由来の型のプロパティを素で読む箇所が無い（許可リスト以外）',
    () => {
      const { violations, unused } = applyAllowlist(
        findInheritedReads(SDK_ROOT, ts, {
          publicEntries: publicEntries(),
          narrowedRequired: true,
        }),
      );
      expect(violations.map((r) => `${r.file}:${r.line} ${r.expression}`)).toEqual([]);
      // 許可リストが腐らない: 検出されなくなった許可は削除する。
      expect(unused).toEqual([]);
    },
    SCAN_TIMEOUT_MS,
  );

  it('許可リストは file + expression の完全一致だけを免除し、未使用の許可を unused で返す', () => {
    const read = (file: string, expression: string) => ({ file, line: 1, expression });
    const allowed = [
      { file: 'src/a.ts', expression: 'x.a', reason: 'r' },
      { file: 'src/gone.ts', expression: 'y.b', reason: 'r' },
    ];
    const { violations, unused } = applyAllowlist(
      [read('src/a.ts', 'x.a'), read('src/a.ts', 'x.b'), read('src/b.ts', 'x.a')],
      allowed,
    );
    expect(violations.map((r) => `${r.file} ${r.expression}`)).toEqual([
      'src/a.ts x.b',
      'src/b.ts x.a',
    ]);
    expect(unused.map((a) => a.file)).toEqual(['src/gone.ts']);
  });

  it('許可リストの各項目に理由がある', () => {
    for (const entry of ALLOWED_READS) expect(entry.reason.length).toBeGreaterThan(20);
  });
});

describe('継承読み検出器の検出力', () => {
  const header =
    'interface O { readonly a?: number; readonly b: number }\nconst own = (o: object, k: string) => Object.hasOwn(o, k);\n';

  it(
    '省略可能プロパティの P.x / P?.x / 分割代入を検出する',
    () => {
      const found = scanSource(
        `${header}export function f(opts: O, options?: O) { const x = opts.a; const y = options?.a; const { a } = opts; return [x, y, a]; }`,
      );
      expect(found).toEqual(['opts.a', 'options.a', '{ a } = opts']);
    },
    SCAN_TIMEOUT_MS,
  );

  it(
    '必須プロパティ・書き込み・オプション袋以外の名前・Object.hasOwn ガード付きは検出しない',
    () => {
      const found = scanSource(
        `${header}export function f(opts: O, vc: O) { opts.b; vc.a; (opts as { a?: number }).a = 1; return Object.hasOwn(opts, 'a') ? opts.a : undefined; }`,
      );
      expect(found).toEqual([]);
    },
    SCAN_TIMEOUT_MS,
  );

  it(
    '別のキーの hasOwn ガードは免除にならない',
    () => {
      const found = scanSource(
        `${header}export function f(opts: O) { return Object.hasOwn(opts, 'b') ? opts.a : undefined; }`,
      );
      expect(found).toEqual(['opts.a']);
    },
    SCAN_TIMEOUT_MS,
  );

  it(
    'パラメータの型を公開 API が受けるとき、名前が opts でなくても検出する',
    () => {
      const source = [
        'export interface Vc { readonly id: string; readonly supportsSelectiveDisclosure?: boolean; readonly alg?: string }',
        'export function evaluate(candidates: readonly Vc[]) {',
        '  const vc = candidates[0]!;',
        '  return [vc.supportsSelectiveDisclosure !== undefined, vc.alg, candidates.map((c) => c.alg)];',
        '}',
      ].join('\n');
      expect(scanSource(source, ['src/a.ts'])).toEqual([
        'vc.supportsSelectiveDisclosure',
        'vc.alg',
        'c.alg',
      ]);
      // 公開 API の入口を渡さなければ（= 型が公開 API に現れない）名前が opts でない読みは対象にしない。
      expect(scanSource(source)).toEqual([]);
    },
    SCAN_TIMEOUT_MS,
  );

  it(
    '別名・ネスト・要素アクセス・分割代入・パラメータの分割代入を検出する',
    () => {
      const source = [
        'export interface R { readonly clientId: string; readonly tx?: string; readonly inner?: { readonly deep?: number } }',
        'export function a(request: R) { const r = request; return r.tx; }',
        "export function b(request: R) { return request['tx']; }",
        'export function c(request: R) { const { tx } = request; return tx; }',
        'export function d({ tx }: R) { return tx; }',
        'export function e(request: R) { return request.inner?.deep; }',
        'export function f(request: R) { const { inner } = request; return inner?.deep; }',
        "export function g(request: R) { return Object.hasOwn(request, 'tx') && request.tx; }",
        'export function h(request: R) { const { tx: _dropped, ...rest } = request; return rest; }',
      ].join('\n');
      expect(scanSource(source, ['src/a.ts'])).toEqual([
        'r.tx',
        'request.tx',
        '{ tx } = request',
        '{ tx } = R',
        'request.inner.deep',
        'request.inner',
        '{ inner } = request',
        'inner.deep',
      ]);
    },
    SCAN_TIMEOUT_MS,
  );

  it(
    '公開 API から到達できない内部構造体・必須プロパティ・own ヘルパ経由の読みは検出しない（偽陽性の確認）',
    () => {
      const source = [
        'export interface Pub { readonly id: string; readonly note?: string }',
        'interface Internal { readonly state?: string }',
        'const ownProperty = <T>(o: object, k: string): T | undefined => (Object.hasOwn(o, k) ? (o as Record<string, T>)[k] : undefined);',
        "export function a(p: Pub) { return [p.id, ownProperty<string>(p, 'note')]; }",
        'function b(rows: Internal[]) { return rows[0]?.state; }',
        'export const c = () => b([]);',
      ].join('\n');
      expect(scanSource(source, ['src/a.ts'])).toEqual([]);
    },
    SCAN_TIMEOUT_MS,
  );

  it(
    'パラメータでないローカル変数の同名は検出しない',
    () => {
      const found = scanSource(
        `${header}export function f() { const opts: O = { b: 1 }; return opts.a; }`,
      );
      expect(found).toEqual([]);
    },
    SCAN_TIMEOUT_MS,
  );

  it(
    'JSON の絞り込み先（JSON.parse の as / 型述語 / 型注釈付き変数）の必須プロパティも検出する',
    () => {
      const source = [
        'interface Svc { readonly type: string; readonly endpoint: { readonly uri: string } }',
        'interface Doc { readonly id: string; readonly service: readonly Svc[] }',
        'function isDoc(x: unknown): x is Doc { return typeof x === "object"; }',
        'export function a(text: string) { const d = JSON.parse(text) as Doc; return d.id; }',
        'export function b(raw: unknown) { return isDoc(raw) ? raw.service.map((s) => s.type) : []; }',
        'export function c(text: string) { const d: Doc = JSON.parse(text); return d.service[0]?.endpoint.uri; }',
        'export function e(text: string) { const { id } = JSON.parse(text) as Doc; return id; }',
      ].join('\n');
      // 既定（extension 用）では絞り込み先の必須プロパティは見ない。
      expect(scanSource(source)).toEqual([]);
      expect(scanSource(source, undefined, { narrowedRequired: true })).toEqual([
        'd.id',
        'raw.service',
        's.type',
        'd.service[0]?.endpoint.uri',
        'd.service[0].endpoint',
        'd.service',
        '{ id } = JSON.parse(text) as Doc',
      ]);
    },
    SCAN_TIMEOUT_MS,
  );

  it(
    '絞り込み先でない内部構造体の必須プロパティ・own 読み・Object.hasOwn ガード付きは検出しない（偽陽性の確認）',
    () => {
      const source = [
        'interface Doc { readonly id: string; readonly note: string }',
        'interface Internal { readonly id: string }',
        'const ownProperty = <T>(o: object, k: string): T | undefined => (Object.hasOwn(o, k) ? (o as Record<string, T>)[k] : undefined);',
        'export function a(text: string) { const d = JSON.parse(text) as Doc; return [ownProperty<string>(d, "id"), Object.hasOwn(d, "note") ? d.note : undefined]; }',
        'export function b(rows: Internal[]) { return rows.map((r) => r.id); }',
        'export function c(text: string) { const d = JSON.parse(text) as Doc; (d as { id: string }).id = "x"; return typeof d; }',
      ].join('\n');
      expect(scanSource(source, undefined, { narrowedRequired: true })).toEqual([]);
    },
    SCAN_TIMEOUT_MS,
  );
});
