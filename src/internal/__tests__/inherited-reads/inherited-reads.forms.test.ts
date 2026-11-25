/**
 * 継承読みゲートの「型起点」検出力。パラメータを介さずに公開型の値へ到達する読み方（ループ変数・`this` のフィールド・
 * 呼び出し結果・ジェネリクス・メソッド・型アサーション）と、必須だが `T | undefined` のプロパティ、`any` / `unknown` からの絞り込み先を、
 * 1 形ずつ最小コードで固定する。偽陽性（このライブラリ自身が組み立てた内部の写し）も固定する。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { HEAVY_INPUT_TIMEOUT_MS } from '../heavy-input-timeout.js';
import { SCAN_TIMEOUT_MS, scanSource } from './scan-source.js';

setDefaultTimeout(HEAVY_INPUT_TIMEOUT_MS);

const O = [
  'export interface O { readonly id: string; readonly a?: number; readonly inner?: { readonly deep?: number } }',
  'export declare function entry(o: O, list: readonly O[]): void;',
].join('\n');

/** 公開 API の入口 `src/a.ts` に `body` を足して走査する。 */
const scan = (body: string): string[] => scanSource(`${O}\n${body}`, ['src/a.ts']);

describe('継承読みゲートの見逃し形（22 形中の 17 形）', () => {
  const cases: ReadonlyArray<readonly [name: string, body: string, expected: string[]]> = [
    ['対照: 関数パラメータ', 'export function f(o: O) { return o.a; }', ['o.a']],
    [
      'コンストラクタ引数プロパティ → this.o.a（名前が opts でなくても）',
      'export class C { constructor(private readonly o: O) {} read() { return this.o.a; } }',
      ['this.o.a'],
    ],
    [
      'クラスフィールド代入 this.o = o',
      'export class C { private o: O; constructor(o: O) { this.o = o; } read() { return this.o.a; } }',
      ['this.o.a'],
    ],
    [
      'for-of のループ変数',
      'export function f(list: readonly O[]) { for (const x of list) { void x.a; } }',
      ['x.a'],
    ],
    [
      'for-of の分割代入',
      'export function f(list: readonly O[]) { for (const { a } of list) { void a; } }',
      ['{ a } = O'],
    ],
    [
      'コールバックの分割代入 list.map(({ a }) => a)',
      'export function f(list: readonly O[]) { return list.map(({ a }) => a); }',
      ['{ a } = O'],
    ],
    [
      'list.find(…)?.a',
      'export function f(list: readonly O[]) { return list.find((x) => x.id === "k")?.a; }',
      ['list.find((x) => x.id === "k").a'],
    ],
    [
      'list.find(…)?.inner?.deep',
      'export function f(list: readonly O[]) { return list.find((x) => x.id === "k")?.inner?.deep; }',
      ['list.find((x) => x.id === "k")?.inner.deep', 'list.find((x) => x.id === "k").inner'],
    ],
    [
      '呼び出し結果 const x = id(o)',
      'declare function id<T>(v: T): T;\nexport function f(o: O) { const x = id(o); return x.a; }',
      ['x.a'],
    ],
    [
      'await した値',
      'export async function f(p: Promise<O>) { const x = await p; return x.a; }',
      ['x.a'],
    ],
    [
      '三項の合流',
      'export function f(o: O, p: O, c: boolean) { const x = c ? o : p; return x.a; }',
      ['x.a'],
    ],
    ['?? の合流', 'export function f(o: O, d: O) { const x = o ?? d; return x.a; }', ['x.a']],
    ['スプレッドの写し', 'export function f(o: O) { const x = { ...o }; return x.a; }', ['x.a']],
    ['ジェネリクス T extends O', 'export function f<T extends O>(o: T) { return o.a; }', ['o.a']],
    ['オブジェクトリテラルのメソッド', 'export const m = { run(o: O) { return o.a; } };', ['o.a']],
    [
      '要素アクセス o[k]（k: keyof O）',
      'export function f(o: O, k: keyof O) { return o[k]; }',
      ['o.a', 'o.inner'],
    ],
    [
      '型アサーション (o as Required<O>).a',
      'export function f(o: O) { return (o as Required<O>).a; }',
      ['(o as Required<O>).a'],
    ],
  ];
  for (const [name, body, expected] of cases) {
    it(
      `${name} を検出する`,
      () => {
        expect(scan(body).slice(0, expected.length)).toEqual(expected);
      },
      SCAN_TIMEOUT_MS,
    );
  }
});

describe('継承読みゲート: 必須だが T | undefined / any・unknown の絞り込み', () => {
  it(
    '公開 API の入力の必須 `T | undefined` プロパティを検出する（input.audience 等）',
    () => {
      const source = [
        'export interface In { readonly nowSeconds: number; readonly audience: string | undefined }',
        'export function verify(input: In) { return [input.nowSeconds, input.audience]; }',
      ].join('\n');
      expect(scanSource(source, ['src/a.ts'])).toEqual(['input.audience']);
      // 公開 API から到達できない型（内部で解決済みの写し）は、パラメータ名が input でも対象にしない。
      expect(scanSource(source)).toEqual([]);
    },
    SCAN_TIMEOUT_MS,
  );

  it(
    '`as T` / 型述語 / 型注釈付き変数による any・unknown からの絞り込み先を外部入力の型として扱う',
    () => {
      const source = [
        'interface Wire { readonly kid?: string }',
        'interface Doc { readonly extends?: string }',
        'interface Row { readonly note?: string }',
        'declare function isDoc(v: unknown): v is Doc;',
        'export function a(raw: string) { const w = JSON.parse(raw) as Wire; return w.kid; }',
        'export function b(v: unknown) { return isDoc(v) ? v.extends : undefined; }',
        'export function c(raw: string) { const r: Row = JSON.parse(raw); return r.note; }',
        'export function d(raw: string) { return (JSON.parse(raw) as Wire | null)?.kid; }',
      ].join('\n');
      expect(scanSource(source)).toEqual([
        'w.kid',
        'v.extends',
        'r.note',
        '(JSON.parse(raw) as Wire | null).kid',
      ]);
    },
    SCAN_TIMEOUT_MS,
  );

  it(
    'リテラルが Required の写しで、検査も own 限定のため、内部の写しは検出しない（偽陽性の確認）',
    () => {
      const source = [
        'export interface Opts { readonly a?: number }',
        'declare function ownProperty<T>(o: object, k: string): T | undefined;',
        'export function f(o: Opts) {',
        '  const snapshot: Readonly<Required<Opts>> = { a: ownProperty<number>(o, "a") ?? 1 };',
        '  return snapshot.a;',
        '}',
        'class Holder { private readonly storage?: string; constructor(storage?: string) { this.storage = storage; } read() { return this.storage; } }',
        'export const h = (s?: string) => new Holder(s).read();',
      ].join('\n');
      expect(scanSource(source, ['src/a.ts'])).toEqual([]);
    },
    SCAN_TIMEOUT_MS,
  );
});
