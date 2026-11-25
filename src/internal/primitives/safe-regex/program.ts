/**
 * AST を Thompson NFA の命令列へコンパイルし、状態集合の同時進行（Pike VM 相当・キャプチャ無し）で
 * 実行する。バックトラッキングをしないので、時間は O(命令数 × 入力長) に収まる。
 *
 * 公開 API からは直接呼ばれない内部実装。
 */

import { SafeRegexError } from './error.js';
import type { AssertionKind, RegexNode } from './parse.js';

/** 命令列の最大長（`a{1000}` を数個並べる程度まで。展開サイズの暴走を止める）。 */
const MAX_PROGRAM_SIZE = 4096;
/** コンパイル中に辿ってよい AST ノード回数の上限（命令を出さない空の繰り返しの入れ子対策）。 */
const MAX_COMPILE_WORK = 20_000;

/** 命令。`x` / `y` は分岐先の命令インデックス。 */
type Inst =
  | { op: 'char'; test: (codePoint: number) => boolean }
  | { op: 'split'; x: number; y: number }
  | { op: 'jmp'; x: number }
  | { op: 'assert'; kind: AssertionKind }
  | { op: 'match' };

/** 評価ステップの残量。複数の `test` 呼び出しで共有して総量を抑える。 */
export interface RegexBudget {
  /** 残りステップ数。 */
  remaining: number;
}

/** 1 回の `test` が単独で使えるステップ数の既定上限。 */
export const DEFAULT_REGEX_STEPS = 2_000_000;

/** AST を命令列へコンパイルする。 */
export function compileProgram(root: RegexNode): readonly Inst[] {
  const prog: Inst[] = [];
  let work = 0;

  const push = (inst: Inst): Inst => {
    if (prog.length >= MAX_PROGRAM_SIZE) {
      throw new SafeRegexError('too-complex');
    }
    prog.push(inst);
    return inst;
  };

  const emit = (node: RegexNode): void => {
    work += 1;
    if (work > MAX_COMPILE_WORK) {
      throw new SafeRegexError('too-complex');
    }
    switch (node.t) {
      case 'atom':
        push({ op: 'char', test: node.test });
        return;
      case 'assert':
        push({ op: 'assert', kind: node.kind });
        return;
      case 'cat':
        for (const item of node.items) {
          emit(item);
        }
        return;
      case 'alt': {
        const jumps: { op: 'jmp'; x: number }[] = [];
        node.items.forEach((item, index) => {
          if (index < node.items.length - 1) {
            const split = push({ op: 'split', x: prog.length + 1, y: -1 }) as { y: number };
            emit(item);
            jumps.push(push({ op: 'jmp', x: -1 }) as { op: 'jmp'; x: number });
            split.y = prog.length;
          } else {
            emit(item);
          }
        });
        for (const jump of jumps) {
          jump.x = prog.length;
        }
        return;
      }
      case 'rep':
        emitRepeat(node);
        return;
    }
  };

  const emitRepeat = (node: Extract<RegexNode, { t: 'rep' }>): void => {
    for (let k = 0; k < node.min; k += 1) {
      emit(node.node);
    }
    if (node.max === Number.POSITIVE_INFINITY) {
      const loopStart = prog.length;
      const split = push({ op: 'split', x: loopStart + 1, y: -1 }) as { y: number };
      emit(node.node);
      push({ op: 'jmp', x: loopStart });
      split.y = prog.length;
      return;
    }
    const splits: { y: number }[] = [];
    for (let k = node.min; k < node.max; k += 1) {
      splits.push(push({ op: 'split', x: prog.length + 1, y: -1 }) as { y: number });
      emit(node.node);
    }
    for (const split of splits) {
      split.y = prog.length;
    }
  };

  emit(root);
  push({ op: 'match' });
  return prog;
}

const isWord = (cp: number | undefined): boolean =>
  cp !== undefined &&
  ((cp >= 48 && cp <= 57) || (cp >= 65 && cp <= 90) || (cp >= 97 && cp <= 122) || cp === 95);

/** 位置 `pos`（コードポイント添字）でアサーションが成立するか。 */
function assertionHolds(kind: AssertionKind, cps: readonly number[], pos: number): boolean {
  switch (kind) {
    case 'bol':
      return pos === 0;
    case 'eol':
      return pos === cps.length;
    case 'wordBoundary':
      return isWord(cps[pos - 1]) !== isWord(cps[pos]);
    case 'notWordBoundary':
      return isWord(cps[pos - 1]) === isWord(cps[pos]);
  }
}

/**
 * `value` のどこかに一致するか（`RegExp#test` 相当・非アンカー探索）を、`budget` の範囲で判定する。
 *
 * @param unicode `true` はコードポイント単位、`false` は UTF-16 コードユニット単位で走査する。
 * @throws SafeRegexError `too-complex` — ステップ予算を使い切った（呼び出し側は不一致として扱う）。
 */
export function runProgram(
  prog: readonly Inst[],
  value: string,
  budget: RegexBudget,
  unicode = true,
): boolean {
  // 各位置で最低 1 ステップ要るため、予算を超える長さの入力は走査前に拒否する。
  if (value.length > budget.remaining) {
    throw new SafeRegexError('too-complex');
  }
  const cps = unicode
    ? Array.from(value, (ch) => ch.codePointAt(0) as number)
    : Array.from({ length: value.length }, (_, i) => value.charCodeAt(i));
  const last = cps.length;
  // mark[pc] === pos は「位置 pos の状態集合に pc を追加済み」を表す。
  const mark = new Int32Array(prog.length).fill(-1);
  let current: number[] = [];
  let next: number[] = [];

  const spend = (): void => {
    budget.remaining -= 1;
    if (budget.remaining < 0) {
      throw new SafeRegexError('too-complex');
    }
  };

  /** `start` から ε 遷移を辿り、`char` / `match` 命令を位置 `pos` の集合 `list` に加える。 */
  const addThread = (list: number[], start: number, pos: number): void => {
    const stack = [start];
    for (let pc = stack.pop(); pc !== undefined; pc = stack.pop()) {
      if (mark[pc] === pos) {
        continue;
      }
      mark[pc] = pos;
      spend();
      const inst = prog[pc] as Inst;
      if (inst.op === 'jmp') {
        stack.push(inst.x);
      } else if (inst.op === 'split') {
        stack.push(inst.y, inst.x);
      } else if (inst.op === 'assert') {
        if (assertionHolds(inst.kind, cps, pos)) {
          stack.push(pc + 1);
        }
      } else {
        list.push(pc);
      }
    }
  };

  for (let pos = 0; pos <= last; pos += 1) {
    // 非アンカー探索: 各位置から新しいスレッドを 1 本起こす。
    addThread(current, 0, pos);
    for (const pc of current) {
      if ((prog[pc] as Inst).op === 'match') {
        return true;
      }
    }
    if (pos === last) {
      break;
    }
    const cp = cps[pos] as number;
    for (const pc of current) {
      const inst = prog[pc] as Inst;
      spend();
      if (inst.op === 'char' && inst.test(cp)) {
        addThread(next, pc + 1, pos + 1);
      }
    }
    [current, next] = [next, []];
  }
  return false;
}
