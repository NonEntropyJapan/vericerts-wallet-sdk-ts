/**
 * Credential Chain の親エッジ走査とノード単体評価（`verify.ts` の下位ロジック）。
 *
 * 1 つの VC が持つ**すべて**の親エッジ（`derivedFrom` /
 * `supersedes` / `amends` / `basedOn`。`basedOn` は配列可）を辿る。グラフは木ではなく DAG になり得る
 * ため、幅優先で走査しつつ以下を守る:
 *
 * - **循環検出**: 起点からその親までの経路（祖先パス）に同じ VC ID が現れたら `CHAIN_CYCLE`（4050）。
 *   訪問済み集合ではなく経路で判定するため、共通の祖先を持つダイヤモンド構造を循環と誤検出しない。
 * - **重複解決の回避**: 同じ VC の解決（`resolveCredential`）と単体評価（署名 / 失効）は 1 回だけ行い
 *   メモ化する。2 度目以降の到達は `duplicate: true` の訪問として記録し、経路ごとの失効伝搬判定に使う。
 * - **親の再展開**: 解決はメモ化する一方、親エッジの展開は経路依存の情報（`propagating` / `depth`）が
 *   前回の展開より強くなった再到達で**やり直す**。これがないと、非伝搬経路（`basedOn` / `supersedes`）が
 *   合流ノードへ先着した場合に伝搬経路の先の祖先が `propagating: false` で固定され、失効が伝搬しない
 *   fail-open になる。同時に、既訪ノードを
 *   経由するより長い経路も探索されるため `depth` の過小報告と `maxDepth` の未強制も防げる。
 * - **深さ**: 各経路の段数が `maxDepth` を超えたら `CHAIN_TOO_DEEP`（4051）。
 * - **走査量**: 相異なる VC 数（`MAX_CHAIN_NODES`）・キューに積む訪問の総数（`MAX_CHAIN_VISITS`）・1 VC の親エッジ数
 *   （`MAX_CHAIN_PARENT_EDGES`、`edges.ts`）の超過も `CHAIN_TOO_DEEP`（4051）。深さだけでは親の fan-out による
 *   指数展開を止められない。
 *
 * セキュリティ: 例外 message / context に VC 本文・親 ID を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PresentationWorkBudget } from '../../primitives/presentation-work-budget.js';
import { chainTooLarge, spendWork } from '../../primitives/presentation-work-budget.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import type { VerifiableCredential } from '../vc/vc.js';
import { parentEdges, propagatesRevocation } from './edges.js';
import { MAX_CHAIN_NODES, MAX_CHAIN_VISITS } from './limits.js';
import type { ChainRelation, ChainVerifyDependencies, ChainVerifyOptions } from './types.js';
import { DEFAULT_MAX_CHAIN_DEPTH } from './types.js';

/** ノード単体の失効/署名評価（例外は投げず valid + revoked フラグを返す）。 */
export interface NodeEvaluation {
  readonly valid: boolean;
  /** 失効/停止していたか（失効伝搬判定に使う）。 */
  readonly revoked: boolean;
}

/**
 * ノード単体を評価する: 署名検証（`verifyLink`）と、`credentialStatus` があれば失効評価（`resolveStatus`）。
 *
 * 署名無効は `valid=false`。失効/停止は `valid=false, revoked=true`。いずれも例外は投げない。
 */
export async function evaluateNode(
  vc: VerifiableCredential,
  deps: ChainVerifyDependencies,
): Promise<NodeEvaluation> {
  // DI される判定関数も自身のプロパティに限って読む。`verifyLink` は署名の、
  // `resolveStatus` は失効の**判定そのもの**であり、型上必須でも型の無い JS から渡し忘れると
  // プロトタイプ鎖の汚染値が「渡された判定器」に化け、チェーンの有効性判定が攻撃者の関数へ
  // 委譲される。同ファイルの `maxDepth` は own 化済みで、こちらだけが読み方の食い違いだった。
  // 判定器が無い場合は署名不成立として fail-closed に倒す。
  const verifyLink = nonObjectPrototypeProperty<ChainVerifyDependencies['verifyLink']>(
    deps,
    'verifyLink',
  );
  if (typeof verifyLink !== 'function') {
    return { valid: false, revoked: false };
  }
  const sigValid = await verifyLink(vc);
  if (!sigValid) {
    return { valid: false, revoked: false };
  }
  // `credentialStatus` は VC 本文（データ）。継承値を拾うと、失効参照を**持たない** VC でも
  // 汚染値の参照で失効解決が走る（逆に own 限定なら「参照なし = 失効チェック対象外」を保つ）。
  if (ownProperty<unknown>(vc, 'credentialStatus') === undefined) {
    return { valid: true, revoked: false };
  }
  const resolveStatus = nonObjectPrototypeProperty<ChainVerifyDependencies['resolveStatus']>(
    deps,
    'resolveStatus',
  );
  if (typeof resolveStatus !== 'function') {
    // 失効参照はあるのに解決手段が無い ＝ 失効未確認。有効とは主張しない（fail-closed）。
    return { valid: false, revoked: false };
  }
  const status = await resolveStatus(vc);
  if (status !== undefined && !status.valid) {
    return { valid: false, revoked: true };
  }
  return { valid: true, revoked: false };
}

/** 走査で 1 つのノードへ到達したことの記録（同じ VC へ複数経路で到達し得る）。 */
export interface ChainVisit {
  /** 到達した VC の ID。 */
  readonly vcId: string;
  /** この到達に使った親エッジの種別（起点は `derivedFrom` を既定とする）。 */
  readonly relation: ChainRelation;
  /** 起点からの段数（起点=0）。 */
  readonly depth: number;
  /** 起点からこのノードまでの全エッジが失効伝搬対象か。 */
  readonly propagating: boolean;
  /** 解決済みの VC 本体。 */
  readonly vc: VerifiableCredential;
  /**
   * この到達に使った親エッジを宣言した子 VC（起点ノードは親エッジを持たないので `undefined`）。
   *
   * `revocationPropagation` は派生 VC（子）に埋め込む属性なので、
   * ポリシー解決と `customHandler` の `child` 引数にはこの VC を使う。
   */
  readonly child: VerifiableCredential | undefined;
  /** ノード単体の評価結果。 */
  readonly evaluation: NodeEvaluation;
  /** 別経路で既に到達済みのノードへの再到達か（`chain` には 1 度だけ載せる）。 */
  readonly duplicate: boolean;
}

/** 走査結果。 */
export interface ChainTraversal {
  /** 到達順（幅優先: 起点 → 浅い親 → 深い親）の訪問記録。 */
  readonly visits: readonly ChainVisit[];
  /** 走査した経路の最大段数。 */
  readonly depth: number;
}

/** 幅優先キューの 1 要素。 */
interface QueueEntry {
  readonly id: string;
  readonly relation: ChainRelation;
  readonly depth: number;
  readonly propagating: boolean;
  /** 起点からこのノードの子までの経路上の VC ID（循環検出用）。 */
  readonly ancestors: readonly string[];
  /** このエッジを宣言した子 VC（起点は `undefined`）。 */
  readonly child: VerifiableCredential | undefined;
}

/** あるノードの親を展開したときの条件（再展開の要否判定に使う）。 */
interface ExpansionState {
  /** これまでに展開した中で最大の depth。 */
  readonly depth: number;
  /** これまでに `propagating=true` で展開したことがあるか。 */
  readonly propagating: boolean;
}

/**
 * 再展開が必要か（前回までの展開条件より「強い」経路で再到達したか）を判定する。
 *
 * 条件はいずれも単調なので停止性が保証される:
 * - `propagating` は false → true の一方向にしか上がらない（1 ノードあたり高々 1 回の再展開）。
 * - `depth` は増加のみで、`depth > maxDepth` は必ず throw されるため上限が存在する。
 *
 * よって 1 ノードあたりの展開回数は高々 `maxDepth + 2` 回で、無限ループにはならない。
 */
function needsExpansion(prev: ExpansionState | undefined, entry: QueueEntry): boolean {
  if (prev === undefined) {
    return true;
  }
  return entry.depth > prev.depth || (entry.propagating && !prev.propagating);
}

/** 展開条件を記録し直す（depth は最大値、propagating は論理和で単調に引き上げる）。 */
function mergeExpansion(prev: ExpansionState | undefined, entry: QueueEntry): ExpansionState {
  return {
    depth: Math.max(prev?.depth ?? 0, entry.depth),
    propagating: (prev?.propagating ?? false) || entry.propagating,
  };
}

/** キュー要素と評価結果から訪問記録を組み立てる（`ancestors` は結果に持ち出さない）。 */
function toVisit(
  entry: QueueEntry,
  vc: VerifiableCredential,
  evaluation: NodeEvaluation,
  duplicate: boolean,
): ChainVisit {
  return {
    vcId: entry.id,
    relation: entry.relation,
    depth: entry.depth,
    propagating: entry.propagating,
    vc,
    child: entry.child,
    evaluation,
    duplicate,
  };
}

/**
 * 起点 VC から全親エッジを幅優先で辿り、各ノードの評価結果を集める。
 *
 * @param vcId 起点 VC の ID。
 * @param opts DI（resolveCredential / verifyLink / resolveStatus）+ maxDepth。
 * @param budget 複数チェーンで共有する残予算（VP 経由）。省略時は 1 走査ごとの上限のみ。
 * @throws 循環（`4050`）/ 深さ超過・走査量（ノード数・訪問数・親エッジ数）超過（`4051`）/ 解決不能（`4052`）の場合（VericertsError）。
 */
export async function traverseChain(
  vcId: string,
  opts: ChainVerifyOptions,
  budget?: PresentationWorkBudget,
): Promise<ChainTraversal> {
  // 任意プロパティは自身のプロパティに限って読む。継承した `maxDepth`（例
  // `Infinity`）は深さ超過ガード（4051）を無効化し、`cacheKeyFor` 側の読み方とも食い違う。
  const maxDepth = ownProperty<number>(opts, 'maxDepth') ?? DEFAULT_MAX_CHAIN_DEPTH;
  const visits: ChainVisit[] = [];
  /** 解決・評価済みのノード（同じ VC を 2 度解決しない）。 */
  const evaluated = new Map<string, { vc: VerifiableCredential; evaluation: NodeEvaluation }>();
  /** ノードごとの親展開条件（経路依存の情報が強まった再到達でのみ再展開する）。 */
  const expanded = new Map<string, ExpansionState>();
  const queue: QueueEntry[] = [
    {
      id: vcId,
      relation: 'derivedFrom',
      depth: 0,
      propagating: true,
      ancestors: [],
      child: undefined,
    },
  ];
  let deepest = 0;
  /** キューに積んだ訪問の総数（起点を含む）。 */
  let enqueued = 1;
  spendWork(budget, 'chainVisits');

  while (queue.length > 0) {
    const entry = queue.shift() as QueueEntry;
    if (entry.depth > maxDepth) {
      throw new VericertsError(ErrorCodes.CHAIN_TOO_DEEP);
    }
    if (entry.ancestors.includes(entry.id)) {
      throw new VericertsError(ErrorCodes.CHAIN_CYCLE);
    }
    deepest = Math.max(deepest, entry.depth);

    const known = evaluated.get(entry.id);
    let vc: VerifiableCredential;
    let evaluation: NodeEvaluation;
    if (known !== undefined) {
      // 別経路から到達済み。解決・評価は再利用し、訪問だけ経路ごとに記録する。
      ({ vc, evaluation } = known);
      visits.push(toVisit(entry, vc, evaluation, true));
    } else {
      // `resolveCredential` も同様に own 限定で読む（親 VC の解決先が攻撃者の関数に化けると、
      // チェーンに任意の VC を注入できる）。
      const resolveCredential = nonObjectPrototypeProperty<ChainVerifyOptions['resolveCredential']>(
        opts,
        'resolveCredential',
      );
      // 新しい VC の解決（ネットワーク往復）に入る前に、相異なるノード数を縛る。
      if (evaluated.size >= MAX_CHAIN_NODES) {
        throw chainTooLarge();
      }
      spendWork(budget, 'chainNodes');
      if (typeof resolveCredential !== 'function') {
        throw new VericertsError(ErrorCodes.CHAIN_PARENT_UNRESOLVABLE);
      }
      const resolved = await resolveCredential(entry.id);
      if (resolved === undefined) {
        // 起点・親いずれの解決不能もチェーン破断として同コードで扱う。
        throw new VericertsError(ErrorCodes.CHAIN_PARENT_UNRESOLVABLE);
      }
      vc = resolved;
      evaluation = await evaluateNode(vc, opts);
      evaluated.set(entry.id, { vc, evaluation });
      visits.push(toVisit(entry, vc, evaluation, false));
    }

    // 親の再展開は「経路依存の情報が前回より強い」ときだけ行う（単調なので必ず停止する）。
    const prev = expanded.get(entry.id);
    if (!needsExpansion(prev, entry)) {
      continue;
    }
    expanded.set(entry.id, mergeExpansion(prev, entry));

    for (const edge of parentEdges(vc)) {
      // 経路ごとの訪問（再到達・再展開を含む）の総数を、積む前に縛る。
      enqueued += 1;
      if (enqueued > MAX_CHAIN_VISITS) {
        throw chainTooLarge();
      }
      spendWork(budget, 'chainVisits');
      queue.push({
        id: edge.id,
        relation: edge.relation,
        depth: entry.depth + 1,
        propagating: entry.propagating && propagatesRevocation(edge.relation),
        ancestors: [...entry.ancestors, entry.id],
        child: vc,
      });
    }
  }

  return { visits, depth: deepest };
}
