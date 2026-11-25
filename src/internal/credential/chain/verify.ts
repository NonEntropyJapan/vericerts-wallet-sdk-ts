/**
 * Credential Chain の再帰検証と失効伝搬。
 *
 * チェーンは `derivedFrom` / `basedOn` / `supersedes` / `amends` の親エッジを起点から根まで
 * 再帰的に辿り、各ノードの署名検証（`verifyLink`）と失効評価（`resolveStatus`）を行う。失効伝搬はまず
 * 関係種別で決まり（`basedOn` / `supersedes` は伝搬しない）、伝搬する関係については各 VC の
 * `revocationPropagation` または `opts.policy` に従う（`strict` / `permissive` / `custom`）。
 *
 * VC 解決 / 署名検証 / 失効ビット読取りは DI し（`resolveCredential` / `verifyLink` / `resolveStatus`）、
 * DID 解決・ネットワーク I/O を持ち込まず単体テスト可能にする。構造エラー（循環 `CHAIN_CYCLE` 4050 /
 * 深さ超過 `CHAIN_TOO_DEEP` 4051 / 親解決不能 `CHAIN_PARENT_UNRESOLVABLE` 4052）は throw し、失効伝搬に
 * よる無効は `ChainVerificationResult.valid=false` + `reason` として返す。
 *
 * セキュリティ: 例外 message / context / reason に VC 本文・親 ID・エンドポイント応答を含めない。reason は静的な分類文字列に限定する。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PresentationWorkBudget } from '../../primitives/presentation-work-budget.js';
import {
  chainTooLarge,
  MAX_PRESENTATION_CREDENTIALS,
  newPresentationWorkBudget,
} from '../../primitives/presentation-work-budget.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import { propagatesRevocation } from './edges.js';
import { normalizeChainPolicy, resolveChainPolicy } from './policy.js';
import type { ChainVisit } from './traverse.js';
import { traverseChain } from './traverse.js';
import type {
  ChainNode,
  ChainVerificationResult,
  ChainVerifyOptions,
  PresentationChainVerifyOptions,
} from './types.js';

/** チェーン走査の可変状態。無効判定と警告を蓄積する。 */
interface ChainAccumulator {
  overallValid: boolean;
  reason: string | undefined;
  readonly warnings: string[];
}

/** `customHandler` に割り当てた安定 ID（関数は文字列化できないためキャッシュキー用に採番する）。 */
const handlerIds = new WeakMap<object, number>();
let nextHandlerId = 0;

/** `customHandler` の識別子を返す（同じ関数には同じ値）。 */
function handlerKey(handler: ChainVerifyOptions['customHandler']): string {
  if (handler === undefined) {
    return '';
  }
  let id = handlerIds.get(handler);
  if (id === undefined) {
    id = nextHandlerId++;
    handlerIds.set(handler, id);
  }
  return String(id);
}

/**
 * キャッシュキーを組み立てる。
 *
 * 起点 VC ID だけをキーにすると、**結果を左右するオプションが違う呼び出しに前回の結果を配ってしまう**。
 * 特に `policy: "permissive"` で得た `valid: true` が、その後の `policy: "strict"` の呼び出しに
 * TTL（5 分）の間ヒットし続け、失効した親を持つチェーンが有効と判定される（fail-open）。
 * 走査範囲を変える `maxDepth` と、判定そのものを差し替える `customHandler` も同様にキーへ含める。
 */
function cacheKeyFor(vcId: string, opts: ChainVerifyOptions): string {
  // 任意プロパティは自身のプロパティに限って読む。キー生成と実際の判定で読み方が
  // 食い違うと、判定に使われなかった継承値がキーに混ざる（またはその逆）ためキャッシュが
  // 別条件の結果を配る。判定側（`applyPolicy` / `traverseChain`）と同じ読み方に揃える。
  // `policy` は判定側と同じ正規化を通す。生の値を `join` に渡すと、列挙外の値が実効ポリシー
  // （`strict`）と別キーになるうえ、null プロトタイプ値の暗黙 `ToString` で `TypeError` になる。
  return [
    vcId,
    normalizeChainPolicy(ownProperty<unknown>(opts, 'policy')) ?? '',
    ownProperty<number>(opts, 'maxDepth') ?? '',
    handlerKey(ownProperty<ChainVerifyOptions['customHandler']>(opts, 'customHandler')),
  ].join('\u0000');
}

/**
 * ノード評価結果をポリシーに従いチェーン全体の有効性へ反映する。
 *
 * 起点（葉）の無効はポリシーに関わらず全体を無効化する。祖先の署名不正も同様に無効化する。祖先の失効は
 * まず関係種別で伝搬可否を判定し（`basedOn` / `supersedes` は伝搬しない）、伝搬する場合に
 * `strict`（既定）で無効化、`permissive` で警告に留め、`custom` で `customHandler` の判定に委ねる。
 *
 * `revocationPropagation` は親エッジを**宣言した側の子 VC** が持つ属性なので、
 * ポリシー解決と `customHandler` の `child` 引数には祖先ノード自身ではなく `visit.child` を使う。
 *
 * @param visit 経路ごとの訪問記録（`propagating` は起点からこのノードまで全エッジが伝搬対象なら true）。
 */
function applyPolicy(
  acc: ChainAccumulator,
  visit: ChainVisit,
  node: ChainNode,
  opts: ChainVerifyOptions,
): void {
  const { evaluation } = visit;
  if (evaluation.valid) {
    return;
  }
  if (visit.depth === 0) {
    // 起点 VC 自体の無効はポリシーに関わらず全体を無効化する。
    acc.overallValid = false;
    acc.reason ??= evaluation.revoked ? 'leaf-revoked' : 'leaf-signature-invalid';
    return;
  }
  if (!evaluation.revoked) {
    // 祖先の署名不正はポリシーに関わらず全体を無効化する（改ざん / 不正発行）。
    acc.overallValid = false;
    acc.reason ??= 'ancestor-signature-invalid';
    return;
  }
  // 祖先の失効。まず関係種別で伝搬可否が決まる。
  if (!visit.propagating) {
    // basedOn（参考）/ supersedes（親は廃止済み）を経由した祖先の失効は子へ伝搬しない。
    acc.warnings.push('ancestor-revoked');
    return;
  }
  // depth > 0 の訪問は必ず親エッジ経由なので `child` は存在する（`?? visit.vc` は型を閉じるための保険）。
  const child = visit.child ?? visit.vc;
  // 任意プロパティは自身のプロパティに限って読む。継承値を拾うと失効伝搬が
  // permissive 側へ落ち、失効した祖先があっても `overallValid` が true のまま残る:
  // - `child.revocationPropagation`: VC が宣言していないのに汚染値が「Issuer 宣言」に化ける。
  // - `opts.policy`: 検証者が渡していない `permissive` が実効ポリシーになる。
  // - `opts.customHandler`: 渡していないハンドラが呼ばれ、伝搬判定が攻撃者の関数へ委譲される。
  // 値の妥当性は `resolveChainPolicy` が許可集合で確認する。計算プロパティキーで直接引くと、
  // パース境界で null プロトタイプ化された型不正な宣言が `TypeError` になり、「未知は strict」の
  // fail-closed フォールバックごと迂回される。
  const declared = ownProperty<unknown>(child, 'revocationPropagation');
  const policy = resolveChainPolicy(declared, ownProperty<unknown>(opts, 'policy'));
  if (policy === 'permissive') {
    acc.warnings.push('ancestor-revoked');
    return;
  }
  const customHandler = ownProperty<ChainVerifyOptions['customHandler']>(opts, 'customHandler');
  if (policy === 'custom' && customHandler !== undefined) {
    if (!customHandler(node, child)) {
      acc.overallValid = false;
      acc.reason ??= 'ancestor-revoked';
    }
    return;
  }
  // strict（既定）: 祖先失効はチェーン全体を無効化する（失効伝搬）。
  acc.overallValid = false;
  acc.reason ??= 'ancestor-revoked';
}

/**
 * VC チェーンを起点 VC から根まで検証する。
 *
 * 親エッジ（`derivedFrom` / `supersedes` / `amends` / `basedOn`）は 1 つの VC が複数持てる。すべての親を
 * 幅優先で辿り（`traverse.ts`）、各ノードで署名検証と失効状態評価を行う。失効伝搬はまず関係種別で決まり、
 * 伝搬する関係については各 VC の `revocationPropagation`（未設定時は `opts.policy`、それも無ければ
 * `strict`）に従う。同じ VC へ複数経路で到達した場合、`chain` には 1 度だけ載せ、伝搬判定は経路ごとに
 * 行う（1 本でも伝搬経路があれば伝搬する）。キャッシュが渡された場合は起点 VC ID をキーに 5 分間結果を
 * 再利用する。
 *
 * @param vcId 検証の起点となる VC の ID。
 * @param opts DI（resolveCredential / verifyLink / resolveStatus）+ maxDepth / policy / customHandler /
 *             cache / now。
 * @returns チェーン検証結果（起点→根の順のノード列と全体の有効性。`depth` は最長経路の段数）。
 * @throws 循環（`4050`）/ 深さ超過（`4051`）/ 解決不能（`4052`）の場合（VericertsError）。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export async function verifyCredentialChain(
  vcId: string,
  opts: ChainVerifyOptions,
): Promise<ChainVerificationResult> {
  return verifyChainWithBudget(vcId, opts, undefined);
}

/** `verifyCredentialChain` の本体。`budget` は VP 経由で複数チェーンが共有する仕事量の残予算。 */
async function verifyChainWithBudget(
  vcId: string,
  opts: ChainVerifyOptions,
  budget: PresentationWorkBudget | undefined,
): Promise<ChainVerificationResult> {
  // 継承値を拾うと、`now` を渡していない呼び出しがキャッシュ TTL を攻撃者の時刻で評価し、
  // 期限切れのチェーン検証結果を再利用できる。`cache` も同様に、渡していない
  // 呼び出しが攻撃者のキャッシュへ判定結果を委譲する。
  const now = ownProperty<number>(opts, 'now') ?? Date.now();

  // 結果を左右するオプションをキーに含める（起点 ID だけだと permissive の結果が strict の
  // 呼び出しにヒットする fail-open になる）。
  const cacheKey = cacheKeyFor(vcId, opts);
  const cache = ownProperty<ChainVerifyOptions['cache']>(opts, 'cache');
  if (cache !== undefined) {
    const cached = cache.get(cacheKey, now);
    if (cached !== undefined) {
      return cached;
    }
  }

  const chain: ChainNode[] = [];
  const acc: ChainAccumulator = { overallValid: true, reason: undefined, warnings: [] };
  const { visits, depth } = await traverseChain(vcId, opts, budget);

  /** `chain` に載せた位置（同じ VC へ再到達したときに報告する関係を引き上げるため）。 */
  const chainIndex = new Map<string, number>();

  for (const visit of visits) {
    const node: ChainNode = {
      vcId: visit.vcId,
      relation: visit.relation,
      valid: visit.evaluation.valid,
    };
    // 同じ VC へ複数経路で到達した場合、ノードは 1 度だけ載せる。一方でポリシー適用は経路ごとに
    // 行い、1 本でも伝搬経路があれば失効が伝搬するようにする（保守的側に倒す）。
    if (visit.duplicate) {
      // 到達順の都合で非伝搬の関係（例: `supersedes`）を先に載せていることがある。伝搬経路から
      // 再到達したらそちらを報告に採る。`chain[].relation` から伝搬可否を読む利用側が、
      // `valid: false` なのに非伝搬の関係を見て「伝搬しないはず」と誤読するのを防ぐ
      // （伝搬する経路が一つでもあれば、その経路を報告する）。
      const at = chainIndex.get(visit.vcId);
      const recorded = at === undefined ? undefined : chain[at];
      if (
        at !== undefined &&
        recorded !== undefined &&
        visit.propagating &&
        !propagatesRevocation(recorded.relation)
      ) {
        chain[at] = node;
      }
    } else {
      chainIndex.set(visit.vcId, chain.length);
      chain.push(node);
    }
    applyPolicy(acc, visit, node, opts);
  }

  const result: ChainVerificationResult = {
    vcId,
    valid: acc.overallValid,
    depth,
    chain,
    ...(acc.reason !== undefined ? { reason: acc.reason } : {}),
    ...(acc.warnings.length > 0 ? { warnings: acc.warnings } : {}),
  };
  if (cache !== undefined) {
    cache.set(cacheKey, result, now);
  }
  return result;
}

/**
 * VP 内の各 VC のチェーン関係（4 種の親エッジ）を検証する。
 *
 * VP の `verifiableCredential` を走査し、ID を持つ各 VC について `verifyCredentialChain` を実行して
 * 結果配列を返す。ID を抽出できない要素はスキップする（チェーンを持たない単発 VC 等）。
 * 同一 ID の要素は 1 度だけ検証し、結果を共有する。
 *
 * 走査量の上限（`MAX_CHAIN_*`）は 1 チェーンごとにリセットされるため、要素数 N に比例して N 倍へ増幅しない
 * よう、要素数（`MAX_PRESENTATION_CREDENTIALS`）と VP 全体の合計ノード数・訪問数の予算を全チェーンで
 * 共有する。予算は `opts.workBudget` で渡された共有予算（`verifyPresentation` の内包 VC 検証・
 * type metadata 解決と同じもの）を消費し、省略時は本関数が新しく作る。超過は
 * `4051`（`reason: "chain_too_large"`）。
 *
 * @param vp 検証対象の VP（構造検証済みの `VerifiablePresentation` 相当）。
 * @param opts チェーン検証オプション + `extractVcId`。
 * @returns 各 VC のチェーン検証結果の配列（`verifiableCredential` の順）。
 * @throws 個々のチェーン検証で循環（`4050`）/ 深さ超過・走査量超過（`4051`）/ 解決不能（`4052`）の場合（VericertsError）。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export async function verifyCredentialChainOnPresentation(
  vp: { readonly verifiableCredential: ReadonlyArray<string | Readonly<Record<string, unknown>>> },
  opts: PresentationChainVerifyOptions,
): Promise<ChainVerificationResult[]> {
  // 関数値の DI。継承値だと VP 内の各 VC の ID 抽出が攻撃者の関数へ委譲され、空を返すだけで
  // **VP 内全 VC の失効チェーン検証が無言でスキップ**される。抽出手段が無ければ
  // 検証不能として扱い、成立していない結果を返さない（fail-closed）。
  const extractVcId = nonObjectPrototypeProperty<PresentationChainVerifyOptions['extractVcId']>(
    opts,
    'extractVcId',
  );
  if (typeof extractVcId !== 'function') {
    throw new VericertsError(ErrorCodes.CHAIN_PARENT_UNRESOLVABLE);
  }
  // 件数は走査（ネットワーク往復）を始める前に縛る。
  if (vp.verifiableCredential.length > MAX_PRESENTATION_CREDENTIALS) {
    throw chainTooLarge();
  }
  const budget =
    ownProperty<PresentationWorkBudget>(opts, 'workBudget') ?? newPresentationWorkBudget();
  /** 同一 ID の要素は結果が同一なので 1 度だけ検証する。 */
  const verified = new Map<string, ChainVerificationResult>();
  const results: ChainVerificationResult[] = [];
  for (const entry of vp.verifiableCredential) {
    const vcId = extractVcId(entry);
    if (vcId === undefined) {
      continue;
    }
    let result = verified.get(vcId);
    if (result === undefined) {
      result = await verifyChainWithBudget(vcId, opts, budget);
      verified.set(vcId, result);
    }
    results.push(result);
  }
  return results;
}
