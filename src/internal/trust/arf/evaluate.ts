/**
 * 3 層統合信頼判定ロジック。
 *
 * ETSI Trusted List（Layer 1）> OpenID Federation（Layer 2）> ARF Catalogue（Layer 3）の優先順位で
 * 各層の検証結果は、次の優先順位で単一の `TrustDecision` にまとめる。
 *
 * | 条件                                          | 採用                                                           |
 * | ---------------------------------------------- | --------------------------------------------------------------- |
 * | 上位 Layer に、この判定へ適用される明示的な REVOKED がある | 下位 Layer の状態によらず **拒否**（`rejected`）とする（下位が PASS でも上書きしない。全 Layer に PASS が無くても `UNKNOWN` にはしない） |
 * | 複数 Layer で一致（REVOKED 無し）           | 上位 Layer の判定を採用 (TSL > OIDF > ARF)                      |
 * | 上位で PASS、下位で REVOKED                 | 上位を優先（強い警告ログ + 再検証タスクをキュー）。1 行目と異なり「採用層より上位に REVOKED が無い」ケースのみ該当する |
 * | 上位で該当なし、下位で PASS（REVOKED 無し） | 下位 Layer の判定を採用                                         |
 * | 全 Layer で該当なし（REVOKED も PASS も無し）| UNKNOWN（UI で不明確さを明示しユーザー明示同意のみで許可）      |
 * | オフライン（全外部取得失敗）                 | Cache 内の最終判定を使用（Stale-If-Error、TTL + grace_period）  |
 *
 * 「明示的な REVOKED による拒否」は「上位で該当なし・下位で PASS」より優先する。すなわち、ある Layer
 * が REVOKED なら、それより優先度の低い Layer に PASS があってもなくても `rejected` を返す
 * （T-Hirotaro 氏の方針決定・選択肢B「fail-closed 明示拒否」。旧挙動は下位 PASS を警告付きで採用
 * する防御的デフォルトだったが、2026-09-10 の spec 改訂 2.10 でこの表に明文化された）。
 *
 * ネットワーク I/O・署名検証は各層モジュール（etsi-tsl / federation / arf）の責務で、本関数は
 * 正規化済みの `LayerVerdict` を入力に取る。判定結果のログ記録は呼び出し側（decision-log.ts）が
 * DI シンクへ委譲する。
 */

import { ownProperty } from '../../prototype-safety/own-property.js';
import type {
  EvaluateTrustInput,
  LayerStatus,
  LayerVerdict,
  TrustDecision,
  TrustDecisionCode,
  TrustDecisionWarning,
  TrustLayer,
} from './trust-decision-types.js';

/** 優先度順（先頭が最優先）の層リスト。競合解消の「上位 Layer」判定に使う。 */
const LAYER_PRIORITY: readonly TrustLayer[] = ['tsl', 'oidf', 'arf'];

/** 層 → PASS 時の判定コード。 */
const PASS_CODE: Readonly<Record<TrustLayer, TrustDecisionCode>> = {
  tsl: 'tsl-qualified',
  oidf: 'oidf-federated',
  arf: 'arf-listed',
};

/** Stale-If-Error の既定 grace period（72 時間）。 */
const DEFAULT_GRACE_PERIOD_MS = 72 * 60 * 60 * 1000;

/**
 * 各層の検証結果を優先順位・競合解消ルールに従って統合し、単一の信頼判定を返す。
 *
 * @param input 判定対象・各層の検証結果・任意のキャッシュ状態。
 * @returns 統合信頼判定（採用層・警告・再検証要否を含む）。
 */
export function evaluateTrust(input: EvaluateTrustInput): TrustDecision {
  // 任意オプションは自身のプロパティに限って読む。継承した `nowMs` は
  // Stale-If-Error の経過時間（grace period）判定を攻撃者が選んだ時刻で行わせ、
  // 期限切れのキャッシュ判定を `stale` として採用させる。
  const nowMs = ownProperty<number>(input, 'nowMs') ?? Date.now();
  const statusByLayer = normalizeVerdicts(input.verdicts);
  const warnings: TrustDecisionWarning[] = [];

  const passIndex = LAYER_PRIORITY.findIndex((layer) => statusByLayer.get(layer) === 'pass');
  const revokedIndex = LAYER_PRIORITY.findIndex((layer) => statusByLayer.get(layer) === 'revoked');

  // 明示的な REVOKED による拒否。`revokedIndex` は
  // 優先順位順で最初に見つかった REVOKED 層（＝最上位の REVOKED）。それが最良の PASS より
  // 同順位以上（`passIndex === -1` または `revokedIndex < passIndex`）なら、下位に PASS があって
  // もなくても明示的に拒否する。下位が PASS でも上書きしない。
  if (revokedIndex !== -1 && (passIndex === -1 || revokedIndex < passIndex)) {
    return {
      subjectId: input.subjectId,
      code: 'rejected',
      layer: LAYER_PRIORITY[revokedIndex] as TrustLayer,
      warnings: ['higher-layer-revoked'],
      requiresRevalidation: false,
      decidedAtMs: nowMs,
    };
  }

  if (passIndex !== -1) {
    const winner = LAYER_PRIORITY[passIndex] as TrustLayer;
    // ここに到達する時点で「winner より上位の REVOKED」は無い（上のガードで拒否済み）ため、
    // 残る警告対象は winner より下位の REVOKED のみ。
    const lowerRevoked = hasLowerRevoked(winner, statusByLayer);
    if (lowerRevoked) {
      warnings.push('lower-layer-revoked');
    }
    return {
      subjectId: input.subjectId,
      code: PASS_CODE[winner],
      layer: winner,
      warnings,
      requiresRevalidation: lowerRevoked,
      decidedAtMs: nowMs,
    };
  }

  // どの層も PASS でない（REVOKED も無い）。全層が取得失敗（error）ならオフライン相当で
  // Stale-If-Error を試みる。
  if (allLayersErrored(statusByLayer)) {
    const stale = staleFallback(input, nowMs);
    if (stale !== undefined) {
      return stale;
    }
  }

  // 全 Layer で該当なし（もしくは stale フォールバック不可）→ UNKNOWN。
  warnings.push('unknown-requires-consent');
  return {
    subjectId: input.subjectId,
    code: 'unknown',
    warnings,
    requiresRevalidation: false,
    decidedAtMs: nowMs,
  };
}

/**
 * 入力の `verdicts` を層 → 状態の Map に正規化する。
 *
 * 同一層が複数指定された場合は最初の要素を採用する（決定的挙動）。指定のない層は含めない
 * （`not-found` 相当として扱われる）。
 */
function normalizeVerdicts(verdicts: readonly LayerVerdict[]): Map<TrustLayer, LayerStatus> {
  const map = new Map<TrustLayer, LayerStatus>();
  for (const v of verdicts) {
    if (!map.has(v.layer)) {
      map.set(v.layer, v.status);
    }
  }
  return map;
}

/**
 * 採用層より下位（優先度が低い）層のいずれかが REVOKED かを判定する。
 *
 * 呼び出し元では既に「採用層より上位に REVOKED が無い」ことが確定している（上位に REVOKED が
 * あれば `evaluateTrust` は先に `rejected` を返している）。そのため、ここで検出する REVOKED は
 * 常に採用層より下位のものである。その場合は上位層の結果を保持し、警告の対象とする。
 */
function hasLowerRevoked(winner: TrustLayer, statusByLayer: Map<TrustLayer, LayerStatus>): boolean {
  const winnerRank = LAYER_PRIORITY.indexOf(winner);
  return LAYER_PRIORITY.some(
    (layer, rank) => rank > winnerRank && statusByLayer.get(layer) === 'revoked',
  );
}

/**
 * 全層が取得失敗（error）か、または未指定（＝取得を試みていない）かを判定する。
 *
 * 1 つでも `pass` / `revoked` / `not-found` の確定状態があれば「オフラインで全滅」ではないため false。
 * なお `pass` の有無は呼び出し前に確認済みだが、`revoked` / `not-found` が 1 つでもあれば確定情報が
 * 得られているので Stale フォールバックはしない（fail-closed 側に倒す）。
 */
function allLayersErrored(statusByLayer: Map<TrustLayer, LayerStatus>): boolean {
  return LAYER_PRIORITY.every((layer) => {
    const status = statusByLayer.get(layer);
    return status === undefined || status === 'error';
  });
}

/**
 * Stale-If-Error のフォールバック判定を組み立てる。
 *
 * キャッシュ済みの**最終判定**の種別を保って返す:
 * - PASS 系（`tsl-qualified` 等）で、層が own に載り PASS コードと一致する場合のみ `stale`
 *   （grace period 内に限る）。`stale` には元の判定時刻を `staleSinceMs` として載せ、再キャッシュ
 *   しても grace の起点が延びない（`stale` 自体は PASS 系でないため再入力しても `unknown` に落ちる）。
 * - `rejected`（明示的な REVOKED による拒否）は `rejected` のまま返す。オフラインにするだけで
 *   拒否が `stale`（layer 付きの「信頼されていた」判定）に化けないようにする。
 * - `unknown` / `stale` / 層欠落・不整合の PASS・不明なコードは採用しない（呼び出し側で UNKNOWN 化）。
 * grace period を超過した PASS / キャッシュがない場合は undefined。
 */
function staleFallback(input: EvaluateTrustInput, nowMs: number): TrustDecision | undefined {
  // `cached` / `gracePeriodMs` も自身のプロパティに限って読む。継承値を拾うと、
  // キャッシュを渡していない評価に攻撃者のキャッシュ判定が入り込み、grace period も伸ばされる。
  const cached = ownProperty<EvaluateTrustInput['cached']>(input, 'cached');
  if (cached === undefined) {
    return undefined;
  }
  const gracePeriodMs = ownProperty<number>(input, 'gracePeriodMs') ?? DEFAULT_GRACE_PERIOD_MS;
  // キャッシュ本体のフィールドも自身のプロパティに限って読む。`decidedAtMs` を
  // プロトタイプ鎖で読むと、当該フィールドを**持たない**キャッシュで `ageMs` が `NaN` になり、
  // `NaN < 0` も `NaN > gracePeriodMs` も false のため **72h の grace period 検査が黙って全
  // スキップ**され、任意に古いキャッシュ判定が `stale` として採用される（`replay-window.ts` で
  // 是正したのと同じ NaN 比較の fail-open）。非有限値もここで fail-closed に倒す。
  const decidedAtMs = ownProperty<number>(cached, 'decidedAtMs');
  if (typeof decidedAtMs !== 'number' || !Number.isFinite(decidedAtMs)) {
    return undefined;
  }
  const cachedCode = ownProperty<TrustDecisionCode>(cached, 'code');
  const cachedLayer = ownProperty<TrustLayer>(cached, 'layer');
  if (cachedCode === 'rejected') {
    // 失効は時間経過で薄めない（grace を超えても `unknown` へ緩めない）。
    return {
      subjectId: input.subjectId,
      code: 'rejected',
      ...(cachedLayer !== undefined && LAYER_PRIORITY.includes(cachedLayer)
        ? { layer: cachedLayer }
        : {}),
      warnings: ['higher-layer-revoked'],
      requiresRevalidation: false,
      decidedAtMs: nowMs,
    };
  }
  if (cachedLayer === undefined || !LAYER_PRIORITY.includes(cachedLayer)) {
    return undefined;
  }
  if (cachedCode !== PASS_CODE[cachedLayer]) {
    // `unknown` / `stale` / 層と食い違う PASS / 未知のコードは「信頼されていた」根拠にならない。
    return undefined;
  }
  // `nowMs` / `gracePeriodMs` が非有限（NaN 等）だと `ageMs` 比較が両方 false になり grace 検査が黙って
  // 全スキップされる。非有限は採用せず、比較も肯定形（`!(0 <= age <= grace)`）で書く。
  if (!Number.isFinite(nowMs) || !Number.isFinite(gracePeriodMs)) {
    return undefined;
  }
  const ageMs = nowMs - decidedAtMs;
  if (!(ageMs >= 0 && ageMs <= gracePeriodMs)) {
    // 未来時刻のキャッシュ（時計不整合）や grace period 超過は信頼しない（fail-closed）。
    return undefined;
  }
  return {
    subjectId: input.subjectId,
    code: 'stale',
    layer: cachedLayer,
    warnings: ['stale-fallback'],
    requiresRevalidation: true,
    decidedAtMs: nowMs,
    staleSinceMs: decidedAtMs,
  };
}
