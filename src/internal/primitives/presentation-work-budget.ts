/**
 * VP 1 通の検証が消費してよい仕事量の共有予算（chain 予算を拡張）。
 *
 * 個別の入力サイズ上限は、同種の別経路を迂回口にしてきた。
 * 高コストな操作（署名検証・チェーン解決・信頼リスト走査・Type Metadata 取得）の**総回数 / 総量**を
 * 1 つの {@link PresentationWorkBudget} に数え、`verifyPresentation` が作った 1 つを内包 VC の検証・issuer 信頼評価・
 * chain 検証・type metadata 解決へ通して消費させる。要素数 N や 1 要素のサイズでなく仕事量そのものを縛る
 * ので、少数の巨大要素でも多数の極小要素でも同じ天井に当たる。
 *
 * 超過は fail-closed（例外）。例外種別は消費した種別で決まり、既存のコードを使う:
 * - chain（`chainNodes` / `chainVisits`）: `CHAIN_TOO_DEEP`（4051、`reason: 'chain_too_large'`）。
 * - Type Metadata（`metadataDocuments` / `metadataBytes`）: `TYPE_METADATA_INVALID`（3061、`reason: 'metadata_too_large'`）。
 * - それ以外: `VC_SCHEMA_INVALID`（3002、`reason: 'work_budget_exceeded'`）。
 * 例外の context に VC 本文・親 ID・URL は含めない。
 */

import { ErrorCodes, VericertsError } from '../errors.js';

/** VP の `verifiableCredential` 要素数の上限。超過は署名検証にも chain 走査にも入る前に拒否する。 */
export const MAX_PRESENTATION_CREDENTIALS = 64;

/** 1 つの VC の `type`（重複排除後）として照合する種別の最大数。超過は「種別を取り出せない」として扱う。 */
export const MAX_CREDENTIAL_TYPES = 64;

/** 消費の種別。 */
export type WorkKind =
  | 'signatures'
  | 'trustScans'
  | 'chainNodes'
  | 'chainVisits'
  | 'metadataDocuments'
  | 'metadataBytes';

/** 残予算。各値は残り単位数で、0 以下になった種別の消費は拒否される。 */
export interface PresentationWorkBudget {
  /** 発行者署名・KB-JWT などの署名検証の残り回数。 */
  signatures: number;
  /** 信頼リスト照合で走査する発行者エントリの残り件数。 */
  trustScans: number;
  /** チェーン走査で解決・評価する相異なる VC の残り件数。 */
  chainNodes: number;
  /** チェーン走査で積む訪問（経路）の残り延べ件数。 */
  chainVisits: number;
  /** ネットワークから取得する Type Metadata / スキーマ文書の残り件数。 */
  metadataDocuments: number;
  /** ネットワークから取得する Type Metadata / スキーマ文書の残りバイト数。 */
  metadataBytes: number;
  /** 種別を問わない合計の残り（バイトを除く全消費で 1 単位ずつ減る）。 */
  total: number;
}

/** VP 1 通あたりの上限。正規の VP は数十単位で済むので、いずれも十分な余裕を持たせた固定値。 */
export const PRESENTATION_WORK_LIMITS: Readonly<PresentationWorkBudget> = Object.freeze({
  signatures: 2 * MAX_PRESENTATION_CREDENTIALS,
  trustScans: 8192,
  chainNodes: 512,
  chainVisits: 4096,
  metadataDocuments: 32,
  metadataBytes: 2 * 1024 * 1024,
  total: 16384,
});

/** 新しい共有予算を作る（VP 1 通 / Type Metadata 解決 1 回ごとに 1 つ）。 */
export function newPresentationWorkBudget(): PresentationWorkBudget {
  return { ...PRESENTATION_WORK_LIMITS };
}

/** 種別ごとの超過エラーを組み立てる（context は静的な分類文字列のみ）。 */
export function workBudgetExceeded(kind: WorkKind): VericertsError {
  switch (kind) {
    case 'chainNodes':
    case 'chainVisits':
      return new VericertsError(ErrorCodes.CHAIN_TOO_DEEP, {
        context: { reason: 'chain_too_large' },
      });
    case 'metadataDocuments':
    case 'metadataBytes':
      return new VericertsError(ErrorCodes.TYPE_METADATA_INVALID, {
        context: { reason: 'metadata_too_large' },
      });
    default:
      return new VericertsError(ErrorCodes.VC_SCHEMA_INVALID, {
        context: { reason: 'work_budget_exceeded' },
      });
  }
}

/** chain 走査量の超過（`MAX_CHAIN_*` の個別上限と共通のエラー）。 */
export const chainTooLarge = (): VericertsError => workBudgetExceeded('chainNodes');

/**
 * 共有予算から `units` 単位を消費する。種別の残りか合計が足りなければ種別に応じた例外を投げる。
 * 予算なし（単独実行）では何もしない。
 *
 * 失敗した消費は予算を減らさない（超過後も残りの検査が同じ結果になる）。
 */
export function spendWork(
  budget: PresentationWorkBudget | undefined,
  kind: WorkKind,
  units = 1,
): void {
  if (budget === undefined) {
    return;
  }
  if (budget[kind] < units || (kind !== 'metadataBytes' && budget.total < units)) {
    throw workBudgetExceeded(kind);
  }
  budget[kind] -= units;
  if (kind !== 'metadataBytes') {
    budget.total -= units;
  }
}

/** `kind` の残り単位数（予算なしは無制限）。取得前の打ち切り幅の算出に使う。 */
export function remainingWork(budget: PresentationWorkBudget | undefined, kind: WorkKind): number {
  return budget === undefined ? Number.POSITIVE_INFINITY : Math.max(0, budget[kind]);
}

/**
 * VP の内包 VC 数が上限内であることを確かめる。超過は `VC_SCHEMA_INVALID`（3002）。
 *
 * 重複を含む延べ数で数える。重複の検証結果は共有するが、結果配列・ID 抽出・鍵解決は要素数に比例するため。
 */
export function assertCredentialCount(count: number): void {
  if (count > MAX_PRESENTATION_CREDENTIALS) {
    throw workBudgetExceeded('signatures');
  }
}
