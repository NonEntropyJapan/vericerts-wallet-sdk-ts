/**
 * Credential Chain の型定義。検証では既定で親エッジを最大 10 段まで辿り、キャッシュ利用時の既定 TTL は 5 分。
 */

import type { PresentationWorkBudget } from '../../primitives/presentation-work-budget.js';
import type { StatusCheckResult } from '../sdjwt/status.js';
import type { VerifiableCredential } from '../vc/vc.js';
import type { ChainVerificationCache } from './cache.js';

/** チェーン検証で辿る親エッジの最大深さの既定値（10）。 */
export const DEFAULT_MAX_CHAIN_DEPTH = 10;

/** チェーン検証結果のキャッシュ TTL（5 分、ミリ秒単位）。 */
export const CHAIN_CACHE_TTL_MS = 5 * 60 * 1000;

/**
 * チェーン関係の種別。
 *
 * - `derivedFrom`: 親 VC を根拠として派生（失効伝搬対象）
 * - `basedOn`: 参考に過ぎない（失効伝搬しない）
 * - `supersedes`: 親 VC の置換。親は論理的に廃止済み（失効伝搬しない）
 * - `amends`: 親 VC の部分訂正。親は有効なまま（失効伝搬対象）
 */
export type ChainRelation = 'derivedFrom' | 'basedOn' | 'supersedes' | 'amends';

/** 子 VC の `revocationPropagation` または検証時の `ChainVerifyOptions.policy` で指定する失効伝搬ポリシー。 */
export type ChainPolicy = 'strict' | 'permissive' | 'custom';

/** 派生 VC を構築するための入力（親エッジを除く VC 本体のフィールド）。 */
export type DerivedCredentialInput = Omit<
  VerifiableCredential,
  'derivedFrom' | 'basedOn' | 'supersedes' | 'amends'
>;

/**
 * `verifyCredentialChain` の依存注入（VC 解決・署名検証・失効評価を外出しする）。
 */
export interface ChainVerifyDependencies {
  /**
   * VC ID から VC 本体を解決する（ストア / ネットワーク）。
   *
   * 起点 VC・親 VC の両方に使う。解決不能な場合は `undefined` を返す。起点 VC が解決不能なら
   * `CHAIN_PARENT_UNRESOLVABLE`（4052）、親 VC が解決不能でも同コードで扱う。
   */
  readonly resolveCredential: (vcId: string) => Promise<VerifiableCredential | undefined>;
  /**
   * チェーン内の 1 リンク（VC）の署名・時刻・envelope を検証する。
   *
   * 有効なら `true`、無効（署名不一致 / 期限切れ等）なら `false` を返す。署名検証鍵は発行者ごとに
   * 異なるため、VC から発行者鍵を解決するのは呼び出し側の責務。例外は投げず boolean を返す
   * （リンク単位の valid を `ChainVerificationResult.chain[].valid` に反映するため）。
   */
  readonly verifyLink: (vc: VerifiableCredential) => Promise<boolean> | boolean;
  /**
   * チェーン内の 1 リンク（VC）の失効状態を評価する。
   *
   * `credentialStatus` が無い VC には呼ばれない。評価結果（`valid` / `purpose` / `value`）を返す。
   * `undefined` を返すと「失効情報なし（有効扱い）」とする。
   */
  readonly resolveStatus: (vc: VerifiableCredential) => Promise<StatusCheckResult | undefined>;
}

/** チェーン内の 1 ノードの検証結果。 */
export interface ChainNode {
  /** VC の ID。 */
  readonly vcId: string;
  /** このノードへ辿った親エッジの種別（起点ノードは `derivedFrom` を既定とする）。 */
  readonly relation: ChainRelation;
  /** このノード単体が有効か（署名 OK ∧ 失効/停止していない）。 */
  readonly valid: boolean;
}

/**
 * `verifyCredentialChain` の結果。
 *
 * `chain` と `depth` は `valid: false` の場合にも診断に使える。失効伝搬ポリシーによる無効理由は
 * `reason` で返す。`permissive` では祖先の失効を `warnings` に記録して検証を続ける。
 * 構造エラー（4050 / 4051 / 4052）は例外になる。
 */
export interface ChainVerificationResult {
  /** 検証起点の VC ID。 */
  readonly vcId: string;
  /** チェーンが全体として有効か（ポリシーに基づく失効伝搬を適用した最終判定）。 */
  readonly valid: boolean;
  /** 辿った親エッジの段数（起点=0、親 1 つで 1）。 */
  readonly depth: number;
  /** 葉（起点）→ 根の順のノード列。 */
  readonly chain: readonly ChainNode[];
  /** 無効理由の静的分類（`valid=false` のときのみ設定。VC 本文は含めない）。 */
  readonly reason?: string;
  /** 警告（`permissive` ポリシーで親が失効している等、無効化はしないが注意喚起）。 */
  readonly warnings?: readonly string[];
}

/** `verifyCredentialChain` の検証条件、依存関数、キャッシュのオプション。 */
export interface ChainVerifyOptions extends ChainVerifyDependencies {
  /** 辿る親エッジの最大深さ（既定 10）。 */
  readonly maxDepth?: number;
  /**
   * 失効伝搬ポリシー（既定は各 VC の `revocationPropagation`、未設定なら `strict`）。
   * `custom` の場合は `customHandler` で親→子の伝搬可否を判定する。
   */
  readonly policy?: ChainPolicy;
  /**
   * `custom` ポリシー時の伝搬判定ハンドラ。
   * 親ノードの検証結果と子 VC を受け取り、子を有効として扱ってよいなら `true` を返す。
   */
  readonly customHandler?: (parent: ChainNode, child: VerifiableCredential) => boolean;
  /**
   * チェーン検証結果キャッシュ（任意）。有効なキャッシュエントリ（既定 TTL は 5 分）の検証結果を再利用する。
   * 親 VC 失効時のバスト無効化は `ChainVerificationCache.invalidateChain` で行う。
   */
  readonly cache?: ChainVerificationCache;
  /** キャッシュ判定に使う現在時刻（エポックミリ秒、テスト注入用）。既定 `Date.now()`。 */
  readonly now?: number;
}

/** `verifyCredentialChainOnPresentation` のオプション（チェーン検証オプション + VP からの VC ID 抽出）。 */
export interface PresentationChainVerifyOptions extends ChainVerifyOptions {
  /**
   * VP の `verifiableCredential` 要素（JWT-VC 文字列 / JSON-LD VC object）から VC の ID を抽出する。
   *
   * JWT-VC のデコードや JSON-LD の `id` 読取りは呼び出し側（Verifier facade）の責務のため DI する。
   * ID を持たない VC（チェーン検証対象外）は `undefined` を返すと結果からスキップする。
   */
  readonly extractVcId: (entry: string | Readonly<Record<string, unknown>>) => string | undefined;
  /**
   * VP 全体で共有する仕事量の残予算（`verifyPresentation` に渡したものと同じ `PresentationWorkBudget`）。
   * 省略時は本呼び出し専用の予算を新しく作る。渡した予算は本呼び出しが消費する。
   */
  readonly workBudget?: PresentationWorkBudget;
}
