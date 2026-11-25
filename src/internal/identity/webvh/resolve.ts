/**
 * did:webvh の解決。DID Log を取得して検証し、解決オプションに従う版の DID Document と
 * 解決メタデータ（DID Document Metadata）を返す。
 *
 * spec: DIF didwebvh v1.0「Read (Resolve)」。
 * - 解決オプション: `versionId`（完全一致）・`versionTime`（その時刻に有効だった版）・`versionNumber`（版番号）。
 *   該当する版が無ければ拒否する（仕様の `notFound`。SDK は `INVALID_DID`）。複数同時の指定は拒否する。
 * - 解決メタデータ: `versionId` / `versionTime`（解決した版）、`created` / `updated`、`scid`、`portable`、`deactivated`、
 *   `ttl`（文字列）、`witness`（`threshold` は文字列）、`watchers`。`updated` 以降は最後の有効な版（＝最終エントリ）の値。
 * - witness: 承認を要する版があるログは、隣の `did-witness.json` を取得し、閾値以上の witness に承認されていなければ拒否する
 *   （`./witness/verify.ts`）。
 * - 失効（`parameters.deactivated: true`）した版の DID Document は返さない。過去の版を指定して解決した場合は
 *   メタデータの `deactivated` が `true` になる（DID の最新状態）。
 *
 * 例外メッセージ・`context` に DID 文字列・URL・Log 本文・鍵バイトを含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import type { DIDDocument } from '../did.js';
import { assertNetworkDidDocumentShape } from '../did-document-read.js';
import {
  assertResolutionWorkRemaining,
  type ResolutionWorkBudget,
  WORK_UNITS_PER_SIGNATURE,
} from '../resolution-budget.js';
import { type AttemptWork, trackAttempt } from '../resolution-charge.js';
import {
  DID_WITNESS_MEDIA_TYPES,
  fetchDidLog,
  parseDidLog,
  parseWebVh,
  webVhLogUrl,
  webVhWitnessUrl,
} from './codec.js';
import { parseVersionTime } from './lifecycle/version-time.js';
import type { ActiveParameters } from './parameters.js';
import { type VerifiedLog, verifyChain } from './verify.js';
import { parseWitnessFile } from './witness/file.js';
import { verifyWitnessApprovals } from './witness/verify.js';

/** did:webvh の DID 解決オプション。`versionId` / `versionTime` / `versionNumber` はいずれか 1 つ。未指定で最新版を返す。 */
export interface WebVhResolveOptions {
  /** 版の識別子（`<n>-<entryHash>`）。ログのエントリと完全に一致する版を返す。 */
  readonly versionId?: string;
  /** ISO 8601（UTC）の時刻。その時刻に有効だった版（`versionTime` がその時刻以前の最新の版）を返す。 */
  readonly versionTime?: string;
  /** 版番号（1 始まりの整数）。`versionId` の `-` の前の数と一致する版を返す。 */
  readonly versionNumber?: number;
  /**
   * DID Log 取得に使う `fetch` 実装。未指定ならグローバル `fetch`。
   *
   * ホストアプリが証明書ピン留め済み（あるいはプロキシ済み）の `fetch` を注入するための seam で
   * あり、did:web の `ResolveDidWebDeps.fetchFn` と同形である。ここを配線しないと did:web は
   * ピン留めできるのに did:webvh だけがグローバル `fetch` へ素通りする。
   */
  readonly fetchFn?: typeof fetch;
}

/** 解決の途中で呼ばれる内部フック（公開 API ではない。バレル非公開）。拡張の in-flight 予算が witness 用の取得ぶんを確保するための仕組み。 */
export interface WebVhResolveHooks {
  /**
   * `did-witness.json` を取得する**直前**に呼ぶ（DID Log の検証を終え、承認を要する版があると分かったときだけ。
   * witness を使わない解決では呼ばない）。投げた例外は握りつぶさず、そのまま解決の失敗として伝わり、取得は始まらない。
   * 投げた試行が解決スコープ（`ResolutionWorkBudget`）に消費した量は**差し戻さず**、`ledger` に控えて残す（取り直しの試行は
   * その分を控除枠にして自分の消費を相殺し、1 つの解決の計上は `max(1 回目, 2 回目)`。`trackAttempt`）。
   * 同期で待たずに返すこと（待つと、予約を抱えたまま互いに待つデッドロックの元になる）。
   */
  readonly beforeWitnessFile?: () => void;
  /** 取り直しをまたいで、前の試行の課金を引き継ぐ控え（{@link WebVhAttemptLedger} の不変条件を守って渡す）。 */
  readonly ledger: WebVhAttemptLedger;
}

/**
 * 取り直しをまたいで引き継ぐ、前の試行が解決スコープへ課金した仕事量・本文量（内部用）。
 *
 * **不変条件: 1 つの解決（1 回の `resolve()`。取り直しの 1 回目と 2 回目を含む）につき 1 つ作り、その 2 つの試行だけが
 * 使う。別の解決や別の DID と共有しない**（共有すると、他の解決の控除枠を取り違えて、課金が `max(1 回目, 2 回目)` から
 * ずれる）。この不変条件は呼び出し側が守る。
 */
export type WebVhAttemptLedger = AttemptWork;

/** 空の控え（前の試行なし）。 */
export function createWebVhAttemptLedger(): WebVhAttemptLedger {
  return { units: 0, body: 0 };
}

/** 解決メタデータの `witness`（`threshold` は文字列。DID Resolution が整数を禁じるため。`{}` は witness なし）。 */
export interface WebVhWitnessMetadata {
  readonly threshold?: string;
  readonly witnesses?: readonly { readonly id: string }[];
}

/** did:webvh の解決メタデータ（DID Document Metadata）。 */
export interface WebVhDidMetadata {
  /** 解決した版の `versionId`。 */
  readonly versionId: string;
  /** 解決した版の `versionTime`。 */
  readonly versionTime: string;
  /** 初版の `versionTime`。 */
  readonly created: string;
  /** 最後の有効な版の `versionTime`。 */
  readonly updated: string;
  readonly scid: string;
  readonly portable: boolean;
  /** DID が失効しているか（過去の版を指定して解決したときも DID の最新状態）。 */
  readonly deactivated: boolean;
  /** キャッシュ秒数（文字列）。 */
  readonly ttl: string;
  readonly witness: WebVhWitnessMetadata;
  readonly watchers: readonly string[];
}

/** {@link resolveDidWebVhWithMetadata} の結果。 */
export interface WebVhResolution {
  readonly document: DIDDocument;
  readonly metadata: WebVhDidMetadata;
}

function invalid(): VericertsError {
  return new VericertsError(ErrorCodes.INVALID_DID);
}

/**
 * 解決オプションに該当する版の添字を選ぶ（オプションは own 限定で読む。汚染で「最新版の解決」が攻撃者指定の版ピンに化けるのを
 * 防ぐ）。
 */
function selectIndex(log: VerifiedLog, options: WebVhResolveOptions | undefined): number {
  const { entries } = log;
  const versionId = options ? ownProperty<string>(options, 'versionId') : undefined;
  const versionTime = options ? ownProperty<string>(options, 'versionTime') : undefined;
  const versionNumber = options ? ownProperty<number>(options, 'versionNumber') : undefined;
  const given = [versionId, versionTime, versionNumber].filter((value) => value !== undefined);
  if (given.length > 1) {
    throw invalid();
  }
  let index = entries.length - 1;
  if (versionId !== undefined) {
    index = entries.findIndex((entry) => entry.versionId === versionId);
  } else if (versionNumber !== undefined) {
    index =
      Number.isSafeInteger(versionNumber) && versionNumber >= 1 && versionNumber <= entries.length
        ? versionNumber - 1
        : -1;
  } else if (versionTime !== undefined) {
    const at = parseVersionTime(versionTime);
    index = entries.findLastIndex((entry) => parseVersionTime(entry.versionTime) <= at);
  }
  if (index < 0) {
    throw invalid();
  }
  return index;
}

/** 解決メタデータを組み立てる。 */
function buildMetadata(log: VerifiedLog, index: number): WebVhDidMetadata {
  const entry = log.entries[index] as VerifiedLog['entries'][number];
  const last = log.parameters[log.parameters.length - 1] as ActiveParameters;
  const { witness } = last;
  return {
    versionId: entry.versionId,
    versionTime: entry.versionTime,
    created: (log.entries[0] as VerifiedLog['entries'][number]).versionTime,
    updated: (log.entries[log.entries.length - 1] as VerifiedLog['entries'][number]).versionTime,
    scid: last.scid,
    portable: last.portable,
    deactivated: last.deactivated,
    ttl: String(last.ttl),
    witness:
      witness === undefined
        ? {}
        : {
            threshold: String(witness.threshold),
            witnesses: witness.witnesses.map((id) => ({ id })),
          },
    watchers: last.watchers,
  };
}

/**
 * did:webvh 文字列を DID Log の検証付きで解決し、DID Document と解決メタデータを返す。
 *
 * 失効（`deactivated`）した版の DID Document は返さない（最新版が失効している DID は拒否される）。失効前の版を
 * `versionId` などで指定した場合は、その版の state を返す（履歴上の特定時点の DID Document を取得する用途）。
 * 解決した DID Document の `id` は、解決対象の DID と一致しなければならない（portable な移動の前後で別の DID の
 * Document を返さない）。
 *
 * エラーコード粒度の方針: DID 文字列形式不正・チェーン検証失敗・
 * deactivated は `INVALID_DID`（code `2001`）にマップする。取得失敗（network / タイムアウト /
 * 4xx・5xx・非 HTTPS リダイレクト）は `fetchDidLog` 内で `DID_NOT_FOUND`（code `2003`、再試行可）
 * に分離する（「取得＝resolution 失敗」と「検証失敗」を区別）。
 *
 * @param did did:webvh 文字列。
 * @param options 解決オプション（versionId / versionTime / versionNumber / fetchFn）。
 * @param scope 解決スコープ全体の仕事量予算（署名検証・鍵ハッシュを計上する。省略時は計上しない）。
 * @returns 対象版の DID Document と解決メタデータ。
 * @throws 形式不正・チェーン検証失敗・deactivated・該当する版なしの場合（code `2001`）、取得失敗の場合（code `2003`）、
 *         state の verificationMethod / relationship / service が配列でない場合（code `2010`）。
 */
export async function resolveDidWebVhWithMetadata(
  did: string,
  options?: WebVhResolveOptions,
  scope?: ResolutionWorkBudget,
): Promise<WebVhResolution> {
  return resolveWithHooks(did, options, scope, undefined);
}

/**
 * {@link resolveDidWebVhWithMetadata} に内部フックを渡して解決し、DID Document を返す（拡張の in-flight 予算用。バレル非公開）。
 *
 * @param did did:webvh 文字列。
 * @param scope 解決スコープ全体の仕事量予算。
 * @param hooks 内部フック。
 * @returns 最新版の DID Document。
 * @throws {@link resolveDidWebVhWithMetadata} と同じ、およびフックが投げた例外。
 */
export async function resolveDidWebVhHooked(
  did: string,
  scope: ResolutionWorkBudget | undefined,
  hooks: WebVhResolveHooks,
): Promise<DIDDocument> {
  return (await resolveWithHooks(did, undefined, scope, hooks)).document;
}

async function resolveWithHooks(
  did: string,
  options: WebVhResolveOptions | undefined,
  callerScope: ResolutionWorkBudget | undefined,
  hooks: WebVhResolveHooks | undefined,
): Promise<WebVhResolution> {
  const parsed = parseWebVh(did);
  // 取り直しでは 1 回目の課金を残し、2 回目はその分を控除枠にして自分の消費を相殺する（`trackAttempt`。計上は max(1 回目, 2 回目)）。
  const ledger = hooks?.ledger;
  const prior = { units: ledger?.units ?? 0, body: ledger?.body ?? 0 };
  if (ledger) {
    ledger.units = 0;
    ledger.body = 0;
  }
  const attempt =
    hooks !== undefined && callerScope !== undefined ? trackAttempt(callerScope, prior) : undefined;
  const scope = attempt?.view ?? callerScope;
  // 予算が尽きたスコープでは、最大 1 MiB の DID Log 取得（外部 I/O）自体を始めない。本文量が尽きた場合も同じ。
  assertResolutionWorkRemaining(scope, WORK_UNITS_PER_SIGNATURE);
  const text = await fetchDidLog(
    webVhLogUrl(parsed),
    options ? nonObjectPrototypeProperty<typeof fetch>(options, 'fetchFn') : undefined,
    scope,
  );
  const log = verifyChain(parseDidLog(text), did, parsed.scid, scope);
  // witness は、非 witness の検証（entryHash・署名）を全て終えてから検証する（witness 検証はその代わりにならない）。
  // 承認を要する版が 1 つでもあれば `did-witness.json` を取得する（取得できなければ解決は失敗する）。
  if (log.witnessRequired.some((required) => required !== undefined)) {
    assertResolutionWorkRemaining(scope, WORK_UNITS_PER_SIGNATURE);
    try {
      hooks?.beforeWitnessFile?.();
    } catch (error) {
      if (ledger !== undefined && attempt !== undefined) {
        const used = attempt.consumed();
        ledger.units = Math.max(prior.units, used.units);
        ledger.body = Math.max(prior.body, used.body);
      }
      throw error;
    }
    const witnessText = await fetchDidLog(
      webVhWitnessUrl(parsed),
      options ? nonObjectPrototypeProperty<typeof fetch>(options, 'fetchFn') : undefined,
      scope,
      DID_WITNESS_MEDIA_TYPES,
    );
    verifyWitnessApprovals(log, parseWitnessFile(witnessText), scope);
  }
  const index = selectIndex(log, options);
  const target = log.entries[index] as VerifiedLog['entries'][number];
  if ((log.parameters[index] as ActiveParameters).deactivated) {
    throw invalid();
  }
  if (ownProperty<unknown>(target.state, 'id') !== did) {
    throw invalid();
  }
  assertNetworkDidDocumentShape(target.state);
  return { document: target.state, metadata: buildMetadata(log, index) };
}

/**
 * did:webvh 文字列を DID Log の検証付きで解決し、DID Document を返す。
 * 解決メタデータが要る場合は {@link resolveDidWebVhWithMetadata} を使う。
 *
 * @param did did:webvh 文字列。
 * @param options 解決オプション（versionId / versionTime / versionNumber / fetchFn）。
 * @param scope 解決スコープ全体の仕事量予算。
 * @returns 対象版の DID Document。
 * @throws {@link resolveDidWebVhWithMetadata} と同じ。
 */
export async function resolveDidWebVh(
  did: string,
  options?: WebVhResolveOptions,
  scope?: ResolutionWorkBudget,
): Promise<DIDDocument> {
  return (await resolveDidWebVhWithMetadata(did, options, scope)).document;
}
