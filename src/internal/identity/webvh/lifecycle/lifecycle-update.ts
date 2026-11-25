/**
 * did:webvh の次版（更新・失効）DID Log エントリ生成。生成は `./lifecycle.ts`。
 *
 * 更新・失効は新しい行を JSONL に append する運用であり、`DIDMethod` の `update` / `deactivate` では表現できないため
 * 専用 API として提供する。proof は updateKeys を持つ呼び出し側が後段で付与する。
 *
 * 例外メッセージ・`context` に DID 文字列・URL・Log 本文・鍵バイトを含めない。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { assertNoSpecialCategoryOnChain } from '../../../special-category.js';
import type { DIDDocument } from '../../did.js';
import { normalizeLogInput } from '../../normalized-log-input.js';
import {
  deriveVersionId,
  updateKeyHash,
  versionNumberOf,
  type WebVhLogEntry,
  type WebVhWitnessParameter,
} from '../codec.js';
import {
  type ActiveParameters,
  activeParametersOf,
  applyParameters,
  parseTtl,
  parseWatchers,
  readParameterDelta,
} from '../parameters.js';
import { assertPortableMove, locationOfStateId } from '../state-id.js';
import { parseWitnessParameter, witnessParameterOf } from '../witness/config.js';
import { assertLogAppendWithinLimits } from './append-limits.js';
import { assertNextKeyHashes, assertUpdateKeys } from './update-keys.js';
import { resolveAppendVersionTime } from './version-time.js';

/** did:webvh の次版 DID Log エントリ生成オプション。 */
export interface WebVhUpdateOptions {
  /** 直前の Log エントリ全件（行順）。少なくとも初版を含む。 */
  readonly previousLog: readonly WebVhLogEntry[];
  /**
   * 新しい state。`id` は前版と同じ SCID の `did:webvh` で、前版と同じ DID（portable な DID だけが host / path を変えて
   * 移動できる。その場合 `alsoKnownAs` に前版の DID を含める）。失効は `deactivated` オプションで行う
   * （`state.deactivated` ではない）。
   */
  readonly state: DIDDocument;
  /**
   * この版以降の updateKeys（未指定なら前版を継続。事前コミット中は明示が必須）。空配列は `deactivated: true` のときだけ許す。
   */
  readonly updateKeys?: readonly string[];
  /**
   * 次版の更新鍵ハッシュ（事前コミット）。`updateKeyHash` で計算する。`[]` で事前コミットを解除する。
   * 事前コミット中（前版の `nextKeyHashes` が非空）は明示が必須。
   */
  readonly nextKeyHashes?: readonly string[];
  /** versionTime（UTC の ISO 8601。`Z` / `+00:00`。UTC 以外は 2001）。未指定なら呼び出し時刻。 */
  readonly versionTime?: string;
  /** `true` で失効行にする（`parameters.deactivated`）。以降の版は追記できない。 */
  readonly deactivated?: boolean;
  /** witness の構成の更新（`{}` で witness を使わない）。新しい構成は、この版が公開された**後**の版から有効になる。 */
  readonly witness?: WebVhWitnessParameter;
  /** watcher の URL の更新（`[]` で解除）。 */
  readonly watchers?: readonly string[];
  /** キャッシュ秒数の更新（0〜2^31）。 */
  readonly ttl?: number;
  /** `false` で移動を恒久的に禁じる。`true` は初版でだけ設定できるため、更新では拒否される。 */
  readonly portable?: boolean;
}

/** 更新オプションの任意パラメータから、次版の `parameters`（JSON）を作る。 */
function buildParameters(
  options: WebVhUpdateOptions,
  previousActive: ActiveParameters,
): Record<string, unknown> {
  const requestedUpdateKeys = ownProperty<readonly string[]>(options, 'updateKeys');
  const nextKeyHashes = ownProperty<readonly string[]>(options, 'nextKeyHashes');
  const witness = ownProperty<WebVhWitnessParameter>(options, 'witness');
  const watchers = ownProperty<readonly string[]>(options, 'watchers');
  const ttl = ownProperty<number>(options, 'ttl');
  const portable = ownProperty<boolean>(options, 'portable');
  const deactivated = ownProperty<boolean>(options, 'deactivated');
  const clearsUpdateKeys =
    deactivated === true && Array.isArray(requestedUpdateKeys) && requestedUpdateKeys.length === 0;
  return {
    // 未指定なら前版の鍵を継続する（事前コミット中は検証側が継承を拒否するため、`applyParameters` に任せて省略のまま通す）。
    ...(requestedUpdateKeys !== undefined
      ? { updateKeys: clearsUpdateKeys ? [] : assertUpdateKeys(requestedUpdateKeys) }
      : previousActive.nextKeyHashes.length === 0
        ? { updateKeys: [...previousActive.updateKeys] }
        : {}),
    ...(nextKeyHashes !== undefined ? { nextKeyHashes: assertNextKeyHashes(nextKeyHashes) } : {}),
    ...(witness !== undefined
      ? { witness: witnessParameterOf(parseWitnessParameter(witness)) }
      : {}),
    ...(watchers !== undefined ? { watchers: parseWatchers(watchers) } : {}),
    ...(ttl !== undefined ? { ttl: parseTtl(ttl) } : {}),
    ...(portable !== undefined ? { portable } : {}),
    ...(deactivated !== undefined ? { deactivated } : {}),
  };
}

/**
 * 次版 DID Log エントリ（proof 前の正規形）を生成する。前版 versionId を含む
 * ハッシュチェーンで versionId を計算する。`deactivated: true` で失効行になる。
 *
 * 検証側（`verifyChain`）と同じ規則で `parameters` と `state.id` を検査し、解決不能になるログを署名前に拒否する
 * （`updateKeys` が空配列・Ed25519 Multikey でない、事前コミット中の `updateKeys` / `nextKeyHashes` の省略や、事前コミットに
 * 含まれない鍵、portable でない DID の移動、など）。
 *
 * @param options 更新オプション。
 * @returns 次版 Log エントリ（proof なし）。
 * @throws previousLog 空・state.id 不正（SCID 違い・移動の条件不足）・updateKeys 不正・nextKeyHashes 不正・
 *         witness / watchers / ttl / portable が仕様の値域に合わない・事前コミット違反・前版が失効行・
 *         versionTime が不正（ISO 8601 でない・UTC（`Z` / `+00:00`）以外・前版以下・現在 +5 分超）の場合（VericertsError、code `2001`）、
 *         `state` が GDPR Art.9 特別カテゴリ属性を含む場合（code `10601`）。
 *         内訳が必要な場合は `findSpecialCategoryAttributes(state)` を使う。
 */
export function updateDidWebVh(options: WebVhUpdateOptions): WebVhLogEntry {
  // `previousLog` も自身のプロパティに限って読む。他の全フィールドと同じく
  // own 限定にしないと、`Object.prototype.previousLog` が汚染された環境では previousLog を
  // 省略した（あるいは空配列を渡した）呼び出しが攻撃者の用意した偽の Log 配列を「前版」として
  // 受理してしまう。previousLog はハッシュチェーンの起点そのものなので、他フィールドと違い
  // 「継承値を拾う」ではなく「起点が汚染される」＝チェーン全体の正当性の前提が崩れる。
  const previousLog = ownProperty<readonly WebVhLogEntry[]>(options, 'previousLog');
  if (!Array.isArray(previousLog) || previousLog.length === 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const previous = previousLog[previousLog.length - 1];
  if (previous === undefined) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  // `state` は型上必須だが、省略された JS 呼び出しで継承値が署名済み Log へ入るのを防ぐため
  // own 限定で読む。読み取りは **1 度きり**にして正規化スナップショットへ畳む
  // `ownProperty` は own アクセサを読むたびに再評価するため、継続性ガードと
  // Log entry で 2 度読むと「1 回目は前版と同じ id・2 回目は別 id / 別鍵」を返す `get state()` が
  // ガードを素通りし、すり替え済み state がハッシュ連鎖された Log に載る。スナップショットは
  // `state` 自身の `get id()` による同じすり替えも同時に塞ぐ。写しは own の**全**キーを元の
  // 列挙可能性のまま畳むので、Art.9 走査（own 全域）から見える範囲も `canonicalize`（own かつ
  // 列挙可能）から見える範囲も元の `state` と一致し、挙動は変わらない。
  const state = normalizeLogInput<DIDDocument>(ownProperty<DIDDocument>(options, 'state'));
  // 前版までの有効なパラメータ（署名は検証しない）。失効済みの Log への追記はここで拒否される。
  const previousActive = activeParametersOf(previousLog);
  const previousState = ownProperty<DIDDocument>(previous, 'state');
  // `id` は両辺とも own 限定で読む。`previousLog` は呼び出し側が渡す値で、`id` を省略した state / 前版が
  // 汚染値を拾って同一 DID とみなされない。SCID は全版で同じ（portable でも変えられない）。
  const stateId = ownProperty<unknown>(state, 'id');
  const previousStateId =
    previousState === undefined ? undefined : ownProperty<unknown>(previousState, 'id');
  if (typeof stateId !== 'string' || typeof previousStateId !== 'string') {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  if (
    locationOfStateId(stateId, previousActive.scid) !==
    locationOfStateId(previousStateId, previousActive.scid)
  ) {
    assertPortableMove(state, previousActive.portable, previousStateId);
  }
  // 次版も公開されるため、初版と同一のガードを通す。検査対象は Log へ載るスナップショットそのもの。
  assertNoSpecialCategoryOnChain(state);
  // `state.deactivated` は失効を表さない（`parameters.deactivated`）。取り違えて「失効したつもりの有効な DID」を公開しない。
  if (ownProperty<unknown>(state, 'deactivated') !== undefined) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const parameters = buildParameters(options, previousActive);
  // 検証側と同じ規則（型・値域・事前コミット中の明示・失効後の追記禁止・portable の扱い）で検査する。
  const next = applyParameters(previousActive, readParameterDelta(parameters, false));
  if (previousActive.nextKeyHashes.length > 0) {
    const committed = new Set(previousActive.nextKeyHashes);
    if (!next.updateKeys.every((key) => committed.has(updateKeyHash(key)))) {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
  }
  const draft: WebVhLogEntry = {
    versionId: '',
    versionTime: resolveAppendVersionTime(previous, ownProperty<string>(options, 'versionTime')),
    parameters,
    state,
  };
  const entry: WebVhLogEntry = {
    ...draft,
    versionId: deriveVersionId(draft, versionNumberOf(previous.versionId) + 1, previous.versionId),
  };
  // 追記専用のログが検証側の上限を超えて解決不能にならないよう、署名前に拒否する。
  assertLogAppendWithinLimits(previousLog, entry);
  return entry;
}
