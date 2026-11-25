/**
 * did:webvh の DID Log 検証アルゴリズム。DIF didwebvh v1.0「Read (Resolve)」の
 * 各エントリに対する手順に対応する。witness の承認（did-witness.json）の検証は `./witness/verify.ts`。
 *
 * - `parameters` の検証と版ごとの有効値（`./parameters.ts`。`method` は `did:webvh:1.0` のみ）。
 * - versionId: 版番号が 1 から連続し、`entryHash`（`./codec.ts` の `deriveVersionId`）が一致すること（全版）。
 * - 初版の SCID を self-certifying に検証（`parameters.scid` と DID の SCID が一致し、プレースホルダ置換後の JCS ハッシュと一致）。
 * - 全版の `state.id` を `did:webvh` として解釈し、SCID が DID の SCID と一致すること。`state.id` の host / path が変わる版は
 *   portable が有効で、`alsoKnownAs` に直前の DID を含むこと。
 * - 各エントリの proof を「有効な updateKeys」で検証する（事前コミット中は当該版の `updateKeys`、それ以外は前版の `updateKeys`。
 *   `./proof.ts`）。事前コミット中は `updateKeys` の**全部**が前版の `nextKeyHashes` に含まれること。
 * - versionTime の単調増加、失効（`parameters.deactivated`）後の追記の拒否。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` に DID 文字列・Log 本文・鍵バイトを含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { ResolutionWorkBudget } from '../resolution-budget.js';
import {
  computeScid,
  deriveVersionId,
  entryWithoutProof,
  replaceInJson,
  SCID_PLACEHOLDER,
  updateKeyHash,
  versionNumberOf,
  type WebVhLogEntry,
} from './codec.js';
import { assertVersionTimeAdvances } from './lifecycle/version-time.js';
import {
  consumeKeyHashBudget,
  createKeyHashBudget,
  createSignatureBudget,
  type KeyHashBudget,
  MAX_LOG_ENTRIES,
  rejectDidLogOversized,
} from './limits.js';
import { isSha256MultihashBase58 } from './multihash.js';
import {
  type ActiveParameters,
  applyParameters,
  type ParameterDelta,
  readParameterDelta,
} from './parameters.js';
import { verifyEntryProof } from './proof.js';
import { assertPortableMove, locationOfStateId } from './state-id.js';
import type { WebVhWitnessConfig } from './witness/config.js';

/** 検証済みの DID Log。 */
export interface VerifiedLog {
  /** 検証したエントリ（行順）。 */
  readonly entries: readonly WebVhLogEntry[];
  /** 各版を処理した後に有効なパラメータ（`parameters[i]` が `entries[i]` 時点）。 */
  readonly parameters: readonly ActiveParameters[];
  /** 各版が承認を要する witness 構成（要さなければ `undefined`）。 */
  readonly witnessRequired: readonly (WebVhWitnessConfig | undefined)[];
}

function invalid(): VericertsError {
  return new VericertsError(ErrorCodes.INVALID_DID);
}

/**
 * 初版の SCID を検証する（spec: Verify SCID）。`proof` を除き、`versionId` を `{SCID}` にし、エントリ全体の文字列で
 * SCID を `{SCID}` に置換して JCS ハッシュを取り、SCID と一致することを確かめる。
 *
 * @throws 不一致の場合（VericertsError、code `2001`）。
 */
function verifyScid(entry: WebVhLogEntry, scid: string): void {
  const preliminary = replaceInJson(
    { ...entryWithoutProof(entry), versionId: SCID_PLACEHOLDER },
    scid,
    SCID_PLACEHOLDER,
  );
  if (computeScid(preliminary) !== scid) {
    throw invalid();
  }
}

/**
 * 事前コミット（pre-rotation）を検証する（spec: Read (Resolve) 7 / Pre-Rotation Key Hash Generation and Verification）。
 *
 * 直前の `nextKeyHashes` が非空の間は、当該版の `updateKeys` の**全部**（新しく現れたものだけでなく）の multihash が
 * 前版の `nextKeyHashes` に含まれていなければならない。省略・空配列は `applyParameters` が拒否する。
 *
 * @param budget ログ全体の鍵ハッシュ計算予算。尽きたらハッシュを計算せず `did_log_too_large` で拒否する。
 * @throws 含まれない鍵がある場合（VericertsError、code `2001`）。
 */
function verifyKeyPreCommit(
  updateKeys: readonly string[],
  committed: ReadonlySet<string>,
  budget: KeyHashBudget,
): void {
  for (const key of updateKeys) {
    consumeKeyHashBudget(budget);
    if (!committed.has(updateKeyHash(key))) {
      throw invalid();
    }
  }
}

/** 版 `index` の proof を検証する鍵（有効な updateKeys）。 */
function authorizedKeys(
  index: number,
  previous: ActiveParameters | undefined,
  current: ActiveParameters,
): ReadonlySet<string> {
  // 初版は自身の updateKeys。事前コミット中は当該版の updateKeys（前版の nextKeyHashes に拘束済み）、
  // それ以外は前版の updateKeys（spec: Authorized Keys）。
  const preRotationActive = previous !== undefined && previous.nextKeyHashes.length > 0;
  return new Set(index === 0 || preRotationActive ? current.updateKeys : previous?.updateKeys);
}

/**
 * DID Log の全エントリを検証する。
 *
 * @param entries DID Log エントリ配列（行順）。
 * @param did 解決対象の DID 文字列。
 * @param scid DID 文字列の scid セグメント。
 * @param scope 解決スコープ全体の仕事量予算（署名検証・鍵ハッシュを計上する。省略時は計上しない）。
 * @returns 各版の有効なパラメータと、各版が要する witness 構成。
 * @throws 検証失敗・エントリ数超過の場合（VericertsError、code `2001`）。
 */
export function verifyChain(
  entries: readonly WebVhLogEntry[],
  did: string,
  scid: string,
  scope?: ResolutionWorkBudget,
): VerifiedLog {
  // 署名検証・ハッシュ計算の前に件数だけで拒否する。
  rejectDidLogOversized(entries.length, MAX_LOG_ENTRIES);
  // ログ全体の署名検証回数の予算。proof の件数上限はエントリ単位なので、全エントリに不正 proof を
  // 並べて総検証数を膨らませる攻撃は、ここで総数として拒否する。
  const signatureBudget = createSignatureBudget(entries.length, scope);
  // 事前コミット検証の鍵ハッシュ計算も総数で縛る。1 エントリの件数上限だけでは全エントリに並べられる。
  const keyHashBudget = createKeyHashBudget(scope);
  // parameters は（`parseDidLog` を通らない呼び出しに備えて）ハッシュ・署名検証の前に全版ぶん検査する（件数上限を含む）。
  const deltas: ParameterDelta[] = entries.map((entry, index) =>
    readParameterDelta(ownProperty<unknown>(entry, 'parameters'), index === 0),
  );
  const parameters: ActiveParameters[] = [];
  const witnessRequired: (WebVhWitnessConfig | undefined)[] = [];
  let previousId = scid;
  let previousTime = Number.NEGATIVE_INFINITY;
  let previousLocation: string | undefined;
  let previousStateId: string | undefined;
  let didIdMatchCount = 0;
  const now = Date.now();

  for (const [index, entry] of entries.entries()) {
    const delta = deltas[index] as ParameterDelta;
    const previous = parameters[index - 1];
    // 失効（deactivated）後の追記は、updateKey 漏えいによる失効の取り消し（再有効化）に当たるため拒否する。
    // 版番号は 1 から連続し、`<n>-<entryHash>` の entryHash は SHA-256 multihash であること。
    const current = applyParameters(previous, delta);
    if (
      versionNumberOf(entry.versionId) !== index + 1 ||
      !isSha256MultihashBase58(entry.versionId.slice(entry.versionId.indexOf('-') + 1))
    ) {
      throw invalid();
    }
    // 初版: `parameters.scid` は DID の SCID と一致すること。
    if (index === 0 && current.scid !== scid) {
      throw invalid();
    }
    // `state.id` は own 限定で読む。全版で SCID が DID の SCID と一致すること（spec: Read (Resolve) 6.2）。
    const stateId = ownProperty<unknown>(entry.state, 'id');
    const location = locationOfStateId(stateId, scid);
    if (previousLocation !== undefined && location !== previousLocation) {
      assertPortableMove(
        entry.state,
        (previous as ActiveParameters).portable,
        previousStateId as string,
      );
    }
    if (stateId === did) {
      didIdMatchCount += 1;
    }
    // versionTime は前版より厳密に大きく、未来であってはならない。
    previousTime = assertVersionTimeAdvances(entry.versionTime, previousTime, now);

    if (index === 0) {
      verifyScid(entry, scid);
    }
    if (deriveVersionId(entry, index + 1, previousId) !== entry.versionId) {
      throw invalid();
    }
    if (previous !== undefined && previous.nextKeyHashes.length > 0) {
      verifyKeyPreCommit(current.updateKeys, new Set(previous.nextKeyHashes), keyHashBudget);
    }
    verifyEntryProof(entry, authorizedKeys(index, previous, current), signatureBudget);

    parameters.push(current);
    // 承認を要する witness: 初版は自身の構成、以降は前版までの有効な構成（なければ当該版が新しく宣言した構成。
    // `{}` から設定する版は即座に有効で、その版自身が承認の対象になる。spec: `witness`）。
    witnessRequired.push(index === 0 ? current.witness : (previous?.witness ?? current.witness));
    previousId = entry.versionId;
    previousLocation = location;
    previousStateId = stateId as string;
  }
  // 解決対象の DID と一致する `state.id` が 1 つも無いログは拒否する（spec: Read (Resolve) の最後）。
  if (didIdMatchCount === 0) {
    throw invalid();
  }
  return { entries, parameters, witnessRequired };
}
