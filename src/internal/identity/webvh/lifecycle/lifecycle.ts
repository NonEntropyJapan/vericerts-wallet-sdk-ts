/**
 * did:webvh のライフサイクル（生成・更新）API。
 *
 * メソッドプラグイン（`method-webvh.ts`）から再エクスポートされる
 * 生成ヘルパ（更新は `./lifecycle-update.ts`。1 ファイル 300 行以下のため分割）。
 *
 * 生成・更新・失効は新しい行を JSONL に append する運用であり、`DIDMethod` の
 * `create` / `update` / `deactivate` では表現できないため専用 API として提供する。
 * proof は updateKeys を持つ呼び出し側が後段で付与する（`./witness/sign.ts` に witness proof の生成・収集がある）。
 *
 * 例外メッセージ・`context` に DID 文字列・URL・Log 本文・鍵バイトを含めない。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { assertNoSpecialCategoryOnChain } from '../../../special-category.js';
import type { DIDDocument } from '../../did.js';
import { type NormalizedLogInput, normalizeLogInput } from '../../normalized-log-input.js';
import {
  computeScid,
  DID_WEBVH_PREFIX,
  deriveVersionId,
  replaceInJson,
  SCID_PLACEHOLDER,
  type WebVhLogEntry,
  type WebVhWitnessParameter,
} from '../codec.js';
import { DID_WEBVH_METHOD, parseTtl, parseWatchers } from '../parameters.js';
import { parseWitnessParameter, witnessParameterOf } from '../witness/config.js';
import { assertLogAppendWithinLimits } from './append-limits.js';
import { assertDidLocation } from './did-location.js';
import { assertNextKeyHashes, assertUpdateKeys } from './update-keys.js';
import { resolveCreateVersionTime } from './version-time.js';

/**
 * 初版 DID Document の既定 JSON-LD コンテキスト。
 *
 * **参照をそのまま state に載せてはならない。** モジュール定数は呼び出し間で共有されるため、
 * ある呼び出しの戻り値 `state['@context']` への破壊的変更が次の呼び出しの SCID / `versionId` へ
 * 焼き付く。補完のたびに写しを作る（`[...DID_WEBVH_CONTEXT]`）こととし、`Object.freeze` で
 * 定数側からも二重に守る。
 */
const DID_WEBVH_CONTEXT: readonly string[] = Object.freeze([
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/multikey/v1',
]);

/** create 時に呼び出し側が指定できる DID Document の部分（id は SDK が設定）。 */
export type WebVhCreateDocument = Omit<DIDDocument, 'id'>;

/** did:webvh の初版 DID Log エントリ生成オプション。 */
export interface WebVhCreateOptions {
  /** ドメイン（`example.com` / `example.com%3A8443`）。 */
  readonly domain: string;
  /** path セグメント（`:` 区切り、未指定で well-known）。 */
  readonly path?: string;
  /** 初版の更新鍵（Ed25519 Multikey 文字列、`z...`）。1 つ以上必須。 */
  readonly updateKeys: readonly string[];
  /** 次版の更新鍵ハッシュ（事前コミット）。`updateKeyHash` で計算する。 */
  readonly nextKeyHashes?: readonly string[];
  /** 初版 DID Document（id / scid は SDK が補完。`{SCID}` は SCID へ置換される）。 */
  readonly document?: WebVhCreateDocument;
  /** versionTime（UTC の ISO 8601。`Z` / `+00:00`）。未指定なら呼び出し時刻。未来（+5 分超）・解釈不能・UTC 以外は 2001。 */
  readonly versionTime?: string;
  /** 移動（`state.id` の host / path の変更）を許すか。初版でだけ `true` にできる。未指定は `false`（明示して書く）。 */
  readonly portable?: boolean;
  /** キャッシュ秒数（0〜2^31）。未指定は仕様の既定値（3600）。 */
  readonly ttl?: number;
  /** watcher の URL（http(s)）。 */
  readonly watchers?: readonly string[];
  /**
   * witness の構成（`{ threshold, witnesses: [{ id: <did:key> }] }`。`weight` は無い）。`did-witness.json` と proof の
   * 収集は `collectWebVhWitnessProofs`（`./witness/sign.ts`）。
   */
  readonly witness?: WebVhWitnessParameter;
}

/** did:webvh create の戻り値（DID 文字列と初版 Log エントリ）。 */
export interface WebVhCreateResult {
  readonly did: string;
  readonly logEntry: WebVhLogEntry;
}

/**
 * 初版 state（DID Document）を組み立てる。`id` と既定コンテキストを補完し、relationship 群は
 * 未指定なら空配列で埋める（DIDDocument 型の必須メンバ）。
 *
 * `document` に正規化スナップショットの公称型を要求するのは、本関数が初版生成で **2 回**
 * （SCID 用プレースホルダ entry と最終 entry）呼ばれるためである。生の入力を
 * 受け取れると、`get verificationMethod()` のような own アクセサが呼び出しごとに別の値を返し、
 * **SCID がその SCID の下で公開される文書とは別の文書に対して計算される**。
 *
 * @param did DID 文字列（scid 確定後またはプレースホルダ）。
 * @param document 呼び出し側指定の DID Document の正規化スナップショット（id を除く）。
 * @returns 初版 state。
 */
function buildGenesisState(
  did: string,
  document: NormalizedLogInput<WebVhCreateDocument>,
): DIDDocument {
  // DID Document の各フィールドは自身のプロパティに限って読む。プロトタイプ鎖を
  // 辿ると、`verificationMethod` / `authentication` 等を**持たない** Document でも汚染値が
  // 初版 state に載り、SCID と `versionId` にハッシュされて署名済み DID ログへ焼き付く
  // （＝ 攻撃者の検証鍵が DID の認証手段として確定する）。スナップショット済みなので
  // 再評価は起きない。
  const controller = ownProperty<DIDDocument['controller']>(document, 'controller');
  const keyAgreement = ownProperty<DIDDocument['keyAgreement']>(document, 'keyAgreement');
  const capabilityInvocation = ownProperty<DIDDocument['capabilityInvocation']>(
    document,
    'capabilityInvocation',
  );
  const capabilityDelegation = ownProperty<DIDDocument['capabilityDelegation']>(
    document,
    'capabilityDelegation',
  );
  const service = ownProperty<DIDDocument['service']>(document, 'service');
  return {
    '@context': ownProperty<readonly string[]>(document, '@context') ?? [...DID_WEBVH_CONTEXT],
    id: did,
    verificationMethod:
      ownProperty<DIDDocument['verificationMethod']>(document, 'verificationMethod') ?? [],
    authentication: ownProperty<DIDDocument['authentication']>(document, 'authentication') ?? [],
    assertionMethod: ownProperty<DIDDocument['assertionMethod']>(document, 'assertionMethod') ?? [],
    ...(controller !== undefined ? { controller } : {}),
    ...(keyAgreement !== undefined ? { keyAgreement } : {}),
    ...(capabilityInvocation !== undefined ? { capabilityInvocation } : {}),
    ...(capabilityDelegation !== undefined ? { capabilityDelegation } : {}),
    ...(service !== undefined ? { service } : {}),
  };
}

/**
 * 初版 DID Log エントリ（proof 前の正規形）を生成する。
 *
 * SCID をプレースホルダ（`{SCID}`）にした preliminary entry を JCS 正規化して SHA-256 multihash を算出し、
 * それを SCID として全出現を置換し、entryHash で `1-<entryHash>` の versionId を確定する（did:webvh v1.0 の
 * Create 4〜5）。proof は updateKeys を持つ呼び出し側が後段で付与する。
 *
 * @param options 生成オプション。
 * @returns DID 文字列と初版 Log エントリ。
 * @throws domain / path が resolver の URL 解釈と一致しない・updateKeys が空または Ed25519
 *         Multikey でない・nextKeyHashes が multihash でない・witness / watchers / ttl / portable が
 *         仕様の値域に合わない・versionTime が不正（解釈不能・未来・UTC（`Z` / `+00:00`）以外）の場合（VericertsError、code `2001`）、
 *         `document` が GDPR Art.9 特別カテゴリ属性を含む場合（code `10601`）。
 *         10601 は原因の属性名を載せないため、内訳が必要な場合は
 *         `findSpecialCategoryAttributes(document)` で正規化済みの該当属性名を取得する。
 */
export function createDidWebVh(options: WebVhCreateOptions): WebVhCreateResult {
  // `domain` / `updateKeys` は型上必須だが、型の無い JS から省略されるとプロトタイプ鎖の
  // 汚染値が「指定された値」に化ける。`updateKeys` は **DID の更新権限鍵集合**
  // であり、汚染値が採用されると攻撃者の鍵が SCID / `versionId` にハッシュされて署名済み
  // DID ログへ焼き付く（＝ DID の乗っ取り）。空配列ガードも汚染値に対して行う必要がある。
  const domain = ownProperty<string>(options, 'domain') as string;
  const path = ownProperty<string>(options, 'path');
  // `domain` / `path` は resolver（`parseWebVh` → `webVhLogUrl`）と同じ解釈で意図した場所を指すこと。
  // SCID に焼き付くため、公開後には直せない。
  assertDidLocation(domain, path);
  // `updateKeys` の各要素は Ed25519 Multikey であること。署名不能・更新不能な Log を作らない。
  const updateKeys = assertUpdateKeys(ownProperty<readonly string[]>(options, 'updateKeys'));
  // 任意プロパティは自身のプロパティに限って読む。継承値を拾うと、これらを
  // **省略した**正当な生成でも汚染値が DID の更新権限鍵集合（`updateKeys` / `nextKeyHashes`）へ
  // 入り、`versionId` にハッシュされて署名済み DID ログに焼き付く（＝ DID の乗っ取り）。
  const pathSuffix = path !== undefined && path.length > 0 ? `:${path}` : '';
  const versionTime = resolveCreateVersionTime(ownProperty<string>(options, 'versionTime'));
  // DID Log は公開・追記専用で取り消せないため、GDPR Art.9 属性は公開前に止める。
  // 検査対象は **実際に state へ載る** `document`（own 限定で読んだ値）でなければならない。
  // `options.document` をプロトタイプ鎖で読むと、汚染された別オブジェクトを検査してしまう。
  // 読み取りは 1 度きりで正規化スナップショットへ畳む（Art.9 の検査と SCID に焼き付く state が
  // 別の値にならないよう、own アクセサの再評価を断つ）。
  const document = normalizeLogInput<WebVhCreateDocument>(
    ownProperty<WebVhCreateDocument>(options, 'document'),
  );
  assertNoSpecialCategoryOnChain(document);

  const optionalNextKeyHashes = ownProperty<readonly string[]>(options, 'nextKeyHashes');
  const optionalWatchers = ownProperty<readonly string[]>(options, 'watchers');
  const optionalTtl = ownProperty<number>(options, 'ttl');
  const optionalWitness = ownProperty<WebVhWitnessParameter>(options, 'witness');
  const portable = ownProperty<unknown>(options, 'portable') ?? false;
  if (typeof portable !== 'boolean') {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  // 初版のパラメータ（SCID はプレースホルダ）。`witness` / `watchers` / `ttl` は指定されたときだけ書く。
  const parameters: Record<string, unknown> = {
    method: DID_WEBVH_METHOD,
    scid: SCID_PLACEHOLDER,
    updateKeys,
    portable,
    ...(optionalNextKeyHashes !== undefined
      ? { nextKeyHashes: assertNextKeyHashes(optionalNextKeyHashes) }
      : {}),
    ...(optionalWitness !== undefined
      ? { witness: witnessParameterOf(parseWitnessParameter(optionalWitness)) }
      : {}),
    ...(optionalWatchers !== undefined ? { watchers: parseWatchers(optionalWatchers) } : {}),
    ...(optionalTtl !== undefined ? { ttl: parseTtl(optionalTtl) } : {}),
  };
  // 仕様（Create 4〜5）: 初版を「versionId・SCID の位置がプレースホルダ `{SCID}`」の preliminary entry として作り、
  // JCS のハッシュから SCID を求め、全出現を置換し、entryHash（直前の識別子 = SCID）で versionId を確定する。
  // `document` は 1 度だけ組み立てる（SCID と公開 state が別文書にならない）。
  const placeholderDid = `${DID_WEBVH_PREFIX}${SCID_PLACEHOLDER}:${domain}${pathSuffix}`;
  const placeholderEntry = {
    versionId: SCID_PLACEHOLDER,
    versionTime,
    parameters,
    state: buildGenesisState(placeholderDid, document),
  };
  const scid = computeScid(placeholderEntry);
  const did = `${DID_WEBVH_PREFIX}${scid}:${domain}${pathSuffix}`;
  const withScid = replaceInJson(placeholderEntry, SCID_PLACEHOLDER, scid) as WebVhLogEntry;
  const logEntry: WebVhLogEntry = {
    ...withScid,
    versionId: deriveVersionId(withScid, 1, scid),
  };
  // 検証側の上限（版数・1 行・ログ全体・鍵ハッシュ）を超えるログは、署名前に作らない。
  assertLogAppendWithinLimits([], logEntry);
  return { did, logEntry };
}
