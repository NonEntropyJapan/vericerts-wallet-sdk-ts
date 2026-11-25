/**
 * SD-JWT VC Type Metadata の解決（`extends` 継承 + キャッシュ）とクレーム構造検証。
 *
 * 準拠規格: draft-ietf-oauth-sd-jwt-vc §6。
 *
 * **`extends` のマージ規則:** 継承元（親）→ 継承先（子）の順に**浅くマージ**し、同名メンバは
 * 子を優先する。ただし `claims` は「親の定義を子が上書きしつつ、子に無い親の定義は残す」ため、
 * `path` をキーに親→子の順で統合する。`extends` はマージ結果から取り除く（解決済みのため意味を
 * 持たない）。`#integrity` は取得時点で拒否済みのためここには現れない（fetch.ts）。
 *
 * **スキーマは置換でなく全件評価（SD-JWT VC §6.5.2 MUST）:** `schema` / `schema_uri` だけは
 * 継承せず、`extends` チェーン上の**各文書のスキーマをすべて**同じクレームに対して評価する（`allOf`
 * 相当、`schemas.ts`）。マージ後の `metadata.schema` を使うと、派生型が `schema: {}` で基底型の制約を
 * 外せてしまう。
 *
 * **fail-safe:** Type Metadata / スキーマの
 * **取得失敗（3060）は FO-3**、**任意属性のみの違反は FO-4** として共有ゲート
 * （`schema-validation/fail-safe.ts`）へ渡す。警告通過（FO-3 は `schemaAvailable: false` + 監査キー、
 * FO-4 は `valid: true` + 監査キー + 内容確認用の `errors`）が成立するのは、同意コールバックと
 * 監査記録先が与えられ、同意が得られ、60 秒の時間上限内である場合に限る。成立しなければ FO-3 は
 * 3060 をそのまま伝播し、FO-4 は `valid: false` になる。**必須属性違反**は FO-4 の対象外で
 * 常に `valid: false` とする。
 *
 * **構造不正（3061）は fail-open しない。** `vct` 不一致（種別すり替え）・`extends` 循環・
 * `schema` と `schema_uri` の併記などは `escalate` の設定に関わらず 3061 になる。
 * この場合は Issuer に Type Metadata の修正を依頼する。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  newPresentationWorkBudget,
  type PresentationWorkBudget,
  spendWork,
} from '../../../primitives/presentation-work-budget.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../../prototype-safety/own-property.js';
import { clearFailOpenWindow, schemaFetchFailedResult } from '../../schema-validation/fail-safe.js';
import { TypeMetadataCache } from './cache.js';
import {
  assertNoUnverifiableVctIntegrity,
  fetchTypeMetadataDocument,
  isTypeMetadataUrl,
} from './fetch.js';
import { mergeMetadata } from './merge.js';
import { collectSchemaSources, validateAgainstChainSchemas } from './schemas.js';
import type {
  ResolvedTypeMetadata,
  ResolveTypeMetadataOptions,
  SdJwtTypeMetadata,
  TypeMetadataValidationResult,
} from './types.js';
import { MAX_EXTENDS_DEPTH } from './types.js';

/** モジュール既定の共有キャッシュ（`vct` は VC 種別ごとに固定のため共有が有効）。 */
const defaultMetadataCache = new TypeMetadataCache<SdJwtTypeMetadata>();

/**
 * キャッシュ経由で Type Metadata 文書を 1 件取得する。
 *
 * 文書数はキャッシュヒットでも `budget` に計上する（チェーン全体が評価の終わりまでメモリに載るため）。
 * バイト数はネットワークから読んだ分だけ `fetchTypeMetadataDocument` が計上する。
 */
async function loadDocument(
  vct: string,
  options: ResolveTypeMetadataOptions,
  now: number,
  budget: PresentationWorkBudget,
): Promise<SdJwtTypeMetadata> {
  spendWork(budget, 'metadataDocuments');
  // クラスインスタンス DI のため `ownProperty` は使えない。`Object.prototype` 由来の汚染値だけを
  // 除外する（鎖読みだと汚染した get() が攻撃者の Type Metadata を返す）。
  const cache =
    nonObjectPrototypeProperty<TypeMetadataCache<SdJwtTypeMetadata>>(options, 'metadataCache') ??
    defaultMetadataCache;
  const cached = cache.get(vct, now);
  if (cached !== undefined) {
    return cached;
  }
  const document = await fetchTypeMetadataDocument(vct, options, budget);
  cache.set(vct, document, now);
  return document;
}

/**
 * `vct` URL から Type Metadata を取得し、`extends` チェーンを解決してマージする。
 *
 * `extends` は最大 {@link MAX_EXTENDS_DEPTH} 段まで辿る。同じ URL が再出現した場合は循環として
 * 拒否する。取得済み文書は TTL キャッシュに載せるため、同一種別の VC を続けて検証しても
 * ネットワーク往復は 1 回で済む。
 *
 * @param vct VC 種別識別子（HTTPS URL）。
 * @param options キャッシュ・`fetchImpl`・現在時刻の注入。
 * @returns マージ済み Type Metadata と解決に辿った URL 列。
 * @throws 取得失敗・`vct` / `extends` が HTTPS URL でない場合（`3060`）、
 *         `extends` の循環 / 深さ超過・文書の構造不正（`3061`）。
 */
export async function resolveTypeMetadata(
  vct: string,
  options: ResolveTypeMetadataOptions = {},
): Promise<ResolvedTypeMetadata> {
  if (!isTypeMetadataUrl(vct)) {
    // 非 HTTPS URL は `json-schema/fetch-document.ts` と同様に取得失敗（3060）で拒否する。
    throw new VericertsError(ErrorCodes.TYPE_METADATA_FETCH_FAILED, {
      context: { reason: 'vct_not_https_url' },
    });
  }
  const now = ownProperty<number>(options, 'nowMs') ?? Date.now();
  // 共有予算は own 限定で読む（継承値は予算を攻撃者の巨大な値に差し替える）。指定が無ければ 1 回の解決専用。
  const budget =
    ownProperty<PresentationWorkBudget>(options, 'workBudget') ?? newPresentationWorkBudget();

  // 起点から祖先方向へ辿って収集する（chain[0] が起点）。
  const chain: string[] = [];
  const documents: SdJwtTypeMetadata[] = [];
  const seen = new Set<string>();
  let current: string | undefined = vct;

  while (current !== undefined) {
    if (seen.has(current)) {
      throw new VericertsError(ErrorCodes.TYPE_METADATA_INVALID, {
        context: { reason: 'extends_cycle' },
      });
    }
    if (chain.length >= MAX_EXTENDS_DEPTH) {
      throw new VericertsError(ErrorCodes.TYPE_METADATA_INVALID, {
        context: { reason: 'extends_too_deep' },
      });
    }
    seen.add(current);
    chain.push(current);
    const document: SdJwtTypeMetadata = await loadDocument(current, options, now, budget);
    documents.push(document);

    const next = ownProperty<string>(document, 'extends');
    if (next !== undefined && !isTypeMetadataUrl(next)) {
      // `vct` と同じく非 HTTPS URL は 3060（取得できない URL）に統一する。
      throw new VericertsError(ErrorCodes.TYPE_METADATA_FETCH_FAILED, {
        context: { reason: 'extends_not_https_url' },
      });
    }
    current = next;
  }

  // 最も遠い祖先から順に子を重ねる（子が優先）。
  const metadata = documents
    .slice()
    .reverse()
    .reduce((acc, document) => mergeMetadata(acc, document));

  return { metadata, chain, schemas: collectSchemaSources(documents) };
}

/**
 * SD-JWT VC のクレームを `vct` の Type Metadata（`schema` / `schema_uri`）で検証する。
 *
 * Type Metadata 経路の入口。`vct` が HTTPS URL でない場合は Type Metadata が存在しないため、
 * 検証をスキップして `schemaAvailable: false` を返す（従来どおり `vct` は文字列一致で扱う）。
 *
 * 取得失敗（3060）は FO-3、任意属性のみの違反は FO-4 として扱う。共有の `failOpenWindow` を指定し、利用者の同意と監査記録があり、
 * 60 秒の上限内で警告通過が成立すると、FO-3 は `schemaAvailable: false`、FO-4 は `valid: true` を
 * それぞれ監査キー付きで返す。FO-4 の違反内容は `errors` に残る。
 * `failSafePolicy.escalate` に事象 ID を指定すると、その事象の警告通過を禁止する。
 *
 * **構造不正（3061）は fail-open の対象外**で、override の指定によらず常に throw する
 * （`vct` 不一致による型すり替えを黙って通さないため）。
 *
 * @param vct SD-JWT VC の `vct` クレーム。
 * @param claims 検証対象のクレーム（開示済みクレームを復元したオブジェクト）。
 * @param options キャッシュ・`fetchImpl`・現在時刻・fail-safe override。
 * @returns 検証結果（適合可否・スキーマ取得可否・違反・監査キー）。
 * @throws 構造不正（`3061`）は常に。取得失敗（`3060`）は fail-open ゲートが通過を許さなかった場合
 *         （`escalate: ['FO-3']` / `failOpenWindow`・同意コールバック・監査記録先のいずれかが無い / 不同意 / 60 秒上限超過）。
 */
export async function validateClaimsAgainstTypeMetadata(
  vct: string,
  claims: Readonly<Record<string, unknown>>,
  options: ResolveTypeMetadataOptions = {},
): Promise<TypeMetadataValidationResult> {
  if (!isTypeMetadataUrl(vct)) {
    // vct が URL でない場合、Type Metadata は定義されない。
    return { valid: true, schemaAvailable: false, warnings: [] };
  }
  // `vct#integrity` は検証手段が無いため、宣言があれば取得より前に 3061 で拒否する。
  // 構造不正と同じく fail-open の対象外（ハッシュ固定を黙って捨てると、すり替えた文書で通ってしまう）。
  assertNoUnverifiableVctIntegrity(claims);
  // own 限定で読む。鎖経由だと汚染値が固定 `nowMs` となり、
  // fail-open の 60 秒上限が恒久的に無効化される。
  const now = ownProperty<number>(options, 'nowMs') ?? Date.now();
  // `resolveTypeMetadata` と `validateAgainstChainSchemas`（`schema_uri` の取得）で 1 つの予算を共有する。
  const budget =
    ownProperty<PresentationWorkBudget>(options, 'workBudget') ?? newPresentationWorkBudget();
  // fail-open の時間上限はエポック秒で数える（`FailOpenWindow` の契約）。
  const nowSeconds = Math.floor(now / 1000);
  // Fail-open ウィンドウのキーは経路プレフィックスを付けて資源単位で管理する。
  // W3C VC の `credentialSchema` 経路もスキーマ URL を資源キーに使うため、
  // プレフィックス無しだと `vct`（HTTPS URL）と同じ文字列空間で衝突しうる。
  const vctResourceKey = `sdjwt-vct:${vct}`;

  let resolved: ResolvedTypeMetadata;
  try {
    resolved = await resolveTypeMetadata(vct, { ...options, nowMs: now, workBudget: budget });
  } catch (e) {
    // FO-3 の対象は「取得失敗（3060）」のみ。構造不正（3061）は FO-3 の対象外のため、
    // ここで警告通過させると `vct` 不一致（型すり替え）や `extends` 循環が黙って通ってしまう。
    // `vct` チェーン（起点 / `extends` 祖先）の取得失敗はチェーン起点の `vct` で計時する。
    if (e instanceof VericertsError && e.code === ErrorCodes.TYPE_METADATA_FETCH_FAILED) {
      // 同意・監査記録・時間上限を満たしたときだけ警告通過させる。
      const gated = await schemaFetchFailedResult(vctResourceKey, nowSeconds, options);
      if (gated !== undefined) {
        return gated;
      }
    }
    throw e;
  }

  // `vct` チェーン（起点 + `extends` 祖先）の取得に成功した時点で FO-3 側の資源キーを破棄する。取得後の適合性検証は別途行う。
  clearFailOpenWindow(vctResourceKey, options);

  // 検証用スキーマは `extends` チェーン上の**全文書**から集める（SD-JWT VC §6.5.2）。
  // マージ済み `metadata` の `schema` / `schema_uri` は子が親を置換した後の値で祖先のスキーマが落ちる
  // ため使わない。各スキーマの取得失敗は `schema_uri` ごとの資源キーで FO-3 のゲートに掛け、取得に
  // 成功した資源の計時はその場で破棄する。FO-4（任意属性のみの違反）の時間上限は
  // 評価した資源キーにクレームの指紋を連結してクレデンシャル単位で管理する。
  return await validateAgainstChainSchemas(
    resolved.schemas,
    claims,
    vctResourceKey,
    now,
    options,
    budget,
  );
}
