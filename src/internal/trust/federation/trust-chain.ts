/**
 * OpenID Federation Trust Chain 構築・検証（`buildTrustChain`）と信頼アンカー検証。
 *
 * OpenID Federation 1.0 §4 に沿って Trust Chain を構築する。
 *
 * Trust Chain の構築手順:
 *
 * 1. Leaf（`entityId`）の Entity Configuration（自己署名）を解決する。
 * 2. Leaf の `authority_hints` から Trust Anchor 方向の上位を辿る。
 * 3. 各上位について:
 *    a. 上位の Entity Configuration（自己署名）を解決し、その署名鍵集合を得る。
 *    b. 上位の `federation_fetch_endpoint` から「下位（child）についての Subordinate Statement」を取得する。
 *    c. Subordinate Statement の署名を上位の鍵集合で検証する（`iss == 上位`, `sub == child`）。
 *    d. Subordinate Statement 内の `jwks`（= child の正当な鍵）が、直前に検証した child の鍵と一致することを確認する。
 * 4. 上位が Trust Anchor（`trustAnchor`）に一致したら終了。到達不能・ループ・深度超過・
 *    署名/鍵/期限の不整合は Trust Chain 不成立とする。
 *
 * b-d（Subordinate Statement の取得・署名/鍵検証）と JWK Set 等価判定は `subordinate.ts` に分離する。
 * 本ファイルはチェーン走査（authority_hints の追跡・上限・循環検出・ノード列組み立て）を担う。
 *
 * 信頼アンカー検証: Trust Anchor は「Leaf から Subordinate Statement 連鎖で到達でき、かつ
 * 各 Statement の署名・鍵・有効期間が全て成立する」ことをもって検証成立とする。到達不能なら
 * `verifyTrustAnchor` は `false` を返す。
 *
 * 鍵無効化宣言（`revoked_keys`）: 各 Subordinate Statement は「下位の鍵 `kid` を `revoked_at` 以降は
 * 信頼しない」という override を宣言できる。本ファイルは各段でこの宣言を
 * 下位の Entity Configuration に適用し（`assertChildKeysNotRevoked`）、さらにチェーン確定後に
 * 各 Subordinate Statement を実際に署名した鍵とも突合する（`assertChainSignaturesNotRevoked`）。
 * **どちらの判定時刻も Statement の自己申告 `iat` ではなく検証時刻 `now`** とする。Federation の
 * Statement は「`now` 時点で誰を信頼してよいか」を表す基盤情報である一方、その `iat` は失効
 * させられた当の鍵の保有者が自己申告する値だからである。
 * 宣言は `sub` を紐付けたまま `TrustChain.revokedKeys` に集約する。`kid` は 1 つの JWKS 内でしか
 * 一意でないため、`sub` を捨てると別エンティティの同名 `kid` と衝突する。
 *
 * **VC への適用は VC 検証経路が行う。** `buildTrustChain` は VC を受け取らないため chain 構築時には
 * 突合できない。`verifyCredential` / `verifySdJwt` に `issuerTrust` として本 chain を渡すと、署名検証の
 * 直後に `assertCredentialKeyNotRevoked` が自動的に適用される。渡さなければ突合は
 * 走らない（opt-in）。
 *
 * エラーコード:
 * - チェーン不成立（到達不能 / 署名 / 鍵不一致 / policy 不整合 / 期限）→ `TRUST_CHAIN_INVALID`（5010）。
 * - Entity Configuration 取得失敗 → `resolveEntityConfiguration` 由来の `FEDERATION_FETCH_FAILED`（5011）。
 * - 鍵無効化宣言に該当する署名 → `FEDERATION_KEY_REVOKED`（5012）。fail-closed（FC-11）であり
 *   5010 へ正規化しない。`FailSafePolicy` による fail-open の対象外。
 * - `10304`（FEDERATION_TRUST_CHAIN_FAILED）は本ファイルからは送出しない。
 *   到達不能を含むチェーン不成立は上記のとおり全て 5010 に正規化する設計であり、`10304` は
 *   spec 側で Deprecated 済み。`ErrorCodes` にも未定義。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に entity_id・URL・JWT・鍵を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { FailSafeWarning } from '../../failsafe-policy/index.js';
import { MetricNames, type Metrics } from '../../observability/metrics.js';
import { safeEmit } from '../../observability/safe-emit.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import {
  assertAnchorPinned,
  type BuildTrustChainOptions,
  parsePinnedJwks,
} from './anchor-pin/anchor-pin.js';
import { enforceChainConstraints } from './constraints/enforce.js';
import { resolveEntityConfiguration } from './entity-configuration.js';
import {
  anchorEntityConfigurationDeps,
  type BuildTrustChainDeps,
} from './fail-open/trust-chain-anchor-deps.js';
import type {
  EntityConfiguration,
  EntityStatement,
  RevokedKeyDeclaration,
  ScopedRevokedKeyDeclaration,
  TrustChain,
  TrustChainNode,
} from './federation-types.js';
import {
  assertChainSignaturesNotRevoked,
  assertChildKeysNotRevoked,
} from './revocation/trust-chain-revocation.js';
import { createStatementBudget } from './statement/statement-budget.js';
import { verifySubordinate } from './subordinate.js';

export type { BuildTrustChainOptions } from './anchor-pin/anchor-pin.js';
export type { BuildTrustChainDeps } from './fail-open/trust-chain-anchor-deps.js';
export { assertCredentialKeyNotRevoked } from './revocation/trust-chain-revocation.js';
export { jwksEqual } from './subordinate.js';

/** Trust Chain の最大段数（Leaf から Trust Anchor まで、最大 5 段）。 */
export const MAX_TRUST_CHAIN_LENGTH = 5;

/**
 * OpenID Federation Trust Chain を構築・検証する。
 *
 * `vericerts_trust_chain_build_duration_seconds`（labels: `source`）を
 * `source: 'federation'` 固定で記録する薄いラッパ。計時対象を本体（`buildTrustChainImpl`）と
 * 分けているのは、本体が複数箇所から `return` するため（退化ケース・チェーン完成・最大段数超過）、
 * 呼び出し全体を 1 箇所の `try/finally` で計測する方が本体の分岐を計装で汚さないため。
 *
 * @param entityId Leaf の Entity Identifier（HTTPS URL）。
 * @param trustAnchor Trust Anchor の Entity Identifier（HTTPS URL）。
 * @param deps 依存注入（`fetchFn` / `now` / `metrics`）。省略時はランタイム既定。
 * @param options `trustAnchorJwks`: Trust Anchor の公開鍵をピン留めする（未指定なら従来どおり
 *        自己署名のみで、戻り値の `anchorPinned` が `false`）。
 * @returns 構築・検証済み Trust Chain（`valid === true`）。
 * @throws 到達不能・署名/鍵/期限/policy 不整合の場合（VericertsError、TRUST_CHAIN_INVALID）、
 *         Entity Configuration 取得失敗の場合（FEDERATION_FETCH_FAILED）。
 */
export async function buildTrustChain(
  entityId: string,
  trustAnchor: string,
  deps: BuildTrustChainDeps = {},
  options: BuildTrustChainOptions = {},
): Promise<TrustChain> {
  const metrics = nonObjectPrototypeProperty<Metrics>(deps, 'metrics');
  if (metrics === undefined) {
    return buildTrustChainImpl(entityId, trustAnchor, deps, options);
  }
  const startedAt = Date.now();
  try {
    return await buildTrustChainImpl(entityId, trustAnchor, deps, options);
  } finally {
    safeEmit(() =>
      metrics
        .histogram(MetricNames.TRUST_CHAIN_BUILD_DURATION_SECONDS, { source: 'federation' })
        .observe((Date.now() - startedAt) / 1000),
    );
  }
}

/** `buildTrustChain` の構築本体（計装を挟まない素の経路）。 */
async function buildTrustChainImpl(
  entityId: string,
  trustAnchor: string,
  deps: BuildTrustChainDeps,
  options: BuildTrustChainOptions,
): Promise<TrustChain> {
  // ピン留め鍵は取得より前に検証する（不正な設定を「未指定」へ倒さない）。
  const pinned = parsePinnedJwks(options);
  // 任意の依存注入は自身のプロパティに限って読む。継承した `now` は Entity
  // Statement の有効期間（exp / iat）と鍵無効化（revoked_at）の突合を攻撃者が選んだ時刻で
  // 行わせ、期限切れ Statement・失効済み鍵で組んだチェーンを成立させる。継承した `fetchFn` は
  // Statement の取得先を攻撃者の関数へ委譲する。
  const nowFn = ownProperty<() => number>(deps, 'now');
  const nowSeconds = Math.floor((nowFn?.() ?? Date.now()) / 1000);
  // 連鎖全体で Statement 本文（デコード・JSON パース量）を数える予算。
  const statementBudget = createStatementBudget();

  // 1. Leaf の Entity Configuration（自己署名）を解決する。Leaf==Anchor の退化ケースは FO-6 対象外。
  const leafDeps = entityId === trustAnchor ? anchorEntityConfigurationDeps(deps) : deps;
  const leafConfig = await resolveEntityConfiguration(entityId, leafDeps, statementBudget);
  if (pinned !== undefined && entityId === trustAnchor) {
    assertAnchorPinned(leafConfig, pinned, statementBudget);
  }
  // FO-6（Entity Configuration 到達不能時の stale キャッシュ通過）は各ノードで独立に起こり得るため
  // チェーン単位で集約する。Subordinate Statement の取得は FO-6 の対象外。
  const warnings: FailSafeWarning[] = [...(leafConfig.warnings ?? [])];
  const finish = (revoked: readonly ScopedRevokedKeyDeclaration[]): TrustChain =>
    finalizeChain(
      entityId,
      trustAnchor,
      nodes,
      revoked,
      nowSeconds,
      warnings,
      pinned !== undefined,
    );
  const nodes: TrustChainNode[] = [
    {
      iss: leafConfig.statement.iss,
      sub: leafConfig.statement.sub,
      kind: 'entity-configuration',
      statement: leafConfig.statement,
      jwt: leafConfig.jwt,
    },
  ];

  // Leaf 自身が Trust Anchor である退化ケース（1 段チェーン）。Subordinate Statement が無いため
  // 鍵無効化宣言も存在しない。
  if (entityId === trustAnchor) {
    return finish([]);
  }

  // 2-4. authority_hints を辿って Trust Anchor へ到達する。
  // 段数（=チェーンに含まれるエンティティ数）で上限を判定する。Leaf を 1 段目とし、
  // 上位を 1 つ辿るごとに +1。MAX_TRUST_CHAIN_LENGTH を超えたら不成立とする。
  let current = leafConfig;
  const visited = new Set<string>([entityId]);
  const revokedKeys: ScopedRevokedKeyDeclaration[] = [];
  let entityDepth = 1;
  // 今の `current` から Leaf までの全エンティティの Entity Configuration（`nodes` には Anchor 以外の中間の EC が
  // 積まれないため別に持つ。`allowed_entity_types` の強制が 2 段以上下の中間を見落とさないため）。
  const belowStatements: EntityStatement[] = [leafConfig.statement];

  while (entityDepth < MAX_TRUST_CHAIN_LENGTH) {
    const parentId = selectAuthorityHint(current, trustAnchor);
    if (parentId === undefined) {
      // 上位がない / Trust Anchor が hints に含まれない → 到達不能。
      throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
    }
    if (visited.has(parentId)) {
      // 循環参照。
      throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
    }
    visited.add(parentId);
    entityDepth += 1;

    // 3a. 上位の Entity Configuration（自己署名）を解決する。上位==Anchor なら FO-6 対象外。
    const parentDeps = parentId === trustAnchor ? anchorEntityConfigurationDeps(deps) : deps;
    const parentConfig = await resolveEntityConfiguration(parentId, parentDeps, statementBudget);
    if (pinned !== undefined && parentId === trustAnchor) {
      assertAnchorPinned(parentConfig, pinned, statementBudget);
    }
    warnings.push(...(parentConfig.warnings ?? []));
    // 3b-d. 上位が発行する「current についての Subordinate Statement」を検証する。
    const verifiedSubordinate = await verifySubordinate(
      parentConfig,
      current.entityId,
      current.statement.jwks,
      nowSeconds,
      deps,
      statementBudget,
    );
    const subordinate = verifiedSubordinate.statement;
    nodes.push({
      iss: subordinate.iss,
      sub: subordinate.sub,
      kind: 'subordinate-statement',
      statement: subordinate,
      ...(verifiedSubordinate.signingKid === undefined
        ? {}
        : { signingKid: verifiedSubordinate.signingKid }),
      ...(verifiedSubordinate.jwt === undefined ? {} : { jwt: verifiedSubordinate.jwt }),
    });

    // §6.2: この Statement の発行者が課す constraints を、`sub` から Leaf までの下位全体へ強制する。
    enforceChainConstraints(subordinate, nodes, belowStatements, statementBudget);

    // 宣言は「この Statement の `sub`（= child）の鍵」についてのものなので、平坦化する前に
    // `sub` を紐付ける。`kid` は JWKS 内でしか一意でないため、これを捨てると別エンティティの
    // 同名 `kid` と衝突する。
    const scoped: readonly ScopedRevokedKeyDeclaration[] = (
      ownProperty<readonly RevokedKeyDeclaration[]>(subordinate, 'revoked_keys') ?? []
    ).map((declaration) => ({ ...declaration, sub: subordinate.sub }));

    // FC-11: 上位が宣言した鍵無効化を、直下（child）の Entity Configuration に適用する。
    // fail-closed であり `resolveFailOpen` / `FailSafePolicy` を経由しない。
    assertChildKeysNotRevoked(scoped, current, nowSeconds);
    revokedKeys.push(...scoped);

    if (parentId === trustAnchor) {
      // Trust Anchor の自己署名 Entity Configuration をチェーン末尾に加える。
      nodes.push({
        iss: parentConfig.statement.iss,
        sub: parentConfig.statement.sub,
        kind: 'entity-configuration',
        statement: parentConfig.statement,
        jwt: parentConfig.jwt,
      });
      return finish(revokedKeys);
    }
    belowStatements.push(parentConfig.statement);
    current = parentConfig;
  }

  // 最大段数を超えても Trust Anchor に到達しなかった。
  throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
}

/**
 * `authority_hints` から次に辿る上位を選ぶ。
 *
 * Trust Anchor が hints に含まれればそれを優先し、無ければ先頭の hint を辿る（単純化した
 * 深さ優先。複数分岐の網羅探索は本スコープ外）。
 *
 * @param config 現在ノードの検証済み Entity Configuration。
 * @param trustAnchor 目標 Trust Anchor。
 * @returns 次に辿る上位の Entity Identifier。上位が無ければ `undefined`。
 */
function selectAuthorityHint(config: EntityConfiguration, trustAnchor: string): string | undefined {
  const hints = ownProperty<readonly string[]>(config.statement, 'authority_hints');
  if (hints === undefined || hints.length === 0) {
    return undefined;
  }
  if (hints.includes(trustAnchor)) {
    return trustAnchor;
  }
  return hints[0];
}

/** 検証済みノード列から TrustChain を構築する。 */
function finalizeChain(
  leaf: string,
  trustAnchor: string,
  nodes: TrustChainNode[],
  revokedKeys: readonly ScopedRevokedKeyDeclaration[],
  nowSeconds: number,
  warnings: readonly FailSafeWarning[],
  anchorPinned: boolean,
): TrustChain {
  // チェーンが揃ってから、各 Subordinate Statement の署名鍵を宣言と突合する（FC-11）。
  // 判定は検証時刻 `nowSeconds` 基準（Statement の `iat` は自己申告値で詐称可能なため）。
  // Entity Configuration 側（`assertChildKeysNotRevoked`）も同じ `nowSeconds` を使う。
  assertChainSignaturesNotRevoked(nodes, revokedKeys, nowSeconds);
  return {
    valid: true,
    leaf,
    trustAnchor,
    nodes,
    length: nodes.length,
    revokedKeys,
    anchorPinned,
    // 警告が無いときはフィールド自体を生やさない（`[]` を返すと「FO-6 が起きた」と読めるため）。
    ...(warnings.length === 0 ? {} : { warnings }),
  };
}
