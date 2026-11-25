/**
 * Subordinate Statement の鍵無効化宣言（`revoked_keys`）のパース・集約・判定。
 *
 * 上位（Intermediate / Trust Anchor）が「主体の鍵 `kid` を `revoked_at` 以降は信頼しない」と宣言する
 * override を表現する。Issuer の KMS 鍵が漏洩した後に残る唯一の実効的な防御線であり、任意クレームで
 * あっても検証は必須とする。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に `kid`・entity_id・URL・JWT を含めない。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { isNonEmptyString } from '../../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import type {
  RevokedKeyDeclaration,
  ScopedRevokedKeyDeclaration,
  TrustChainNode,
} from '../federation-types.js';

/**
 * 鍵無効化宣言の伝播を遅らせないためのキャッシュ上限（秒）。
 *
 * Federation Entity Statement のキャッシュ TTL はこの値で頭打ちにする（採用 TTL は
 * `min(exp - now, 600)`）。構造上 FO-6 が成立し得るのは取得時点で
 * `exp - now > 600` だったケース（採用 TTL が常に 600 秒固定）に限られ、FO-6 の判定に回される
 * stale なキャッシュは常に取得から 600 秒を超えている。キャッシュ層はこの定数を参照する。
 */
export const KEY_REVOCATION_PROPAGATION_MAX_SECONDS = 600;

/**
 * 単一の鍵無効化宣言を厳格にパースする。
 *
 * @param value `revoked_keys` の 1 要素（未検証）。
 * @returns 検証済み宣言。
 * @throws 構造不正の場合（VericertsError、TRUST_CHAIN_INVALID）。
 */
function parseRevokedKey(value: unknown): RevokedKeyDeclaration {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  const { kid, revoked_at: revokedAt, reason } = value as Record<string, unknown>;
  if (!isNonEmptyString(kid)) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  // NumericDate は非負整数。NaN / Infinity / 小数 / 負値はいずれも宣言の取り違えを招くため拒否する。
  if (typeof revokedAt !== 'number' || !Number.isInteger(revokedAt) || revokedAt < 0) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  if (reason !== undefined && typeof reason !== 'string') {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  return reason === undefined
    ? { kid, revoked_at: revokedAt }
    : { kid, revoked_at: revokedAt, reason };
}

/**
 * Entity Statement の `revoked_keys` クレームを厳格にパースする。
 *
 * 構造不正の宣言を黙って読み飛ばすと鍵漏洩からの復旧という防御目的そのものが崩れるため、
 * 1 要素でも不正なら Statement 全体を構造不正として拒否する（`statement.ts` の他のパース失敗と同じ扱い）。
 *
 * @param value payload の `revoked_keys` 値（未検証）。未設定なら `undefined`。
 * @returns 検証済み宣言の配列。`value` が `undefined` なら空配列。
 * @throws 配列でない / 要素が構造不正の場合（VericertsError、TRUST_CHAIN_INVALID）。
 */
export function parseRevokedKeys(value: unknown): readonly RevokedKeyDeclaration[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  return value.map((element) => parseRevokedKey(element));
}

/**
 * Trust Chain のノード列から鍵無効化宣言を集約する。
 *
 * **Subordinate Statement のみを権威とする**。Entity Configuration は自己署名であり、鍵を掌握した
 * 攻撃者が自ら宣言を偽装したり、逆に自分に不利な宣言を省略したりできるため、`entity-configuration`
 * ノードは無視する。
 *
 * 各宣言には**その宣言を含む Statement の `sub`**（= 宣言対象のエンティティ）を紐付ける。`kid` は
 * 1 つの JWKS 内でしか一意でないため、`sub` を捨てて平坦化すると別エンティティの同名 `kid` と
 * 衝突し、無関係な署名を巻き添えで拒否してしまう（`ScopedRevokedKeyDeclaration` の注記を参照）。
 *
 * @param nodes Trust Chain のノード列。
 * @returns 全 Subordinate Statement の宣言に `sub` を紐付けて連結した配列（宣言が無ければ空配列）。
 */
export function collectRevokedKeys(
  nodes: readonly TrustChainNode[],
): readonly ScopedRevokedKeyDeclaration[] {
  const collected: ScopedRevokedKeyDeclaration[] = [];
  for (const node of nodes) {
    if (node.kind !== 'subordinate-statement') {
      continue;
    }
    for (const declaration of ownProperty<readonly RevokedKeyDeclaration[]>(
      node.statement,
      'revoked_keys',
    ) ?? []) {
      collected.push({ ...declaration, sub: node.sub });
    }
  }
  return collected;
}

/**
 * 指定した subject・鍵・発行時刻に該当する鍵無効化宣言を探す。
 *
 * `sub` と `kid` の**両方**が一致し、かつ `iatSeconds >= revoked_at`（境界を含む）なら該当とする。
 * `sub` を条件に含めるのは、`kid` が JWKS 内でしか一意でなく、別エンティティが同じ `kid` を
 * 使っている場合に無関係な署名を拒否してしまうためである。
 *
 * 同一 subject の同一 `kid` に複数の宣言がある場合は**最も早い `revoked_at`** を採用する（後から
 * より遅い時刻で再宣言しても、既に無効化された署名を復活させられないようにするため）。
 *
 * @param revocations 集約済みの鍵無効化宣言（`sub` 紐付き）。
 * @param sub 判定対象の鍵を保有するエンティティ。
 * @param kid 判定対象の鍵の `kid`。
 * @param iatSeconds 判定対象の発行時刻（エポック秒）。
 * @returns 該当する宣言（複数該当時は `revoked_at` が最小のもの）。該当が無ければ `undefined`。
 */
export function findKeyRevocation(
  revocations: readonly ScopedRevokedKeyDeclaration[],
  sub: string,
  kid: string,
  iatSeconds: number,
): ScopedRevokedKeyDeclaration | undefined {
  let earliest: ScopedRevokedKeyDeclaration | undefined;
  for (const revocation of revocations) {
    if (revocation.sub !== sub || revocation.kid !== kid || iatSeconds < revocation.revoked_at) {
      continue;
    }
    if (earliest === undefined || revocation.revoked_at < earliest.revoked_at) {
      earliest = revocation;
    }
  }
  return earliest;
}

/**
 * 鍵無効化宣言に該当する署名を拒否する（FC-11）。
 *
 * この判定は **fail-closed** であり、`resolveFailOpen` / `FailSafePolicy` を意図的に一切経由しない。
 * `escalate` / `suppressPrompt` のどのような設定でも無効化された鍵を通すことはできない
 * （FC-11）。鍵漏洩からの復旧はこの拒否が
 * 唯一の防御線であるため、fail-open ゲートの配線をここに足してはならない。
 *
 * @param revocations 集約済みの鍵無効化宣言（`sub` 紐付き）。
 * @param sub 判定対象の鍵を保有するエンティティ。
 * @param kid 判定対象の鍵の `kid`。
 * @param iatSeconds 判定対象の発行時刻（エポック秒）。
 * @throws 該当する宣言がある場合（VericertsError、FEDERATION_KEY_REVOKED）。
 */
export function assertKeyNotRevoked(
  revocations: readonly ScopedRevokedKeyDeclaration[],
  sub: string,
  kid: string,
  iatSeconds: number,
): void {
  if (findKeyRevocation(revocations, sub, kid, iatSeconds) !== undefined) {
    // kid・entity_id 等は例外に載せない。
    throw new VericertsError(ErrorCodes.FEDERATION_KEY_REVOKED);
  }
}
