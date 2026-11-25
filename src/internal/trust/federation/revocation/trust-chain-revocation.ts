/**
 * Trust Chain における鍵無効化宣言（`revoked_keys`）の強制（FC-11）。
 *
 * `trust-chain.ts` から分離した「宣言をどこに適用するか」の判断をまとめる（1 ファイル 300 行以下）。
 * 宣言の突合そのもの（`sub` + `kid` + `iat` の一致判定）は `key-revocation.ts` が担う。
 *
 * 適用点は 3 つあり、いずれも欠けると迂回路になる:
 *
 * 1. 子の Entity Configuration が主張する鍵（`assertChildKeysNotRevoked`）。
 * 2. チェーン内の各 Subordinate Statement を実際に署名した鍵（`assertChainSignaturesNotRevoked`）。
 * 3. その鍵で署名された VC（`assertCredentialKeyNotRevoked`。VC 検証経路が `issuerTrust` 経由で適用）。
 *
 * いずれも **fail-closed** であり、`resolveFailOpen` / `FailSafePolicy` を一切経由しない。
 * fail-open ゲートの配線をここに足してはならない。
 *
 * 突合の**時刻基準は 2 種類**ある:
 *
 * - Federation の Statement（1・2）は**検証時刻 `now`** で判定する。Entity Configuration も
 *   Subordinate Statement も「`now` 時点でこの鍵／この下位を信頼してよいか」を表す**基盤情報**で
 *   あって過去の事実の証明ではない。しかもその `iat` は**失効させられた当の鍵の保有者が自分で
 *   署名して申告する値**であり、有効期間検証は `iat <= now < exp` しか見ず `iat` の古さに上限が
 *   無いため、`iat` を基準にすると `iat = revoked_at - 1` への詐称だけで素通りする。
 * - VC（3）は**当該 VC の `iat`** で判定する。VC は第三者（Issuer）が発行した過去の事実の記録で
 *   あり、`now` 基準にすると漏洩前に正当に発行された VC まで巻き添えで無効化してしまう。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に `kid`・entity_id・URL・JWT を含めない。
 */

import { ownProperty } from '../../../prototype-safety/own-property.js';
import type {
  EntityConfiguration,
  ScopedRevokedKeyDeclaration,
  TrustChain,
  TrustChainNode,
} from '../federation-types.js';
import { assertKeyNotRevoked } from './key-revocation.js';

/**
 * 上位の鍵無効化宣言を child の Entity Configuration に適用する（FC-11）。
 *
 * child が自己 Entity Configuration で主張した各鍵のうち `kid` を持つものを、宣言と突合する。
 * `kid` を持たない鍵は宣言の対象を特定できないため判定をスキップする（宣言側が `kid` で対象を
 * 指定する仕様のため）。
 *
 * 突合は `child.entityId` で絞る。宣言は特定の subject の JWKS 内の鍵を指すため、別エンティティ
 * 宛の同名 `kid` を巻き込んではならない。
 *
 * ## 判定時刻は Entity Configuration の `iat` ではなく `nowSeconds`
 *
 * `child.statement.iat` を基準にしてはならない。Entity Configuration は**自己署名**であり、その
 * `iat` は「無効化される当の本人」が自分で署名して申告する値である。有効期間検証は
 * `iat <= now < exp` しか見ず `iat` の古さに上限が無いため、`iat` 基準では失効鍵の保有者が
 * `iat = revoked_at - 1`・`exp = 将来` の Entity Configuration を publish するだけで本検査を
 * 素通りできる。leaf の場合これは致命的で、leaf は自分が署名した Subordinate Statement を
 * チェーンに持たないため `assertChainSignaturesNotRevoked` の網にも掛からず、失効した鍵のまま
 * `buildTrustChain` / `verifyTrustAnchor` が成立してしまう（＝失効鍵でエンティティ認証が通る）。
 *
 * Entity Configuration は「`now` 時点で自分の鍵はこれである」という**基盤情報**であって過去の
 * 事実の証明ではないため、`revoked_at <= nowSeconds` なら申告 `iat` に関わらず拒否する。
 * 鍵をローテートした正当なエンティティは新しい鍵だけを
 * 載せた Entity Configuration を publish すればよく、失効鍵が JWKS に残っていない限り該当しない。
 * 第三者が発行し `iat` に意味がある VC（`assertCredentialKeyNotRevoked`）とは基準が異なる。
 *
 * @param revocations 上位が発行した Subordinate Statement の鍵無効化宣言（`sub` 紐付き）。
 * @param child 判定対象の child の検証済み Entity Configuration。
 * @param nowSeconds 検証時刻（エポック秒）。
 * @throws 無効化宣言に該当する鍵がある場合（VericertsError、FEDERATION_KEY_REVOKED）。
 */
export function assertChildKeysNotRevoked(
  revocations: readonly ScopedRevokedKeyDeclaration[],
  child: EntityConfiguration,
  nowSeconds: number,
): void {
  if (revocations.length === 0) {
    return;
  }
  for (const key of child.statement.jwks.keys) {
    const kid = (key as { kid?: unknown }).kid;
    if (typeof kid !== 'string' || kid.length === 0) {
      continue;
    }
    // 時刻は `child.statement.iat`（自己署名の自己申告）ではなく `nowSeconds`（上の注記を参照）。
    assertKeyNotRevoked(revocations, child.entityId, kid, nowSeconds);
  }
}

/**
 * チェーン内の各 Subordinate Statement が、無効化された鍵で署名されていないことを確認する（FC-11）。
 *
 * `assertChildKeysNotRevoked` が見るのは child の Entity Configuration が**主張する鍵**だけであり、
 * 「無効化された鍵が実際に何に署名したか」は見ていない。そこが空くと次の迂回が成立する:
 * `L → I → TA` で TA が `I` の鍵を失効させても、`I` の Entity Configuration が
 * `iat < revoked_at` を持っていれば `I` は検査を通り、その失効鍵で `iat >= revoked_at` の
 * 新しい Subordinate Statement を任意の子に発行できてしまう。
 *
 * そこでチェーン確定後に、各 Subordinate Statement を**実際に署名した鍵**（`signingKid`）を
 * 発行者（`iss`）に紐付いた宣言と突合する。宣言は上位から下位へ向かうため、`I` についての宣言は
 * `I` より上位のノードから来る。チェーンを全て集約し終えた後に一括で突合する必要があるのはこの
 * ためで、走査中には未取得の宣言があり得る。
 *
 * ## 判定時刻は Statement の `iat` ではなく `nowSeconds`
 *
 * 判定に Statement 自身の `iat` を使ってはならない。`iat` は**失効させられた当の鍵の保有者が
 * 自分で署名して申告する値**であり、有効期間検証は `iat <= now < exp` しか見ず `iat` の古さに
 * 上限が無い。したがって `iat` 基準では、失効鍵 `k_I` の保有者が `iat` を `revoked_at - 1`・
 * `exp` を将来に詐称した Subordinate Statement を作るだけで本検査と `assertChildKeysNotRevoked`
 * の両方を通過し、失効後も Trust Anchor 配下に任意の leaf を新規発行できてしまう。
 *
 * Subordinate Statement は「`now` 時点でこの下位を信頼してよいか」を表す**基盤情報**であって
 * 過去の事実の証明ではないため、`revoked_at <= nowSeconds` なら申告 `iat` に関わらず拒否する。
 * 第三者が発行し `iat` に意味がある VC
 * （`assertCredentialKeyNotRevoked`）とは基準が異なる。
 *
 * @param nodes 検証済みノード列。
 * @param revocations チェーン全体から集約した鍵無効化宣言（`sub` 紐付き）。
 * @param nowSeconds 検証時刻（エポック秒）。
 * @throws 無効化された鍵で署名された Statement がある場合（VericertsError、FEDERATION_KEY_REVOKED）。
 */
export function assertChainSignaturesNotRevoked(
  nodes: readonly TrustChainNode[],
  revocations: readonly ScopedRevokedKeyDeclaration[],
  nowSeconds: number,
): void {
  if (revocations.length === 0) {
    return;
  }
  for (const node of nodes) {
    // Entity Configuration は自己署名であり、その署名鍵は同じノードの jwks として
    // `assertChildKeysNotRevoked` が既に検査している。
    // `signingKid` は条件付きで生やすキーなので own 限定で読む（汚染値の kid で無関係な鍵の無効化判定が走らない）。
    const signingKid = ownProperty<string>(node, 'signingKid');
    if (node.kind !== 'subordinate-statement' || signingKid === undefined) {
      continue;
    }
    // 署名したのは発行者（`iss`）の鍵。宣言も `iss` を subject とするものだけが該当する。
    // 時刻は `node.statement.iat`（自己申告）ではなく `nowSeconds` を使う（上の注記を参照）。
    assertKeyNotRevoked(revocations, node.iss, signingKid, nowSeconds);
  }
}

/**
 * VC の署名鍵が Trust Chain 内の鍵無効化宣言に該当しないことを確認する（FC-11）。
 *
 * `buildTrustChain` が集約した `TrustChain.revokedKeys` を VC に適用する。対象鍵で署名された VC の
 * `iat` が無効化時刻以降なら拒否する。漏洩前に正当に発行された VC
 * （`iat < revoked_at`）は巻き添えにしない。
 *
 * ## ここは `nowSeconds` 基準にしてはならない
 *
 * Federation の Statement 側（`assertChildKeysNotRevoked` / `assertChainSignaturesNotRevoked`）が
 * `nowSeconds` 基準なのに対し、本関数は **VC の `iat` 基準**である。VC は**第三者（Issuer）が
 * 発行した過去の事実の記録**であり `iat` に「いつ発行されたか」という意味がある。`nowSeconds`
 * 基準にすると、失効前に発行した VC も一律に拒否する結果になる。一方 Entity Configuration / Subordinate Statement は
 * `now` 時点の信頼を表す基盤情報で、その `iat` は失効鍵の保有者の自己申告に過ぎないため `now`
 * 基準が正しい。
 *
 * ## 呼び出しは VC 検証経路に配線されている
 *
 * `buildTrustChain` は VC を受け取らないため、chain の構築時点では本判定を行えない。代わりに
 * `verifyCredential` / `verifySdJwt` の `issuerTrust` オプションが Trust Chain を受け取り、署名検証を
 * 通した直後に本関数を適用する（`credential/issuer-key-revocation.ts`）。呼び出し側が本関数を明示的に
 * 呼ぶ必要は無い。ただしこれは **opt-in** であり、`issuerTrust` を渡さない検証では
 * 突合が一切走らない点は変わらない。本関数を直接呼ぶのは、SDK の検証経路を通さずに VC を検証する
 * 構成の場合だけでよい。
 *
 * `kid` は呼び出し側が解決して渡す。`issuer-key-revocation.ts` は上位が署名した Subordinate
 * Statement の `jwks` を検証鍵の鍵素材で引いて決めている（JWS ヘッダや検証鍵 JWK の `kid` ラベルは
 * 署名者＝攻撃者が決められるため権威にしない）。本関数を直接呼ぶ場合も同じ方法で解決すること。
 *
 * `subject` を省略した場合は `chain.leaf`（= Trust Chain を張った対象エンティティ）についての
 * 宣言だけを見る。通常 VC の発行者は leaf なのでこれが既定である。leaf 以外のエンティティが
 * 署名した VC を判定する場合は `subject` を明示する。宣言の突合に `subject` が要るのは、`kid` が
 * JWKS 内でしか一意でなく、別エンティティの同名 `kid` と衝突するためである。
 *
 * この判定は fail-closed であり、`FailSafePolicy` では緩められない（FC-11）。
 *
 * @param chain 構築済み Trust Chain。
 * @param kid VC の署名鍵の `kid`。
 * @param credentialIatSeconds VC の発行時刻（エポック秒）。
 * @param subject VC の署名鍵を保有するエンティティ。省略時は `chain.leaf`。
 * @throws 無効化宣言に該当する場合（VericertsError、FEDERATION_KEY_REVOKED）。
 */
export function assertCredentialKeyNotRevoked(
  chain: TrustChain,
  kid: string,
  credentialIatSeconds: number,
  subject: string = chain.leaf,
): void {
  assertKeyNotRevoked(chain.revokedKeys, subject, kid, credentialIatSeconds);
}
