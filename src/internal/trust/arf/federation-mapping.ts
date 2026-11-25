/**
 * OpenID Federation ⇔ ARF Catalogue マッピング。
 *
 * OpenID Federation（trust/federation）の検証済み Trust Chain（Layer 2）と、ARF Trust Anchor
 * Catalogue（catalogue.ts、Layer 3）の登録エントリを突き合わせ、両 Trust Framework 間の対応
 * 関係を返す。3 層統合信頼判定（Layer 1: ETSI TSL > Layer 2: OpenID Federation > Layer 3: ARF）に
 * おける「複数 Layer で一致」「上位 PASS・下位 REVOKED」等の競合解消
 * に必要な、同一 Trust Anchor の可視化データを提供する。
 *
 * 突き合わせキーは Entity Identifier とする。OpenID Federation の Leaf は `entity_id`（== iss == sub）
 * で識別され、ARF Catalogue も同一の識別子（`did:web:...` / `https://...`）でエントリを登録する
 * （arf-types.ts `ArfCatalogueEntry.id`）。仕様のシーケンスがいずれの Layer も
 * `issuer_id` / `entity_id` をキーに信頼判定する以上、両層の突き合わせも識別子の完全一致で行う。
 *
 * 統合信頼判定そのもの（優先順位付き採用・キャッシュ・TTL・強い警告ログ）は後続スコープ
 * （evaluateTrust）の責務とし、本モジュールは対応関係の算出に専念する。
 *
 * セキュリティ上の注意:
 * - 突き合わせは Entity Identifier の完全一致のみで判定する（部分一致・サブドメイン一致は用いない）。
 *   識別子は取得元 URL からの派生ではなく検証済み Statement の `sub` を用いる（改ざん耐性）。
 * - 検証に成功していない Trust Chain（`valid !== true`）は突き合わせ対象にしない（fail-closed）。
 * - 例外・戻り値に鍵素材・JWT・URL 断片を含めない。
 */

import type {
  ScopedRevokedKeyDeclaration,
  TrustChain,
  TrustChainNode,
} from '../federation/federation-types.js';
import type { ArfCatalogueEntry } from './arf-types.js';

/** OpenID Federation で検証された Leaf エンティティと ARF Catalogue エントリの 1 対応。 */
export interface FederationArfMatch {
  /** 対応した Leaf の Entity Identifier（検証済み Trust Chain の leaf）。 */
  readonly entityId: string;
  /** 対応した ARF Catalogue エントリ。 */
  readonly entry: ArfCatalogueEntry;
  /**
   * 対応の根拠となった検証済み Trust Chain（`entityId === chain.leaf`）。
   *
   * **`chain.revokedKeys`（FC-11 の鍵無効化宣言）を落とさないために保持する。** 本モジュールが
   * 識別子だけを返していた頃は、突き合わせを通過した時点で宣言が失われ、この Leaf が発行した VC を
   * 検証する下流が FC-11 を適用する術を持たなかった。Trust Chain 自体の検証
   * （Entity Configuration の鍵・各 Subordinate Statement の署名鍵）は `buildTrustChain` が
   * `nowSeconds` 基準で済ませているが、**VC 側の突合は VC の発行時刻基準**であり、VC を手にした
   * 下流でしか行えない。
   *
   * この Leaf が発行した VC を検証する際は、本 chain を `verifyCredential` / `verifySdJwt` の
   * `issuerTrust.trustChain` に渡すこと。渡した時点で FC-11 の突合が自動的に適用される。
   *
   * **同一 Leaf に複数の有効チェーンがある場合の意味論**: `valid` / `leaf` / `trustAnchor` /
   * `nodes` / `length` は**採用した 1 本**（入力順で最初の有効チェーン）を表すが、`revokedKeys`
   * だけは**その Leaf を持つ全ての有効チェーンの和集合**である。これは fail-closed の要請による。
   * 同じ Leaf が 2 つの Trust Anchor から到達可能なとき、一方の Trust Anchor だけが公開した
   * 無効化宣言を採用チェーンの選択で取りこぼすと、失効鍵で署名された VC が受理されてしまう
   * （宣言はどの Trust Anchor 由来であっても失ってはならない）。
   */
  readonly chain: TrustChain;
}

/** `mapFederationToArf` の結果。 */
export interface FederationArfMapping {
  /** OpenID Federation ⇔ ARF Catalogue の両方に載る Trust Anchor（Entity Identifier 一致）。 */
  readonly matched: readonly FederationArfMatch[];
  /** ARF に対応がない、検証済み Federation の Leaf 識別子（Federation のみ・Layer 2 限定）。 */
  readonly federationOnly: readonly string[];
  /** Federation に対応がない ARF エントリ（ARF のみ・Layer 3 限定）。 */
  readonly arfOnly: readonly ArfCatalogueEntry[];
}

/**
 * 検証済み OpenID Federation Trust Chain 群と ARF Catalogue エントリを Entity Identifier で突き合わせる。
 *
 * 各 Trust Chain の Leaf 識別子（`chain.leaf`）を突き合わせキーとする。`valid` でない Trust Chain は
 * 対象外とし、`federationOnly` にも含めない（信頼判定に使えないため）。重複する Leaf 識別子は 1 つに
 * まとめる。ARF エントリ側は SPKI の有無を問わず識別子でのみ突き合わせる（Federation は JWK、ARF は
 * SPKI(DER) と鍵表現が異なり、直接比較は別スコープの責務とするため）。
 *
 * @param chains OpenID Federation の Trust Chain 群（`buildTrustChain` の結果）。
 * @param arfEntries ARF Catalogue の登録エントリ。
 * @returns Federation ⇔ ARF の対応関係（一致・Federation のみ・ARF のみ）。
 */
export function mapFederationToArf(
  chains: readonly TrustChain[],
  arfEntries: readonly ArfCatalogueEntry[],
): FederationArfMapping {
  const validChains = dedupeValidChains(chains);
  const arfById = indexByEntityId(arfEntries);

  const matched: FederationArfMatch[] = [];
  const federationOnly: string[] = [];
  const matchedArfIds = new Set<string>();

  for (const chain of validChains) {
    const entityId = chain.leaf;
    const entry = arfById.get(entityId);
    if (entry !== undefined) {
      matched.push({ entityId, entry, chain });
      matchedArfIds.add(entityId);
    } else {
      federationOnly.push(entityId);
    }
  }

  const arfOnly = arfEntries.filter((e) => !matchedArfIds.has(e.id));

  return { matched, federationOnly, arfOnly };
}

/**
 * 検証済み（`valid`）Trust Chain を Leaf 識別子でまとめつつ入力順で返す。
 *
 * 同一 Leaf の chain が複数ある場合、チェーンとしての同一性（`trustAnchor` / `nodes` / `length`）は
 * 最初のものを採用する（`indexByEntityId` と同じ決定的挙動）。ただし `revokedKeys` は
 * **全ての有効チェーンの和集合**に置き換える。最初の 1 本だけを残すと、同じ Leaf が 2 つの
 * Trust Anchor から到達可能な Federation で、2 本目にしか載っていない無効化宣言が黙って捨てられ、
 * 失効鍵で署名された VC が受理される fail-open になるためである（FC-11）。
 * chain 全体を返すのは、突き合わせ結果に `revokedKeys` を持ち越すためである
 * （`FederationArfMatch.chain` の注記を参照）。
 */
function dedupeValidChains(chains: readonly TrustChain[]): TrustChain[] {
  const byLeaf = new Map<string, TrustChain[]>();
  for (const chain of chains) {
    if (!chain.valid || chain.leaf.length === 0) {
      continue;
    }
    const group = byLeaf.get(chain.leaf);
    if (group === undefined) {
      byLeaf.set(chain.leaf, [chain]);
    } else {
      group.push(chain);
    }
  }
  return [...byLeaf.values()].map(withUnionedRevokedKeys);
}

/**
 * 同一 Leaf の有効チェーン群を 1 本に畳む（`revokedKeys` と `nodes` を和集合に差し替える）。
 *
 * 1 本しか無ければ入力の chain をそのまま返し、余計な射影を作らない。複数ある場合は先頭の
 * chain の同一性（`trustAnchor`）を保ったまま `revokedKeys` と `nodes` を和集合で上書きする。
 *
 * ## `nodes` も一緒に畳まねばならない理由（FC-11）
 *
 * `revokedKeys` だけを和集合にして `nodes` を先頭チェーンのままにすると、**宣言とその出自の JWKS が
 * 切り離される**。`kid` は 1 つの JWKS の中でしか一意でないため、これは fail-open を生む。
 *
 * 例: Leaf `L` が Anchor `A` と `B` の双方から到達可能で、`B` は鍵 `K` を `"b-1"` として attest し
 * `{sub: L, kid: "b-1"}` を宣言、`A` は同じ `K` を `"a-1"` として attest しているとする。`nodes` が
 * `A` 側のままだと、VC 検証経路（`credential/issuer-key-revocation.ts`）が鍵素材から解決する `kid` は
 * `"a-1"` だけになり、`B` の宣言は永久に一致しない。失効鍵 `K` で署名された VC が受理されてしまう。
 * 逆向き（同じラベル・異なる鍵素材）では無関係な VC を巻き添えで拒否する。
 *
 * したがって畳んだチェーンには、各宣言の出自である Subordinate Statement をすべて残す（重複排除は
 * しない。理由は `unionNodes` を参照）。`length` は `nodes.length` との整合を保つため連結後の要素数に
 * 合わせる（畳んだ結果は単一の経路ではなく**同一 Leaf に関する集約ビュー**であり、`length` を
 * 「経路長」として読んではならない）。
 */
function withUnionedRevokedKeys(group: readonly TrustChain[]): TrustChain {
  const [first, ...rest] = group;
  // 呼び出し元が空配列を作らないため first は必ず存在するが、型の上では絞り込みが要る。
  if (first === undefined) {
    throw new TypeError('empty trust chain group');
  }
  if (rest.length === 0) {
    return first;
  }
  const nodes = unionNodes(group);
  return { ...first, nodes, length: nodes.length, revokedKeys: unionRevokedKeys(group) };
}

/**
 * チェーン群のノードを入力順にそのまま連結する。
 *
 * **重複排除はしない。** ノードを畳む唯一の目的は「どの宣言についても、その出自の JWKS が残っている
 * こと」を保証することであり、重複が残っても害が無い一方、取りこぼしは fail-open に直結するためである。
 * 実際、`(kind, iss, sub, iat, exp)` のような `jwks` を含まないキーで重複排除すると、同じ上位が同じ
 * subject について**同じ秒内に固定 TTL（`exp = iat + ttl`）で再発行**した内容の異なる 2 つの Statement
 * が衝突し、2 本目の `kid` ラベルが捨てられる。そのラベルを指す宣言は永久に一致しなくなり、本関数が
 * 塞いだはずの fail-open がそのまま再発する。
 *
 * 重複を残すコストは無い。鍵の解決側（`credential/issuer-key-revocation.ts` の
 * `resolveAuthenticatedKids`）は解決した `kid` を重複排除しながら走査し、`revokedKeys` は
 * `unionRevokedKeys` が別途重複排除する。
 */
function unionNodes(group: readonly TrustChain[]): readonly TrustChainNode[] {
  return group.flatMap((chain) => chain.nodes);
}

/**
 * 鍵無効化宣言を `(sub, kid, revoked_at)` の組で重複排除しつつ入力順に連結する。
 *
 * `reason` は判定に使わないため重複判定のキーに含めない。同一 subject・同一 `kid` に
 * 複数の `revoked_at` がある場合は全て残す。最早の `revoked_at` を採用する規則は突合側
 * （`assertCredentialKeyNotRevoked`）の責務であり、ここで宣言を間引くと最早の宣言を失いかねない。
 */
function unionRevokedKeys(group: readonly TrustChain[]): readonly ScopedRevokedKeyDeclaration[] {
  const seen = new Set<string>();
  const out: ScopedRevokedKeyDeclaration[] = [];
  for (const chain of group) {
    for (const declaration of chain.revokedKeys) {
      const key = JSON.stringify([declaration.sub, declaration.kid, declaration.revoked_at]);
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      out.push(declaration);
    }
  }
  return out;
}

/**
 * ARF エントリを Entity Identifier で索引化する。
 *
 * 同一識別子が複数登録された場合は最初のエントリを採用する（Catalogue 側の重複は想定外だが
 * fail-closed に決定的挙動とする）。
 */
function indexByEntityId(entries: readonly ArfCatalogueEntry[]): Map<string, ArfCatalogueEntry> {
  const map = new Map<string, ArfCatalogueEntry>();
  for (const entry of entries) {
    if (entry.id.length === 0 || map.has(entry.id)) {
      continue;
    }
    map.set(entry.id, entry);
  }
  return map;
}
