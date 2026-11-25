/**
 * OIDF 層（OpenID Federation Trust Chain）の Trust Anchor 判定（`jar-trust-evaluation.ts` から
 * 分割した実体。Linterly 300 行/ファイル上限）。
 *
 * `trust/federation` の `buildTrustChain` をそのまま呼び出す。x5c 先頭証明書は、構築された
 * Trust Chain の Leaf ノードが宣言する `jwks` のいずれかの鍵が埋め込む `x5c`
 * （RFC 7517 §4.7、標準 base64 の DER 1 要素）と一致する場合にのみ「この Federation Trust
 * Chain が起点である」とみなす（鍵種の変換は行わず、証明書バイト列の一致だけで判定する）。
 *
 * Leaf の Entity Identifier には**必ず `expectedClientId`（deep link 由来）を使う**。JAR
 * Request Object 本体の `iss` / `client_id` は署名検証前は攻撃者が選べる値であり、これを
 * Entity Configuration 取得先に使うと任意 URL への GET を誘発できてしまう（`fetchJAR` が
 * `request_uri` について払っている注意と同じ）。したがって `expectedClientId` を渡さない
 * 呼び出しでは、`JarFederationTrustAnchorOption` を渡していても OIDF 層は評価しない
 * （呼び出し元 `jar-trust-evaluation.ts` が担う。黙って通さない）。
 */

import { base64 } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import type { LayerStatus } from '../../trust/arf/index.js';
import { derEquals } from '../../trust/etsi-tsl/index.js';
import {
  type BuildTrustChainDeps,
  buildTrustChain,
  type JsonWebKeySet,
} from '../../trust/federation/index.js';
import { certValidityStatus, tryParseRpAccessCertificate } from './jar-trust-cert-status.js';

/**
 * OpenID Federation Trust Chain を JAR 署名者検証の起点にする場合の設定（`JarTrustOptions`
 * `federationTrustAnchor`）。
 */
export interface JarFederationTrustAnchorOption {
  /** OIDF Trust Anchor の Entity Identifier（HTTPS URL）。 */
  readonly trustAnchorEntityId: string;
  /** `buildTrustChain` への依存注入（`fetchFn` / `now` / `metrics`）。省略時はランタイム既定。 */
  readonly deps?: BuildTrustChainDeps;
  /**
   * OIDF Trust Anchor の公開鍵（JWK Set。out-of-band で設定した鍵）。指定すると Anchor の
   * Entity Configuration がこの鍵のいずれかで署名され、自己 `jwks` に含まれることを要求する
   * （満たさなければ OIDF 層は `pass` にならない）。**未指定なら従来どおり Anchor の自己署名と
   * TLS だけを根拠にする**（後方互換。本番では指定を推奨）。空の `keys` など不正な値は未指定へ倒さず
   * 拒否する（OIDF 層は `pass` にならない）。
   */
  readonly trustAnchorJwks?: JsonWebKeySet;
}

/**
 * OIDF 層の `LayerStatus`。leaf 証明書の有効期間・失効を検査したうえで `buildTrustChain` を呼び、
 * 成立すれば Leaf の `jwks` に x5c 先頭証明書と一致する鍵があるかを確かめる（鍵種の変換は行わず、
 * 鍵が埋め込む `x5c`（RFC 7517 §4.7）の DER バイト列を比較するだけ）。
 */
export async function federationLayerStatus(
  leafDer: Uint8Array,
  entityId: string,
  option: JarFederationTrustAnchorOption,
  revokedSerials: ReadonlySet<string> | undefined,
  now: number | undefined,
): Promise<LayerStatus> {
  const parsed = tryParseRpAccessCertificate(leafDer);
  if (parsed === undefined) {
    return 'not-found';
  }
  const validity = certValidityStatus(parsed, revokedSerials, now);
  if (validity !== undefined) {
    return validity;
  }
  // `option` は own 限定で読む。`trustAnchorEntityId` が
  // `Object.prototype` 汚染値に化けると、OIDF の Trust Anchor そのものが攻撃者の Entity に
  // なり得る（本来 undefined 送出になるべき呼び出しが攻撃者の Entity Identifier を掴む）。
  const trustAnchorEntityId = ownProperty<string>(option, 'trustAnchorEntityId');
  if (!isNonBlankString(trustAnchorEntityId)) {
    return 'error';
  }
  // `deps` は DI コンテナ/クラスインスタンスであり得るため own 限定ではなく `Object.prototype`
  // 由来だけを弾く（`own-property.ts`「どちらのヘルパーを使うか」）。own 限定のままだと `class Deps { get fetchFn() {…} }` のようにアクセサ実装した
  // 正当な `deps` が「未指定」に化け、既定のランタイム実装（グローバル `fetch` 等）へ黙って
  // フォールバックしてしまう。
  const deps = nonObjectPrototypeProperty<BuildTrustChainDeps>(option, 'deps') ?? {};
  let chain: Awaited<ReturnType<typeof buildTrustChain>>;
  try {
    // own 限定で読み、指定された場合のみピン留めする（継承値でピン留め鍵を差し替えさせない）。
    const trustAnchorJwks = ownProperty<JsonWebKeySet>(option, 'trustAnchorJwks');
    chain = await buildTrustChain(
      entityId,
      trustAnchorEntityId,
      deps,
      trustAnchorJwks === undefined ? {} : { trustAnchorJwks },
    );
  } catch (error) {
    if (error instanceof VericertsError) {
      if (error.code === ErrorCodes.FEDERATION_KEY_REVOKED) {
        return 'revoked';
      }
      if (error.code === ErrorCodes.TRUST_CHAIN_INVALID) {
        return 'not-found';
      }
    }
    // 取得失敗（FEDERATION_FETCH_FAILED）等の再試行可能なエラーを含め、確定情報が得られない
    // 場合は fail-closed 側の `error` として扱う（PASS を主張しない）。
    return 'error';
  }
  const leafNode = chain.nodes[0];
  if (leafNode === undefined) {
    return 'not-found';
  }
  const matches = leafNode.statement.jwks.keys.some((key) => jwkEmbedsCert(key, leafDer));
  return matches ? 'pass' : 'not-found';
}

/** JWK が埋め込む `x5c`（RFC 7517 §4.7・標準 base64）の先頭要素が `leafDer` と一致するか。 */
function jwkEmbedsCert(key: object, leafDer: Uint8Array): boolean {
  const x5c = ownProperty<unknown>(key, 'x5c');
  if (!Array.isArray(x5c) || x5c.length === 0 || typeof x5c[0] !== 'string') {
    return false;
  }
  let certDer: Uint8Array;
  try {
    // RFC 7517 §4.7 の `x5c` は標準 base64（`@scure/base` の `base64`。base64url ではない）。
    certDer = base64.decode(x5c[0]);
  } catch {
    return false;
  }
  return derEquals(certDer, leafDer);
}
