/**
 * JAR 署名者検証の Trust Anchor 到達判定。
 *
 * x5c 先頭証明書が次の
 * 3 層（ETSI TSL / LOTL、OpenID Federation Trust Chain、ARF Trust Anchor Catalogue）のいずれかへ
 * 到達し、`evaluateTrust` の優先順位・競合解消（上位層
 * REVOKED 時の fail-closed 拒否を含む）を経て信頼できると判定されることを確かめる。
 *
 * 各層の検証は既存プリミティブへそのまま委譲する（新しい暗号検証は行わない）:
 * - TSL: `trust/rp-access` の `verifyRpAccessCertificate`。
 *   JAR の署名鍵は RP Access Certificate の鍵であるため、新たなチェーン検証の流儀を
 *   作らずに既存の検証をそのまま使う。`requestedClaims` を空配列で渡すのは、**この段階では
 *   要求属性がまだ解析されていない**ためである（属性の権限判定は DCQL 評価後に
 *   `verifyRpAccessCertificate` を改めて呼ぶ呼び出し側の責務）。有効期間・失効
 *   （`revokedSerials` / `now`）の検査も本関数の内部で行う（TSL 層専用）。
 * - OIDF（`jar-trust-oidf.ts`）: `trust/federation` の `buildTrustChain`。Leaf の Entity
 *   Identifier には `expectedClientId`（deep link 由来）のみを使う（`JarFederationTrustAnchorOption`
 *   の JSDoc 参照。JAR 本体の `iss` / `client_id` は署名検証前は攻撃者が選べる値のため使わない）。
 * - ARF（`jar-trust-arf.ts`）: `trust/arf` の `ArfTrustAnchorSet` エントリと x5c 先頭証明書の
 *   SPKI 一致に加え、エントリの `id` と x5c 先頭証明書の SubjectAltName（URI）origin（および
 *   渡されていれば `expectedClientId` の origin）の一致を要求する。SPKI 一致のみで受理すると、ARF Catalogue に登録済みの任意エンティティが
 *   自己署名証明書の SAN を偽装するだけで任意の RP（origin）になりすませてしまう。role が
 *   `relying-party`のエントリのみを ARF 層の Trust Anchor として採用し、
 *   `wallet-provider` / `issuer` / `attestation-provider` として登録されたエンティティは
 *   SPKI・origin が一致しても不採用とする。
 *
 * 有効期間・失効検査（`jar-trust-cert-status.ts`）は TSL 層専用だった検査を OIDF / ARF 層にも
 * 共通化する。`trustAnchors: []` +
 * `federationTrustAnchor` / `arfTrustAnchor` の場合、以前は失効済み・期限切れの証明書がそのまま
 * 受理され得た。
 *
 * セキュリティ上の注意:
 * - 失敗はすべて `jarFailure('rp_cert_untrusted')`（8030）へ正規化する。証明書 DER・DN・鍵材料は
 *   例外・戻り値に含めない。
 * - オプションは `ownProperty` で own 限定に読む（継承値が Trust Anchor 集合や検証基準時刻に
 *   化けると、攻撃者 CA が信頼の起点になり、期限切れ証明書が有効期間内と判定される）。同じ理由で
 *   OIDF / ARF 層内部の `arfSet.entries` / `entry.spki` / `entry.id`・
 *   `option.trustAnchorEntityId` も own 限定で読む。
 *   `option.trustAnchorEntityId` は特に汚染されると OIDF の Trust Anchor そのものが攻撃者の
 *   Entity に化ける。`option.deps` だけは例外で、DI コンテナ/クラスインスタンスであり得るため
 *   own 限定ではなく `nonObjectPrototypeProperty`（`Object.prototype` 由来のみ弾く）で読む
 *   （`jar-trust-oidf.ts`）。
 * - `federationTrustAnchor` / `arfTrustAnchor` に `null` や非オブジェクトが渡された場合、および
 *   `arfSet.entries` に `null` が混じる場合は、`isObject`（`typeof x === 'object' && x !== null`。
 *   `trust/arf/catalogue.ts` と同じ形）で弾いてから読む。弾かずに `ownProperty` へ渡すと
 *   `Object.hasOwn` が生の `TypeError` を投げ、8030 への正規化を素通りしてしまう。
 */

import type { TtlCache } from '../../cache/index.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { isObject } from '../../trust/arf/catalogue.js';
import {
  type ArfTrustAnchorSet,
  evaluateTrust,
  type LayerStatus,
  type LayerVerdict,
} from '../../trust/arf/index.js';
import { MAX_INTERMEDIATES, type QtspServiceCertificate } from '../../trust/etsi-tsl/index.js';
import {
  parseRpAccessCertificate,
  type RpAccessVerificationResult,
  verifyRpAccessCertificate,
} from '../../trust/rp-access/index.js';
import { jarFailure } from './jar-failure.js';
import { arfLayerStatus } from './jar-trust-arf.js';
import type { JarFederationTrustAnchorOption } from './jar-trust-oidf.js';
import { federationLayerStatus } from './jar-trust-oidf.js';
import { readCachedRpCertJudgment, storeRpCertJudgmentForLeaf } from './rp-cert-judgment-cache.js';

export type { JarFederationTrustAnchorOption } from './jar-trust-oidf.js';

/** `evaluateTrust` が PASS と判定するコード（採用可能な層のいずれかで検証成立）。 */
const TRUST_PASS_CODES: ReadonlySet<string> = new Set([
  'tsl-qualified',
  'oidf-federated',
  'arf-listed',
]);

/**
 * `x5c` 先頭証明書が 3 層（TSL / OIDF / ARF）のいずれかの Trust Anchor まで連鎖し、
 * `evaluateTrust` の優先順位・競合解消を経て信頼できると判定されることを確かめる。
 *
 * `options.rpCertJudgmentCache` は、TSL 単独（`federationTrustAnchor` / `arfTrustAnchor` を
 * 渡さない従来どおりの呼び出し）の場合のみ引き続き使う。複数層を
 * 組み合わせる呼び出しは `evaluateTrust` による統合判定が入るため、真偽値だけの既存キャッシュ
 * では判定を再現できない（キャッシュ対象を広げない。キーは証明書 DER 全体のハッシュ）。
 *
 * @throws 起点未確認の場合（`jarFailure('rp_cert_untrusted')`）。
 */
export async function requireTrustedSigner(
  leafDer: Uint8Array,
  intermediatesDer: readonly Uint8Array[],
  anchors: readonly QtspServiceCertificate[],
  options: object,
): Promise<void> {
  // 常に拒否される枚数の入力はキャッシュキーの計算・読み書きの**前**に落とす（`extractX5cChain` を
  // 通らず直接呼ばれても、失敗判定としてキャッシュへ載せない）。
  if (intermediatesDer.length > MAX_INTERMEDIATES) {
    throw jarFailure('rp_cert_untrusted');
  }
  const revokedSerials = ownProperty<ReadonlySet<string>>(options, 'revokedSerials');
  const now = ownProperty<number>(options, 'now');
  const cache = ownProperty<TtlCache<boolean>>(options, 'rpCertJudgmentCache');
  const federationOption = ownProperty<JarFederationTrustAnchorOption>(
    options,
    'federationTrustAnchor',
  );
  const arfSet = ownProperty<ArfTrustAnchorSet>(options, 'arfTrustAnchor');
  const tslOnly = federationOption === undefined && arfSet === undefined;
  // キャッシュの時間軸は検証に使う基準時刻と揃える（TTL は証明書の有効期間で頭打ちにされるため、
  // 期限を過ぎた基準時刻ではヒットさせない）。
  const nowSeconds = now ?? Math.floor(Date.now() / 1000);

  if (tslOnly && cache !== undefined) {
    const cached = readCachedRpCertJudgment(
      cache,
      leafDer,
      intermediatesDer,
      anchors,
      revokedSerials,
      nowSeconds,
    );
    if (cached !== undefined) {
      if (!cached) {
        throw jarFailure('rp_cert_untrusted');
      }
      return;
    }
  }

  const verdicts: LayerVerdict[] = [];

  if (anchors.length > 0) {
    const result = await verifyRpAccessCertificate({
      certDer: leafDer,
      requestedClaims: [],
      trustAnchors: anchors,
      intermediatesDer,
      // 任意メンバは値が `undefined` でも own プロパティとして載せる（下流も own 限定で読むため、
      // 省略すると `Object.prototype` 汚染値が「渡された失効集合 / 基準時刻」に化ける）。
      revokedSerials,
      now,
    });
    if (tslOnly && cache !== undefined) {
      storeRpCertJudgmentForLeaf(
        cache,
        leafDer,
        intermediatesDer,
        anchors,
        revokedSerials,
        result.valid,
        nowSeconds,
        result.validUntil,
      );
    }
    verdicts.push({ layer: 'tsl', status: tslLayerStatus(result) });
  }

  // `expectedClientId` は OIDF 層の Entity Identifier 決定と ARF 層の identity binding の
  // 双方で使うため 1 度だけ own 限定で読む。
  const rawExpectedClientId = ownProperty<unknown>(options, 'expectedClientId');
  const expectedClientId = isNonBlankString(rawExpectedClientId) ? rawExpectedClientId : undefined;

  if (federationOption !== undefined) {
    // `expectedClientId` が無ければ OIDF 層は評価しない（`JarFederationTrustAnchorOption` の
    // JSDoc 参照。SSRF 相当のリスクを避けるため、署名検証前の JAR 本体クレームは Entity
    // Identifier に使わない）。
    if (expectedClientId !== undefined) {
      // `federationTrustAnchor: null` のような呼び出しは `ownProperty` 越しでも
      // `federationOption !== undefined` を満たすため、`isObject` で弾かずに
      // `federationLayerStatus` へ渡すと内部の `ownProperty(option, …)` が `null` に対する
      // `Object.hasOwn` 呼び出しで生の `TypeError` を投げ、`jarFailure('rp_cert_untrusted')` へ
      // 正規化されないまま外へ漏れる。信頼の起点が壊れた
      // 形で渡された場合も「起点未確認」と同じ `error` 判定にする。
      verdicts.push({
        layer: 'oidf',
        status: isObject(federationOption)
          ? await federationLayerStatus(
              leafDer,
              expectedClientId,
              federationOption,
              revokedSerials,
              now,
            )
          : 'error',
      });
    }
  }

  if (arfSet !== undefined) {
    // 同じ理由で `arfTrustAnchor: null` も `isObject` で弾く（`arfLayerStatus` 内の
    // `ownProperty(arfSet, 'entries')` が `null` に対して生の `TypeError` を投げないようにする）。
    verdicts.push({
      layer: 'arf',
      status: isObject(arfSet)
        ? arfLayerStatus(leafDer, arfSet, expectedClientId, revokedSerials, now)
        : 'error',
    });
  }

  const decision = evaluateTrust({
    subjectId: trustSubjectId(leafDer),
    verdicts,
    ...(now !== undefined ? { nowMs: now * 1000 } : {}),
  });
  if (!TRUST_PASS_CODES.has(decision.code)) {
    // `rejected`（上位層 REVOKED による fail-closed 拒否）/ `unknown` / `stale` はいずれも
    // JAR 検証ゲートとしては「起点未確認」と同じ扱いにする（3 層の優先順位・競合解消の結果を
    // 尊重し、8030 固定の失敗理由へ正規化する）。
    throw jarFailure('rp_cert_untrusted');
  }
}

/** TSL 層の `LayerStatus`。`verifyRpAccessCertificate` の結果をそのまま解釈する。 */
function tslLayerStatus(result: RpAccessVerificationResult): LayerStatus {
  if (result.valid) {
    return 'pass';
  }
  if (result.revocation.checked && result.revocation.revoked) {
    return 'revoked';
  }
  return 'not-found';
}

/**
 * `evaluateTrust` の監査用 `subjectId`。x5c 先頭証明書の SubjectAltName（URI）origin を使い、
 * 取れなければシリアル番号（16 進）にフォールバックする。証明書 DER・DN 本体は含めない。
 */
function trustSubjectId(leafDer: Uint8Array): string {
  try {
    const parsed = parseRpAccessCertificate(leafDer);
    return isNonBlankString(parsed.identity.origin) ? parsed.identity.origin : parsed.serialHex;
  } catch {
    return 'jar-request-object';
  }
}
