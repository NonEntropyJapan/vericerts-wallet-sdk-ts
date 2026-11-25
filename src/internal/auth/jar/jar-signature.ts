/**
 * JAR JWS の署名と署名者の信頼性を検証する。
 *
 * `fetchJAR` / `parsePresentationRequest` は取得した Request Object を**解析する前に**本モジュール
 * を通し、通らなかった要求は `8030` で拒否する。
 *
 * **なぜ署名検証が必須か。** `fetchJAR` が課す HTTPS 強制・リダイレクト降格拒否と、
 * `parseJarRequest` が課す `response_uri` の HTTPS 検査・`client_id` オリジン一致検査は、
 * 中間者と素朴なフィッシングを塞ぐが**署名検証の代わりにはならない**。`request_uri` は
 * deep link / QR 由来 = 攻撃者が値を選べる URL なので、攻撃者は自分のホストに `request_uri` を
 * 向け、Request Object 内の `client_id` と `response_uri` を**自分のドメインで揃えて**しまえば
 * それらの検査をすべて通過できる。Verifier の実在性を確かめるものが 1 つも無い状態では、
 * 任意の提示要求（任意の `dcql_query` と任意の送信先）を Wallet に注入できる。
 *
 * 次の 6 項目がすべて成立する場合にのみ、提示要求の処理を続行する。
 *
 * 1. `alg` が SDK の許可リスト（`RS256` / `ES256`）にあり、呼び出し側が Trust Anchor の
 *    `request_object_signing_alg_values_supported` を渡した場合はそこにも含まれる
 * 2. `x5c` の先頭証明書が Trust Anchor まで連鎖し、有効期間内で失効していない
 *    （信頼の起点判定は `jar-trust-evaluation.ts` に委譲する）
 * 3. その先頭証明書の公開鍵で JWS 署名が検証できる
 * 4. `iss == client_id`、かつ先頭証明書の SubjectAltName（URI）の origin ==
 *    `client_id` の origin == `response_uri` の origin
 * 5. `typ` が Request Object のもの（`oauth-authz-req+jwt`。RFC 9101 §10.8 の互換値 `JWT` も可）
 *    であること。型混同で他用途の JWS を Request Object として受理しない
 * 6. `exp` を持ち、`exp` / `nbf` / `iat` が 30 秒スキューの範囲で有効であること。署名済み要求の
 *    無期限再利用を止める（`jar-request-validity.ts`）
 *
 * **Trust Anchor は呼び出し側が渡す。** SDK は LOTL / TSL / OpenID Federation / ARF Catalogue の
 * 取得タイミングを決めない（`loadTrustedList` / `loadArfTrustAnchor` は DI シームで、取得と
 * キャッシュはアプリの責務。OpenID Federation の Trust Chain 構築（`buildTrustChain`）のみ、
 * Federation の設計上チェーン走査そのものが取得を伴う）。本モジュールは `trustAnchors` /
 * `federationTrustAnchor` / `arfTrustAnchor` を引数で受け取り、**いずれも渡されなければ検証
 * できないので拒否する**（fail-closed）。`walletProviderJwk` 未設定で WUA 取得が `10102` に
 * 倒れるのと同じ方針で、「信頼の起点が設定されていない」ことを「検証済み」に読み替えない。
 *
 * **3 層すべてを本モジュールが受け付ける。** `trustAnchors`
 * （ETSI TSL 由来の `QtspServiceCertificate`。LOTL→TSL 層）に加え、`federationTrustAnchor`
 * （OpenID Federation Trust Chain。OIDF 層）・`arfTrustAnchor`（ARF Trust Anchor Catalogue。
 * ARF 層）のいずれかで x5c 先頭証明書の起点が確認できれば受理する。3 層の統合・優先順位・
 * 競合解消（上位 REVOKED 時の fail-closed 拒否を含む）は各層の判定を `jar-trust-evaluation.ts`
 * が `trust/arf` の `evaluateTrust` へ渡して行う。
 *
 * セキュリティ上の注意:
 * - 失敗はすべて `8030` へ正規化し、`context.reason` は固定識別子のみ。証明書 DER・DN・
 *   Request Object 本文・`request_uri`・`cause` を載せない。
 * - オプションは `ownProperty` で読む（継承値が Trust Anchor 集合や検証基準時刻に化けると、
 *   攻撃者 CA が信頼の起点になり、期限切れ証明書が有効期間内と判定される）。
 */

import type { TtlCache } from '../../cache/index.js';
import { decodeCompactJwsOrThrow } from '../../credential/vc/jws.js';
import { ErrorCodes } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { ArfTrustAnchorSet } from '../../trust/arf/index.js';
import {
  type CertSignatureAlg,
  parseCertificate,
  type QtspServiceCertificate,
} from '../../trust/etsi-tsl/index.js';
import { verifySignature } from '../../trust/etsi-tsl/verify.js';
import { jarFailure } from './jar-failure.js';
import { requireIdentityBinding } from './jar-identity-binding.js';
import { requireRequestObjectValidity } from './jar-request-validity.js';
import type { JarFederationTrustAnchorOption } from './jar-trust-evaluation.js';
import { requireTrustedSigner } from './jar-trust-evaluation.js';
import { certSignatureAlgOf, extractX5cChain, jwsAlgOf } from './jar-x5c.js';

/**
 * JAR JWS 署名検証に必要な信頼の起点と突き合わせ材料。
 *
 * `trustAnchors` だけが必須である。他は「渡されたときにだけ追加で締める」検査で、渡されない
 * 場合は**その検査を省くのではなく、SDK 側の許可リストと Request Object 内の整合性検査だけで
 * 判定する**（`iss == client_id` と SubjectAltName 一致は Request Object と証明書だけで完結する
 * ため、常に効く）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export interface JarTrustOptions {
  /**
   * `x5c` チェーンの到達先とする Trust Anchor（ETSI TSL / LOTL 由来の QTSP サービス証明書）。
   *
   * `loadTrustedList` → `extractQtspCertificates` で得た集合をそのまま渡す。空配列 / 省略は
   * 「TSL 層は使わない」ことを意味する。`federationTrustAnchor` / `arfTrustAnchor` のいずれも
   * 渡されていなければ、信頼の起点が一切無いことになるため拒否する（fail-closed）。
   */
  readonly trustAnchors: readonly QtspServiceCertificate[];
  /**
   * `x5c` チェーンの起点として OpenID Federation Trust Chain を使う場合の設定。
   * 詳細は `JarFederationTrustAnchorOption` を参照。
   */
  readonly federationTrustAnchor?: JarFederationTrustAnchorOption;
  /**
   * `x5c` チェーンの起点として ARF Trust Anchor Catalogue を使う場合の設定。
   *
   * `loadArfTrustAnchor`（trust/arf）で取得・署名検証済みの集合をそのまま渡す。x5c 先頭証明書の
   * SPKI（subjectPublicKeyInfo）が Catalogue エントリの `spki` と一致する**だけでは受理しない**。
   * 加えてそのエントリの `id` が x5c 先頭証明書の SubjectAltName（URI）origin（渡されていれば
   * `expectedClientId` の origin も）と一致することを要求する（`jar-trust-arf.ts` 参照）。SPKI 一致のみで受理すると、Catalogue に登録済みの任意エンティティが
   * 自己署名証明書の SAN を偽装するだけで任意の RP（origin）になりすませてしまう。role が
   * `relying-party` のエントリのみを ARF 層の Trust Anchor として採用し、`wallet-provider` / `issuer` /
   * `attestation-provider` として登録されたエンティティは SPKI・origin が一致しても不採用とする。
   */
  readonly arfTrustAnchor?: ArfTrustAnchorSet;
  /**
   * 参照形式の deep link に載っていた `client_id`（例: `openid4vp://?client_id=<cid>`）。
   *
   * Request Object 内の `client_id` がこれと一致することを確認する。deep link 側と Request
   * Object 側で `client_id` が食い違う要求は、**ユーザが見た（あるいはアプリが表示した）相手と
   * 実際に署名した相手が違う**ことを意味するため拒否する。省略時はこの突き合わせを行わない
   * （呼び出し側が deep link を持たず Request Object だけを扱う低レベル用途）。OIDF 層を評価
   * する場合は本フィールドが実質必須になる（`federationTrustAnchor` の JSDoc 参照）。
   */
  readonly expectedClientId?: string;
  /**
   * `request_object_signing_alg_values_supported`。
   *
   * TSL / OIDF / ARF のいずれの場合も、対応する metadata は呼び出し側で取得して値を渡す。
   * 省略時は SDK の許可リスト（`RS256` / `ES256`。`jar-x5c.ts`）だけで判定する。
   */
  readonly requestObjectSigningAlgValuesSupported?: readonly string[];
  /**
   * Trusted List Status で失効と判定された RP 証明書のシリアル番号（16 進・小文字）。
   * 省略時は失効**未確認**として扱う（`verifyRpAccessCertificate` と同じ規則）。
   */
  readonly revokedSerials?: ReadonlySet<string>;
  /** 検証基準時刻（Unix 秒・任意。既定は現在時刻）。 */
  readonly now?: number;
  /**
   * RP Cert 判定結果（Trust Anchor 到達 + 失効チェック）の TTL キャッシュ。
   *
   * `trust/rp-access/cache.ts` の `createRpCertJudgmentCache` で生成する。渡すと、同一証明書 +
   * 同一 `trustAnchors` + 同一 `revokedSerials` の組み合わせは TTL（既定 45 分）内は再検証しない。
   * **省略時はキャッシュを使わず毎回検証する**（既定動作は変わらない）。TSL 単独（`federationTrustAnchor`
   * / `arfTrustAnchor` を渡さない）呼び出しでのみ使う（`jar-trust-evaluation.ts` 参照）。
   */
  readonly rpCertJudgmentCache?: TtlCache<boolean>;
}

/**
 * `trustAnchors` を own 限定で読む。`federationTrustAnchor` / `arfTrustAnchor` を含め、
 * 3 層のうちいずれも信頼の起点として設定されていなければ拒否する。
 *
 * `fetchJAR` は**取得より前に**本関数を呼ぶ。検証できないと判っている Request Object を
 * 取りに行く意味が無いだけでなく、Trust Anchor 未設定の呼び出しが `request_uri`（= 攻撃者が
 * 値を選べる URL）へ HTTP リクエストを出すこと自体が、SSRF と存在確認の副作用になるためである。
 * `verifyJarSignature` も自身で再度呼ぶ（多層防御。単独で呼ばれても素通りしない）。
 *
 * @returns `trustAnchors`（TSL 層。未設定 / 空配列なら空配列）。
 */
export function requireJarTrustAnchors(options: object): readonly QtspServiceCertificate[] {
  const anchors = ownProperty<readonly QtspServiceCertificate[]>(options, 'trustAnchors');
  const tslAnchors = Array.isArray(anchors) ? anchors : [];
  if (!hasAnyJarTrustSource(options)) {
    // 信頼の起点が一切無い状態を「検証済み」に読み替えない（fail-closed）。
    throw jarFailure('jar_trust_anchors_unconfigured');
  }
  return tslAnchors;
}

/**
 * TSL / OIDF / ARF のいずれか 1 つでも信頼の起点が設定されているかを own 限定で確かめる。
 *
 * `trustAnchors` は「空配列 = TSL 層は使わない」を意味するため、非空である場合のみ TSL 層が
 * 設定済みとみなす。`federationTrustAnchor` / `arfTrustAnchor` は値が渡されていれば設定済みと
 * みなす（内部で `expectedClientId` 欠落等によりさらに評価しない場合はあるが、それは
 * `requireTrustedSigner` 側の判断であり、ここでは「呼び出し側が起点を渡そうとしたか」だけを見る）。
 */
function hasAnyJarTrustSource(options: object): boolean {
  const anchors = ownProperty<readonly QtspServiceCertificate[]>(options, 'trustAnchors');
  const hasTsl = Array.isArray(anchors) && anchors.length > 0;
  const federation = ownProperty<unknown>(options, 'federationTrustAnchor');
  const arf = ownProperty<unknown>(options, 'arfTrustAnchor');
  return hasTsl || federation !== undefined || arf !== undefined;
}

/**
 * `alg` が SDK の許可リストと（渡されていれば）Verifier metadata の双方に含まれることを確かめる。
 *
 * @returns 証明書署名アルゴリズム（`verifySignature` に渡す形）。
 * @throws 許可されない `alg` の場合（8030）。
 */
function requireSupportedAlg(header: object, options: object): CertSignatureAlg {
  const alg = jwsAlgOf(header);
  const certAlg = certSignatureAlgOf(alg);
  if (alg === undefined || certAlg === undefined) {
    // `alg` 欠落 / `none` / MAC / 未対応の署名方式。
    throw jarFailure('unsupported_jar_alg');
  }
  const advertised = ownProperty<unknown>(options, 'requestObjectSigningAlgValuesSupported');
  if (advertised === undefined) {
    // 未指定 = SDK の許可リスト（`RS256` / `ES256`）だけで判定する。
    return certAlg;
  }
  // **指定されたが形が不正**な場合は署名アルゴリズムが告知リストに含まれるか確認できない。ここで黙って検査を
  // 飛ばすと「告知リストを渡したのに照合されていない」状態になり、呼び出し側は照合済みだと
  // 思い込む（fail-open）。渡された以上は照合できなければ拒否する。
  if (!Array.isArray(advertised) || !advertised.every((v) => typeof v === 'string')) {
    throw jarFailure('jar_alg_not_advertised');
  }
  if (!advertised.includes(alg)) {
    throw jarFailure('jar_alg_not_advertised');
  }
  return certAlg;
}

/**
 * 取得した JAR Request Object（コンパクト JWS）の署名と発行者同一性を検証する。
 *
 * 検証を通った場合のみ戻る（戻り値は無い）。`PresentationRequest` への正規化は呼び出し側
 * （`parseJarRequest`）が行う。検証結果を戻り値に載せないのは、本検証が**通過させるか否かの
 * ゲート**であり、呼び出し側に「検証したが結果を見ない」余地を残さないためである。
 *
 * @param jarJwt 取得済みの Request Object（コンパクト JWS）。
 * @param options Trust Anchor と突き合わせ材料。
 * @throws JWS 形式不正 / 未対応 `alg` / `x5c` 欠落・不正 / Trust Anchor 未到達 / 失効 /
 *         署名不正 / `iss != client_id` / ドメイン不一致 / `typ` 不一致 / `exp` 欠落・期限切れの場合
 *         （VericertsError、code `8030`。`context.reason` は固定識別子。非有限の `now` は `invalid_now`）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export async function verifyJarSignature(jarJwt: string, options: JarTrustOptions): Promise<void> {
  const anchors = requireJarTrustAnchors(options);
  // 非有限 `now`（NaN / Infinity）は下流の各層（Trust Anchor 評価・RP Cert・Request Object 有効期間）で
  // 扱いが食い違い、素の RangeError が漏れる。入口で 1 度だけ弾き 8030 に揃える。
  const now = ownProperty<unknown>(options, 'now');
  if (now !== undefined && !(typeof now === 'number' && Number.isFinite(now))) {
    throw jarFailure('invalid_now');
  }
  const decoded = decodeCompactJwsOrThrow(jarJwt, ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  const certAlg = requireSupportedAlg(decoded.header, options);
  const chain = extractX5cChain(decoded.header);
  if (chain === undefined) {
    throw jarFailure('missing_x5c');
  }
  await requireTrustedSigner(chain.leafDer, chain.intermediatesDer, anchors, options);
  let spki: Uint8Array;
  try {
    spki = parseCertificate(chain.leafDer).spki;
  } catch {
    // `requireTrustedSigner` を通った証明書はパースできるはずだが、鎖の途中で例外を
    // 「検証成功」に読み替えないため明示的に拒否する。
    throw jarFailure('invalid_x5c');
  }
  // `verifySignature` は fail-closed（import / verify の失敗は false）。ECDSA の JWS 署名は
  // raw(P1363・64B) で、DER 併用の正規化も同関数が担う。
  const signatureValid = await verifySignature(
    certAlg,
    spki,
    decoded.signature,
    decoded.signingInput,
  );
  if (!signatureValid) {
    throw jarFailure('jar_signature_invalid');
  }
  requireIdentityBinding(decoded.payload, chain.leafDer, options);
  requireRequestObjectValidity(decoded.header, decoded.payload, options);
}
