/**
 * Qualified Certificate チェーン検証（trust/etsi-tsl）。
 *
 * リーフ証明書から TSL 由来の Trust Anchor（Qualified Trust Service Provider の CA 証明書）まで
 * のチェーンを検証する。課す検査は次の 9 つ:
 * (1) 各リンクの issuer/subject DN の連結（RFC 5280 §6.1.3 (a)(4)）、
 * (2) 各証明書の有効期間（Trust Anchor を含む。§6.1.3 (a)(2)）、
 * (3) 発行者公開鍵による署名検証（WebCrypto。§6.1.3 (a)(1)）、
 * (4) 中間証明書の basicConstraints `cA:TRUE`（§6.1.4 (k)）、
 * (5) 中間証明書の basicConstraints `pathLenConstraint`（§6.1.4 (m)）、
 * (6) 中間証明書の keyUsage `keyCertSign`（拡張がある場合。§6.1.4 (n)）、
 * (7) 中間証明書の nameConstraints を**その配下の全証明書**へ課す
 *     （RFC 5280 §6.1.3 (b)(c) / §6.1.4 (g)）、
 * (8) 同一 subject DN の再利用を拒否する（自己ループ検出。これが成り立つので
 *     pathLenConstraint の self-issued 例外を省ける）、
 * (9) leaf の keyUsage `digitalSignature` / `nonRepudiation`（拡張がある場合。§4.2.1.3）。
 * 加えて leaf / 中間証明書は、**解釈できない critical 拡張**を持つだけで拒否する
 * （§6.1.4 (f)。判定は `trust/x509/critical.ts`）。
 * 制約の解釈は `trust/x509/path-constraints.ts`（(4)〜(7)）と `trust/x509/ca-constraints.ts`（(9)）に
 * 置き、本モジュールは走査と適用順だけを持つ。
 *
 * **読み取れない拡張・評価できない制約は「制約なし」ではなく拒否に倒す（fail-closed）。** 拡張を
 * 壊すだけで制約が消えるなら、制約を読む意味が無い。
 *
 * **nameConstraints の評価範囲は directoryName（subject DN）と uniformResourceIdentifier
 * （URI SAN）に限る。** それ以外の GeneralName 種別（`dNSName` / `rfc822Name` / `iPAddress` 等）を
 * base に持つ nameConstraints、および nameConstraints が有効な区間でそれらの SAN を持つ証明書は、
 * 評価できないものとして `trusted:false` にする。SDK が証明書から読む識別子は URI SAN（RP の
 * `origin`、SD-JWT VC の `iss`）と subject DN だけで、評価規約を持たない名前形式を「制約なし」と
 * 読むと CA が絞ったはずの名前空間が黙って開くためである。DN の突き合わせはバイト列一致ではなく
 * 正規化（文字列型の差・大小・空白の吸収）で行い、正規化できない表現（BMPString 等）は
 * 「一致しない」ではなく「評価不能」として拒否する。
 *
 * **RFC 5280 の完全な path validation は行わない。** 行わない検査とその理由:
 * - **失効（CRL / OCSP）**: チェーン検証では見ない。呼び出し側が Trusted List の Status
 *   （granted 集合に Anchor が残っているか）で評価する。
 * - **extendedKeyUsage**: 値は検査しない。QTSP がリーフに載せる EKU は用途ごとに異なり、特定 OID を
 *   要求すると真正な Qualified Certificate を落とす。「この鍵でデータに署名してよいか」は
 *   keyUsage（(9)）で必要十分である。ただし critical で載っている場合は上記 §6.1.4 (f) により
 *   「解釈しない critical 拡張」として拒否になる。
 * - **policy constraints / certificate policies / inhibitAnyPolicy**: 値は検査しない。ポリシー OID の
 *   意味づけは QTSP ごとに異なり SDK が単独で判定できない。Qualified 判定は TSL のサービス種別で行う。
 *   critical で載っている場合の扱いは extendedKeyUsage と同じである。
 * - **Trust Anchor の拡張**: 課さない（有効期間だけ確認する）。Anchor は呼び出し側が設定する信頼の
 *   起点であり、攻撃者が差し込める `intermediatesDer` とは前提が違う（RFC 5280 §6.1 も同じ）。
 * - **発行者候補のバックトラック**: 行わない。各リンクで述語を通った最初の候補に確定する
 *   （{@link findSignedIssuer}）。
 *
 * **`intermediatesDer` は {@link MAX_INTERMEDIATES} 枚までしか受け取らない。** 候補ごとの署名検証は
 * 候補数に比例し、その枚数は `x5c` 由来＝攻撃者が決められるためである。
 *
 * セキュリティ上の注意:
 * - fail-closed。Trust Anchor に到達できない / いずれかのリンク検証に失敗した場合は `trusted:false`。
 * - 例外・戻り値に証明書本文 / DN を含めない。
 */

import { ownProperty } from '../../prototype-safety/own-property.js';
import {
  allowsNamesBelow,
  canIssueCertificates,
  withinPathLength,
} from '../x509/path-constraints.js';
import { verifySignature } from './verify.js';
import { derEquals, type ParsedCertificate, parseCertificate } from './x509.js';

/** チェーン検証結果。 */
export interface CertChainResult {
  /**
   * Trust Anchor まで連鎖し、docblock 冒頭の (1)〜(9)（および critical 拡張の検査）を
   * 全リンクが満たしたなら `true`。
   */
  readonly trusted: boolean;
  /** 到達した Trust Anchor の subject DN（DER）。未到達なら undefined。 */
  readonly anchorSubjectDer?: Uint8Array;
  /**
   * 検証に使った全証明書（leaf・辿った中間・到達した Anchor）の `notAfter` の最小値（Unix 秒）。
   * `trusted:true` のときだけ立つ。この時刻を過ぎるとチェーンは成立しなくなるため、判定結果を
   * 記憶する呼び出し側（RP Cert 判定キャッシュ）は有効期間をここで頭打ちにする。
   */
  readonly notAfter?: number;
}

/** チェーン検証のオプション。 */
export interface VerifyChainOptions {
  /** 信頼済み CA 証明書（TSL から抽出した QTSP の CA）の DER 群。 */
  readonly trustAnchorsDer: readonly Uint8Array[];
  /** 検証基準時刻（Unix 秒）。既定は現在時刻。 */
  readonly now?: number;
  /** チェーン深さの上限（ループ / 過大チェーン防止）。既定 5。 */
  readonly maxDepth?: number;
}

/**
 * チェーン深さの既定上限。
 *
 * RP Access Certificate の検証 API は、この定数が示す **5 段**を常に上限として使う。
 *
 * この既定上限は
 * `trust/rp-access/verify.ts`・`trust/etsi-tsl/etsi-tsl.ts`・`wallet/issuer-trust/x5c.ts` の
 * 3 経路で共有する。既定を変えると 3 経路すべての受理条件が動くので、引き上げは呼び出し側が
 * `maxDepth` を明示した場合に限る。
 */
const DEFAULT_MAX_DEPTH = 5;

/**
 * `intermediatesDer` として受け取る中間証明書の上限枚数。
 *
 * **なぜ要るか。** {@link findSignedIssuer} は候補ごとに公開鍵検証まで行うため、1 段あたりの
 * 署名検証回数が候補数 N に比例する（チェーン全体で最大 `N × maxDepth` 回）。N は JWS ヘッダの
 * `x5c`（`auth/jar/jar-x5c.ts`）由来で、**攻撃者が長さを決められる**。本物の中間と同じ subject DN
 * を持つおとり CA を並べるだけで検証回数を押し上げられるので、Anchor 側（呼び出し側が設定する
 * 有限集合）と違い明示的な上限が要る。事前パースも同じ N 回走る。
 *
 * 10 は運用上の余裕を見た値である。QTSP のチェーンは leaf を除いて 2〜3 段で、`maxDepth` の既定も
 * 5 段。上限を超えたバンドルは切り詰めずチェーンごと `trusted:false` にする（切り詰めると、
 * どの証明書を落としたかで結果が変わり fail-closed の判断が読めなくなる）。
 */
export const MAX_INTERMEDIATES = 10;

/** 証明書が基準時刻に有効か（notBefore ≤ now ≤ notAfter）。 */
function isTemporallyValid(cert: ParsedCertificate, now: number): boolean {
  return now >= cert.notBefore && now <= cert.notAfter;
}

/** `cert` が `issuer` の公開鍵で正しく署名されているか検証する。 */
async function isSignedBy(cert: ParsedCertificate, issuer: ParsedCertificate): Promise<boolean> {
  if (cert.signatureAlg === undefined) {
    return false;
  }
  return verifySignature(cert.signatureAlg, issuer.spki, cert.signature, cert.tbsBytes);
}

/**
 * `cert` の issuer DN に一致する Trust Anchor のうち、**実際に `cert` を署名したもの**を返す。
 *
 * **DN 一致の最初の 1 通で打ち切らない。** subject DN は攻撃者が自由に名乗れるので、正当な
 * Anchor と同じ DN を持つおとり証明書を `trustAnchorsDer` に紛れ込ませられる環境では、最初の
 * 候補だけを試す実装は正当なチェーンを `trusted:false` に落とす。署名検証まで候補ごとの述語に
 * 含め、通った候補を採用する。試行回数は Anchor 数で上限が決まる。
 */
async function findSignedAnchor(
  cert: ParsedCertificate,
  anchors: readonly ParsedCertificate[],
  now: number,
): Promise<ParsedCertificate | undefined> {
  for (const anchor of anchors) {
    if (!derEquals(anchor.subjectDer, cert.issuerDer) || !isTemporallyValid(anchor, now)) {
      continue;
    }
    if (await isSignedBy(cert, anchor)) {
      return anchor;
    }
  }
  return undefined;
}

/**
 * `cert` の発行者として使える中間証明書のうち、**実際に `cert` を署名したもの**を返す。
 *
 * 中間として使えるのは **CA を名乗る証明書だけ**（{@link canIssueCertificates}）。DN 一致だけで
 * 選ぶと、信頼済み QTSP が発行したエンドエンティティ証明書を中間に差し込める。さらに有効期間、
 * pathLenConstraint（{@link withinPathLength}）で段数、nameConstraints
 * （{@link allowsNamesBelow}）で配下の名前、critical 拡張（RFC 5280 §6.1.4 (f)）も確かめる。
 *
 * **制約も署名検証も候補ごとに評価する。** どれかを述語の外に出すと、それで落ちた 1 候補が
 * 他候補を試す前にチェーン全体を失敗させる（= おとり証明書 1 通で正当なチェーンを落とせる）。
 * 有効期間もここに含める — CA 証明書の更新期には**同一 subject DN・同一鍵の旧証明書と新証明書が
 * 同じ `x5c` バンドルに入る**のが通常運用であり、期限切れの旧証明書が先に来るだけで、新証明書で
 * 成立するはずのチェーンが落ちてしまう。
 *
 * **保証はこのリンク 1 本に閉じる（バックトラックしない）。** 述語を通った最初の候補に確定し、
 * その候補から先で Trust Anchor へ届かなくても他候補を試し直さない。したがって cross-signed
 * 中間証明書（同一 subject DN・同一 subject 鍵で 2 つの root に署名されたもの）が両方とも子の
 * 署名検証を通り、選ばれた側の発行者が `trustAnchorsDer` / `intermediatesDer` に無い場合は
 * チェーン全体が失敗する（root ロールオーバー時の cross-certification で起こり得る）。候補ごとの
 * 再帰にすれば直せるが、試行回数が候補数の深さ乗になるため、現状は「候補ごとの保証は当該リンクに
 * 限る」として単段の探索にとどめている。
 *
 * @param now 検証基準時刻（Unix 秒）。
 * @param depth そのまま「この候補 CA より下にある中間 CA の数」になる（depth=0 では `cert` が
 *   leaf なので候補の下に中間 CA は 0 個、depth=1 では 1 個…）。
 * @param below 候補より下（leaf 側）にある証明書すべて（leaf を含む）。
 */
async function findSignedIssuer(
  cert: ParsedCertificate,
  intermediates: readonly ParsedCertificate[],
  now: number,
  depth: number,
  below: readonly ParsedCertificate[],
): Promise<ParsedCertificate | undefined> {
  for (const candidate of intermediates) {
    if (
      !derEquals(candidate.subjectDer, cert.issuerDer) ||
      !isTemporallyValid(candidate, now) ||
      candidate.hasUnrecognizedCriticalExtension ||
      !canIssueCertificates(candidate.ca) ||
      !withinPathLength(candidate.ca, depth)
    ) {
      continue;
    }
    // nameConstraints の照合は名前数 × base 数の比較で、署名検証より高くつき得る。署名を持たない
    // 候補（DN だけ合わせたおとり）で計算を起こさせないよう、署名検証の**後**に評価する。
    // 件数そのものの上限は `name-constraints.ts` の MAX_NAME_CONSTRAINT_ENTRIES が担う。
    if ((await isSignedBy(cert, candidate)) && allowsNamesBelow(candidate.nameConstraints, below)) {
      return candidate;
    }
  }
  return undefined;
}

/**
 * リーフ証明書から Trust Anchor までのチェーンを検証する。
 *
 * 中間証明書は `intermediatesDer` から DN 連結で辿る。各リンクで有効期間と署名を確認し、辿る
 * 中間証明書には CA 制約（{@link canIssueCertificates} / {@link withinPathLength}）と
 * 名前制約（{@link allowsNamesBelow}）を、leaf には鍵用途（`canSignData`）を課す。
 * issuer が Trust Anchor に一致し、
 * かつ Anchor 公開鍵での署名検証に成功したら `trusted:true`。
 *
 * @param leafDer 検証対象（PID/QEAA Issuer）のリーフ証明書 DER。
 * @param intermediatesDer 中間 CA 証明書 DER 群（順不同）。
 * @param options Trust Anchor・基準時刻・深さ上限。
 * @returns チェーン検証結果。パース不能な入力は `trusted:false`。
 */
export async function verifyCertificateChain(
  leafDer: Uint8Array,
  intermediatesDer: readonly Uint8Array[],
  options: VerifyChainOptions,
): Promise<CertChainResult> {
  // 任意オプションは自身のプロパティに限って読む。継承した `now` は証明書
  // チェーンの有効期間検証を攻撃者が選んだ時刻で行わせ、期限切れ証明書を通す。継承した
  // `maxDepth` はチェーン長の上限を緩め、想定より深い（＝検証されにくい）経路を許す。
  const now = ownProperty<number>(options, 'now') ?? Math.floor(Date.now() / 1000);
  const maxDepth = ownProperty<number>(options, 'maxDepth') ?? DEFAULT_MAX_DEPTH;
  // 同関数の `now` / `maxDepth` は own 化済み。アンカー集合だけ鎖読みだと、汚染値が
  // Trust Anchor になり攻撃者 CA が発行した証明書チェーンが trusted になる。
  // 無検証の `as` キャストは own-property.ts の docblock が禁じているので、配列であることを
  // 確かめてから使う（そうでなければ Anchor を 1 つも持たない = 到達不能）。
  const trustAnchorsDer = ownProperty<unknown>(options, 'trustAnchorsDer');
  if (!Array.isArray(trustAnchorsDer)) {
    return { trusted: false };
  }
  // 候補ごとの署名検証（{@link findSignedIssuer}）は候補数に比例する。`x5c` 由来で攻撃者が
  // 長さを決められるため、パースの前に枚数で落とす。
  if (intermediatesDer.length > MAX_INTERMEDIATES) {
    return { trusted: false };
  }
  let anchors: ParsedCertificate[];
  let intermediates: ParsedCertificate[];
  let current: ParsedCertificate;
  try {
    anchors = (trustAnchorsDer as readonly Uint8Array[]).map(parseCertificate);
    intermediates = intermediatesDer.map(parseCertificate);
    current = parseCertificate(leafDer);
  } catch {
    return { trusted: false };
  }

  // **leaf にだけ**データ署名の許可を要求する。leaf の公開鍵は必ず JWS 署名の検証鍵として使われる
  // （`wallet/issuer-trust/x5c.ts` の Issuer 鍵解決・`trust/rp-access/verify.ts`・
  // `auth/jar/jar-trust-evaluation.ts`）。CA が keyUsage で「この鍵で任意のデータに署名しては
  // ならない」と書いた証明書を通すと、その用途違反をチェーン検証が追認してしまう。
  // 中間証明書には課さない — 中間の用途は `keyCertSign`（{@link canIssueCertificates}）で既に
  // 見ており、証明書発行専用に keyUsage を絞った真正な CA をここで落とす理由が無い。
  if (!current.canSignData) {
    return { trusted: false };
  }
  // RFC 5280 §6.1.4 (f): 解釈しない critical 拡張を持つ証明書は使わない（中間証明書側の
  // 同じ検査は {@link findSignedIssuer} が候補ごとに行う）。
  if (current.hasUnrecognizedCriticalExtension) {
    return { trusted: false };
  }

  const usedSubjects = new Set<string>();
  let earliestNotAfter = Number.POSITIVE_INFINITY;
  // 候補 CA の nameConstraints は**その下にある証明書すべて**に課すので、辿った順に積む。
  const below: ParsedCertificate[] = [];
  for (let depth = 0; depth < maxDepth; depth++) {
    below.push(current);
    if (!isTemporallyValid(current, now)) {
      return { trusted: false };
    }
    // 自己ループ検出（同一 subject を 2 度使わない）。
    const subjectKey = hexOf(current.subjectDer);
    if (usedSubjects.has(subjectKey)) {
      return { trusted: false };
    }
    usedSubjects.add(subjectKey);
    earliestNotAfter = Math.min(earliestNotAfter, current.notAfter);

    const anchor = await findSignedAnchor(current, anchors, now);
    if (anchor !== undefined) {
      return {
        trusted: true,
        anchorSubjectDer: anchor.subjectDer,
        notAfter: Math.min(earliestNotAfter, anchor.notAfter),
      };
    }
    const issuer = await findSignedIssuer(current, intermediates, now, depth, below);
    if (issuer === undefined) {
      return { trusted: false };
    }
    current = issuer;
  }
  return { trusted: false };
}

/** DN(DER) を 16 進文字列に（ループ検出のキー用途）。 */
function hexOf(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) {
    out += b.toString(16).padStart(2, '0');
  }
  return out;
}
