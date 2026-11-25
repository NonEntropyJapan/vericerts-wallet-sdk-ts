/**
 * LOTL / TSL の XMLDSig 署名者証明書を Trust Anchor へ連結させる検査。
 *
 * `xmldsig.ts` の `verifyXmlDsig` は**検証対象の XML 自身**の `ds:KeyInfo/ds:X509Certificate` を
 * 署名鍵として取り出すため、その成否が示すのは「この文書は自分が署名したと主張している」ことだけ
 * である。つまり自己署名の Trusted List もそのまま通る。`loadTrustedList` の戻り値
 * （`serviceCertificates`）は `createWallet({ rpTrustAnchors })` / `{ issuerTrustAnchors }` を経て
 * `jar-signature.ts` / `issuer-trust/x5c.ts` の Trust Anchor になるため、ここを素通りさせると
 * **RP と Issuer の信頼の起点全体が取得元 URL への TLS だけに依存**し、暗号的なアンカリングが
 * ゼロになる。
 *
 * 本モジュールは呼び出し側が設定した Trust Anchor（LOTL 運用者の署名証明書、加盟国 TSL なら LOTL の
 * `ServiceDigitalIdentity` が示す証明書）へ署名者証明書を連結させる。**アンカーは文書からは導出
 * しない** — 文書自身から導いたアンカーは何も縛らない。
 *
 * 配置: `etsi-tsl/` 直下は linterly のディレクトリ行数上限（`.linterly.yml`）に達しているため、
 * 本検査は同階層のサブモジュールとして切り出す。
 */

import { ownProperty } from '../../../prototype-safety/own-property.js';
import { verifyCertificateChain } from '../chain.js';
import { derEquals, parseCertificate } from '../x509.js';

/** `loadTrustedList` のうち署名者アンカリングに関わるオプション。 */
export interface SigningAnchorOptions {
  /**
   * LOTL / TSL の **XMLDSig 署名者証明書**を連結させる Trust Anchor（DER）。
   *
   * 設定すると署名検証の成功に加えてチェーン検証（`chain.ts`）を課し、連結しなければ署名検証失敗
   * （LOTL: 10302 / TSL: 5002）で拒否する。`verifyQualifiedCertificate` の `trustAnchors`（TSL の
   * **中身**である QTSP CA）とは対象が別で、こちらは Trusted List 文書そのものの署名者を縛る。
   *
   * **省略・空配列なら拒否せず、結果の `signatureAnchored` を `false` にする。** 既存呼び出しの
   * 互換性を保つための扱いであり、「アンカー未設定でも検証済み」という意味ではない。
   *
   * **明示指定したが配列でない / `Uint8Array` 以外を含む場合は「未設定」に畳まず拒否する**
   * （10302 / 5002）。畳むと、素の `Uint8Array` を 1 つ渡した・`Set` を渡した・JSON 往復で
   * `{"0":...}` になった、のいずれもが「アンカー未設定」と同じ受理に落ち、呼び出し側は
   * ピン留めしたつもりのまま何もピン留めしていない状態になる（`loadTrustedList` の
   * `explicitInvalidKind` と同じ規律）。
   */
  readonly signingTrustAnchorsDer?: readonly Uint8Array[];
}

/** `loadTrustedList` の結果のうち署名者アンカリングに関わる部分。 */
export interface SigningAnchorResult {
  /**
   * 署名者証明書が `signingTrustAnchorsDer` の Trust Anchor へ連結したか。
   *
   * **`signatureValid: true` だけでは信頼の起点は無い**（本モジュール冒頭）。アンカー未設定なら
   * `false` になるのは、そのギャップを公開境界で沈黙させないためである（`jar-signature.ts` の
   * `jar_trust_anchors_unconfigured` と同じ方針で、信頼の起点が設定されていないことを「検証済み」に
   * 読み替えない）。`serviceCertificates` を Trust Anchor として採用する運用では
   * **`signatureAnchored: false` の結果を使わないこと**。
   */
  readonly signatureAnchored: boolean;
}

/**
 * 署名者証明書のアンカリングを判定する。
 *
 * Trust Anchor は own 限定で読む。継承値を拾うと攻撃者が `Object.prototype` へ置いた
 * 証明書が信頼の起点になり、`verifyCertificateChain` 側の own 限定読み取りと同じ穴がその 1 つ手前で
 * 開く。
 *
 * **「未設定」と「明示指定したが不正」を区別する。** 未設定（`undefined`）と空配列だけが
 * `signatureAnchored: false` での受理で、配列でない値や `Uint8Array` 以外を含む配列は拒否
 * （`undefined` を返す）。不正値を「未設定」に畳むと fail-open になる（{@link SigningAnchorOptions}）。
 * 無検証の `as` キャストは `own-property.ts` の docblock が禁じているため、要素まで実型で確かめる。
 *
 * 受理するのは 2 形だけである: **署名者証明書そのものがピン留めされている**（DER 完全一致。
 * {@link isPinnedSigningCert}）か、**アンカーが直接発行した証明書**（{@link verifyCertificateChain}）
 * か。中間証明書は受け取らない — 文書側が中間を差し込める口を開くと攻撃者が連結経路を選べる
 * （`x5c` と同じ問題）。
 *
 * DER 一致をチェーン検証の前に置くのは、`verifyCertificateChain` がアンカーへ到達する条件が
 * 「アンカーの subject DN が証明書の issuer DN と一致し、かつアンカーの鍵でその証明書が署名されて
 * いる」ことだけであり、**自己署名でない証明書を自分自身でピン留めしても一致しない**ためである
 * （subject ≠ issuer）。実在の EU LOTL 署名証明書は QTSP CA が発行したもので自己署名ではないので、
 * これが無いと運用者は発行 CA 全体（＝要求より広い信頼）をピン留めするしかなくなる。
 *
 * @param options `loadTrustedList` のオプション（`signingTrustAnchorsDer` を own 限定で読む）。
 * @param signingCertDer `verifyXmlDsig` が取り出した署名者証明書 DER。
 * @param nowSeconds チェーン検証の基準時刻（エポック秒）。
 * @returns アンカー未設定（省略・空配列）なら `false`、連結したなら `true`、**連結しない / アンカー
 *          指定が不正なら `undefined`**（呼び出し側が署名検証失敗として拒否する）。
 */
export async function resolveSigningAnchor(
  options: object,
  signingCertDer: Uint8Array | undefined,
  nowSeconds: number,
): Promise<boolean | undefined> {
  const anchors = ownProperty<unknown>(options, 'signingTrustAnchorsDer');
  if (anchors === undefined) {
    return false;
  }
  if (!Array.isArray(anchors)) {
    return undefined;
  }
  if (anchors.length === 0) {
    return false;
  }
  const anchorsDer = anchors.filter((a: unknown): a is Uint8Array => a instanceof Uint8Array);
  if (anchorsDer.length !== anchors.length) {
    return undefined;
  }
  if (signingCertDer === undefined) {
    return undefined;
  }
  if (isPinnedSigningCert(anchorsDer, signingCertDer, nowSeconds)) {
    return true;
  }
  const chain = await verifyCertificateChain(signingCertDer, [], {
    trustAnchorsDer: anchorsDer,
    now: nowSeconds,
  });
  return chain.trusted ? true : undefined;
}

/**
 * 署名者証明書そのものが Trust Anchor としてピン留めされているかを判定する（DER 完全一致）。
 *
 * **等価判定は DER のバイト列で行う。** subject DN や公開鍵での突き合わせは、攻撃者が同じ DN / 同じ
 * 鍵を名乗る別証明書（有効期間や拡張だけ違うもの）を作れる余地を残す。ピン留めは「この 1 通」を
 * 指す操作なので、比較対象もその 1 通のバイト列そのものにする。
 *
 * **有効期間は一致しても確かめる。** `verifyCertificateChain` はアンカー経由でもリーフの有効期間を
 * 課す（`chain.ts` の (2)）ので、ここを省くとピン留め経路だけが期限切れ証明書を通す抜け道になる。
 * パースできない DER は有効期間を評価できないため拒否に倒す（fail-closed）。
 *
 * @param anchorsDer ピン留めされた Trust Anchor の DER 群。
 * @param signingCertDer `verifyXmlDsig` が取り出した署名者証明書 DER。
 * @param nowSeconds 有効期間の基準時刻（エポック秒）。
 * @returns ピン留め済みかつ基準時刻に有効なら `true`。
 */
function isPinnedSigningCert(
  anchorsDer: readonly Uint8Array[],
  signingCertDer: Uint8Array,
  nowSeconds: number,
): boolean {
  if (!anchorsDer.some((anchor) => derEquals(anchor, signingCertDer))) {
    return false;
  }
  try {
    const cert = parseCertificate(signingCertDer);
    return nowSeconds >= cert.notBefore && nowSeconds <= cert.notAfter;
  } catch {
    return false;
  }
}
