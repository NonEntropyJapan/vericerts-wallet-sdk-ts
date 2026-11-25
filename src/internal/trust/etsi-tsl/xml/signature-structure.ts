/**
 * enveloped `ds:Signature` の構造検証（trust/etsi-tsl）。
 *
 * 署名（SignatureValue）が掛かるのは `SignedInfo` のオクテットだけで、`KeyInfo` / `ds:Object` など
 * それ以外の領域は署名されない。したがって署名検証に使う値（アルゴリズム・ダイジェスト・署名者証明書）は
 * 署名済み領域または規定の位置からだけ取り出さなければならない。Signature 全体から `DigestValue` を
 * 探索すると、未署名領域へ注入されたダイジェストが本体ダイジェストとして受理されてしまう。
 *
 * 本モジュールは次を満たす場合にのみ検証材料を返す（それ以外は undefined = fail-closed）。
 *  - `Signature` はルート直下に 1 つだけ存在する（enveloped・署名が文書全体を覆う）。
 *  - `Signature` 直下に `SignedInfo` / `SignatureValue` / `KeyInfo` が各 1 つ。`Signature` 内の `SignedInfo` は 1 つのみ。
 *  - `SignedInfo` 直下の `Reference` はちょうど 1 件で、`URI=""`・Transform は enveloped-signature のみ・
 *    DigestMethod は SHA-256・`DigestValue` は 1 つ。
 *  - 署名者証明書は `KeyInfo/X509Data/X509Certificate`（最初の 1 件）。
 *
 * 署名対象オクテットの範囲（`signedInfoRange`）・除外範囲（`signatureRange`）も、値を読んだのと
 * **同じパースノード**の原文オフセットから返す。別の読み方（正規表現探索）で署名対象を決めると、
 * 検証する SignedInfo と DigestValue の取得元がずれて未署名の本体が通る。
 * `Signature` 内の `ds:Object` 等は署名されないため値としては一切使わない（`signed-region.ts` が
 * 抽出側で `Signature` 全体を除外する）。
 */

import type { XmlElement } from './parse.js';

const ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
const SHA256_DIGEST = 'http://www.w3.org/2001/04/xmlenc#sha256';

/** 検証に使う Signature の構成要素（すべて署名済み領域 / 規定位置から取り出した値）。 */
export interface SignatureParts {
  /** `SignedInfo/SignatureMethod@Algorithm`。 */
  readonly signatureMethod: string;
  /** `SignatureValue` のテキスト（base64）。 */
  readonly signatureValue: string;
  /** `KeyInfo/X509Data/X509Certificate` のテキスト（base64）。 */
  readonly certificate: string;
  /** `SignedInfo/Reference/DigestValue` のテキスト（base64）。 */
  readonly digestValue: string;
  /** 署名対象 `SignedInfo` の原文範囲 `[start, end)`（値を読んだ要素と同一のパースノードのオフセット）。 */
  readonly signedInfoRange: SourceRange;
  /** enveloped 変換で除外する `Signature` の原文範囲 `[start, end)`。 */
  readonly signatureRange: SourceRange;
}

/** 原文上の範囲 `[start, end)`。 */
export interface SourceRange {
  readonly start: number;
  readonly end: number;
}

/** 直下の子のうち、ローカル名が一致するものを返す。 */
function childrenNamed(el: XmlElement, localName: string): XmlElement[] {
  return el.children.filter((c) => c.localName === localName);
}

/** 直下の子のうち、ローカル名が一致するものがちょうど 1 件ならそれを返す。 */
function onlyChild(el: XmlElement, localName: string): XmlElement | undefined {
  const found = childrenNamed(el, localName);
  return found.length === 1 ? found[0] : undefined;
}

/** 子孫を含め、ローカル名が一致する要素の個数を数える。 */
function countByLocalName(root: XmlElement, localName: string): number {
  let count = root.localName === localName ? 1 : 0;
  for (const c of root.children) {
    count += countByLocalName(c, localName);
  }
  return count;
}

/** Reference が「文書全体 + enveloped-signature のみ + SHA-256」であることを確認し DigestValue を返す。 */
function envelopedDigestOf(reference: XmlElement): string | undefined {
  if (reference.attributes.URI !== '') {
    return undefined;
  }
  const transforms = onlyChild(reference, 'Transforms');
  const transform = transforms === undefined ? undefined : onlyChild(transforms, 'Transform');
  if (transform?.attributes.Algorithm !== ENVELOPED_SIGNATURE) {
    return undefined;
  }
  if (onlyChild(reference, 'DigestMethod')?.attributes.Algorithm !== SHA256_DIGEST) {
    return undefined;
  }
  return onlyChild(reference, 'DigestValue')?.text;
}

/**
 * ルート要素から enveloped Signature を取り出し、検証材料を返す。
 *
 * @param root 文書のルート要素。
 * @returns 構造が厳密に満たされた場合のみ検証材料。
 */
export function parseSignatureParts(root: XmlElement): SignatureParts | undefined {
  // 文書内の Signature はルート直下の 1 つだけ（入れ子・複数・ルート自身は不可）。
  const signature = onlyChild(root, 'Signature');
  if (signature === undefined || countByLocalName(root, 'Signature') !== 1) {
    return undefined;
  }
  const signedInfo = onlyChild(signature, 'SignedInfo');
  const signatureValue = onlyChild(signature, 'SignatureValue');
  const keyInfo = onlyChild(signature, 'KeyInfo');
  if (
    signedInfo === undefined ||
    signatureValue === undefined ||
    keyInfo === undefined ||
    countByLocalName(signature, 'SignedInfo') !== 1
  ) {
    return undefined;
  }
  const reference = onlyChild(signedInfo, 'Reference');
  const signatureMethod = onlyChild(signedInfo, 'SignatureMethod')?.attributes.Algorithm;
  const digestValue = reference === undefined ? undefined : envelopedDigestOf(reference);
  const x509Data = onlyChild(keyInfo, 'X509Data');
  const certificate =
    x509Data === undefined ? undefined : childrenNamed(x509Data, 'X509Certificate')[0];
  if (signatureMethod === undefined || digestValue === undefined || certificate === undefined) {
    return undefined;
  }
  return {
    signatureMethod,
    signatureValue: signatureValue.text,
    certificate: certificate.text,
    digestValue,
    signedInfoRange: { start: signedInfo.start, end: signedInfo.end },
    signatureRange: { start: signature.start, end: signature.end },
  };
}
