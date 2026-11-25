/**
 * XMLDSig（enveloped 署名）検証（trust/etsi-tsl）。
 *
 * ETSI TS 119 612 の LOTL / TSL は `ds:Signature`（enveloped）で署名される。本モジュールは
 * その署名を検証する。汎用 XMLDSig ライブラリ（xml-crypto 等・Node 専用 DOM 依存）は導入せず、
 * `xml.ts` の軽量パーサと `verify.ts`（WebCrypto）で構成する。
 *
 * 検証手順:
 *  1. `ds:SignedInfo` の署名対象オクテットを原文からそのまま抽出する（再カノニカライズによる
 *     バイト差異を避けるため、機械生成 XML の元バイトを署名対象とみなす enveloped 前提）。範囲は
 *     DigestValue 等を読むのと同じパースノードの `start` / `end`（正規表現探索は使わない）。
 *  2. `ds:SignatureValue` を base64 デコードする。
 *  3. `ds:KeyInfo/ds:X509Data/ds:X509Certificate` の署名者公開鍵（SPKI）で SignedInfo 署名を検証する。
 *  4. `ds:SignedInfo` 内の唯一の `ds:Reference`（`URI=""`・enveloped-signature のみ・SHA-256）の
 *     `DigestValue` が対象文書（Signature 要素を除いた本体）の SHA-256 と一致するか検証する。
 *
 * セキュリティ上の注意:
 * - fail-closed。抽出・デコード・検証のいずれかに失敗したら `false`。
 * - **`valid: true` は信頼の起点を意味しない**（署名鍵は検証対象の XML 自身から取り出すため、単体では
 *   自己署名の LOTL / TSL も通る）。どの Trust Anchor に連結するかの判定は呼び出し側の責務であり、
 *   `loadTrustedList` の `signingTrustAnchorsDer` で設定する（未設定は同関数の戻り値
 *   `signatureAnchored: false` として公開境界に現れる）。
 * - 例外・戻り値に XML 本文 / 鍵素材を含めない。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64 } from '@scure/base';
import { verifySignature } from '../verify.js';
import { type ParsedCertificate, parseCertificate } from '../x509.js';
import { parseXml } from './parse.js';
import { parseSignatureParts, type SignatureParts } from './signature-structure.js';

/** XMLDSig 検証の結果。 */
export interface XmlDsigResult {
  /** 署名（SignedInfo）と参照ダイジェストの双方が有効なら `true`。 */
  readonly valid: boolean;
  /** 署名に使われた X.509 証明書（KeyInfo から抽出、DER）。抽出できなければ undefined。 */
  readonly signingCertDer?: Uint8Array;
}

/** SignatureMethod OID/URI → 証明書署名アルゴリズム。 */
const SIG_METHOD_ALG: Readonly<Record<string, 'RSASSA-PKCS1-v1_5-SHA256' | 'ECDSA-P256-SHA256'>> = {
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'RSASSA-PKCS1-v1_5-SHA256',
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256': 'ECDSA-P256-SHA256',
};

/** SignatureValue / DigestValue / X509Certificate のテキストから base64 デコードする（空白除去）。 */
function decodeBase64Text(text: string): Uint8Array {
  return base64.decode(text.replace(/\s+/g, ''));
}

/** 署名者証明書（base64 DER）をパースする。 */
function parseSigningCert(text: string):
  | {
      der: Uint8Array;
      cert: ParsedCertificate;
    }
  | undefined {
  if (text.trim().length === 0) {
    return undefined;
  }
  try {
    const der = decodeBase64Text(text);
    return { der, cert: parseCertificate(der) };
  } catch {
    return undefined;
  }
}

/** 定数時間ではないが早期 return しない bytes 比較（ダイジェスト照合用）。 */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] as number) ^ (b[i] as number);
  }
  return diff === 0;
}

/**
 * enveloped XMLDSig 署名を検証する。
 *
 * 検証材料（アルゴリズム・ダイジェスト・署名者証明書）は `signature-structure.ts` が規定位置から
 * 厳密に取り出す。署名が掛かる `SignedInfo` の外（`KeyInfo` / `ds:Object` 等）の値は採用しない。
 *
 * @param xml LOTL / TSL の XML テキスト（`ds:Signature` を含む）。
 * @returns 検証結果（valid・署名者証明書 DER）。
 */
export async function verifyXmlDsig(xml: string): Promise<XmlDsigResult> {
  let parts: SignatureParts | undefined;
  try {
    parts = parseSignatureParts(parseXml(xml));
  } catch {
    return { valid: false };
  }
  if (parts === undefined) {
    return { valid: false };
  }
  const alg = Object.hasOwn(SIG_METHOD_ALG, parts.signatureMethod)
    ? SIG_METHOD_ALG[parts.signatureMethod]
    : undefined;
  const signingCert = parseSigningCert(parts.certificate);
  if (alg === undefined || signingCert === undefined) {
    return { valid: false };
  }
  // 署名対象は、値（DigestValue 等）を読んだ SignedInfo ノード自身の原文範囲。
  const { signedInfoRange, signatureRange } = parts;
  const signedInfoOctets = new TextEncoder().encode(
    xml.slice(signedInfoRange.start, signedInfoRange.end),
  );

  let signatureBytes: Uint8Array;
  let expectedDigest: Uint8Array;
  try {
    signatureBytes = decodeBase64Text(parts.signatureValue);
    expectedDigest = decodeBase64Text(parts.digestValue);
  } catch {
    return { valid: false };
  }

  const sigOk = await verifySignature(alg, signingCert.cert.spki, signatureBytes, signedInfoOctets);
  if (!sigOk) {
    return { valid: false };
  }

  // enveloped transform: Signature 要素を除いた本体の SHA-256 が、SignedInfo 内 Reference の DigestValue と一致すること。
  const body = new TextEncoder().encode(
    xml.slice(0, signatureRange.start) + xml.slice(signatureRange.end),
  );
  if (!bytesEqual(sha256(body), expectedDigest)) {
    return { valid: false };
  }
  return { valid: true, signingCertDer: signingCert.der };
}
