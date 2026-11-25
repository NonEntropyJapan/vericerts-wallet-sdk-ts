/**
 * trust/etsi-tsl テスト用の enveloped XMLDSig 署名 XML ビルダ。
 *
 * `verifyXmlDsig` の検証手順（SignedInfo 元オクテット署名 + enveloped 本体 SHA-256 ダイジェスト）に
 * 整合する署名 XML を Node `crypto` で生成する。production コードに XML 署名生成は持たせない。
 */

import { createSign, type KeyObject } from 'node:crypto';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64 } from '@scure/base';

/** SignatureMethod URI（RSA/EC）。 */
const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const ECDSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';

/** 既定の Reference（URI="" + enveloped-signature + SHA-256）。 */
function defaultReference(digest: string): string {
  return (
    `<ds:Reference URI="">` +
    `<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform></ds:Transforms>` +
    `<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>` +
    `<ds:DigestValue>${digest}</ds:DigestValue>` +
    `</ds:Reference>`
  );
}

/** 遠い未来の `NextUpdate`（`bodyInner` に `NextUpdate` が無いとき補う。期限切れ拒否を対象外にする）。 */
const FAR_FUTURE_SCHEME_INFORMATION =
  '<SchemeInformation><NextUpdate><dateTime>2999-01-01T00:00:00Z</dateTime></NextUpdate></SchemeInformation>';

/** enveloped 署名 XML を組み立てる。 */
export function signEnvelopedXml(opts: {
  /** 署名対象ルート開始（例 `<TrustServiceStatusList>`）。 */
  bodyOpen: string;
  /** ルート内の子要素群（署名前の本体内容）。 */
  bodyInner: string;
  /** ルート終了（例 `</TrustServiceStatusList>`）。 */
  bodyClose: string;
  /** 署名鍵。 */
  privateKey: KeyObject;
  /** 署名者証明書 DER。 */
  certDer: Uint8Array;
  /** 鍵種別。 */
  kind: 'rsa' | 'ec';
  /** SignedInfo 内の Reference 要素を差し替える（否定テスト用）。引数は本体ダイジェスト（base64）。 */
  referenceXml?: (digestB64: string) => string;
  /** `true` なら `NextUpdate` を補わない（`NextUpdate` 欠落の否定テスト用）。 */
  omitNextUpdate?: boolean;
  /** `ds:Signature` 内（`SignatureValue` の後）へ差し込む未署名の追加要素（Signature Wrapping の否定テスト用）。 */
  signatureExtra?: string;
}): string {
  const inner =
    opts.omitNextUpdate === true || opts.bodyInner.includes('NextUpdate')
      ? opts.bodyInner
      : FAR_FUTURE_SCHEME_INFORMATION + opts.bodyInner;
  // enveloped 本体 = 署名を除いた全 XML。verify 側の extractEnvelopedBody と一致させる。
  const body = `${opts.bodyOpen}${inner}${opts.bodyClose}`;
  const digest = base64.encode(sha256(new TextEncoder().encode(body)));
  const method = opts.kind === 'rsa' ? RSA_SHA256 : ECDSA_SHA256;
  const signedInfo =
    `<ds:SignedInfo>` +
    `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>` +
    `<ds:SignatureMethod Algorithm="${method}"></ds:SignatureMethod>` +
    (opts.referenceXml?.(digest) ?? defaultReference(digest)) +
    `</ds:SignedInfo>`;

  const signer = createSign('SHA256');
  signer.update(Buffer.from(new TextEncoder().encode(signedInfo)));
  signer.end();
  const sig = signer.sign(
    opts.kind === 'rsa' ? opts.privateKey : { key: opts.privateKey, dsaEncoding: 'der' },
  );
  const sigValue = base64.encode(Uint8Array.from(sig));
  const certB64 = base64.encode(opts.certDer);

  const signature =
    `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
    signedInfo +
    `<ds:SignatureValue>${sigValue}</ds:SignatureValue>` +
    `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>${certB64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>` +
    (opts.signatureExtra ?? '') +
    `</ds:Signature>`;

  // 署名を本体末尾（bodyClose の直前）に挿入。removeEnveloped で元 body に戻る。
  return `${opts.bodyOpen}${inner}${signature}${opts.bodyClose}`;
}
