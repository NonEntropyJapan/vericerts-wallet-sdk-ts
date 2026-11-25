import { describe, expect, test } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64 } from '@scure/base';
import { findAllByLocalName, findByLocalName, parseXml } from '../../xml/parse.js';
import { verifyXmlDsig } from '../../xml/xmldsig.js';
import { makeCertificate } from '../fixtures.js';
import { signEnvelopedXml } from './xml-fixtures.js';

describe('parseXml', () => {
  test('要素・属性・テキスト・名前空間 prefix を読む', () => {
    const root = parseXml('<a:Root x="1"><b:Child>hello</b:Child></a:Root>');
    expect(root.localName).toBe('Root');
    expect(root.attributes.x).toBe('1');
    const child = findByLocalName(root, 'Child');
    expect(child?.text).toBe('hello');
  });

  test('自己終了タグと複数一致を扱う', () => {
    const root = parseXml('<Root><Item/><Item/></Root>');
    expect(findAllByLocalName(root, 'Item').length).toBe(2);
  });

  test('DOCTYPE は解釈せず削除する（XXE 対策）', () => {
    const root = parseXml('<!DOCTYPE foo><Root>ok</Root>');
    expect(root.localName).toBe('Root');
    expect(root.text).toBe('ok');
  });

  test('閉じタグ不一致は例外', () => {
    expect(() => parseXml('<a></b>')).toThrow();
  });
});

const BODY_OPEN = '<TrustServiceStatusList>';
const BODY_INNER = '<SchemeName>EU</SchemeName>';
const BODY_CLOSE = '</TrustServiceStatusList>';

describe('verifyXmlDsig（enveloped）', () => {
  test('RSA 署名済み TSL を検証し署名者証明書を返す', async () => {
    const cert = makeCertificate({ cn: 'TSL Signer', kind: 'rsa' });
    const xml = signEnvelopedXml({
      bodyOpen: BODY_OPEN,
      bodyInner: BODY_INNER,
      bodyClose: BODY_CLOSE,
      privateKey: cert.privateKey,
      certDer: cert.der,
      kind: 'rsa',
    });
    const result = await verifyXmlDsig(xml);
    expect(result.valid).toBe(true);
    expect(result.signingCertDer).toBeDefined();
  });

  test('EC 署名済み LOTL を検証する', async () => {
    const cert = makeCertificate({ cn: 'LOTL Signer', kind: 'ec' });
    const xml = signEnvelopedXml({
      bodyOpen: BODY_OPEN,
      bodyInner: BODY_INNER,
      bodyClose: BODY_CLOSE,
      privateKey: cert.privateKey,
      certDer: cert.der,
      kind: 'ec',
    });
    const result = await verifyXmlDsig(xml);
    expect(result.valid).toBe(true);
  });

  test('本体を改ざんするとダイジェスト不一致で false', async () => {
    const cert = makeCertificate({ cn: 'Signer', kind: 'rsa' });
    const xml = signEnvelopedXml({
      bodyOpen: BODY_OPEN,
      bodyInner: BODY_INNER,
      bodyClose: BODY_CLOSE,
      privateKey: cert.privateKey,
      certDer: cert.der,
      kind: 'rsa',
    });
    const tampered = xml.replace('<SchemeName>EU</SchemeName>', '<SchemeName>XX</SchemeName>');
    const result = await verifyXmlDsig(tampered);
    expect(result.valid).toBe(false);
  });

  test('SignatureValue を差し替えると署名検証で false', async () => {
    const cert = makeCertificate({ cn: 'Signer', kind: 'rsa' });
    const xml = signEnvelopedXml({
      bodyOpen: BODY_OPEN,
      bodyInner: BODY_INNER,
      bodyClose: BODY_CLOSE,
      privateKey: cert.privateKey,
      certDer: cert.der,
      kind: 'rsa',
    });
    const broken = xml.replace(
      /<ds:SignatureValue>[^<]+<\/ds:SignatureValue>/,
      '<ds:SignatureValue>AAAA</ds:SignatureValue>',
    );
    const result = await verifyXmlDsig(broken);
    expect(result.valid).toBe(false);
  });

  test('Signature が無い XML は false', async () => {
    const result = await verifyXmlDsig('<TrustServiceStatusList></TrustServiceStatusList>');
    expect(result.valid).toBe(false);
  });

  test('本体に SignedInfo 風の要素があっても Signature 内へスコープして検証する', async () => {
    const cert = makeCertificate({ cn: 'Scoped Signer', kind: 'rsa' });
    // 本文に囮の SignedInfo を仕込む。抽出が Signature 要素内にスコープしていれば影響しない。
    const decoy = '<ds:SignedInfo>decoy</ds:SignedInfo>';
    const xml = signEnvelopedXml({
      bodyOpen: BODY_OPEN,
      bodyInner: `${decoy}${BODY_INNER}`,
      bodyClose: BODY_CLOSE,
      privateKey: cert.privateKey,
      certDer: cert.der,
      kind: 'rsa',
    });
    const result = await verifyXmlDsig(xml);
    expect(result.valid).toBe(true);
  });

  describe('署名ラッピング / ダイジェスト注入の拒否', () => {
    const cert = makeCertificate({ cn: 'Attack Signer', kind: 'rsa' });
    const sign = (referenceXml?: (digest: string) => string): string =>
      signEnvelopedXml({
        bodyOpen: BODY_OPEN,
        bodyInner: BODY_INNER,
        bodyClose: BODY_CLOSE,
        privateKey: cert.privateKey,
        certDer: cert.der,
        kind: 'rsa',
        ...(referenceXml === undefined ? {} : { referenceXml }),
      });

    test('KeyInfo の外へ注入した改ざん本体の DigestValue は採用しない', async () => {
      const evilBody = `${BODY_OPEN}<SchemeName>EVIL</SchemeName>${BODY_CLOSE}`;
      const evilDigest = base64.encode(sha256(new TextEncoder().encode(evilBody)));
      const forged = sign()
        .replace('<SchemeName>EU</SchemeName>', '<SchemeName>EVIL</SchemeName>')
        .replace(
          '</ds:KeyInfo>',
          `</ds:KeyInfo><ds:Object><ds:DigestValue>${evilDigest}</ds:DigestValue></ds:Object>`,
        );
      expect((await verifyXmlDsig(forged)).valid).toBe(false);
    });

    test('コメント内の偽 Signature タグで本体の一部をダイジェスト対象外にできない', async () => {
      // 元の本体が空コメントを含む場合、偽の開始 / 終了タグを両コメント内に置くと、旧実装は
      // 「偽開始 〜 偽終了」を Signature 範囲とみなし、間に挟んだ EVIL を未検証のまま通した。
      const signed = signEnvelopedXml({
        bodyOpen: BODY_OPEN,
        bodyInner: `${BODY_INNER}<!--  -->`,
        bodyClose: BODY_CLOSE,
        privateKey: cert.privateKey,
        certDer: cert.der,
        kind: 'rsa',
      });
      const sigStart = signed.indexOf('<ds:Signature');
      const sigEnd = signed.indexOf('</ds:Signature>') + '</ds:Signature>'.length;
      const signature = signed.slice(sigStart, sigEnd);
      const forged =
        `${BODY_OPEN}${BODY_INNER}<!-- <ds:Signature> --><SchemeName>EVIL</SchemeName>` +
        `${signature}<!-- </ds:Signature> -->${BODY_CLOSE}`;
      expect((await verifyXmlDsig(forged)).valid).toBe(false);
    });

    test('Reference が 2 件ある署名は拒否する', async () => {
      const xml = sign((d) => {
        const ref = `<ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>${d}</ds:DigestValue></ds:Reference>`;
        return ref + ref;
      });
      expect((await verifyXmlDsig(xml)).valid).toBe(false);
    });

    test('URI が空でない Reference は拒否する', async () => {
      const xml = sign(
        (d) =>
          `<ds:Reference URI="#other"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>${d}</ds:DigestValue></ds:Reference>`,
      );
      expect((await verifyXmlDsig(xml)).valid).toBe(false);
    });

    test('enveloped-signature 以外の Transform は拒否する', async () => {
      const xml = sign(
        (d) =>
          `<ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>${d}</ds:DigestValue></ds:Reference>`,
      );
      expect((await verifyXmlDsig(xml)).valid).toBe(false);
    });

    test('SHA-256 以外の DigestMethod は拒否する', async () => {
      const xml = sign(
        (d) =>
          `<ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"></ds:DigestMethod><ds:DigestValue>${d}</ds:DigestValue></ds:Reference>`,
      );
      expect((await verifyXmlDsig(xml)).valid).toBe(false);
    });

    test('KeyInfo 外（ds:Object）の X509Certificate は署名者証明書として採用しない', async () => {
      const signed = sign();
      const other = makeCertificate({ cn: 'Other', kind: 'rsa' });
      const certB64 = base64.encode(cert.der);
      // 正規の KeyInfo から証明書を抜き、ds:Object 側へ移す。
      const moved = signed
        .replace(`<ds:X509Certificate>${certB64}</ds:X509Certificate>`, '')
        .replace(
          '</ds:KeyInfo>',
          `</ds:KeyInfo><ds:Object><ds:X509Certificate>${certB64}</ds:X509Certificate></ds:Object>`,
        );
      expect(other.der.length).toBeGreaterThan(0);
      expect((await verifyXmlDsig(moved)).valid).toBe(false);
    });
  });
});
