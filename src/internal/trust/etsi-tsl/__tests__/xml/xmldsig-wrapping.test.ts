/**
 * enveloped XMLDSig の Signature Wrapping / 解釈ずれ回帰テスト。
 *
 * 署名検証が使う SignedInfo と DigestValue の取得元が同一ノードであること、`ds:Signature` 内の
 * 未署名要素（`ds:Object` 等）が抽出結果に現れないことを固定する。
 */

import { describe, expect, test } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64 } from '@scure/base';
import {
  extractNextUpdate,
  extractQtspCertificates,
  extractTslPointers,
  grantedTrustAnchors,
} from '../../tsl.js';
import { parseXml } from '../../xml/parse.js';
import { verifyXmlDsig } from '../../xml/xmldsig.js';
import { makeCertificate } from '../fixtures.js';
import { signEnvelopedXml } from './xml-fixtures.js';

const OPEN = '<TrustServiceStatusList>';
const CLOSE = '</TrustServiceStatusList>';
const DS = 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"';
const SVC_TYPE = 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC';
const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';

const signer = makeCertificate({ cn: 'TSL Signer', kind: 'ec' });
const legitCa = makeCertificate({ cn: 'Legit CA', kind: 'rsa' });
const attackerCa = makeCertificate({ cn: 'Attacker CA', kind: 'rsa' });

function service(certDer: Uint8Array): string {
  return (
    `<TSPService><ServiceInformation><ServiceTypeIdentifier>${SVC_TYPE}</ServiceTypeIdentifier>` +
    `<ServiceStatus>${GRANTED}</ServiceStatus><ServiceDigitalIdentity><DigitalId>` +
    `<X509Certificate>${base64.encode(certDer)}</X509Certificate></DigitalId></ServiceDigitalIdentity>` +
    `</ServiceInformation></TSPService>`
  );
}

const LEGIT_INNER =
  '<SchemeInformation><NextUpdate><dateTime>2999-01-01T00:00:00Z</dateTime></NextUpdate></SchemeInformation>' +
  `<OtherTSLPointer><TSLLocation>https://legit.example/tsl.xml</TSLLocation></OtherTSLPointer>${service(legitCa.der)}`;

function sign(extra: Record<string, unknown> = {}): string {
  return signEnvelopedXml({
    bodyOpen: OPEN,
    bodyInner: LEGIT_INNER,
    bodyClose: CLOSE,
    privateKey: signer.privateKey,
    certDer: signer.der,
    kind: 'ec',
    ...extra,
  });
}

/** 署名済み XML から `<tag>…</tag>` の最初の出現を取り出す。 */
function pick(xml: string, tag: string): string {
  const m = new RegExp(`<ds:${tag}[ >][\\s\\S]*?</ds:${tag}>`).exec(xml);
  if (m === null) {
    throw new Error(`no ${tag}`);
  }
  return m[0];
}

/** 攻撃者の本体（署名されていない）に合わせたダイジェストを持つ偽 SignedInfo を作る。 */
function forgedSignedInfo(legit: string, forgedBody: string, tag: string): string {
  const digest = base64.encode(sha256(new TextEncoder().encode(forgedBody)));
  return pick(legit, 'SignedInfo')
    .replace(
      /<ds:DigestValue>[^<]*<\/ds:DigestValue>/,
      `<ds:DigestValue>${digest}</ds:DigestValue>`,
    )
    .replaceAll('ds:SignedInfo', tag);
}

describe('署名対象 SignedInfo と DigestValue の取得元ずれ', () => {
  const legit = sign();
  const forgedInner = `<Owner>ATTACKER</Owner>${service(attackerCa.der)}`;
  const forgedBody = `${OPEN}${forgedInner}${CLOSE}`;
  const sigValue = pick(legit, 'SignatureValue');
  const keyInfo = pick(legit, 'KeyInfo');

  test('正規の署名済み領域は検証できる（前提）', async () => {
    expect((await verifyXmlDsig(legit)).valid).toBe(true);
  });

  test('属性値に隠した正規 SignedInfo + 別 prefix の偽 SignedInfo は拒否する', async () => {
    const hidden = pick(legit, 'SignedInfo');
    const fake = forgedSignedInfo(legit, forgedBody, 'x.y:SignedInfo');
    const xml =
      `${OPEN}${forgedInner}<ds:Signature ${DS}>` +
      `<ds:Object Id='${hidden}'/>${fake}${sigValue}${keyInfo}</ds:Signature>${CLOSE}`;
    expect((await verifyXmlDsig(xml)).valid).toBe(false);
  });

  test('正規 SignedInfo を ds:Object 内の要素として置き偽 SignedInfo を並べる構成も拒否する', async () => {
    const fake = forgedSignedInfo(legit, forgedBody, 'x.y:SignedInfo');
    const xml =
      `${OPEN}${forgedInner}<ds:Signature ${DS}>` +
      `<ds:Object>${pick(legit, 'SignedInfo')}</ds:Object>${fake}${sigValue}${keyInfo}</ds:Signature>${CLOSE}`;
    expect((await verifyXmlDsig(xml)).valid).toBe(false);
  });

  test('prefix が `.` を含む SignedInfo だけの文書でも、署名対象は読んだ要素自身になる', async () => {
    // 正規署名値は元の SignedInfo に対するもの。偽 SignedInfo（別内容）に付け替えても検証は通らない。
    const fake = forgedSignedInfo(legit, forgedBody, 'x.y:SignedInfo');
    const xml = `${OPEN}${forgedInner}<ds:Signature ${DS}>${fake}${sigValue}${keyInfo}</ds:Signature>${CLOSE}`;
    expect((await verifyXmlDsig(xml)).valid).toBe(false);
  });

  test('属性値に生の < を含む文書は XML として不正（パース拒否）', () => {
    expect(() => parseXml("<a b='<c/>'/>")).toThrow();
    expect(() => parseXml('<a b="x<y"/>')).toThrow();
  });

  test('XML Name でない要素名・CDATA・処理命令・ルート外テキストは拒否する', () => {
    expect(() => parseXml('<a><b c=d/></a>')).toThrow();
    expect(() => parseXml('<a><![CDATA[x]]></a>')).toThrow();
    expect(() => parseXml('<a><?pi x?></a>')).toThrow();
    expect(() => parseXml('<a/>trailing')).toThrow();
    expect(() => parseXml('<a x="1" x="2"/>')).toThrow();
  });

  test('各要素は原文上の [start, end) を持つ', () => {
    const xml = '<a><b x="1">t</b><c/></a>';
    const root = parseXml(xml);
    const [b, c] = root.children;
    expect(xml.slice(b?.start, b?.end)).toBe('<b x="1">t</b>');
    expect(xml.slice(c?.start, c?.end)).toBe('<c/>');
    expect(xml.slice(root.start, root.end)).toBe(xml);
  });

  test('Reference が複数ある署名は拒否する（先頭 Reference だけを読まない）', async () => {
    const xml = sign({
      referenceXml: (digest: string) =>
        `<ds:Reference URI="#other"><ds:DigestValue>${digest}</ds:DigestValue></ds:Reference>` +
        `<ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform></ds:Transforms>` +
        `<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>${digest}</ds:DigestValue></ds:Reference>`,
    });
    expect((await verifyXmlDsig(xml)).valid).toBe(false);
  });

  test('ルートが 2 つある文書（二重ルート）は拒否する', async () => {
    expect((await verifyXmlDsig(`${legit}<Extra/>`)).valid).toBe(false);
    expect((await verifyXmlDsig(`${legit}${legit}`)).valid).toBe(false);
  });
});

describe('ds:Signature 内の未署名要素は信頼データとして抽出しない', () => {
  const injected =
    `<ds:Object><TrustServiceProvider>${service(attackerCa.der)}</TrustServiceProvider>` +
    '<OtherTSLPointer><TSLLocation>https://attacker.example/tsl.xml</TSLLocation></OtherTSLPointer>' +
    '<SchemeInformation><NextUpdate><dateTime>2998-01-01T00:00:00Z</dateTime></NextUpdate></SchemeInformation></ds:Object>';

  test('署名は有効のまま（Signature 内は署名対象外）だが、注入分は抽出に現れない', async () => {
    const xml = sign({ signatureExtra: injected });
    expect((await verifyXmlDsig(xml)).valid).toBe(true);
    const anchors = grantedTrustAnchors(extractQtspCertificates(xml));
    expect(anchors.length).toBe(1);
    expect(anchors[0]).toEqual(legitCa.der);
    expect(extractTslPointers(xml).map((p) => p.location)).toEqual([
      'https://legit.example/tsl.xml',
    ]);
    expect(extractNextUpdate(xml)).toBe('2999-01-01T00:00:00Z');
  });

  test('Signature が本体より前にあっても、未署名の NextUpdate を採らない', async () => {
    // 署名済み TSL の Signature を先頭に移した文書（`ds:Signature` は enveloped 位置を問わない）。
    const xml = sign({ signatureExtra: injected });
    const signature = /<ds:Signature[\s\S]*<\/ds:Signature>/.exec(xml)?.[0] ?? '';
    const moved = xml.replace(signature, '').replace(OPEN, `${OPEN}${signature}`);
    expect(extractNextUpdate(moved)).toBe('2999-01-01T00:00:00Z');
  });

  test('KeyInfo 内の追加要素に TSPService を足しても抽出に現れない', () => {
    const xml = sign({ signatureExtra: `<ds:KeyInfo>${service(attackerCa.der)}</ds:KeyInfo>` });
    expect(grantedTrustAnchors(extractQtspCertificates(xml)).length).toBe(1);
  });
});
