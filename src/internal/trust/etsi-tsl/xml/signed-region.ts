/**
 * 署名済み領域だけを信頼データとして読むための共通入口（trust/etsi-tsl）。
 *
 * enveloped 署名が覆うのは「`ds:Signature` を除いた本体」だけで、`ds:Signature` の子（`ds:Object`・
 * `KeyInfo` の追加要素・未知の子）は署名されない。署名検証後に文書全体から `TSPService` /
 * `OtherTSLPointer` / `NextUpdate` を探索すると、そこへ注入された未署名の値（攻撃者の Trust Anchor・
 * TSL ポインタ・キャッシュ寿命）が採用されてしまう。`tsl.ts` の抽出関数はすべて本ヘルパを経由する。
 *
 * `verifyXmlDsig` は `Signature` が文書内にちょうど 1 つであることを要求するため、ローカル名
 * `Signature` の要素を全て取り除いた木が「署名済み領域」と一致する。
 */

import { parseXml, type XmlElement, XmlError } from './parse.js';

/** `Signature`（ローカル名）の要素を子孫から取り除いた要素を返す（元の木は変更しない）。 */
function withoutSignature(el: XmlElement): XmlElement {
  return {
    ...el,
    children: el.children.filter((c) => c.localName !== 'Signature').map(withoutSignature),
  };
}

/**
 * XML をパースし、`ds:Signature` サブツリーを除いた署名済み領域のルート要素を返す。
 *
 * @param xml LOTL / TSL の XML テキスト。
 * @returns `Signature` を含まないルート要素。
 * @throws 整形式でない場合（XmlError）。ルート自身が `Signature` の文書も署名済み領域を持たないため拒否する。
 */
export function parseSignedRegion(xml: string): XmlElement {
  const root = parseXml(xml);
  if (root.localName === 'Signature') {
    throw new XmlError('XML: root is a signature');
  }
  return withoutSignature(root);
}
