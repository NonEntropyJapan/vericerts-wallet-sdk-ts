/**
 * 最小 XML パーサ（trust/etsi-tsl）。
 *
 * ETSI TS 119 612 の LOTL / TSL XML と XMLDSig（`ds:Signature`）を読み取るための軽量な DOM を
 * 構築する。ブラウザ専用の `DOMParser` は Node ランタイム（`engines.node >=20`）に無いため、
 * 依存を増やさず両環境で動く小さなパーサを用意する。名前空間解決は prefix を保持したまま
 * `localName` を提供する方式とし、機械生成される Trusted List の整形式 XML を対象とする。
 *
 * 対応範囲: 要素・属性・テキスト・自己終了タグ・XML 宣言・コメント除去。CDATA / DTD /
 * 処理命令は Trusted List では使われないため未対応（出現時は無視 or エラー）。
 *
 * セキュリティ上の注意:
 * - 外部エンティティ展開は行わない（XXE 対策: `<!DOCTYPE>` / `<!ENTITY>` は解釈せず読み飛ばす）。
 */

/** 軽量 XML 要素ノード。 */
export interface XmlElement {
  /** prefix 付きタグ名（例 `ds:Signature`）。 */
  readonly qName: string;
  /** prefix を除いたローカル名（例 `Signature`）。 */
  readonly localName: string;
  /** 属性（qName → 値）。 */
  readonly attributes: Readonly<Record<string, string>>;
  /** 子要素。 */
  readonly children: XmlElement[];
  /** 直接のテキスト内容（子テキストノードの連結）。 */
  readonly text: string;
  /** 原文（`parseXml` に渡した文字列）上の開始タグ先頭 `<` の位置。 */
  readonly start: number;
  /** 原文上の終了位置（終了タグ / 自己終了タグの `>` の次。`[start, end)` が要素の原文範囲）。 */
  readonly end: number;
}

/** XML パース失敗を表すエラー。 */
export class XmlError extends Error {}

/** `parseXml` が受け付ける入力長の上限（UTF-16 コード単位）。拡張の取得上限（8 MiB）に揃える。 */
export const MAX_XML_LENGTH = 8 * 1024 * 1024;

/**
 * `parseXml` が受け付ける要素数の上限。入力長だけでは `<a/>` 連打（4 文字 / 要素）で 8 MiB が
 * 約 200 万要素に膨らみ、署名検証より前に GB 級のヒープを確保させられる。実在の EU 加盟国 TSL は
 * 数万要素規模なので、その十数倍の余裕を持たせる。
 */
export const MAX_XML_ELEMENTS = 300_000;

/**
 * `parseXml` が受け付ける要素のネスト深さの上限。木を再帰で走査する
 * `findByLocalName` / `findAllByLocalName` / `withoutSignature` のスタック枯渇（`RangeError`）を防ぐ。
 * 実在の TSL / XMLDSig は十数段。
 */
export const MAX_XML_DEPTH = 64;

/** マスク対象の開始トークンと、その終端（DOCTYPE の開始のみ大文字小文字を区別しない）。 */
const MASKED_TOKENS: readonly { open: string; close: string; ignoreCase: boolean }[] = [
  { open: '<?xml', close: '?>', ignoreCase: false },
  { open: '<!--', close: '-->', ignoreCase: false },
  { open: '<!doctype', close: '>', ignoreCase: true },
];

/**
 * XML 宣言・コメント・DOCTYPE を同じ長さの空白に置き換える（XXE 対策として DOCTYPE は解釈せず潰す）。
 *
 * 文字位置を保つので、パースツリーの `start` / `end` は原文の位置としてそのまま使える。
 * 署名対象のオクテットは「パーサが選んだ要素の `[start, end)`」だけから切り出し、正規表現による
 * 別解釈の探索を持ち込まない。
 *
 * 1 回の前方走査（O(n)）で行う。終端のない開始トークンは即座に `XmlError`（反復する未閉じ `<!--` で
 * 各開始位置から末尾まで再走査する二次時間の DoS を作らない）。
 */
function maskProlog(xml: string): string {
  const pieces: string[] = [];
  let copied = 0;
  let lt = xml.indexOf('<');
  while (lt !== -1) {
    const token = MASKED_TOKENS.find(({ open, ignoreCase }) => {
      const head = xml.slice(lt, lt + open.length);
      return (ignoreCase ? head.toLowerCase() : head) === open;
    });
    if (token === undefined) {
      lt = xml.indexOf('<', lt + 1);
      continue;
    }
    const close = xml.indexOf(token.close, lt + token.open.length);
    if (close === -1) {
      throw new XmlError('XML: unterminated declaration or comment');
    }
    const end = close + token.close.length;
    pieces.push(xml.slice(copied, lt), ' '.repeat(end - lt));
    copied = end;
    lt = xml.indexOf('<', end);
  }
  pieces.push(xml.slice(copied));
  return pieces.join('');
}

/** XML の実体参照を最小限デコードする（数値参照は対象外・そのまま）。 */
function decodeEntities(text: string): string {
  return text
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

/** XML Name（prefix は高々 1 つ）。 */
const NAME = String.raw`[\p{L}_][\p{L}\p{N}_.\-]*(?::[\p{L}_][\p{L}\p{N}_.\-]*)?`;
/** 属性 1 件の非捕捉形（値に生の `<` を含めない: XML 1.0 §2.3）。 */
const ATTRIBUTE = String.raw`\s+${NAME}\s*=\s*(?:"[^"<]*"|'[^'<]*')`;
/** タグ 1 つ（開始・終了・自己終了）。属性部は `parseAttributes` が再走査する。 */
const TAG_RE = new RegExp(String.raw`<(/?)(${NAME})((?:${ATTRIBUTE})*)\s*(/?)>`, 'uy');
/** 属性 1 件の捕捉形（名前・二重引用符値・単一引用符値）。 */
const ATTRIBUTE_RE = new RegExp(String.raw`\s+(${NAME})\s*=\s*(?:"([^"<]*)"|'([^'<]*)')`, 'gu');

/** 属性文字列（`a="b" c='d'`）をパースする。重複属性は不正。 */
function parseAttributes(raw: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  for (const m of raw.matchAll(ATTRIBUTE_RE)) {
    const name = m[1] as string;
    if (Object.hasOwn(attrs, name)) {
      throw new XmlError('XML: duplicate attribute');
    }
    attrs[name] = decodeEntities(m[2] ?? m[3] ?? '');
  }
  return attrs;
}

/** qName からローカル名を取り出す。 */
function localOf(qName: string): string {
  const idx = qName.indexOf(':');
  return idx === -1 ? qName : qName.slice(idx + 1);
}

/** 内部用のミュータブル要素（構築中に text / children / end を書き換える）。 */
interface MutableElement {
  qName: string;
  localName: string;
  attributes: Record<string, string>;
  children: XmlElement[];
  text: string;
  start: number;
  end: number;
}

/**
 * XML 文字列をパースしてルート要素を返す。
 *
 * 厳格に解釈する（署名検証が参照するパースツリーを唯一の解釈にするため）: 属性値に生の `<`、
 * XML Name でない要素名・属性名、重複属性、CDATA・処理命令（宣言を除く）、ルート外のテキストは拒否する。
 *
 * @param xml XML テキスト。
 * @returns ルート要素（各要素は原文上の `start` / `end` を持つ）。
 * @throws 整形式でない / ルートが 1 つでない / `MAX_XML_LENGTH` 超 / 要素数 `MAX_XML_ELEMENTS` 超 /
 *         ネスト深さ `MAX_XML_DEPTH` 超 / 宣言・コメントが未終端の場合（XmlError）。
 */
export function parseXml(xml: string): XmlElement {
  if (xml.length > MAX_XML_LENGTH) {
    throw new XmlError('XML: input too large');
  }
  const body = maskProlog(xml);
  const stack: MutableElement[] = [];
  let root: MutableElement | undefined;
  let elementCount = 0;
  let pos = 0;
  while (pos < body.length) {
    const lt = body.indexOf('<', pos);
    const between = body.slice(pos, lt === -1 ? body.length : lt);
    if (between.trim().length > 0) {
      const top = stack[stack.length - 1];
      if (top === undefined) {
        throw new XmlError('XML: text outside root');
      }
      top.text += decodeEntities(between);
    }
    if (lt === -1) {
      break;
    }
    TAG_RE.lastIndex = lt;
    const m = TAG_RE.exec(body);
    if (m === null) {
      throw new XmlError('XML: malformed tag');
    }
    const [full, closing, qName, rawAttrs, selfClose] = m as unknown as [
      string,
      string,
      string,
      string,
      string,
    ];
    pos = lt + full.length;
    if (closing === '/') {
      const top = stack.pop();
      if (top === undefined || top.qName !== qName || rawAttrs !== '' || selfClose === '/') {
        throw new XmlError('XML: mismatched closing tag');
      }
      top.end = pos;
      continue;
    }
    elementCount += 1;
    if (elementCount > MAX_XML_ELEMENTS) {
      throw new XmlError('XML: too many elements');
    }
    const el: MutableElement = {
      qName,
      localName: localOf(qName),
      attributes: parseAttributes(rawAttrs),
      children: [],
      text: '',
      start: lt,
      end: pos,
    };
    const parent = stack[stack.length - 1];
    if (parent !== undefined) {
      parent.children.push(el);
    } else if (root === undefined) {
      root = el;
    } else {
      throw new XmlError('XML: multiple root elements');
    }
    if (selfClose !== '/') {
      if (stack.length >= MAX_XML_DEPTH) {
        throw new XmlError('XML: nesting too deep');
      }
      stack.push(el);
    }
  }
  if (root === undefined || stack.length > 0) {
    throw new XmlError('XML: malformed document');
  }
  return root;
}

/** ローカル名でマッチする最初の子孫要素を深さ優先で探す。 */
export function findByLocalName(root: XmlElement, localName: string): XmlElement | undefined {
  if (root.localName === localName) {
    return root;
  }
  for (const child of root.children) {
    const found = findByLocalName(child, localName);
    if (found !== undefined) {
      return found;
    }
  }
  return undefined;
}

/** ローカル名でマッチするすべての子孫要素を返す。 */
export function findAllByLocalName(root: XmlElement, localName: string): XmlElement[] {
  const out: XmlElement[] = [];
  const walk = (el: XmlElement): void => {
    if (el.localName === localName) {
      out.push(el);
    }
    for (const c of el.children) {
      walk(c);
    }
  };
  walk(root);
  return out;
}
