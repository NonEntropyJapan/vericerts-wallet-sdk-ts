import { describe, expect, setDefaultTimeout, test } from 'bun:test';
import { HEAVY_INPUT_TIMEOUT_MS } from '../../../../__tests__/heavy-input-timeout.js';
import { VericertsError } from '../../../../errors.js';
import { loadTrustedList } from '../../etsi-tsl.js';
import {
  findAllByLocalName,
  MAX_XML_DEPTH,
  MAX_XML_ELEMENTS,
  MAX_XML_LENGTH,
  parseXml,
  XmlError,
} from '../../xml/parse.js';
import { parseSignedRegion } from '../../xml/signed-region.js';

setDefaultTimeout(HEAVY_INPUT_TIMEOUT_MS);

describe('parseXml: prolog マスクは線形時間', () => {
  test.each([
    ['<!--', 'コメント'],
    ['<!DOCTYPE ', 'DOCTYPE'],
    ['<?xml ', 'XML 宣言'],
  ])('終端のない %s を 4MB 並べても 500ms 未満で XmlError', (token) => {
    // 二次時間の旧実装は 200KB でも 1.3〜3.4 秒かかった。4MB なら実行環境の速度差を桁で上回って差が出る
    // （線形実装は数 ms）。MAX_XML_LENGTH（8 MiB）以内に収める。
    const input = token.repeat(Math.ceil(4_000_000 / token.length));
    expect(input.length).toBeLessThan(MAX_XML_LENGTH);
    const started = performance.now();
    expect(() => parseXml(input)).toThrow(XmlError);
    expect(performance.now() - started).toBeLessThan(500);
  });

  test('入力長の上限を超える文書は走査せず拒否する', () => {
    expect(() => parseXml(`<a>${' '.repeat(MAX_XML_LENGTH)}</a>`)).toThrow(XmlError);
  });

  test('宣言・コメント・DOCTYPE を同じ長さの空白で潰し、要素位置は原文のまま', () => {
    const xml = '<?xml version="1.0"?><!-- c <b/> --><!doctype x><a><b>t</b></a>';
    const root = parseXml(xml);
    expect(root.qName).toBe('a');
    expect(root.children.map((c) => c.qName)).toEqual(['b']);
    expect(xml.slice(root.start, root.end)).toBe('<a><b>t</b></a>');
  });

  test('コメント内の <?xml / DOCTYPE 風の文字列は要素にならない', () => {
    const root = parseXml('<a><!-- <?xml x ?> <!DOCTYPE y> --><b/></a>');
    expect(root.children.map((c) => c.qName)).toEqual(['b']);
  });
});

describe('parseXml: 要素数・ネスト深さの上限', () => {
  const nested = (depth: number) => '<a>'.repeat(depth) + '</a>'.repeat(depth);

  test('要素数は MAX_XML_ELEMENTS ちょうどまで受理し、1 つ超えると XmlError', () => {
    const flat = (count: number) => `<r>${'<a/>'.repeat(count - 1)}</r>`;
    expect(findAllByLocalName(parseXml(flat(MAX_XML_ELEMENTS)), 'a')).toHaveLength(
      MAX_XML_ELEMENTS - 1,
    );
    expect(() => parseXml(flat(MAX_XML_ELEMENTS + 1))).toThrow(XmlError);
  });

  test('入力長の上限内の <a/> 連打（約 210 万要素）は木を作る前に XmlError', () => {
    const xml = `<r>${'<a/>'.repeat(2_097_000)}</r>`;
    expect(xml.length).toBeLessThanOrEqual(MAX_XML_LENGTH);
    expect(() => parseXml(xml)).toThrow(XmlError);
  });

  test('ネスト深さは MAX_XML_DEPTH ちょうどまで受理し、1 段超えると XmlError', () => {
    expect(parseXml(nested(MAX_XML_DEPTH)).localName).toBe('a');
    expect(() => parseXml(nested(MAX_XML_DEPTH + 1))).toThrow(XmlError);
  });

  test('深い入れ子でも再帰走査のスタックを枯渇させず XmlError で拒否する（RangeError にならない）', () => {
    const xml = nested(1_000_000);
    expect(xml.length).toBeLessThanOrEqual(MAX_XML_LENGTH);
    expect(() => parseSignedRegion(xml)).toThrow(XmlError);
  });

  test.each([
    ['<a/> 連打', `<r>${'<a/>'.repeat(2_000_000)}</r>`],
    ['深い入れ子', '<a>'.repeat(1_000_000) + '</a>'.repeat(1_000_000)],
  ])('loadTrustedList(kind: auto) は署名検証前に %s を拒否する', async (_label, xml) => {
    let caught: unknown;
    try {
      await loadTrustedList('https://tsl.example/DE.xml', { fetcher: async () => xml });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect(['10302', '5002']).toContain((caught as VericertsError).code);
  });
});
