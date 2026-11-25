/**
 * did:webvh の低レベルヘルパ（parseWebVh / webVhLogUrl / canonicalize / parseDidLog）の単体テスト。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { canonicalize, parseDidLog, parseWebVh, webVhLogUrl } from '../codec.js';

const SCID = `Qm${'T'.repeat(44)}`;

describe('parseWebVh', () => {
  it('scid + domain を分解する', () => {
    const parsed = parseWebVh(`did:webvh:${SCID}:vericerts.io`);
    expect(parsed.scid).toBe(SCID);
    expect(parsed.domain).toBe('vericerts.io');
    expect(parsed.pathSegments).toEqual([]);
  });

  it('path セグメントを分解する', () => {
    const parsed = parseWebVh(`did:webvh:${SCID}:vericerts.io:users:alice`);
    expect(parsed.pathSegments).toEqual(['users', 'alice']);
  });

  it('プレフィックス不正は INVALID_DID', () => {
    expect(() => parseWebVh('did:web:vericerts.io')).toThrow(
      new VericertsError(ErrorCodes.INVALID_DID),
    );
  });

  it('domain 欠落（scid のみ）は INVALID_DID', () => {
    expect(() => parseWebVh(`did:webvh:${SCID}`)).toThrow(
      new VericertsError(ErrorCodes.INVALID_DID),
    );
  });

  it('空セグメント（連続コロン）は INVALID_DID', () => {
    expect(() => parseWebVh(`did:webvh:${SCID}::vericerts.io`)).toThrow(
      new VericertsError(ErrorCodes.INVALID_DID),
    );
  });
});

describe('webVhLogUrl', () => {
  it('path なしは well-known を使う', () => {
    const url = webVhLogUrl({ scid: SCID, domain: 'vericerts.io', pathSegments: [] });
    expect(url).toBe('https://vericerts.io/.well-known/did.jsonl');
  });

  it('path ありは /{path}/did.jsonl', () => {
    const url = webVhLogUrl({
      scid: SCID,
      domain: 'vericerts.io',
      pathSegments: ['users', 'alice'],
    });
    expect(url).toBe('https://vericerts.io/users/alice/did.jsonl');
  });

  it('%3A をポートに戻す', () => {
    const url = webVhLogUrl({ scid: SCID, domain: 'vericerts.io%3A8443', pathSegments: [] });
    expect(url).toBe('https://vericerts.io:8443/.well-known/did.jsonl');
  });
});

describe('canonicalize', () => {
  it('オブジェクトキーをソートして決定論的に出力する', () => {
    const a = canonicalize({ b: 1, a: 2, c: { y: 1, x: 2 } });
    const b = canonicalize({ c: { x: 2, y: 1 }, a: 2, b: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":2,"b":1,"c":{"x":2,"y":1}}');
  });

  it('配列順序は保持する', () => {
    expect(canonicalize([3, 1, 2])).toBe('[3,1,2]');
  });

  it('undefined メンバは出力しない', () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
  });

  it('Infinity は INVALID_DID', () => {
    expect(() => canonicalize({ x: Number.POSITIVE_INFINITY })).toThrow(
      new VericertsError(ErrorCodes.INVALID_DID),
    );
  });
});

describe('parseDidLog', () => {
  const validLine = JSON.stringify({
    versionId: '1-zScid',
    versionTime: '2026-04-01T00:00:00Z',
    parameters: { method: 'did:webvh:1.0' },
    state: { id: 'did:webvh:zScid:vericerts.io' },
  });

  it('複数行をパースし空行をスキップする', () => {
    const entries = parseDidLog(`${validLine}\n\n${validLine}\n`);
    expect(entries).toHaveLength(2);
    expect(entries[0]?.versionId).toBe('1-zScid');
  });

  // `method` の値の拒否（did:webvh:0.4 を含む）は検証（`verifyChain`）の責務。パース段階は構造だけを見る。
  // 解決経路での拒否は `v1/method-parameter.test.ts`。
  it('パース段階では parameters.method の値を見ない', () => {
    const legacy = validLine.replace('did:webvh:1.0', 'did:webvh:0.4');
    expect(parseDidLog(legacy)[0]?.parameters.method).toBe('did:webvh:0.4');
  });

  it('空テキストは INVALID_DID', () => {
    expect(() => parseDidLog('\n  \n')).toThrow(new VericertsError(ErrorCodes.INVALID_DID));
  });

  it('JSON 不正行は INVALID_DID', () => {
    expect(() => parseDidLog('{not json')).toThrow(new VericertsError(ErrorCodes.INVALID_DID));
  });

  it('state.id 欠落は INVALID_DID', () => {
    const bad = JSON.stringify({
      versionId: '1-x',
      versionTime: 't',
      parameters: {},
      state: {},
    });
    expect(() => parseDidLog(bad)).toThrow(new VericertsError(ErrorCodes.INVALID_DID));
  });
});
