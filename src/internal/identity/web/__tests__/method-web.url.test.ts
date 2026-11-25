/**
 * didWebToUrl の DID → HTTPS URL 変換検証。
 *
 * ドメインのみ → /.well-known/did.json、パスあり → /<path>/did.json、
 * ポート（%3A）デコード、空セグメント・非 did:web・`/` 混入などの異常系を確認する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { didWebToUrl } from '../method-web.js';

const INVALID_DID = new VericertsError(ErrorCodes.INVALID_DID);

describe('didWebToUrl 正常系', () => {
  it('ドメインのみは /.well-known/did.json になる', () => {
    expect(didWebToUrl('did:web:example.com')).toBe('https://example.com/.well-known/did.json');
  });

  it('パスありは /<path>/did.json になる', () => {
    expect(didWebToUrl('did:web:example.com:users:alice')).toBe(
      'https://example.com/users/alice/did.json',
    );
  });

  it('単一階層パスも /<path>/did.json になる', () => {
    expect(didWebToUrl('did:web:example.com:alice')).toBe('https://example.com/alice/did.json');
  });

  it('ポート番号（%3A）はデコードして : に戻す', () => {
    expect(didWebToUrl('did:web:example.com%3A8443')).toBe(
      'https://example.com:8443/.well-known/did.json',
    );
  });

  it('ポート番号付きパスありも正しく変換する', () => {
    expect(didWebToUrl('did:web:example.com%3A8443:users:alice')).toBe(
      'https://example.com:8443/users/alice/did.json',
    );
  });
});

describe('didWebToUrl 異常系', () => {
  it('did:web プレフィックスがない場合は 2001', () => {
    expect(() => didWebToUrl('did:key:z6Mk')).toThrow(INVALID_DID);
  });

  it('識別子が空（did:web:）は 2001', () => {
    expect(() => didWebToUrl('did:web:')).toThrow(INVALID_DID);
  });

  it('空セグメント（連続コロン）は 2001', () => {
    expect(() => didWebToUrl('did:web:example.com::alice')).toThrow(INVALID_DID);
  });

  it('末尾コロンは 2001', () => {
    expect(() => didWebToUrl('did:web:example.com:')).toThrow(INVALID_DID);
  });

  it('識別子に / が混入する場合は 2001', () => {
    expect(() => didWebToUrl('did:web:example.com/users')).toThrow(INVALID_DID);
  });

  // セグメントの文字種を検証し、URL の構造（?, #, userinfo, パス区切り, ドットセグメント）に
  // 化ける入力を拒否する。
  it.each([
    'did:web:example.com#x',
    'did:web:example.com?x=1',
    'did:web:user@evil.com',
    'did:web:a.com\\@b.com',
    'did:web:example.com:..:x',
    'did:web:example.com:.:x',
    'did:web:example.com:%2e%2e:x',
    'did:web:example.com:%2E:x',
    'did:web:example.com:a%2Fb',
    'did:web:example.com:a?b',
    'did:web:example.com:a#b',
    'did:web:example.com:a b',
    'did:web:example.com:%3A',
    'did:web:example.com%2e:x',
    'did:web:example.com%3Aabc',
    'did:web:%3A8443',
  ])('文字種不正 %s は 2001', (did) => {
    expect(() => didWebToUrl(did)).toThrow(INVALID_DID);
  });
});

describe('didWebToUrl 文字種（許可）', () => {
  it('英数字・. - _ ~ を含む path セグメントは許可する', () => {
    expect(didWebToUrl('did:web:Example.COM:users:a.b-c_d~e')).toBe(
      'https://example.com/users/a.b-c_d~e/did.json',
    );
  });
});
