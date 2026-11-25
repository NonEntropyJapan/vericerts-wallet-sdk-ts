/**
 * 共有 Content-Type 述語の回帰テスト。
 *
 * `isAllowedContentType` は did:web / did:ipid / did:webvh / OID4VCI Offer / OpenID Federation の
 * 5 経路が共有する述語である。以前は各経路が同名のプライベート関数を持ち、**ヘッダ欠落（`null`）
 * の扱いだけが Federation 側で反転していた**。統合後の既定は fail-closed（欠落は拒否）で、逸脱は
 * 呼び出し側が `allowMissing` を明示したときに限る——この非対称を固定する。
 */

import { describe, expect, it } from 'bun:test';
import { isAllowedContentType } from '../body-limit.js';

const ALLOWED: readonly string[] = ['application/did+json', 'application/json'];

describe('isAllowedContentType — media type の照合', () => {
  it('許容集合に含まれる media type は受理する', () => {
    expect(isAllowedContentType('application/json', ALLOWED)).toBe(true);
    expect(isAllowedContentType('application/did+json', ALLOWED)).toBe(true);
  });

  it('許容集合の外（text/html）は拒否する', () => {
    expect(isAllowedContentType('text/html', ALLOWED)).toBe(false);
  });

  it('パラメータ部（charset）と前後の空白は無視する', () => {
    expect(isAllowedContentType('application/json; charset=utf-8', ALLOWED)).toBe(true);
    expect(isAllowedContentType('  application/json  ; charset=utf-8', ALLOWED)).toBe(true);
  });

  it('media type の大文字小文字は無視する', () => {
    expect(isAllowedContentType('Application/JSON', ALLOWED)).toBe(true);
  });

  it('空文字・パラメータだけの値は拒否する', () => {
    expect(isAllowedContentType('', ALLOWED)).toBe(false);
    expect(isAllowedContentType('; charset=utf-8', ALLOWED)).toBe(false);
  });

  it('許容集合が空なら何も受理しない', () => {
    expect(isAllowedContentType('application/json', [])).toBe(false);
  });
});

describe('isAllowedContentType — ヘッダ欠落（null）の扱い', () => {
  it('既定ではヘッダ欠落を拒否する（fail-closed）', () => {
    expect(isAllowedContentType(null, ALLOWED)).toBe(false);
  });

  it('`allowMissing` を省略・false で渡しても拒否する', () => {
    expect(isAllowedContentType(null, ALLOWED, {})).toBe(false);
    expect(isAllowedContentType(null, ALLOWED, { allowMissing: false })).toBe(false);
  });

  it('`allowMissing: true` を明示した呼び出しだけが欠落を許容する', () => {
    expect(isAllowedContentType(null, ALLOWED, { allowMissing: true })).toBe(true);
  });

  it('`allowMissing: true` でも許容集合の外の media type は拒否する', () => {
    expect(isAllowedContentType('text/html', ALLOWED, { allowMissing: true })).toBe(false);
  });
});
