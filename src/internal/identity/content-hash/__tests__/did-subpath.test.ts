/**
 * content-addressed DID のサブパスからの contentHash 抽出の検証。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { hex } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { extractDidContentHash } from '../did-subpath.js';

const DIGEST = sha256(new TextEncoder().encode('artifact.png'));
const HEX = hex.encode(DIGEST);
const CANONICAL = `sha2-256-${HEX}`;
const DID = `did:web:acme.example.com:artifacts:sha256-${HEX}`;

/** 投げられた VericertsError のコードを取り出す。 */
function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    return (error as VericertsError).code;
  }
  throw new Error('例外が発生しませんでした');
}

describe('extractDidContentHash', () => {
  it('Artifact DID から contentHash を抽出する', () => {
    const parsed = extractDidContentHash(DID);
    expect(parsed.algorithm).toBe('sha2-256');
    expect(parsed.notation).toBe(CANONICAL);
    expect(parsed.digest).toEqual(DIGEST);
  });

  it('fragment 付き DID URL でも抽出できる', () => {
    expect(extractDidContentHash(`${DID}#key-1`).notation).toBe(CANONICAL);
  });

  it('query 付き DID URL でも抽出できる', () => {
    expect(extractDidContentHash(`${DID}?versionId=1`).notation).toBe(CANONICAL);
  });

  it('path 付き DID URL でも抽出できる', () => {
    expect(extractDidContentHash(`${DID}/whois`).notation).toBe(CANONICAL);
  });

  it('did:web 以外のメソッドでも最終セグメントから抽出する', () => {
    expect(extractDidContentHash(`did:example:artifacts:sha256-${HEX}`).notation).toBe(CANONICAL);
  });

  it('最終セグメント以外に hash があっても採用しない（fail-closed）', () => {
    // 攻撃者が途中セグメントへ一致する hash を仕込んでも通らないこと。
    const spoofed = `did:web:acme.example.com:sha256-${HEX}:artifacts`;
    expect(codeOf(() => extractDidContentHash(spoofed))).toBe(
      ErrorCodes.CONTENT_HASH_FORMAT_INVALID,
    );
  });

  it('サブパスを持たない DID は 2001 で拒否する', () => {
    expect(codeOf(() => extractDidContentHash('did:web:acme.example.com'))).toBe(
      ErrorCodes.INVALID_DID,
    );
  });

  it('did: で始まらない文字列は 2001 で拒否する', () => {
    expect(codeOf(() => extractDidContentHash(`https://acme.example.com/sha256-${HEX}`))).toBe(
      ErrorCodes.INVALID_DID,
    );
  });

  it('最終セグメントが空（末尾コロン）は 2001 で拒否する', () => {
    expect(codeOf(() => extractDidContentHash('did:web:acme.example.com:artifacts:'))).toBe(
      ErrorCodes.INVALID_DID,
    );
  });

  it('メソッド名が空の DID は 2001 で拒否する', () => {
    expect(codeOf(() => extractDidContentHash(`did::artifacts:sha256-${HEX}`))).toBe(
      ErrorCodes.INVALID_DID,
    );
  });

  it('最終セグメントが contentHash 表記でない場合は 2016 で拒否する', () => {
    expect(codeOf(() => extractDidContentHash('did:web:acme.example.com:artifacts:latest'))).toBe(
      ErrorCodes.CONTENT_HASH_FORMAT_INVALID,
    );
  });
});

describe('extractDidContentHash: 1030 と 2016 の投げ分け', () => {
  // content-addressed でない普通の did:web サブパス DID。ハイフンを含んでいても
  // 「未対応ハッシュアルゴリズム（1030）」ではなく「contentHash 表記でない（2016）」。
  // 形状ヒューリスティクスで 1030 を返すと、呼び出し側がすり替え検知シグナルを
  // 誤って切り分ける。
  it.each([
    ['did:web:acme.example.com:docs:v1-2'],
    ['did:web:acme.example.com:artifacts:my-artifact'],
    ['did:web:acme.example.com:artifacts:latest'],
    ['did:web:acme.example.com:releases:2026-08-27'],
    ['did:web:acme.example.com:team:design-system'],
    ['did:web:acme.example.com:x:a-b-c-d'],
  ])('ハッシュでないサブパス %s は 2016 で拒否する', (did) => {
    expect(codeOf(() => extractDidContentHash(did))).toBe(ErrorCodes.CONTENT_HASH_FORMAT_INVALID);
  });

  // 既知だが未対応のアルゴリズム名は 1030 のまま維持する。
  it.each([
    [`did:web:acme.example.com:artifacts:md5-${'ab'.repeat(16)}`],
    [`did:web:acme.example.com:artifacts:sha3-512-${'ab'.repeat(64)}`],
    [`did:web:acme.example.com:artifacts:sha-1-${'ab'.repeat(20)}`],
    [`did:web:acme.example.com:artifacts:blake2b-256-${HEX}`],
    [`did:web:acme.example.com:artifacts:sha2-512-${'ab'.repeat(64)}`],
  ])('既知だが未対応のアルゴリズム %s は 1030 で拒否する', (did) => {
    expect(codeOf(() => extractDidContentHash(did))).toBe(ErrorCodes.UNSUPPORTED_ALGORITHM);
  });

  it('対応アルゴリズムの正常系は引き続き通る（対照）', () => {
    expect(extractDidContentHash(DID).notation).toBe(CANONICAL);
  });
});
