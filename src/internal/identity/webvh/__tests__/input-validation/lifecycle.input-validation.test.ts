/**
 * createDidWebVh / updateDidWebVh が resolver の解釈と一致しない入力を生成時に拒否すること
 * （domain・path、updateKeys・nextKeyHashes）。
 *
 * 生成側が非空チェックだけだと、解決できない DID や署名不能・更新不能な Log を黙って作れる。
 * いずれも SCID / 署名権限に焼き付き、公開後には直せない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { updateKeyHash } from '../../codec.js';
import { parseWebVh, webVhLogUrl } from '../../did-url.js';
import { createDidWebVh, updateDidWebVh } from '../../method-webvh.js';
import { verifyChain } from '../../verify.js';
import { generateKey, signEntry } from '../webvh-fixtures.js';

const INVALID_DID = new VericertsError(ErrorCodes.INVALID_DID);

describe('createDidWebVh の domain / path', () => {
  it('resolver が別の場所へ解決する・解決できない domain は INVALID_DID', () => {
    const key = generateKey();
    for (const domain of [
      'evil.example/x',
      'evil.example?q=1',
      'evil.example#f',
      'user@evil.example',
      'example.com:8443',
      'example.com%3A',
      'example.com%3Aabc',
      'example.com%3A99999',
      'exa mple.com',
      '.example.com',
      'example..com',
      '-example.com',
      'ex_ample.com',
      '',
    ]) {
      expect(() => createDidWebVh({ domain, updateKeys: [key.multikey] })).toThrow(INVALID_DID);
    }
  });

  it('resolver が別の場所へ解決する・解決できない path は INVALID_DID', () => {
    const key = generateKey();
    for (const path of [
      'a/b',
      '..',
      'a:..',
      'a::b',
      ':a',
      'a:',
      'a?x',
      'a#x',
      'a b',
      '%2e%2e',
      '.',
    ]) {
      expect(() =>
        createDidWebVh({ domain: 'vericerts.io', path, updateKeys: [key.multikey] }),
      ).toThrow(INVALID_DID);
    }
  });

  it('正当な domain（host / host%3Aport）・path は受理され、生成 DID が意図した URL に解決し verifyChain も通る', () => {
    const key = generateKey();
    const cases = [
      { domain: 'vericerts.io', expected: 'https://vericerts.io/.well-known/did.jsonl' },
      { domain: 'Example.COM%3A8443', expected: 'https://example.com:8443/.well-known/did.jsonl' },
      {
        domain: 'vericerts.io',
        path: 'org:team',
        expected: 'https://vericerts.io/org/team/did.jsonl',
      },
      { domain: 'vericerts.io', path: '', expected: 'https://vericerts.io/.well-known/did.jsonl' },
    ];
    for (const { expected, ...options } of cases) {
      const { did, logEntry } = createDidWebVh({ ...options, updateKeys: [key.multikey] });
      expect(webVhLogUrl(parseWebVh(did))).toBe(expected);
      const scid = did.split(':')[2] as string;
      expect(() => verifyChain([signEntry(logEntry, key)], did, scid)).not.toThrow();
    }
  });
});

describe('createDidWebVh / updateDidWebVh の updateKeys・nextKeyHashes', () => {
  const key = generateKey();
  const badKeys: readonly (readonly unknown[])[] = [
    [''],
    ['not-a-multikey'],
    ['zNotEd25519'],
    [key.multikey, 'z6Mk'],
    [123],
    [key.multikey.replace(/^z6Mk/, 'z6Mj')],
  ];

  it('create: 空配列・Ed25519 Multikey でない要素を含む updateKeys は INVALID_DID', () => {
    for (const updateKeys of [[], ...badKeys]) {
      expect(() =>
        createDidWebVh({ domain: 'vericerts.io', updateKeys: updateKeys as readonly string[] }),
      ).toThrow(INVALID_DID);
    }
  });

  it('create: multihash でない nextKeyHashes は INVALID_DID、正当値と空配列は受理', () => {
    for (const nextKeyHashes of [['not-a-hash'], [key.multikey], ['z'], [42]]) {
      expect(() =>
        createDidWebVh({
          domain: 'vericerts.io',
          updateKeys: [key.multikey],
          nextKeyHashes: nextKeyHashes as readonly string[],
        }),
      ).toThrow(INVALID_DID);
    }
    for (const nextKeyHashes of [[], [updateKeyHash(generateKey().multikey)]]) {
      expect(() =>
        createDidWebVh({ domain: 'vericerts.io', updateKeys: [key.multikey], nextKeyHashes }),
      ).not.toThrow();
    }
  });

  it('update: 明示した不正 updateKeys（空配列を含む）・不正 nextKeyHashes は INVALID_DID、省略は継続', () => {
    const { logEntry } = createDidWebVh({ domain: 'vericerts.io', updateKeys: [key.multikey] });
    const genesis = signEntry(logEntry, key);
    for (const updateKeys of [[], ...badKeys]) {
      expect(() =>
        updateDidWebVh({
          previousLog: [genesis],
          state: { ...genesis.state },
          updateKeys: updateKeys as readonly string[],
        }),
      ).toThrow(INVALID_DID);
    }
    expect(() =>
      updateDidWebVh({
        previousLog: [genesis],
        state: { ...genesis.state },
        nextKeyHashes: ['not-a-hash'],
      }),
    ).toThrow(INVALID_DID);
    const next = updateDidWebVh({ previousLog: [genesis], state: { ...genesis.state } });
    expect(next.parameters.updateKeys).toEqual([key.multikey]);
  });
});
