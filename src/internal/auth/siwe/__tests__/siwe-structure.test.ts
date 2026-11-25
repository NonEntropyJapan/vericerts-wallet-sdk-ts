/**
 * assertSiweMessageStructure（parseSiweMessage 経由）の ABNF 順序検査。
 *
 * パーサ（viem の suffixRegex と DATE_TIME_LINES）は固定順の行しか拾わないため、順序外の
 * `Expiration Time` / `Not Before`・未知行・末尾余剰行が黙って無視され、期限切れメッセージを
 * validateSiweMessage が受理していた。構造検査で 8041 に拒否することを固定する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { generateSiweMessage, parseSiweMessage, type SiweParams } from '../siwe.js';

const baseParams: SiweParams = {
  domain: 'example.com',
  address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
  uri: 'https://example.com/login',
  nonce: 'abcd1234',
  chainId: 1,
  issuedAt: new Date('2020-01-01T00:00:00.000Z'),
};

const EXP = 'Expiration Time: 2020-06-01T00:00:00.000Z';
const NBF = 'Not Before: 2020-01-01T00:00:00.000Z';
const REQ = 'Request ID: r';
const RES = 'Resources:\n- https://example.com/a\n- https://example.com/b';

/** `Issued At:` 行までの本体（statement 有無を切替）。 */
function head(statement?: string): string {
  return generateSiweMessage({ ...baseParams, ...(statement ? { statement } : {}) });
}

function expectInvalid(message: string): void {
  try {
    parseSiweMessage(message);
    throw new Error('should have thrown');
  } catch (err) {
    expect(err).toBeInstanceOf(VericertsError);
    expect((err as VericertsError).code).toBe(ErrorCodes.SIWE_MESSAGE_INVALID);
  }
}

describe('SIWE メッセージ構造の ABNF 順序検査', () => {
  it.each([
    ['全任意フィールドが ABNF 順', [EXP, NBF, REQ, RES]],
    ['Expiration Time のみ', [EXP]],
    ['Not Before のみ', [NBF]],
    ['Request ID と Resources', [REQ, RES]],
    ['Resources のみ', [RES]],
    ['任意フィールドなし', []],
  ])('順序どおりなら受理: %s', (_name, extras) => {
    for (const statement of [undefined, 'Sign in with Ethereum']) {
      const message = [head(statement), ...extras].join('\n');
      expect(() => parseSiweMessage(message)).not.toThrow();
    }
  });

  it('順序どおりの Expiration Time / Not Before は parse に反映される', () => {
    const parsed = parseSiweMessage([head(), EXP, NBF].join('\n'));
    expect(parsed.expirationTime).toBe('2020-06-01T00:00:00.000Z');
    expect(parsed.notBefore).toBe('2020-01-01T00:00:00.000Z');
  });

  it.each([
    ['Not Before → Expiration Time', [NBF, EXP]],
    ['Request ID → Expiration Time', [REQ, EXP]],
    ['Request ID → Not Before', [REQ, NBF]],
    ['Resources → Expiration Time', [RES, EXP]],
    ['Resources → Not Before', [RES, NBF]],
    ['Resources → Request ID', [RES, REQ]],
  ])('ABNF 順を外れたフィールドは 8041: %s', (_name, extras) => {
    expectInvalid([head(), ...extras].join('\n'));
  });

  it('同じ任意フィールドの重複は 8041', () => {
    expectInvalid([head(), EXP, EXP].join('\n'));
    expectInvalid([head(), REQ, REQ].join('\n'));
  });

  it('末尾の未知行・空行・余剰行は 8041', () => {
    expectInvalid(`${head()}\nfoo`);
    expectInvalid(`${head()}\n`);
    expectInvalid([head(), EXP, 'foo'].join('\n'));
    expectInvalid([head(), RES, 'foo'].join('\n'));
    expectInvalid([head(), RES, ''].join('\n'));
  });

  it('必須フィールド行の欠落・順序入替は 8041', () => {
    const lines = head().split('\n');
    const nonceAt = lines.findIndex((line) => line.startsWith('Nonce: '));
    const swapped = [...lines];
    swapped.splice(nonceAt, 2, lines[nonceAt + 1] as string, lines[nonceAt] as string);
    expectInvalid(swapped.join('\n'));
    expectInvalid(lines.filter((line) => !line.startsWith('Version: ')).join('\n'));
  });

  it('statement がある場合は statement 直後の空行が必須（8041）', () => {
    const lines = head('Sign in with Ethereum').split('\n');
    const uriAt = lines.findIndex((line) => line.startsWith('URI: '));
    expectInvalid(lines.filter((_line, i) => i !== uriAt - 1).join('\n'));
    // 空行の代わりに非空の行が挟まっていても（URI の位置が合っていても）拒否する。
    expectInvalid(lines.map((line, i) => (i === uriAt - 1 ? 'junk' : line)).join('\n'));
  });

  it('statement なしでヘッダ直後に余剰空行があると 8041', () => {
    const lines = head().split('\n');
    const uriAt = lines.findIndex((line) => line.startsWith('URI: '));
    lines.splice(uriAt, 0, '');
    expectInvalid(lines.join('\n'));
  });
});
