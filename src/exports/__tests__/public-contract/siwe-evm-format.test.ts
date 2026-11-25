/**
 * `/asset` が公開する SIWE 署名・厳密パーサと EVM 形式検証の契約。公開 entry 経由で検査する。
 */

import { describe, expect, test } from 'bun:test';
import * as sdk from '../../../index.js';
import type { Signer } from '../../../internal/keymanager/types.js';
import * as assetEntry from '../../asset.js';
import {
  isHexString,
  isValidEvmAddress,
  parseSiweStrict,
  personalSignMessageBytes,
  personalSignPayload,
  signSIWE,
} from '../../asset.js';

const ADDRESS = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';
const SIWE = [
  'service.org wants you to sign in with your Ethereum account:',
  ADDRESS,
  '',
  'I accept the ServiceOrg Terms of Service: https://service.org/tos',
  '',
  'URI: https://service.org/login',
  'Version: 1',
  'Chain ID: 1',
  'Nonce: 32891756',
  'Issued At: 2021-09-30T16:25:24Z',
].join('\n');
const toHex = (text: string) => `0x${Buffer.from(text).toString('hex')}`;

describe('公開契約: SIWE（vericerts-wallet-sdk/asset）', () => {
  test('parseSiweStrict は承認前の経路（hex 入力）でも素の SIWE と同じフィールドを返す', () => {
    const plain = parseSiweStrict(SIWE);
    expect(plain?.address).toBe(ADDRESS);
    const decoded = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(
      personalSignMessageBytes(toHex(SIWE)),
    );
    expect(parseSiweStrict(decoded)).toEqual(plain);
  });

  test('hex 入力と平文入力は personalSignMessageBytes の戻り値として同一バイト列になる', () => {
    expect([...personalSignMessageBytes(toHex(SIWE))]).toEqual([...personalSignMessageBytes(SIWE)]);
  });

  test('SIWE 風で不正 UTF-8 を含む文面は fatal 復号が失敗する（厳密パースへ渡させない根拠）', () => {
    // 拡張の承認前検証は、fatal 復号（`personalSignMessageText`）が null なら
    // 厳密パースを行わず、lossy 復号した文面が SIWE 風なら SIWE_MALFORMED で拒否する。「SIWE 風かの検出」と
    // 拒否は extension の責務（`looksLikeSiwe` は SDK から見えない）。SDK 側で固定するのは、不正バイトが
    // fatal 復号で必ず失敗すること。parseSiweStrict 自体は U+FFFD 入りの statement を受理するので、
    // lossy 復号した文面を厳密パースへ渡してはならない（渡すと不正 UTF-8 の SIWE が通ってしまう）。
    const bytes = Buffer.from(SIWE);
    // 文字インデックスではなくバイトオフセットで求める（SIWE に非 ASCII が入ってもずれない）。
    const statementEnd = bytes.indexOf('Terms of Service') + 'Terms'.length;
    const injected = (byte: number) =>
      `0x${Buffer.concat([bytes.subarray(0, statementEnd), Buffer.from([byte]), bytes.subarray(statementEnd)]).toString('hex')}`;
    const fatal = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    const lossy = new TextDecoder('utf-8', { fatal: false, ignoreBOM: true });

    const invalidHex = injected(0xff);
    expect(() => fatal.decode(personalSignMessageBytes(invalidHex))).toThrow();
    expect(lossy.decode(personalSignMessageBytes(invalidHex))).toContain('\uFFFD');
    // 次の 1 行は現状の挙動の記録（characterization）であって、承認した契約ではない。parseSiweStrict を
    // U+FFFD 拒否へ厳格化したらここは落ちるが、それは回帰ではないので期待値を toBeNull() へ変えてよい。
    // その際は 拡張の承認前検証の「fatal 復号が null なら厳密パースへ渡さない」前提も見直す
    // （厳格化すれば lossy 文面を厳密パースへ渡しても安全になり、looksLikeSiwe による検出が不要になりうる）。
    expect(parseSiweStrict(lossy.decode(personalSignMessageBytes(invalidHex)))).not.toBeNull();
    // 対照: 有効な ASCII なら fatal 復号は成功する（上の throw が不正バイト起因である証拠）。
    expect(() => fatal.decode(personalSignMessageBytes(injected(0x41)))).not.toThrow();
  });

  test('signSIWE は personalSignPayload と同じバイト列を Signer.sign へ渡す', async () => {
    const signed: Uint8Array[] = [];
    const signer: Signer = {
      sign: async (payload) => {
        signed.push(payload);
        return new Uint8Array(65);
      },
      publicKey: () => new Uint8Array(33),
      address: () => ADDRESS,
    };
    await signSIWE(SIWE, signer);
    expect([...(signed[0] ?? [])]).toEqual([...personalSignPayload(SIWE)]);
  });

  test('/asset の signSIWE はメインバレルと同一参照', () => {
    expect(assetEntry.signSIWE).toBe(sdk.signSIWE);
  });
});

describe('公開契約: EVM 形式検証（vericerts-wallet-sdk/asset）', () => {
  test('isHexString は 0x のみ・奇数桁・0X・allowEmpty の切替を区別する', () => {
    expect(isHexString('0x')).toBe(false);
    expect(isHexString('0x', { allowEmpty: true })).toBe(true);
    expect(isHexString('0xabc')).toBe(true);
    expect(isHexString('0X68656c6c6f')).toBe(false);
    expect(isHexString('0xzz')).toBe(false);
    expect(isHexString(1)).toBe(false);
  });

  test('isHexString は Object.prototype.allowEmpty の汚染を拾わない', () => {
    try {
      (Object.prototype as { allowEmpty?: boolean }).allowEmpty = true;
      expect(isHexString('0x')).toBe(false);
    } finally {
      delete (Object.prototype as { allowEmpty?: boolean }).allowEmpty;
    }
  });

  test('isValidEvmAddress は全小文字・全大文字を形式のみで受理し、混在表記は EIP-55 を要求する', () => {
    expect(isValidEvmAddress(ADDRESS)).toBe(true);
    expect(isValidEvmAddress(ADDRESS.toLowerCase())).toBe(true);
    expect(isValidEvmAddress(`0x${ADDRESS.slice(2).toUpperCase()}`)).toBe(true);
    const wrongChecksum = `${ADDRESS.slice(0, -1)}${ADDRESS.endsWith('c') ? 'C' : 'c'}`;
    expect(isValidEvmAddress(wrongChecksum)).toBe(false);
    expect(isValidEvmAddress('0x1234')).toBe(false);
  });
});
