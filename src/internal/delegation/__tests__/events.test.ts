import { describe, expect, test } from 'bun:test';
import { VericertsError } from '../../errors.js';
import type { OwnerChangeEvent } from '../../identity/ethr/events.js';
import { parseEthrDid } from '../did-ethr.js';
import { detectController, type Erc1056EventSource } from '../events.js';

const A = '0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa';
const B = '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB';
const C = '0xCCcCCCccCCCCccCCCCCCCcCCCccCcCCccccccCCCc';

/**
 * identity アドレス → owner 変更イベント列のマップを返すモック EventSource。
 * did:ethrの `Erc1056EventSource` 互換: `fetchEvents` が `ownerChanges` を返す。
 * キーは小文字アドレス。未登録は空配列（自己所有）。attributeChanges は controller 検出で
 * 使わないため常に空とする。
 */
function mockSource(table: Record<string, readonly OwnerChangeEvent[]>): Erc1056EventSource {
  return {
    async fetchEvents(_chainId, address) {
      return {
        ownerChanges: table[address.toLowerCase()] ?? [],
        attributeChanges: [],
      };
    },
  };
}

describe('detectController', () => {
  test('単一階層: A の owner が B なら controller は did:ethr:B', async () => {
    const source = mockSource({
      [A.toLowerCase()]: [{ owner: B, blockNumber: 10, logIndex: 0 }],
    });
    const controller = await detectController(parseEthrDid(`did:ethr:${A}`), source);
    expect(controller).toBe(`did:ethr:${B}`);
  });

  test('owner 連鎖: A→B→C を最上位 C までたどる', async () => {
    const source = mockSource({
      [A.toLowerCase()]: [{ owner: B, blockNumber: 1, logIndex: 0 }],
      [B.toLowerCase()]: [{ owner: C, blockNumber: 2, logIndex: 0 }],
      // C は自己所有（イベントなし）→ 終端。
    });
    const controller = await detectController(parseEthrDid(`did:ethr:${A}`), source);
    expect(controller).toBe(`did:ethr:${C}`);
  });

  test('複数イベントは blockNumber→logIndex 昇順で最新 owner を採用', async () => {
    const source = mockSource({
      [A.toLowerCase()]: [
        { owner: C, blockNumber: 5, logIndex: 1 },
        { owner: B, blockNumber: 5, logIndex: 0 },
        { owner: A, blockNumber: 3, logIndex: 9 },
      ],
    });
    // 末尾（block5, logIndex1）の owner=C が現 owner。C は自己所有で終端。
    const controller = await detectController(parseEthrDid(`did:ethr:${A}`), source);
    expect(controller).toBe(`did:ethr:${C}`);
  });

  test('controller 未設定（起点が自己所有）は 2006', async () => {
    const source = mockSource({});
    try {
      await detectController(parseEthrDid(`did:ethr:${A}`), source);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('2006');
    }
  });

  test('起点 owner が明示的に自分自身でも 2006', async () => {
    const source = mockSource({
      [A.toLowerCase()]: [{ owner: A, blockNumber: 7, logIndex: 0 }],
    });
    try {
      await detectController(parseEthrDid(`did:ethr:${A}`), source);
      throw new Error('should have thrown');
    } catch (e) {
      expect((e as VericertsError).code).toBe('2006');
    }
  });

  test('循環参照 A→B→A は 2030', async () => {
    const source = mockSource({
      [A.toLowerCase()]: [{ owner: B, blockNumber: 1, logIndex: 0 }],
      [B.toLowerCase()]: [{ owner: A, blockNumber: 2, logIndex: 0 }],
    });
    try {
      await detectController(parseEthrDid(`did:ethr:${A}`), source);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('2030');
    }
  });

  test('owner 比較は大文字小文字を無視', async () => {
    const source = mockSource({
      [A.toLowerCase()]: [{ owner: B.toLowerCase(), blockNumber: 1, logIndex: 0 }],
    });
    const controller = await detectController(parseEthrDid(`did:ethr:${A}`), source);
    // 終端 identity（B の checksum 形）の did を返す。
    expect(controller.toLowerCase()).toBe(`did:ethr:${B}`.toLowerCase());
  });
});
