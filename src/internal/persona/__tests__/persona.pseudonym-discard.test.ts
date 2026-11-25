/**
 * PersonaManager.discardPseudonym / isPseudonymDiscarded のテスト。
 * GDPR Art.7(3) の同意撤回時に、指定された rpIdentifier の Pseudonym を破棄する。
 *
 * - discardPseudonym 前は isPseudonymDiscarded が false を返す。
 * - discardPseudonym 後は isPseudonymDiscarded が true を返す。
 * - rpIdentifier は canonicalizeRpIdentifier で正規化されるため、大文字小文字・URL 表記揺れが異なって
 *   も同一 RP として扱われる（derivePseudonym の正規化と揃える）。
 * - 破棄していない別 RP には影響しない。
 * - 本メソッドは鍵導出・鍵破棄を一切行わない（storage のフラグ操作のみ）ことを、KeyManager が
 *   マスターシード未設定でも動作することで示す。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../storage/storage.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { createDidKey } from '../../identity/method-key.js';
import { KeyManager } from '../../keymanager/keymanager.js';
import { PersonaManager } from '../persona.js';

function newManager(): PersonaManager {
  // discardPseudonym / isPseudonymDiscarded は HD 鍵導出に関与しないため、KeyManager は
  // マスターシード未設定（importMnemonic 未呼び出し）のままでも動作することを兼ねて検証する。
  return new PersonaManager(new KeyManager(), new MemoryStorage(), createDidKey);
}

describe('PersonaManager.discardPseudonym / isPseudonymDiscarded', () => {
  it('discardPseudonym 前は isPseudonymDiscarded が false を返す', async () => {
    const manager = newManager();
    expect(await manager.isPseudonymDiscarded('did:web:rp.example')).toBe(false);
  });

  it('discardPseudonym 後は isPseudonymDiscarded が true を返す（マスターシード未設定でも動作する）', async () => {
    const manager = newManager();
    await manager.discardPseudonym('did:web:rp.example');
    expect(await manager.isPseudonymDiscarded('did:web:rp.example')).toBe(true);
  });

  it('rpIdentifier の大文字小文字揺れは同一エントリとして扱う（canonicalizeRpIdentifier）', async () => {
    const manager = newManager();
    await manager.discardPseudonym('DID:WEB:RP.EXAMPLE');
    expect(await manager.isPseudonymDiscarded('did:web:rp.example')).toBe(true);
  });

  it('URL 形式の rpIdentifier は origin へ正規化して同一視する', async () => {
    const manager = newManager();
    await manager.discardPseudonym('HTTPS://RP.EXAMPLE:443/callback');
    expect(await manager.isPseudonymDiscarded('https://rp.example:443')).toBe(true);
  });

  it('破棄していない別 RP には影響しない', async () => {
    const manager = newManager();
    await manager.discardPseudonym('did:web:rp-a.example');
    expect(await manager.isPseudonymDiscarded('did:web:rp-b.example')).toBe(false);
  });

  it('origin: prefixed client_id は RP ごとに別の破棄フラグになる', async () => {
    const manager = newManager();
    await manager.discardPseudonym('origin:https://rp-a.example');
    expect(await manager.isPseudonymDiscarded('origin:https://rp-a.example/cb')).toBe(true);
    expect(await manager.isPseudonymDiscarded('origin:https://rp-b.example')).toBe(false);
  });
});

describe('PersonaManager.assertPseudonymNotDiscarded', () => {
  it('破棄前は通る', async () => {
    await newManager().assertPseudonymNotDiscarded('https://rp.example');
  });

  it('discardPseudonym 後は 10603 pseudonym_discarded で拒否する', async () => {
    const manager = newManager();
    await manager.discardPseudonym('https://rp.example');
    await expect(manager.assertPseudonymNotDiscarded('https://rp.example')).rejects.toThrow(
      new VericertsError(ErrorCodes.GDPR_CONSENT_NOT_FOUND, {
        context: { reason: 'pseudonym_discarded' },
      }),
    );
  });

  it('表記揺れ（大文字・既定ポート）でも同一 RP として拒否し、別 RP は通る', async () => {
    const manager = newManager();
    await manager.discardPseudonym('HTTPS://RP.EXAMPLE:443');
    await expect(manager.assertPseudonymNotDiscarded('https://rp.example')).rejects.toBeInstanceOf(
      VericertsError,
    );
    await manager.assertPseudonymNotDiscarded('https://other.example');
  });
});

// 破棄マーカー（`pseudonym-discarded/<rpId>`）を一覧で取り出す公開 API。撤回の記録を持つ前に撤回した提示先も、
// 破棄マーカーからなら「撤回済み」として列挙できる。
describe('PersonaManager.listDiscardedPseudonyms', () => {
  function managerAt(storage: MemoryStorage, now: () => number): PersonaManager {
    return new PersonaManager(new KeyManager(), storage, createDidKey, now);
  }

  it('破棄していなければ空', async () => {
    expect(await newManager().listDiscardedPseudonyms()).toEqual([]);
  });

  it('破棄した RP を、正規化済みの識別子と破棄日時で、破棄の古い順に返す', async () => {
    let clock = 1_000;
    const manager = managerAt(new MemoryStorage(), () => clock);
    await manager.discardPseudonym('HTTPS://B.example:443/cb');
    clock = 2_000;
    await manager.discardPseudonym('did:web:a.example');

    expect(await manager.listDiscardedPseudonyms()).toEqual([
      { rpId: 'https://b.example', discardedAt: 1_000 },
      { rpId: 'did:web:a.example', discardedAt: 2_000 },
    ]);
  });

  it('同じ RP を表記違いで 2 回破棄しても 1 件', async () => {
    const manager = newManager();
    await manager.discardPseudonym('https://rp.example');
    await manager.discardPseudonym('HTTPS://RP.EXAMPLE/');

    expect(await manager.listDiscardedPseudonyms()).toHaveLength(1);
  });

  it('列挙するのは破棄マーカーだけ（他の prefix のキーは混ざらない）', async () => {
    const storage = new MemoryStorage();
    const manager = managerAt(storage, () => 1);
    await storage.set('persona/0', new TextEncoder().encode('{}'));
    await storage.set('subject-binding/x', new TextEncoder().encode('{}'));
    await manager.discardPseudonym('https://rp.example');

    expect((await manager.listDiscardedPseudonyms()).map((m) => m.rpId)).toEqual([
      'https://rp.example',
    ]);
  });

  // `isPseudonymDiscarded` は正規化したキーだけを引く。正規形でないキー・RP 識別子として不正なキーは、どの RP の破棄済み判定にも
  // 当たらないので列挙しない（列挙すると、破棄済みと判定されない識別子を「撤回済み」と見せる）。
  it('正規形でないキー・不正な識別子のキーは列挙しない', async () => {
    const storage = new MemoryStorage();
    const manager = managerAt(storage, () => 1);
    await storage.set(
      'pseudonym-discarded/HTTPS://RP.EXAMPLE',
      new TextEncoder().encode('{"discardedAt":5}'),
    );
    await storage.set(
      'pseudonym-discarded/not an rp://',
      new TextEncoder().encode('{"discardedAt":5}'),
    );
    await manager.discardPseudonym('https://rp.example');

    expect((await manager.listDiscardedPseudonyms()).map((m) => m.rpId)).toEqual([
      'https://rp.example',
    ]);
    expect(await manager.isPseudonymDiscarded('HTTPS://RP.EXAMPLE')).toBe(true); // 正規化して正規形のキーを引く
  });

  // 従来の実装が `origin:` 系の RP を `origin://` へ潰して残したキー。`canonicalizeRpIdentifier('origin://')` は `'origin://'` のままなので、
  // 正規形の判定だけでは除けない。特定の RP の撤回ではないので、一覧に載せない。
  it('従来の潰れたキー（`pseudonym-discarded/origin://`）は列挙しない', async () => {
    const storage = new MemoryStorage();
    const manager = managerAt(storage, () => 1);
    await storage.set(
      'pseudonym-discarded/origin://',
      new TextEncoder().encode('{"rpId":"origin://","discardedAt":5}'),
    );
    await manager.discardPseudonym('https://rp.example');

    expect((await manager.listDiscardedPseudonyms()).map((m) => m.rpId)).toEqual([
      'https://rp.example',
    ]);
  });

  // `isPseudonymDiscarded` はマーカーが在るかだけを見る（中身は読まない）。本文が読めなくても、破棄済みの RP は列挙から落とさない。
  it('本文が読めないマーカーも、破棄済みの RP として discardedAt: null で返す', async () => {
    const storage = new MemoryStorage();
    const manager = managerAt(storage, () => 1);
    await storage.set(
      'pseudonym-discarded/https://rp.example',
      new TextEncoder().encode('not json'),
    );

    expect(await manager.isPseudonymDiscarded('https://rp.example')).toBe(true);
    expect(await manager.listDiscardedPseudonyms()).toEqual([
      { rpId: 'https://rp.example', discardedAt: null },
    ]);
  });
});
