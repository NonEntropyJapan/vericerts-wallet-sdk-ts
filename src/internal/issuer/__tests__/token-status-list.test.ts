/**
 * Status List Token（JWT）生成・更新とインデックス管理のユニットテスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - allocate が 0 始まりで連番を返し、容量超過で 3007（INDEX_EXHAUSTED）。
 * - setStatus / getStatus のラウンドトリップ（失効 → 解除）。
 * - reference が VC の status クレーム（idx / uri）を返す。
 * - issueToken が発行者・リスト URI・発行時刻・ビット列を含む署名付きコンパクト JWT を生成する。
 * - issueToken の lst を展開すると set した状態が復元される（圧縮往復 + JWT 整合）。
 * - 不正な uri / issuer を 3002 で拒否する。
 */

import { describe, expect, it } from 'bun:test';
import { decodeCompactJws } from '../../credential/vc/jws.js';
import { createPrivateKeySigner } from '../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { decompressBitstring, StatusBitstring } from '../bitstring.js';
import type { StatusListTokenPayload } from '../status-list-token.js';
import { StatusListManager } from '../token-status-list.js';

const ISSUER_KEY = new Uint8Array(32).fill(7);
const SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const URI = 'https://issuer.example/status/1';
const ISSUER = 'did:web:issuer.example';

function makeManager(size = 100): StatusListManager {
  return new StatusListManager({ uri: URI, issuer: ISSUER, size, bits: 1 });
}

describe('StatusListManager.allocate', () => {
  it('0 始まりで連番を返す', () => {
    const m = makeManager();
    expect(m.allocate()).toBe(0);
    expect(m.allocate()).toBe(1);
    expect(m.allocate()).toBe(2);
  });

  it('容量を使い切ると 3007 を投げる', () => {
    const m = makeManager(2);
    m.allocate();
    m.allocate();
    try {
      m.allocate();
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.STATUS_LIST_INDEX_EXHAUSTED);
      return;
    }
    throw new Error('expected throw');
  });
});

describe('StatusListManager.setStatus/getStatus', () => {
  it('失効 → 解除をラウンドトリップする', () => {
    const m = makeManager();
    const idx = m.allocate();
    expect(m.getStatus(idx)).toBe(0);
    m.setStatus(idx, 1);
    expect(m.getStatus(idx)).toBe(1);
    m.setStatus(idx, 0);
    expect(m.getStatus(idx)).toBe(0);
  });

  it('容量外インデックスを 3002 で拒否する', () => {
    const m = makeManager(4);
    try {
      m.setStatus(100, 1);
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
      return;
    }
    throw new Error('expected throw');
  });
});

describe('StatusListManager.reference', () => {
  it('VC status クレーム（idx / uri）を返す', () => {
    const m = makeManager();
    const idx = m.allocate();
    expect(m.reference(idx)).toEqual({ status_list: { idx, uri: URI } });
  });
});

describe('StatusListManager.issueToken', () => {
  it('署名付き JWT に iss・sub・iat と status_list の bits・lst を含める', async () => {
    const m = makeManager();
    const idx = m.allocate();
    m.setStatus(idx, 1);
    const token = await m.issueToken(SIGNER, { iatSeconds: 1_700_000_000 });

    expect(token.split('.')).toHaveLength(3);
    const decoded = decodeCompactJws(token);
    expect(decoded.header.alg).toBe('ES256');
    expect(decoded.header.typ).toBe('statuslist+jwt');

    const payload = decoded.payload as unknown as StatusListTokenPayload;
    expect(payload.iss).toBe(ISSUER);
    expect(payload.sub).toBe(URI);
    expect(payload.iat).toBe(1_700_000_000);
    expect(payload.status_list.bits).toBe(1);
    expect(typeof payload.status_list.lst).toBe('string');
  });

  it('exp 指定時は payload に exp を含む / 未指定なら含まない', async () => {
    const m = makeManager();
    const withExp = decodeCompactJws(
      await m.issueToken(SIGNER, { iatSeconds: 1_700_000_000, expSeconds: 1_800_000_000 }),
    ).payload as unknown as StatusListTokenPayload;
    expect(withExp.exp).toBe(1_800_000_000);

    const withoutExp = decodeCompactJws(await m.issueToken(SIGNER, { iatSeconds: 1_700_000_000 }))
      .payload as unknown as StatusListTokenPayload;
    expect('exp' in withoutExp).toBe(false);
  });

  it('lst を展開すると set した失効状態が復元される', async () => {
    const m = makeManager();
    const a = m.allocate();
    const b = m.allocate();
    const c = m.allocate();
    m.setStatus(a, 1);
    m.setStatus(c, 1);

    const token = await m.issueToken(SIGNER, { iatSeconds: 1_700_000_000 });
    const payload = decodeCompactJws(token).payload as unknown as StatusListTokenPayload;
    const bytes = await decompressBitstring(payload.status_list.lst);
    const restored = StatusBitstring.fromBytes(bytes, m.size, payload.status_list.bits);

    expect(restored.get(a)).toBe(1);
    expect(restored.get(b)).toBe(0);
    expect(restored.get(c)).toBe(1);
  });

  it('署名はその後の状態更新で変化する（lst が再圧縮される）', async () => {
    const m = makeManager();
    const idx = m.allocate();
    const before = await m.issueToken(SIGNER, { iatSeconds: 1_700_000_000 });
    m.setStatus(idx, 1);
    const after = await m.issueToken(SIGNER, { iatSeconds: 1_700_000_000 });
    expect(before).not.toBe(after);
  });
});

describe('StatusListManager constructor', () => {
  it('空の uri / issuer を 3002 で拒否する', () => {
    expect(() => new StatusListManager({ uri: '', issuer: ISSUER, size: 10 })).toThrow(
      VericertsError,
    );
    expect(() => new StatusListManager({ uri: URI, issuer: '', size: 10 })).toThrow(VericertsError);
  });

  it('不正な size を 3002 で拒否する（StatusBitstring へ委譲）', () => {
    expect(() => new StatusListManager({ uri: URI, issuer: ISSUER, size: 0 })).toThrow(
      VericertsError,
    );
  });
});
