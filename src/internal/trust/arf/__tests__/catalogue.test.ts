import { describe, expect, test } from 'bun:test';
import { base64, base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { ArfTrustAnchorFetcher } from '../arf-types.js';
import { isObject, loadArfTrustAnchor } from '../catalogue.js';
import { makeKeyPair, signedCatalogue } from './arf-fixtures.js';

const KEY = makeKeyPair(3);

/** 固定文字列を返す fetcher。 */
function fetcherOf(body: string): ArfTrustAnchorFetcher {
  return async () => body;
}

async function expectRejectsNotRegistered(promise: Promise<unknown>): Promise<void> {
  await expect(promise).rejects.toBeInstanceOf(VericertsError);
  await expect(promise).rejects.toMatchObject({
    code: ErrorCodes.ARF_TRUST_ANCHOR_NOT_REGISTERED,
  });
}

describe('loadArfTrustAnchor', () => {
  test('署名検証に成功し登録エントリを返す', async () => {
    const body = signedCatalogue(
      {
        version: '2026-07',
        entries: [
          { id: 'did:web:issuer.example.eu', role: 'issuer', country: 'DE' },
          { id: 'https://wp.example.eu', role: 'wallet-provider' },
        ],
      },
      KEY,
    );
    const result = await loadArfTrustAnchor('https://arf.example/anchor.json', {
      fetcher: fetcherOf(body),
      trustAnchorPublicKey: KEY.publicKey,
    });
    expect(result.signatureValid).toBe(true);
    expect(result.version).toBe('2026-07');
    expect(result.entries.length).toBe(2);
    expect(result.entries[0]?.id).toBe('did:web:issuer.example.eu');
    expect(result.entries[0]?.role).toBe('issuer');
    expect(result.entries[0]?.country).toBe('DE');
    expect(result.entries[1]?.country).toBeUndefined();
  });

  test('SPKI 付きエントリは Uint8Array にデコードされる', async () => {
    const spki = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x2a]);
    const body = signedCatalogue(
      { entries: [{ id: 'x', role: 'issuer', spki: base64.encode(spki) }] },
      KEY,
    );
    const result = await loadArfTrustAnchor('https://arf.example/a.json', {
      fetcher: fetcherOf(body),
      trustAnchorPublicKey: KEY.publicKey,
    });
    expect(result.entries[0]?.spki).toEqual(spki);
  });

  test('取得失敗は 10305 で fail-closed', async () => {
    await expectRejectsNotRegistered(
      loadArfTrustAnchor('https://arf.example/a.json', {
        fetcher: async () => {
          throw new Error('network');
        },
        trustAnchorPublicKey: KEY.publicKey,
      }),
    );
  });

  test('別鍵の署名は検証失敗（10305）', async () => {
    const body = signedCatalogue({ entries: [{ id: 'x', role: 'issuer' }] }, makeKeyPair(9));
    await expectRejectsNotRegistered(
      loadArfTrustAnchor('https://arf.example/a.json', {
        fetcher: fetcherOf(body),
        trustAnchorPublicKey: KEY.publicKey,
      }),
    );
  });

  test('payload 改ざんで署名不一致（10305）', async () => {
    const body = signedCatalogue({ entries: [{ id: 'x', role: 'issuer' }] }, KEY);
    const env = JSON.parse(body) as { payload: string; signature: string };
    const tampered = JSON.stringify({
      payload: base64urlnopad.encode(
        new TextEncoder().encode(JSON.stringify({ entries: [{ id: 'evil', role: 'issuer' }] })),
      ),
      signature: env.signature,
    });
    await expectRejectsNotRegistered(
      loadArfTrustAnchor('https://arf.example/a.json', {
        fetcher: fetcherOf(tampered),
        trustAnchorPublicKey: KEY.publicKey,
      }),
    );
  });

  test('不正な JSON エンベロープは 10305', async () => {
    await expectRejectsNotRegistered(
      loadArfTrustAnchor('https://arf.example/a.json', {
        fetcher: fetcherOf('not json'),
        trustAnchorPublicKey: KEY.publicKey,
      }),
    );
  });

  test('payload/signature 欠落は 10305', async () => {
    await expectRejectsNotRegistered(
      loadArfTrustAnchor('https://arf.example/a.json', {
        fetcher: fetcherOf(JSON.stringify({ payload: 'abc' })),
        trustAnchorPublicKey: KEY.publicKey,
      }),
    );
  });

  test('固定鍵長が不正なら 10305（設定ミス）', async () => {
    const body = signedCatalogue({ entries: [] }, KEY);
    await expectRejectsNotRegistered(
      loadArfTrustAnchor('https://arf.example/a.json', {
        fetcher: fetcherOf(body),
        trustAnchorPublicKey: new Uint8Array(16),
      }),
    );
  });

  test('未知の role・空 id のエントリは除外される（fail-closed）', async () => {
    const body = signedCatalogue(
      {
        entries: [
          { id: 'valid', role: 'issuer' },
          { id: '', role: 'issuer' },
          { id: 'bad-role', role: 'unknown' },
          { role: 'issuer' },
          'not-an-object',
        ],
      },
      KEY,
    );
    const result = await loadArfTrustAnchor('https://arf.example/a.json', {
      fetcher: fetcherOf(body),
      trustAnchorPublicKey: KEY.publicKey,
    });
    expect(result.entries.length).toBe(1);
    expect(result.entries[0]?.id).toBe('valid');
  });

  test('relying-party role のエントリは登録される', async () => {
    const body = signedCatalogue(
      { entries: [{ id: 'https://verifier.example.eu', role: 'relying-party' }] },
      KEY,
    );
    const result = await loadArfTrustAnchor('https://arf.example/a.json', {
      fetcher: fetcherOf(body),
      trustAnchorPublicKey: KEY.publicKey,
    });
    expect(result.entries.length).toBe(1);
    expect(result.entries[0]?.role).toBe('relying-party');
  });

  test('entries が配列でない payload は 10305', async () => {
    const body = signedCatalogue({ entries: {} as unknown as unknown[] }, KEY);
    await expectRejectsNotRegistered(
      loadArfTrustAnchor('https://arf.example/a.json', {
        fetcher: fetcherOf(body),
        trustAnchorPublicKey: KEY.publicKey,
      }),
    );
  });

  test('返却オブジェクトは ArfCatalogueEntry / ArfTrustAnchorSet のキーだけを持つ', async () => {
    // 利用側に公開するフィールドの追加・改称を検出する。
    const spki = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x2a]);
    const body = signedCatalogue(
      {
        version: '2026-07',
        entries: [
          {
            id: 'did:web:issuer.example.eu',
            role: 'issuer',
            country: 'DE',
            spki: base64.encode(spki),
          },
        ],
      },
      KEY,
    );
    const result = await loadArfTrustAnchor('https://arf.example/anchor.json', {
      fetcher: fetcherOf(body),
      trustAnchorPublicKey: KEY.publicKey,
    });
    expect(Object.keys(result).sort()).toEqual(['entries', 'signatureValid', 'version']);
    expect(Object.keys(result.entries[0] ?? {}).sort()).toEqual(['country', 'id', 'role', 'spki']);
  });
});

/**
 * `auth/jar/jar-trust-arf.ts` / `auth/jar/jar-trust-evaluation.ts` に個別定義されていた
 * 同一ロジックを `isObject` へ集約した際の**挙動不変**を担保する。
 */
describe('isObject', () => {
  test('非 null のオブジェクトは true（配列も含む）', () => {
    expect(isObject({})).toBe(true);
    expect(isObject({ a: 1 })).toBe(true);
    expect(isObject([])).toBe(true);
  });

  test('null・プリミティブ・undefined は false', () => {
    expect(isObject(null)).toBe(false);
    expect(isObject(undefined)).toBe(false);
    expect(isObject('string')).toBe(false);
    expect(isObject(42)).toBe(false);
  });
});
