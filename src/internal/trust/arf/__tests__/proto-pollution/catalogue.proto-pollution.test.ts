/**
 * ARF Trust Anchor Catalogue の `Object.prototype` 汚染耐性テスト。
 *
 * `loadArfTrustAnchor` の DI オプションと、署名エンベロープ / payload / エントリ（いずれも
 * `JSON.parse` 由来）をプロトタイプ鎖で読むと、
 *
 * - `fetcher` を**省略した**呼び出しが攻撃者の関数へ委譲され Catalogue を丸ごとすり替えられる、
 * - `trustAnchorPublicKey` を省略した呼び出しが攻撃者のピン留め鍵で署名検証を通す（最重要）、
 * - `{}` のエンベロープでも汚染値が payload / signature として採用される、
 * - `entries` を持たない payload に汚染値の登録一覧が生える、
 * - `role` を持たないエントリが汚染値で「登録済み wallet-provider」に化ける、
 *
 * という形で fail-closed が崩れる。異常はすべて 10305（ARF_TRUST_ANCHOR_NOT_REGISTERED）へ。
 */

import { describe, expect, it } from 'bun:test';
import { base64 } from '@scure/base';
import {
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { LoadArfTrustAnchorOptions } from '../../arf-types.js';
import { loadArfTrustAnchor } from '../../catalogue.js';
import { makeKeyPair, signedCatalogue } from '../arf-fixtures.js';

const URL = 'https://arf.example/anchor.json';
/** アプリにピン留めされた正規の ARF Trust Anchor 鍵。 */
const PINNED = makeKeyPair(3);
/** 攻撃者が握る鍵。汚染経由でピン留め鍵に化けると Catalogue をすり替えられる。 */
const EVIL = makeKeyPair(11);

/** 攻撃者が用意した「登録済み wallet-provider」入りの Catalogue。 */
const EVIL_ENTRIES = [{ id: 'https://evil.example', role: 'wallet-provider' }];

/** 固定文字列を返す fetcher。 */
function fetcherOf(body: string): (url: string) => Promise<string> {
  return async () => body;
}

/** 汚染を戻してからアサーションするため、投げられたエラーを捕捉して返す。 */
async function captureError(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn();
    return undefined;
  } catch (error) {
    return error;
  }
}

/** 10305 で fail-closed していることを検証する。 */
function expectNotRegistered(error: unknown): void {
  expect(error).toBeInstanceOf(VericertsError);
  expect((error as VericertsError).code).toBe(ErrorCodes.ARF_TRUST_ANCHOR_NOT_REGISTERED);
}

/** `fetcher` を欠いたオプション（型の穴は意図的。汚染で埋まらないことを検証する）。 */
function optionsWithoutFetcher(): LoadArfTrustAnchorOptions {
  return { trustAnchorPublicKey: PINNED.publicKey } as unknown as LoadArfTrustAnchorOptions;
}

/** `trustAnchorPublicKey` を欠いたオプション。 */
function optionsWithoutKey(body: string): LoadArfTrustAnchorOptions {
  return { fetcher: fetcherOf(body) } as unknown as LoadArfTrustAnchorOptions;
}

describe('loadArfTrustAnchor の DI オプション汚染耐性', () => {
  it('継承した fetcher へ Catalogue 取得を委譲しない', async () => {
    let delegated = false;
    // getter は呼ばれるたび新しい関数を返す（同一性比較では弾けない汚染）。
    const error = await withPollutedPrototypeAccessorAsync(
      {
        fetcher: () => async () => {
          delegated = true;
          // ピン留め鍵で正しく署名された本文。委譲されれば署名検証まで通ってしまう。
          return signedCatalogue({ entries: EVIL_ENTRIES }, PINNED);
        },
      },
      () => captureError(() => loadArfTrustAnchor(URL, optionsWithoutFetcher())),
    );
    expect(delegated).toBe(false);
    expectNotRegistered(error);
  });

  it('継承した trustAnchorPublicKey をピン留め鍵として採用しない', async () => {
    // 攻撃者の鍵で署名された Catalogue。汚染した 32 バイト鍵を拾えば署名検証が通る。
    const body = signedCatalogue({ entries: EVIL_ENTRIES }, EVIL);
    const error = await withPollutedPrototypeAsync({ trustAnchorPublicKey: EVIL.publicKey }, () =>
      captureError(() => loadArfTrustAnchor(URL, optionsWithoutKey(body))),
    );
    expectNotRegistered(error);
  });
});

describe('ARF エンベロープ / payload の汚染耐性', () => {
  it('payload / signature を持たないエンベロープに汚染値を採用しない', async () => {
    const genuine = JSON.parse(signedCatalogue({ entries: EVIL_ENTRIES }, PINNED)) as {
      payload: string;
      signature: string;
    };
    const error = await withPollutedPrototypeAsync(
      { payload: genuine.payload, signature: genuine.signature },
      () =>
        captureError(() =>
          loadArfTrustAnchor(URL, {
            fetcher: fetcherOf('{}'),
            trustAnchorPublicKey: PINNED.publicKey,
          }),
        ),
    );
    expectNotRegistered(error);
  });

  it('entries を持たない payload に汚染値の登録一覧が生えない', async () => {
    // 署名自体は正当（ピン留め鍵）。payload は entries を持たない。
    const body = signedCatalogue({ entries: undefined } as never, PINNED);
    const error = await withPollutedPrototypeAsync({ entries: EVIL_ENTRIES }, () =>
      captureError(() =>
        loadArfTrustAnchor(URL, {
          fetcher: fetcherOf(body),
          trustAnchorPublicKey: PINNED.publicKey,
        }),
      ),
    );
    expectNotRegistered(error);
  });

  it('version を持たない payload に汚染値のバージョンが載らない', async () => {
    const body = signedCatalogue({ entries: [] }, PINNED);
    const result = await withPollutedPrototypeAsync({ version: 'pwned' }, () =>
      loadArfTrustAnchor(URL, {
        fetcher: fetcherOf(body),
        trustAnchorPublicKey: PINNED.publicKey,
      }),
    );
    expect(result.version).toBeUndefined();
  });
});

describe('ARF エントリの汚染耐性', () => {
  /** 署名済み Catalogue を汚染下で読み込む（正当なオプションのみ渡す）。 */
  async function loadPolluted(entries: unknown[], props: Readonly<Record<string, unknown>>) {
    const body = signedCatalogue({ entries }, PINNED);
    return withPollutedPrototypeAsync(props, () =>
      loadArfTrustAnchor(URL, {
        fetcher: fetcherOf(body),
        trustAnchorPublicKey: PINNED.publicKey,
      }),
    );
  }

  it('role を持たないエントリが継承値で wallet-provider に化けない', async () => {
    const result = await loadPolluted([{ id: 'https://unregistered.example' }], {
      role: 'wallet-provider',
    });
    expect(result.entries).toEqual([]);
  });

  it('id を持たないエントリが継承値で識別子を得ない', async () => {
    const result = await loadPolluted([{ role: 'issuer' }], { id: 'https://evil.example' });
    expect(result.entries).toEqual([]);
  });

  it('country を持たないエントリに継承値の所在国が載らない', async () => {
    const result = await loadPolluted([{ id: 'https://issuer.example', role: 'issuer' }], {
      country: 'XX',
    });
    expect(result.entries.length).toBe(1);
    expect(result.entries[0]?.country).toBeUndefined();
  });

  it('spki を持たないエントリに継承値の公開鍵が載らない', async () => {
    const evilSpki = base64.encode(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x2a]));
    const result = await loadPolluted([{ id: 'https://issuer.example', role: 'issuer' }], {
      spki: evilSpki,
    });
    expect(result.entries.length).toBe(1);
    expect(result.entries[0]?.spki).toBeUndefined();
  });
});

/**
 * `fetcher` をプロトタイプメソッドとして実装した正当なクラスベース DI。
 * own 限定で読むとこれが「未指定」に化けるため、正常系として固定する。
 *
 * `fetcher` は `this`（インスタンス状態）を参照する。取り出した関数を裸で呼ぶとレシーバが
 * 失われ、従来の `options.fetcher(url)` では動いていた実装が壊れるため、その回帰も固定する。
 */
class CatalogueLoader {
  readonly requestedUrls: string[] = [];

  constructor(
    readonly trustAnchorPublicKey: Uint8Array,
    private readonly body: string,
  ) {}

  async fetcher(url: string): Promise<string> {
    this.requestedUrls.push(url);
    return this.body;
  }
}

describe('クラスベース DI の正常系（own 化しすぎの回帰検出）', () => {
  it('prototype メソッドの fetcher で Catalogue を取得できる', async () => {
    const loader = new CatalogueLoader(
      PINNED.publicKey,
      signedCatalogue({ version: '2026-07', entries: EVIL_ENTRIES }, PINNED),
    );
    const result = await loadArfTrustAnchor(URL, loader);
    expect(result.signatureValid).toBe(true);
    expect(result.version).toBe('2026-07');
    expect(result.entries.length).toBe(1);
    expect(result.entries[0]?.role).toBe('wallet-provider');
    // レシーバが `options` に束ね直されている（`this` 参照つきメソッドが動く）。
    expect(loader.requestedUrls).toEqual([URL]);
  });

  it('Object.create のプロトタイプに置いた fetcher でも取得できる', async () => {
    const body = signedCatalogue(
      { entries: [{ id: 'https://wp.example', role: 'issuer' }] },
      PINNED,
    );
    const options = Object.create({ fetcher: fetcherOf(body) }) as LoadArfTrustAnchorOptions;
    Object.defineProperty(options, 'trustAnchorPublicKey', { value: PINNED.publicKey });
    const result = await loadArfTrustAnchor(URL, options);
    expect(result.entries[0]?.id).toBe('https://wp.example');
  });
});
