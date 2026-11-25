/**
 * `MethodIpid.update` の `Object.prototype` 汚染耐性テスト。
 *
 * `isIpidUpdateOptions` が `opts.ipnsKeyBytes` / `opts.ipnsKeyName` をプロトタイプ鎖経由で
 * 読んでいると、これらを**渡していない** `update(did, {})` 呼び出し（IPNS 鍵情報なし ＝
 * `METHOD_NOT_SUPPORTED` になるべきケース）が、汚染された `Object.prototype.ipnsKeyBytes` /
 * `Object.prototype.ipnsKeyName` を継承値として拾って通過してしまう。
 *
 * 通過すると `ipfsKeyImport` / `ipfsNamePublish` が攻撃者の鍵バイト列・キー名で実行され、
 * 呼び出し元の IPFS ノードに意図しない IPNS キー import・publish が発生する。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { type IpidUpdateOptions, MethodIpid } from '../../method-ipid.js';
import { ipnsNameOf, rawCidOf } from '../cid-fixture.js';
import { ipnsGateway } from '../ipns-fixture.js';

const CID = rawCidOf('created');
const IPNS = ipnsNameOf(6);

/** `validateIpnsKeyBytes` の許容長（32〜68B）に収まる攻撃者鍵バイト列。 */
const ATTACKER_KEY_BYTES = new Uint8Array(36).fill(0xaa);
const ATTACKER_KEY_NAME = 'attacker-ipns-key';

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

/**
 * IPFS API 呼び出しがあれば記録し、呼ばれた場合は接続不可を装って reject するモック。
 *
 * ガードが正しく機能すれば `fetch` は一度も呼ばれず `calls` は 0 のまま、`update` は
 * `METHOD_NOT_SUPPORTED`（2002）を投げて終わる。ガードが継承値を通してしまうと
 * `ipfsKeyImport` が実際に `fetch` を呼び、この reject で `DID_NOT_FOUND`（2003）等に
 * 化けるため、`calls` とエラーコードの両方で汚染バイパスを検知できる。
 */
function mockApiSpy(): { calls: number } {
  const state = { calls: 0 };
  globalThis.fetch = (async () => {
    state.calls += 1;
    throw new Error('unreachable IPFS node (test double)');
  }) as unknown as typeof fetch;
  return state;
}

async function expectMethodNotSupported(promise: Promise<unknown>): Promise<void> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(ErrorCodes.METHOD_NOT_SUPPORTED);
}

describe('MethodIpid.update の Object.prototype 汚染耐性', () => {
  it('データ汚染された ipnsKeyBytes / ipnsKeyName は IPNS 鍵情報省略時に採用されない', async () => {
    const spy = mockApiSpy();
    await withPollutedPrototype(
      { ipnsKeyBytes: ATTACKER_KEY_BYTES, ipnsKeyName: ATTACKER_KEY_NAME },
      () => expectMethodNotSupported(new MethodIpid().update(`did:ipid:${CID}`, {})),
    );
    // 通過して import/publish が呼ばれてしまうと攻撃者の鍵で IPFS ノードへ書き込みが発生する。
    expect(spy.calls).toBe(0);
  });

  it('アクセサ（getter）汚染された ipnsKeyBytes / ipnsKeyName も採用されない', async () => {
    const spy = mockApiSpy();
    await withPollutedPrototypeAccessor(
      { ipnsKeyBytes: () => ATTACKER_KEY_BYTES, ipnsKeyName: () => ATTACKER_KEY_NAME },
      () => expectMethodNotSupported(new MethodIpid().update(`did:ipid:${CID}`, {})),
    );
    expect(spy.calls).toBe(0);
  });

  it('片方のみ汚染（ipnsKeyBytes だけ）でも IPNS 鍵情報省略時は通過しない', async () => {
    const spy = mockApiSpy();
    await withPollutedPrototype({ ipnsKeyBytes: ATTACKER_KEY_BYTES }, () =>
      expectMethodNotSupported(new MethodIpid().update(`did:ipid:${CID}`, {})),
    );
    expect(spy.calls).toBe(0);
  });

  it('明示指定した IPNS 鍵情報は汚染下でも従来どおり反映される（正常系）', async () => {
    const legitOpts: IpidUpdateOptions = {
      ipnsKeyBytes: new Uint8Array(36).fill(3),
      ipnsKeyName: 'did-ipns-key',
    };
    const docText = JSON.stringify({
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: `did:ipid:${IPNS}`,
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
    });
    const gateway = ipnsGateway(6, docText);
    const calls: Array<{ url: string }> = [];
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: typeof input === 'string' ? input : input.toString() });
      if (init?.method !== 'POST') {
        return gateway.fetch(input, init);
      }
      const payload = calls.length === 1 ? { Name: 'did-ipns-key' } : { Name: IPNS };
      return new Response(JSON.stringify(payload), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;

    const doc = await withPollutedPrototype(
      { ipnsKeyBytes: ATTACKER_KEY_BYTES, ipnsKeyName: ATTACKER_KEY_NAME },
      () => new MethodIpid().update(`did:ipid:${CID}`, legitOpts),
    );

    expect(calls).toHaveLength(4); // key/import, name/publish, ipns レコード, ipfs 本文
    // import に使われたキー名は明示指定した値であり、汚染値ではない。
    expect(calls[0]?.url).toContain('did-ipns-key');
    expect(calls[0]?.url).not.toContain(ATTACKER_KEY_NAME);
    expect(doc.id).toBe(`did:ipid:${IPNS}`);
  });
});
