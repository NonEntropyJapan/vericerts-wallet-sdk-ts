/**
 * MethodIpid の公開（create）・更新（update）・無効化（deactivate）検証。
 *
 * 実 IPFS ノードに依存しないよう `globalThis.fetch` を差し替え、IPFS HTTP API 呼び出しの
 * 形（URL / メソッド / multipart body）を検証する:
 * - create: `POST <api>/api/v0/add` → CIDv1、戻り値 DID が `did:ipid:<CID>`。
 * - update: `POST <api>/api/v0/key/import` → `POST <api>/api/v0/name/publish` → IPNS DID。
 * - deactivate: `METHOD_NOT_SUPPORTED`（2002）。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { CreateOptions } from '../../did.js';
import { type IpidUpdateOptions, MethodIpid } from '../method-ipid.js';
import { ipnsNameOf, rawCidOf } from './cid-fixture.js';
import { ipnsGateway } from './ipns-fixture.js';

const CID = rawCidOf('created');
const IPNS = ipnsNameOf(5);

const CREATE_OPTS: CreateOptions = {
  keyType: 'Ed25519',
  publicKey: new Uint8Array(32).fill(7),
};

interface RecordedCall {
  readonly url: string;
  readonly method: string;
  readonly body?: BodyInit | null;
}

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

/** API レスポンスを順に返すモック。呼び出しを記録する。 */
function mockApi(responses: ReadonlyArray<Record<string, unknown>>): RecordedCall[] {
  const calls: RecordedCall[] = [];
  let index = 0;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({
      url: typeof input === 'string' ? input : input.toString(),
      method: init?.method ?? 'GET',
      body: init?.body,
    });
    const payload = responses[index] ?? {};
    index += 1;
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as unknown as typeof fetch;
  return calls;
}

/**
 * 本文をそのまま返すモック（`"null"` のように構文的に正しいが非オブジェクトの JSON を
 * 返したいケース用。`mockApi` は `??` により `null` を `{}` へ読み替えてしまうため使えない）。
 */
function mockRawApi(bodies: ReadonlyArray<string>): void {
  let index = 0;
  globalThis.fetch = (async () => {
    const body = bodies[index] ?? '{}';
    index += 1;
    return new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
  }) as unknown as typeof fetch;
}

describe('MethodIpid.create', () => {
  it('POST <api>/api/v0/add で multipart アップロードし did:ipid:<CID> を返す', async () => {
    const calls = mockApi([{ Hash: CID }]);
    const doc = await new MethodIpid().create(CREATE_OPTS);

    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.url).toBe('http://localhost:5001/api/v0/add?cid-version=1');
    expect(calls[0]?.body).toBeInstanceOf(FormData);

    expect(doc.id).toBe(`did:ipid:${CID}`);
    // 保存される正規形は content-addressed のため id 非依存（controller は相対参照の空文字）。
    expect(doc.verificationMethod[0]?.controller).toBe('');
    expect(doc.verificationMethod[0]?.id).toBe('#key-1');
    expect(doc.verificationMethod[0]?.type).toBe('Ed25519VerificationKey2020');
    expect(doc.verificationMethod[0]?.publicKeyMultibase).toMatch(/^z/);
  });

  it('CID 形式不正（path traversal）は API を通っても 2001 で弾く', async () => {
    mockApi([{ Hash: '../../secret' }]);
    let caught: unknown;
    try {
      await new MethodIpid().create(CREATE_OPTS);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
  });

  it('注入した API URL を使う', async () => {
    // 平文はループバックに限るため（`ipfs-api.ts` の宛先検査）、遠隔ノードは HTTPS。
    const calls = mockApi([{ Hash: CID }]);
    await new MethodIpid({ apiUrl: 'https://kubo:9000/' }).create(CREATE_OPTS);
    expect(calls[0]?.url).toBe('https://kubo:9000/api/v0/add?cid-version=1');
  });

  it('add のレスポンスに Hash が無いと 2010', async () => {
    mockApi([{ Name: 'x' }]);
    let caught: unknown;
    try {
      await new MethodIpid().create(CREATE_OPTS);
    } catch (error) {
      caught = error;
    }
    expect((caught as VericertsError).code).toBe(ErrorCodes.DID_DOC_INVALID);
  });

  it('add の API 失敗（5xx）は 2003', async () => {
    globalThis.fetch = (async () =>
      new Response('err', { status: 500 })) as unknown as typeof fetch;
    let caught: unknown;
    try {
      await new MethodIpid().create(CREATE_OPTS);
    } catch (error) {
      caught = error;
    }
    expect((caught as VericertsError).code).toBe(ErrorCodes.DID_NOT_FOUND);
  });

  it('add のレスポンス本文が null だと素の TypeError ではなく 2010', async () => {
    mockRawApi(['null']);
    let caught: unknown;
    try {
      await new MethodIpid().create(CREATE_OPTS);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.DID_DOC_INVALID);
  });
});

describe('MethodIpid.update', () => {
  const updateOpts: IpidUpdateOptions = {
    ipnsKeyBytes: new Uint8Array(36).fill(3),
    ipnsKeyName: 'did-ipns-key',
  };

  it('key/import → name/publish を呼び IPNS DID を署名検証つきで解決して返す', async () => {
    const docText = JSON.stringify({
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: `did:ipid:${IPNS}`,
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
    });
    const gateway = ipnsGateway(5, docText);
    const calls = mockApi([
      { Name: 'did-ipns-key' }, // key/import
      { Name: IPNS }, // name/publish
    ]);
    const apiFetch = globalThis.fetch;
    // API 呼び出し（POST）は記録つきモックへ、Gateway（GET）は署名付きレコードを返すダブルへ振り分ける。
    globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) =>
      init?.method === 'POST' ? apiFetch(input, init) : gateway.fetch(input, init)) as typeof fetch;

    const doc = await new MethodIpid().update(`did:ipid:${CID}`, updateOpts);

    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.url).toBe('http://localhost:5001/api/v0/key/import?arg=did-ipns-key');
    expect(calls[0]?.body).toBeInstanceOf(FormData);

    expect(calls[1]?.method).toBe('POST');
    expect(calls[1]?.url).toBe(
      `http://localhost:5001/api/v0/name/publish?arg=${CID}&key=did-ipns-key`,
    );

    expect(gateway.urls[0]).toBe(`https://ipfs.io/ipns/${IPNS}`);
    expect(doc.id).toBe(`did:ipid:${IPNS}`);
  });

  it('IPNS 鍵情報を欠く更新は 2002', async () => {
    let caught: unknown;
    try {
      await new MethodIpid().update(`did:ipid:${CID}`, {});
    } catch (error) {
      caught = error;
    }
    expect((caught as VericertsError).code).toBe(ErrorCodes.METHOD_NOT_SUPPORTED);
  });

  it('DID 形式不正の更新は 2001', async () => {
    let caught: unknown;
    try {
      await new MethodIpid().update('did:web:x', updateOpts);
    } catch (error) {
      caught = error;
    }
    expect((caught as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
  });

  it('IPNS 鍵バイト長不正（短すぎ）は API を呼ばず 1003', async () => {
    const calls = mockApi([{ Name: 'x' }]);
    let caught: unknown;
    try {
      // `UpdateOptions` が差分操作メンバを持つようになったため、メソッド固有の
      // 材料はオブジェクトリテラル直渡しではなく `IpidUpdateOptions` で型付けして渡す。
      const opts: IpidUpdateOptions = {
        ipnsKeyBytes: new Uint8Array(16).fill(1),
        ipnsKeyName: 'did-ipns-key',
      };
      await new MethodIpid().update(`did:ipid:${CID}`, opts);
    } catch (error) {
      caught = error;
    }
    expect((caught as VericertsError).code).toBe(ErrorCodes.INVALID_PRIVATE_KEY);
    expect(calls).toHaveLength(0);
  });

  it('IPNS 鍵バイト長不正（長すぎ）は API を呼ばず 1003', async () => {
    const calls = mockApi([{ Name: 'x' }]);
    let caught: unknown;
    try {
      // `UpdateOptions` が差分操作メンバを持つようになったため、メソッド固有の
      // 材料はオブジェクトリテラル直渡しではなく `IpidUpdateOptions` で型付けして渡す。
      const opts: IpidUpdateOptions = {
        ipnsKeyBytes: new Uint8Array(128).fill(1),
        ipnsKeyName: 'did-ipns-key',
      };
      await new MethodIpid().update(`did:ipid:${CID}`, opts);
    } catch (error) {
      caught = error;
    }
    expect((caught as VericertsError).code).toBe(ErrorCodes.INVALID_PRIVATE_KEY);
    expect(calls).toHaveLength(0);
  });

  it('key/import のレスポンス本文が null だと素の TypeError ではなく 2010', async () => {
    mockRawApi(['null']);
    let caught: unknown;
    try {
      await new MethodIpid().update(`did:ipid:${CID}`, updateOpts);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.DID_DOC_INVALID);
  });

  it('name/publish のレスポンス本文が null だと素の TypeError ではなく 2010', async () => {
    mockRawApi(['{"Name":"did-ipns-key"}', 'null']);
    let caught: unknown;
    try {
      await new MethodIpid().update(`did:ipid:${CID}`, updateOpts);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.DID_DOC_INVALID);
  });
});

describe('MethodIpid ライフサイクル', () => {
  it('method() は ipid を返す', () => {
    expect(new MethodIpid().method()).toBe('ipid');
  });

  it('deactivate は 2002 を投げる', async () => {
    await expect(new MethodIpid().deactivate(`did:ipid:${CID}`)).rejects.toThrow(
      new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED),
    );
  });
});
