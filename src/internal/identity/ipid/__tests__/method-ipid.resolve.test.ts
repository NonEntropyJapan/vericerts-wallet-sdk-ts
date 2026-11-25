/**
 * MethodIpid.resolve の IPFS Gateway 解決検証。
 *
 * `globalThis.fetch` を差し替えてモックし、CID 解決（`/ipfs/`）・IPNS 解決（`/ipns/`）の
 * 正常系と、異常系（Content-Type 不正 / 不正 JSON / 取得失敗 4xx・5xx / network / timeout /
 * 形式不正）と、CID 形式でのコンテンツハッシュ照合を検証する。
 *
 * エラーコード粒度: 取得失敗は `DID_NOT_FOUND`（2003）、Content-Type 不一致 /
 * JSON parse 失敗 / スキーマ不正は `DID_DOC_INVALID`（2010）、DID 文字列形式不正は
 * `INVALID_DID`（2001）。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../errors.js';
import type { CreateOptions, DIDDocument } from '../../did.js';
import { MethodIpid } from '../method-ipid.js';
import { ipnsNameOf, rawCidOf } from './cid-fixture.js';
import { ipnsGateway } from './ipns-fixture.js';

async function expectRejectCode(promise: Promise<unknown>, code: ErrorCode): Promise<void> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(code);
}

/** CID 形式は自己参照 id を含められない正規形（`create` のアップロード内容と同じ形）。 */
const SAMPLE_DOC: Omit<DIDDocument, 'id'> = {
  '@context': ['https://www.w3.org/ns/did/v1'],
  verificationMethod: [
    {
      id: '#key-1',
      type: 'Ed25519VerificationKey2020',
      controller: '',
      publicKeyMultibase: 'z6MkExample',
    },
  ],
  authentication: ['#key-1'],
  assertionMethod: ['#key-1'],
};

const IPNS = ipnsNameOf(4);
const CID = rawCidOf(JSON.stringify(SAMPLE_DOC));
const DID_CID = `did:ipid:${CID}`;
const DID_IPNS = `did:ipid:${IPNS}`;

/** 本文の CID を持つ DID（Gateway の応答が CID と一致する状況を作る）。 */
const didOf = (body: string): string => `did:ipid:${rawCidOf(body)}`;

function mockResponse(opts: {
  body: string;
  status?: number;
  contentType?: string | null;
}): Response {
  const headers = new Headers();
  if (opts.contentType !== null && opts.contentType !== undefined) {
    headers.set('content-type', opts.contentType);
  }
  return new Response(opts.body, { status: opts.status ?? 200, headers });
}

const originalFetch = globalThis.fetch;

function mockFetch(
  impl: (input: string | URL | Request, init?: RequestInit) => Promise<Response>,
): void {
  globalThis.fetch = impl as unknown as typeof fetch;
}

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('MethodIpid.resolve 正常系', () => {
  it('CID は GET <gateway>/ipfs/<CID> で解決する', async () => {
    let calledUrl = '';
    mockFetch(async (input) => {
      calledUrl = typeof input === 'string' ? input : input.toString();
      return mockResponse({
        body: JSON.stringify(SAMPLE_DOC),
        contentType: 'application/did+json',
      });
    });

    const doc = await new MethodIpid().resolve(DID_CID);
    expect(calledUrl).toBe(`https://ipfs.io/ipfs/${CID}`);
    expect(doc.id).toBe(DID_CID);
  });

  it('IPNS 名は署名付きレコードを検証し、解決先 CID の本文を取得して解決する', async () => {
    const gateway = ipnsGateway(4, JSON.stringify(SAMPLE_DOC));
    globalThis.fetch = gateway.fetch;

    const doc = await new MethodIpid().resolve(DID_IPNS);
    expect(gateway.urls).toEqual([
      `https://ipfs.io/ipns/${IPNS}`,
      `https://ipfs.io/ipfs/${gateway.cid}`,
    ]);
    expect(doc.id).toBe(DID_IPNS);
  });

  it('注入した Gateway URL（末尾スラッシュ付き）を使う', async () => {
    let calledUrl = '';
    mockFetch(async (input) => {
      calledUrl = typeof input === 'string' ? input : input.toString();
      return mockResponse({
        body: JSON.stringify(SAMPLE_DOC),
        contentType: 'application/json',
      });
    });

    await new MethodIpid({ gatewayUrl: 'https://gw.example/' }).resolve(DID_CID);
    expect(calledUrl).toBe(`https://gw.example/ipfs/${CID}`);
  });
});

describe('MethodIpid.resolve 異常系', () => {
  it('Content-Type が text/html は 2010', async () => {
    mockFetch(async () =>
      mockResponse({ body: JSON.stringify(SAMPLE_DOC), contentType: 'text/html' }),
    );
    await expectRejectCode(new MethodIpid().resolve(DID_CID), ErrorCodes.DID_DOC_INVALID);
  });

  it('Content-Type ヘッダ欠落は 2010（共有述語の既定は fail-closed）', async () => {
    // Federation は欠落を許容するが、did:ipid は許容しない。共有述語への統合でこの非対称が
    // 崩れていないことを押さえる（`http/body-limit.ts` の `allowMissing` を渡さない経路）。
    mockFetch(async () => mockResponse({ body: JSON.stringify(SAMPLE_DOC), contentType: null }));
    await expectRejectCode(new MethodIpid().resolve(DID_CID), ErrorCodes.DID_DOC_INVALID);
  });

  it('不正な JSON は 2010', async () => {
    const body = '{ not json';
    mockFetch(async () => mockResponse({ body, contentType: 'application/json' }));
    await expectRejectCode(new MethodIpid().resolve(didOf(body)), ErrorCodes.DID_DOC_INVALID);
  });

  it('id が文字列でない（型不正）ドキュメントは 2010', async () => {
    const body = JSON.stringify({ '@context': [], id: 123 });
    mockFetch(async () => mockResponse({ body, contentType: 'application/json' }));
    await expectRejectCode(new MethodIpid().resolve(didOf(body)), ErrorCodes.DID_DOC_INVALID);
  });

  it('HTTP 404 は 2003', async () => {
    mockFetch(async () =>
      mockResponse({ body: 'not found', status: 404, contentType: 'text/plain' }),
    );
    await expectRejectCode(new MethodIpid().resolve(DID_CID), ErrorCodes.DID_NOT_FOUND);
  });

  it('HTTP 500 は 2003', async () => {
    mockFetch(async () =>
      mockResponse({ body: 'error', status: 500, contentType: 'application/json' }),
    );
    await expectRejectCode(new MethodIpid().resolve(DID_CID), ErrorCodes.DID_NOT_FOUND);
  });

  it('ネットワークエラーは 2003', async () => {
    mockFetch(async () => {
      throw new TypeError('Failed to fetch');
    });
    await expectRejectCode(new MethodIpid().resolve(DID_CID), ErrorCodes.DID_NOT_FOUND);
  });

  it('タイムアウト（abort）は 2003', async () => {
    mockFetch(async () => {
      throw new DOMException('The operation was aborted.', 'AbortError');
    });
    await expectRejectCode(new MethodIpid().resolve(DID_CID), ErrorCodes.DID_NOT_FOUND);
  });

  it('Gateway が内部ホストへ 302 しても追従せず 2003', async () => {
    const requested: string[] = [];
    const modes: Array<RequestRedirect | undefined> = [];
    mockFetch(async (input, init) => {
      requested.push(typeof input === 'string' ? input : input.toString());
      modes.push(init?.redirect);
      return new Response(null, { status: 302, headers: { Location: 'https://10.0.0.5/doc' } });
    });
    await expectRejectCode(new MethodIpid().resolve(DID_CID), ErrorCodes.DID_NOT_FOUND);
    expect(requested).toEqual([`https://ipfs.io/ipfs/${CID}`]);
    expect(modes).toEqual(['manual']);
  });

  it('DID 形式不正（プレフィックス不正）は fetch せず 2001', async () => {
    let called = false;
    mockFetch(async () => {
      called = true;
      return mockResponse({ body: '{}', contentType: 'application/json' });
    });
    await expectRejectCode(new MethodIpid().resolve('did:key:z6Mk'), ErrorCodes.INVALID_DID);
    expect(called).toBe(false);
  });
});

describe('MethodIpid.resolve の id 補完', () => {
  it('id 未設定（canonical form）の本文は要求 DID を id として補完する', async () => {
    const body = JSON.stringify({ '@context': ['https://www.w3.org/ns/did/v1'] });
    mockFetch(async () => mockResponse({ body, contentType: 'application/did+json' }));
    const doc = await new MethodIpid().resolve(didOf(body));
    expect(doc.id).toBe(didOf(body));
  });

  it('id を持つ IPNS 本文は要求 DID と一致すれば解決する', async () => {
    const gateway = ipnsGateway(4, JSON.stringify({ ...SAMPLE_DOC, id: DID_IPNS }));
    globalThis.fetch = gateway.fetch;
    const doc = await new MethodIpid().resolve(DID_IPNS);
    expect(doc.id).toBe(DID_IPNS);
  });

  it('id が別 DID の本文は不整合として 2010', async () => {
    const body = JSON.stringify({ ...SAMPLE_DOC, id: 'did:ipid:bafyOtherCid' });
    mockFetch(async () => mockResponse({ body, contentType: 'application/json' }));
    await expectRejectCode(new MethodIpid().resolve(didOf(body)), ErrorCodes.DID_DOC_INVALID);
  });
});

describe('MethodIpid.resolve の CID 照合', () => {
  // Gateway 運営者が、正規 Document の CID に対して攻撃者の鍵を含む別 Document を返す状況。
  const ATTACKER_DOC = {
    ...SAMPLE_DOC,
    verificationMethod: [
      {
        id: '#key-1',
        type: 'Ed25519VerificationKey2020',
        controller: '',
        publicKeyMultibase: 'z6MkAttackerKey',
      },
    ],
  };

  async function reasonOf(promise: Promise<unknown>): Promise<unknown> {
    try {
      await promise;
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.DID_DOC_INVALID);
      return (err as VericertsError).context?.reason;
    }
    throw new Error('should have thrown');
  }

  it('CID とハッシュが一致しない本文（Gateway による鍵のすり替え）は 2010 cid_mismatch', async () => {
    mockFetch(async () =>
      mockResponse({ body: JSON.stringify(ATTACKER_DOC), contentType: 'application/did+json' }),
    );
    expect(await reasonOf(new MethodIpid().resolve(DID_CID))).toBe('cid_mismatch');
  });

  it('本文が 1 バイトでも違えば拒否する（空白の付加）', async () => {
    mockFetch(async () =>
      mockResponse({ body: `${JSON.stringify(SAMPLE_DOC)} `, contentType: 'application/json' }),
    );
    expect(await reasonOf(new MethodIpid().resolve(DID_CID))).toBe('cid_mismatch');
  });

  it('本文だけでは照合できない CID（dag-pb）は fail-closed で 2010 cid_unverifiable', async () => {
    mockFetch(async () =>
      mockResponse({ body: JSON.stringify(SAMPLE_DOC), contentType: 'application/json' }),
    );
    const dagPbDid = 'did:ipid:bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi';
    expect(await reasonOf(new MethodIpid().resolve(dagPbDid))).toBe('cid_unverifiable');
  });
});

describe('MethodIpid create→resolve 往復', () => {
  const CREATE_OPTS: CreateOptions = {
    keyType: 'Ed25519',
    publicKey: new Uint8Array(32).fill(9),
  };

  it('create の戻り値を gateway 本文として与えると同一 DID Document に解決できる', async () => {
    // 1. create: アップロード内容の CID を返す IPFS ノードのモックで、id 補完済みドキュメントを得る。
    globalThis.fetch = (async (_input: unknown, init?: RequestInit) => {
      const file = (init?.body as FormData).get('file') as Blob;
      return new Response(JSON.stringify({ Hash: rawCidOf(await file.text()) }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;
    const method = new MethodIpid();
    const created = await method.create(CREATE_OPTS);
    const createdDid = created.id;
    expect(createdDid.startsWith('did:ipid:b')).toBe(true);

    // 2. 保存される正規形（id を除いた本文）を resolve のモック gateway body として与える。
    const { id: _id, ...canonical } = created;
    mockFetch(async () =>
      mockResponse({ body: JSON.stringify(canonical), contentType: 'application/did+json' }),
    );
    const resolved = await method.resolve(createdDid);

    // 3. 往復が成立し、create 戻り値と resolve 結果が一致する。
    expect(resolved).toEqual(created);
  });
});
