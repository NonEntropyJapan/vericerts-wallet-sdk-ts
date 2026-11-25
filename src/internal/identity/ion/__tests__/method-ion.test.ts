/**
 * resolveDidIon / MethodIon の Sidetree ノード解決の検証。
 *
 * 取得は `fetchFn` 注入のモックで行い、実ネットワークには触れない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import {
  expectRejects,
  jsonReply,
  recordingFetch,
} from '../../__tests__/network-method.fixtures.js';
import {
  createResolutionWorkBudget,
  DEFAULT_MAX_SCOPE_BODY_LENGTH,
  DEFAULT_MAX_SCOPE_WORK_UNITS,
} from '../../resolution-budget.js';
import { Resolver } from '../../resolver.js';
import { WORK_UNITS_PER_ION_LONG_FORM } from '../did-ion.js';
import { MethodIon, resolveDidIon } from '../method-ion.js';
import { ionResponse, makeIonCreate, NODE_URL, withInitialState } from './ion.fixtures.js';

const create = makeIonCreate();

describe('resolveDidIon', () => {
  it('short-form: GET <nodeUrl>/identifiers/<did> で解決し、相対 DID URL を絶対化してメタデータを返す', async () => {
    const { fetchFn, calls } = recordingFetch(() =>
      jsonReply(ionResponse(create.shortForm, create), 'application/did+ld+json'),
    );
    const { document, metadata } = await resolveDidIon(create.shortForm, {
      nodeUrl: `${NODE_URL}/`,
      fetchFn,
    });
    expect(calls.map((call) => call.url)).toEqual([`${NODE_URL}/identifiers/${create.shortForm}`]);
    expect(document.id).toBe(create.shortForm);
    expect(document.verificationMethod[0]?.id).toBe(`${create.shortForm}#signing`);
    expect(document.assertionMethod).toEqual([`${create.shortForm}#signing`]);
    expect(document.authentication).toEqual([]);
    expect(document.service?.[0]?.id).toBe(`${create.shortForm}#hub`);
    expect(metadata).toEqual({
      published: true,
      canonicalId: create.shortForm,
      equivalentId: [create.shortForm, create.longForm],
    });
  });

  it('long-form: ローカル検証のあとノードへ long-form のまま問い合わせる', async () => {
    const { fetchFn, calls } = recordingFetch(() =>
      jsonReply(ionResponse(create.longForm, create)),
    );
    const { document } = await resolveDidIon(create.longForm, { nodeUrl: NODE_URL, fetchFn });
    expect(calls[0]?.url).toBe(`${NODE_URL}/identifiers/${create.longForm}`);
    expect(document.id).toBe(create.longForm);
    expect(document.assertionMethod).toEqual([`${create.longForm}#signing`]);
  });

  it('long-form の要求に同じ did-suffix の short-form id で応答しても受理する', async () => {
    const { fetchFn } = recordingFetch(() => jsonReply(ionResponse(create.shortForm, create)));
    const { document } = await resolveDidIon(create.longForm, { nodeUrl: NODE_URL, fetchFn });
    expect(document.id).toBe(create.shortForm);
  });

  it('形式不正は 2001、long-form 不一致は 2010 で、いずれも取得しない', async () => {
    const { fetchFn, calls } = recordingFetch(() =>
      jsonReply(ionResponse(create.shortForm, create)),
    );
    await expectRejects(
      resolveDidIon('did:ion:test:abc', { nodeUrl: NODE_URL, fetchFn }),
      ErrorCodes.INVALID_DID,
    );
    const other = makeIonCreate(2);
    const mismatched = withInitialState(create, {
      suffixData: other.suffixData,
      delta: other.delta,
    });
    await expectRejects(
      resolveDidIon(mismatched, { nodeUrl: NODE_URL, fetchFn }),
      ErrorCodes.DID_DOC_INVALID,
      'ion_long_form_mismatch',
    );
    expect(calls).toHaveLength(0);
  });

  it('404 / ネットワークエラーは 2003', async () => {
    const notFound = recordingFetch(() => ({ status: 404, body: '{}' }));
    await expectRejects(
      resolveDidIon(create.shortForm, { nodeUrl: NODE_URL, fetchFn: notFound.fetchFn }),
      ErrorCodes.DID_NOT_FOUND,
    );
    const broken = recordingFetch(() => {
      throw new Error('ECONNRESET');
    });
    await expectRejects(
      resolveDidIon(create.shortForm, { nodeUrl: NODE_URL, fetchFn: broken.fetchFn }),
      ErrorCodes.DID_NOT_FOUND,
    );
  });

  it('nodeUrl が https でない / 資格情報付き / 未設定は 2003 で、取得しない', async () => {
    const { fetchFn, calls } = recordingFetch(() =>
      jsonReply(ionResponse(create.shortForm, create)),
    );
    for (const nodeUrl of ['http://ion.example.org', 'https://u:p@ion.example.org', '']) {
      await expectRejects(
        resolveDidIon(create.shortForm, { nodeUrl, fetchFn }),
        ErrorCodes.DID_NOT_FOUND,
        'insecure_endpoint_url',
      );
    }
    expect(calls).toHaveLength(0);
  });

  it('published: false は既定で 2003、allowUnpublished のときだけ採用する', async () => {
    const { fetchFn } = recordingFetch(() =>
      jsonReply(ionResponse(create.longForm, create, { published: false })),
    );
    await expectRejects(
      resolveDidIon(create.longForm, { nodeUrl: NODE_URL, fetchFn }),
      ErrorCodes.DID_NOT_FOUND,
      'ion_unpublished',
    );
    const { document, metadata } = await resolveDidIon(create.longForm, {
      nodeUrl: NODE_URL,
      allowUnpublished: true,
      fetchFn,
    });
    expect(document.id).toBe(create.longForm);
    expect(metadata.published).toBe(false);
  });

  it('deactivated: true は 2001（公開状態に関わらず）', async () => {
    const { fetchFn } = recordingFetch(() =>
      jsonReply(
        ionResponse(create.shortForm, create, {
          metadata: { deactivated: true },
          document: { verificationMethod: [], assertionMethod: [] },
        }),
      ),
    );
    await expectRejects(
      resolveDidIon(create.shortForm, { nodeUrl: NODE_URL, allowUnpublished: true, fetchFn }),
      ErrorCodes.INVALID_DID,
      'ion_deactivated',
    );
  });

  it('id が要求した DID と違う（別 suffix を含む）なら 2010 ion_id_mismatch', async () => {
    const other = makeIonCreate(2);
    const { fetchFn } = recordingFetch(() => jsonReply(ionResponse(other.shortForm, create)));
    await expectRejects(
      resolveDidIon(create.shortForm, { nodeUrl: NODE_URL, fetchFn }),
      ErrorCodes.DID_DOC_INVALID,
      'ion_id_mismatch',
    );
  });

  it('メタデータの欠落・型不正・別 DID を指す canonicalId / equivalentId は 2010', async () => {
    const other = makeIonCreate(2);
    const cases: Record<string, unknown>[] = [
      { method: undefined },
      { method: { published: 'yes' } },
      { canonicalId: other.shortForm },
      { canonicalId: 42 },
      { equivalentId: [create.shortForm, other.longForm] },
      { equivalentId: create.shortForm },
    ];
    for (const metadata of cases) {
      const { fetchFn } = recordingFetch(() =>
        jsonReply(ionResponse(create.shortForm, create, { metadata })),
      );
      await expectRejects(
        resolveDidIon(create.shortForm, { nodeUrl: NODE_URL, fetchFn }),
        ErrorCodes.DID_DOC_INVALID,
        'ion_metadata_invalid',
      );
    }
    const missing = recordingFetch(() =>
      jsonReply({ didDocument: { id: create.shortForm, '@context': [] } }),
    );
    await expectRejects(
      resolveDidIon(create.shortForm, { nodeUrl: NODE_URL, fetchFn: missing.fetchFn }),
      ErrorCodes.DID_DOC_INVALID,
      'ion_metadata_invalid',
    );
  });

  it('Content-Type 不一致・JSON 不正・本文が配列・文書の配列形状不正は 2010', async () => {
    const html = recordingFetch(() => ({ contentType: 'text/html', body: '<html></html>' }));
    const broken = recordingFetch(() => ({ body: '{nope' }));
    const array = recordingFetch(() => jsonReply([]));
    const badShape = recordingFetch(() =>
      jsonReply(ionResponse(create.shortForm, create, { document: { verificationMethod: 'x' } })),
    );
    for (const { fetchFn } of [html, broken, array, badShape]) {
      await expectRejects(
        resolveDidIon(create.shortForm, { nodeUrl: NODE_URL, fetchFn }),
        ErrorCodes.DID_DOC_INVALID,
      );
    }
  });

  it('ResolutionWorkBudget: long-form は仕事量を、取得は本文量を計上する。尽きたスコープは取得しない', async () => {
    const response = ionResponse(create.longForm, create);
    const body = JSON.stringify(response);
    const { fetchFn, calls } = recordingFetch(() => ({ body }));
    const scope = createResolutionWorkBudget();
    await resolveDidIon(create.longForm, { nodeUrl: NODE_URL, fetchFn }, scope);
    expect(scope.remaining).toBe(DEFAULT_MAX_SCOPE_WORK_UNITS - WORK_UNITS_PER_ION_LONG_FORM);
    expect(scope.remainingBodyLength).toBe(DEFAULT_MAX_SCOPE_BODY_LENGTH - body.length);

    // short-form は仕事量を使わない。
    const shortBody = JSON.stringify(ionResponse(create.shortForm, create));
    const shortFetch = recordingFetch(() => ({ body: shortBody }));
    const shortScope = createResolutionWorkBudget();
    await resolveDidIon(
      create.shortForm,
      { nodeUrl: NODE_URL, fetchFn: shortFetch.fetchFn },
      shortScope,
    );
    expect(shortScope.remaining).toBe(DEFAULT_MAX_SCOPE_WORK_UNITS);

    const workLimited = createResolutionWorkBudget(WORK_UNITS_PER_ION_LONG_FORM - 1);
    const before = calls.length;
    await expectRejects(
      resolveDidIon(create.longForm, { nodeUrl: NODE_URL, fetchFn }, workLimited),
      ErrorCodes.INVALID_DID,
      'resolution_work_limit',
    );
    expect(calls).toHaveLength(before);

    const bodyLimited = createResolutionWorkBudget(undefined, body.length - 1);
    await expectRejects(
      resolveDidIon(create.longForm, { nodeUrl: NODE_URL, fetchFn }, bodyLimited),
      ErrorCodes.INVALID_DID,
      'resolution_work_limit',
    );
    expect(bodyLimited.remainingBodyLength).toBe(0);
    const afterOverrun = calls.length;
    await expectRejects(
      resolveDidIon(create.shortForm, { nodeUrl: NODE_URL, fetchFn }, bodyLimited),
      ErrorCodes.INVALID_DID,
      'resolution_work_limit',
    );
    expect(calls).toHaveLength(afterOverrun);
  });
});

describe('MethodIon', () => {
  it('method() は ion。create / update / deactivate は 2002', async () => {
    const method = new MethodIon({ nodeUrl: NODE_URL });
    expect(method.method()).toBe('ion');
    await expectRejects(
      method.create({ keyType: 'secp256k1', publicKey: new Uint8Array(33) }),
      ErrorCodes.METHOD_NOT_SUPPORTED,
    );
    await expectRejects(method.update(create.shortForm, {}), ErrorCodes.METHOD_NOT_SUPPORTED);
    await expectRejects(method.deactivate(create.shortForm), ErrorCodes.METHOD_NOT_SUPPORTED);
  });

  it('Resolver に登録すると解決でき、2002 で拒否しなくなる', async () => {
    const { fetchFn } = recordingFetch(() => jsonReply(ionResponse(create.shortForm, create)));
    const resolver = new Resolver();
    await expectRejects(resolver.resolve(create.shortForm), ErrorCodes.METHOD_NOT_SUPPORTED);
    resolver.register(new MethodIon({ nodeUrl: NODE_URL, fetchFn }));
    expect((await resolver.resolve(create.shortForm)).id).toBe(create.shortForm);
  });

  it('resolveWithMetadata は canonicalId / equivalentId を返し、allowUnpublished を設定から適用する', async () => {
    const { fetchFn } = recordingFetch(() =>
      jsonReply(ionResponse(create.longForm, create, { published: false })),
    );
    await expectRejects(
      new MethodIon({ nodeUrl: NODE_URL, fetchFn }).resolve(create.longForm),
      ErrorCodes.DID_NOT_FOUND,
      'ion_unpublished',
    );
    const { metadata } = await new MethodIon({
      nodeUrl: NODE_URL,
      allowUnpublished: true,
      fetchFn,
    }).resolveWithMetadata(create.longForm);
    expect(metadata.canonicalId).toBe(create.shortForm);
    expect(metadata.equivalentId).toEqual([create.shortForm, create.longForm]);
  });

  it('キャッシュは DID ごと・TTL 600 秒。命中時は long-form を再検証せず、失敗は記憶しない', async () => {
    let now = 5_000;
    let failing = true;
    const { fetchFn, calls } = recordingFetch(() =>
      failing ? { status: 503, body: '' } : jsonReply(ionResponse(create.longForm, create)),
    );
    const method = new MethodIon({ nodeUrl: NODE_URL, fetchFn, nowSeconds: () => now });
    await expectRejects(method.resolve(create.longForm), ErrorCodes.DID_NOT_FOUND);
    failing = false;
    const scope = createResolutionWorkBudget();
    await method.resolve(create.longForm, scope);
    await method.resolve(create.longForm, scope);
    expect(calls).toHaveLength(2);
    expect(scope.remaining).toBe(DEFAULT_MAX_SCOPE_WORK_UNITS - WORK_UNITS_PER_ION_LONG_FORM);
    now += 599;
    await method.resolve(create.longForm);
    expect(calls).toHaveLength(2);
    now += 1;
    await method.resolve(create.longForm);
    expect(calls).toHaveLength(3);
  });

  it('形式不正の DID はキャッシュ・ネットワークに触れず 2001', async () => {
    const { fetchFn, calls } = recordingFetch(() =>
      jsonReply(ionResponse(create.shortForm, create)),
    );
    const method = new MethodIon({ nodeUrl: NODE_URL, fetchFn });
    await expectRejects(
      method.resolve('did:ion:abc'),
      ErrorCodes.INVALID_DID,
      'ion_invalid_suffix',
    );
    expect(calls).toHaveLength(0);
  });
});
