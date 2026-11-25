/**
 * resolveDidWith のテレメトリ失敗耐性。logger / metrics sink が throw しても、
 * 解決結果（成功値）と元のエラー（VericertsError のコード）を置換しない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import type { DIDDocument } from '../../../internal/identity/did.js';
import type { Resolver } from '../../../internal/identity/resolver.js';
import type { Logger } from '../../../internal/observability/logger.js';
import type { Metrics } from '../../../internal/observability/metrics.js';
import { createTracer } from '../../../internal/observability/tracer.js';
import { resolveDidWith } from '../resolve.js';

const DOC = { id: 'did:key:z6Mk' } as DIDDocument;

const throwingLogger: Logger = {
  debug: () => {
    throw new Error('log down');
  },
  info: () => {
    throw new Error('log down');
  },
  warn: () => {
    throw new Error('log down');
  },
  error: () => {
    throw new Error('log down');
  },
  child: () => throwingLogger,
};

const throwingMetrics = {
  counter: () => {
    throw new Error('metrics down');
  },
  histogram: () => {
    throw new Error('metrics down');
  },
  gauge: () => {
    throw new Error('metrics down');
  },
} as Metrics;

describe('resolveDidWith: テレメトリ sink が throw する場合', () => {
  it('解決成功の結果を置換しない', async () => {
    const resolver = { resolve: async () => DOC } as unknown as Resolver;
    await expect(
      resolveDidWith(
        resolver,
        'did:key:z6Mk',
        throwingLogger,
        throwingMetrics,
        createTracer(undefined),
      ),
    ).resolves.toBe(DOC);
  });

  it('解決失敗の元の VericertsError を置換しない', async () => {
    const original = new VericertsError(ErrorCodes.DID_NOT_FOUND);
    const resolver = {
      resolve: async () => {
        throw original;
      },
    } as unknown as Resolver;
    await expect(
      resolveDidWith(
        resolver,
        'did:nope:x',
        throwingLogger,
        throwingMetrics,
        createTracer(undefined),
      ),
    ).rejects.toBe(original);
  });
});
