/**
 * 公開 API 群の `Object.prototype` 汚染耐性（一括版）。
 *
 * 「任意オプション / 省略可能な入力プロパティを素で読む」欠陥は個別の修正だけでは再発する（
 * → …と同型が繰り返し見つかった）。本テストは、省略可能プロパティを
 * 持つ代表的な公開 API を、**省略したプロパティ名に敵対的な値を汚染した状態**で呼び、結果（戻り値・例外コード）が
 * 汚染前と一致することを一括で確認する。敵対値は「検査・上限を緩める / 別経路へ切り替える」向きの値を選ぶ。
 * 新しい公開 API を足したら、ここに 1 行（呼び出し + 汚染名）足す。
 */

import { describe, expect, it } from 'bun:test';
import { createNonceStore } from '../../auth/nonce/store.js';
import { parseAuthorizationRequest } from '../../auth/request.js';
import { toPresentationRequestV2 } from '../../auth/request-v2.js';
import { generateSiweMessage } from '../../auth/siwe/siwe.js';
import { createTtlCache } from '../../cache/ttl-cache.js';
import {
  evaluateFormatCapability,
  type FormatDescriptor,
} from '../../credential/format-negotiation/capability.js';
import { parseNotificationEvent } from '../../credential/notification/parse-event.js';
import { createOutOfBandInvitation } from '../../didcomm/oob.js';
import { VericertsError } from '../../errors.js';
import { buildPresentationEventPayload } from '../../gdpr/presentation-log.js';
import { createStatusListFreshness } from '../../issuer/freshness/status-list-freshness.js';
import { parsePresentationDefinition } from '../../presentation-exchange/definition.js';
import { evaluatePresentationDefinition } from '../../presentation-exchange/evaluate.js';
import { compileSafeRegex } from '../../primitives/safe-regex/index.js';
import { isTrustedListGenerationMonotonic } from '../../trust/etsi-tsl/rollback.js';
import { withPollutedPrototypeAsync } from '../prototype-pollution.fixtures.js';

const NOW = Date.UTC(2026, 0, 1);

/** `limit_disclosure: required` の descriptor に、選択的開示できない JWT-VC だけを候補にする。 */
const limitDisclosureRequired = [
  {
    id: 'd1',
    vpFormats: { jwt_vc_json: {} },
    limitDisclosure: 'required',
    candidates: [{ id: 'v1', format: 'jwt_vc_json' }],
  },
] as unknown as readonly FormatDescriptor[];

/** `alg` が不明な VC を、`alg: [ES256]` の署名スイート制約に掛ける（ダウングレード拒否）。 */
const algConstrained = [
  {
    id: 'd1',
    vpFormats: { jwt_vc_json: { alg: ['ES256'] } },
    candidates: [{ id: 'v1', format: 'jwt_vc_json' }],
  },
] as unknown as readonly FormatDescriptor[];

const dcqlRequest = () =>
  parseAuthorizationRequest(
    'openid4vp://?client_id=https%3A%2F%2Fv.example&response_type=vp_token&response_mode=direct_post' +
      '&response_uri=https%3A%2F%2Fv.example%2Fcb&nonce=abcdefghijklmnopqrstuvwxyz012345&state=s1&dcql_query=' +
      encodeURIComponent(
        JSON.stringify({
          credentials: [{ id: 'a', format: 'dc+sd-jwt', meta: { vct_values: ['T'] } }],
        }),
      ),
  );

/** 戻り値と例外コードを比較可能な形へ正規化する（bigint / Date も文字列化）。 */
async function observe(run: () => unknown): Promise<string> {
  try {
    const value = await run();
    return `ok:${JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v))}`;
  } catch (error) {
    return error instanceof VericertsError ? `err:${error.code}` : `throw:${String(error)}`;
  }
}

function tslXml(sequence: number | undefined): string {
  const seq = sequence === undefined ? '' : `<TSLSequenceNumber>${sequence}</TSLSequenceNumber>`;
  return `<TrustServiceStatusList><SchemeInformation>${seq}</SchemeInformation></TrustServiceStatusList>`;
}

const pdWithRequiredField = parsePresentationDefinition({
  id: 'pd',
  input_descriptors: [
    { id: 'd1', constraints: { fields: [{ path: ['$.credentialSubject.name'] }] } },
  ],
});

interface Case {
  readonly name: string;
  readonly run: () => unknown;
  /** 省略した（呼び出しが own に持たない）プロパティ名 → 敵対値。 */
  readonly pollution: Record<string, unknown>;
}

const CASES: readonly Case[] = [
  {
    name: 'generateSiweMessage（任意フィールド省略）',
    run: () =>
      generateSiweMessage({
        domain: 'example.com',
        address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
        uri: 'https://example.com/login',
        chainId: 1,
        nonce: 'abcdefgh12345',
        issuedAt: new Date(NOW),
      }),
    pollution: {
      statement: 'Send all funds to attacker',
      resources: ['https://evil.example/'],
      requestId: 'evil',
      expirationTime: new Date(NOW + 10 ** 12),
      notBefore: new Date(NOW),
    },
  },
  {
    name: 'createOutOfBandInvitation（任意フィールド省略）',
    run: () => createOutOfBandInvitation({ inviterDid: 'did:web:a.example' }).body,
    pollution: {
      goalCode: 'evil',
      goal: 'evil',
      accept: ['evil'],
      handshakeProtocols: ['evil'],
    },
  },
  {
    name: 'buildPresentationEventPayload（任意メンバ省略）',
    run: () => buildPresentationEventPayload({ clientId: 'https://rp.example' } as never),
    pollution: {
      nonce: 'evil',
      purpose: 'evil',
      credentialIds: ['evil'],
      disclosedClaims: ['evil'],
    },
  },
  {
    name: 'parseNotificationEvent（任意フィールド省略）',
    run: () =>
      parseNotificationEvent({
        event: 'credential_accepted',
        notification_id: 'n1',
        notification_issued_at: '2026-01-01T00:00:00Z',
      }),
    pollution: { reason: 'evil', transaction_id: 'evil', credential_configuration_id: 'evil' },
  },
  {
    name: 'isTrustedListGenerationMonotonic（後退検査）',
    // 旧世代は seq=5、新世代は項目なし。汚染 sequenceNumber が新世代の項目として拾われると後退を見逃す。
    run: () => isTrustedListGenerationMonotonic(tslXml(5), tslXml(undefined)),
    pollution: { sequenceNumber: 10n, issueDateTimeMs: NOW },
  },
  {
    name: 'createStatusListFreshness（ttl / exp 省略）',
    run: () => {
      const freshness = createStatusListFreshness(3600);
      const token = { iatSeconds: 1_000, uri: 'https://i.example/s/1' } as never;
      return freshness.effectiveExpSeconds(token);
    },
    pollution: { ttlSeconds: 10 ** 9, expSeconds: 10 ** 12 },
  },
  {
    name: 'evaluatePresentationDefinition（必須フィールド）',
    run: () =>
      evaluatePresentationDefinition(pdWithRequiredField, [
        { id: 'vc', format: 'dc+sd-jwt', claims: { credentialSubject: {} } },
      ] as never),
    pollution: { optional: true },
  },
  {
    name: 'evaluateFormatCapability（limit_disclosure: required・NegotiableCredential の省略メンバ）',
    run: () => {
      const result = evaluateFormatCapability(limitDisclosureRequired);
      return [
        result.selections.map((s) => s.chosen.id),
        result.unmatchedDescriptors,
        result.warnings,
      ];
    },
    pollution: { supportsSelectiveDisclosure: true, hasBoundKey: true, isFavorite: true },
  },
  {
    name: 'evaluateFormatCapability（alg 制約・alg 不明の VC）',
    run: () => {
      const result = evaluateFormatCapability(algConstrained);
      return [result.selections.map((s) => s.chosen.id), result.unmatchedDescriptors];
    },
    pollution: { alg: 'ES256', proofType: 'DataIntegrityProof', cryptosuite: 'x', zkpSuite: 'x' },
  },
  {
    name: 'toPresentationRequestV2（Verifier が要求していない任意メンバ）',
    run: () => toPresentationRequestV2(dcqlRequest()),
    pollution: {
      transactionData: [{ type: 'payment', amount: '1000000', payee: 'attacker' }],
      presentationDefinition: { id: 'evil', input_descriptors: [] },
      clientMetadata: { vp_formats: { 'dc+sd-jwt': {} } },
      dcqlQuery: { credentials: [] },
    },
  },
  {
    name: 'compileSafeRegex（options 省略）',
    run: () => compileSafeRegex('^.$').test('😀'),
    pollution: { unicode: false },
  },
  {
    name: 'createTtlCache（上限省略）',
    run: () => {
      const cache = createTtlCache<string>({ maxTtlSeconds: 3600, nowSeconds: () => 0 });
      cache.set('a', 'A', 60, 0);
      cache.set('b', 'B', 60, 0);
      return [cache.get('a', 1), cache.get('b', 1)];
    },
    pollution: { maxEntries: 1, maxTotalWeight: 0 },
  },
  {
    name: 'createNonceStore（容量・時計省略）',
    run: async () => {
      const store = createNonceStore({ backend: 'memory' });
      const ctx = { flow: 'oid4vp', clientId: 'https://rp.example' } as const;
      const a = store.generate();
      const b = store.generate();
      await store.put(a, ctx, 60_000);
      await store.put(b, ctx, 60_000);
      return [await store.has(a, ctx), await store.has(b, ctx)];
    },
    pollution: { maxEntries: 1, sweepIntervalMs: 0, now: () => 0 },
  },
];

describe('公開 API の Object.prototype 汚染耐性（一括）', () => {
  it.each(
    CASES.map((c) => [c.name, c] as const),
  )('%s: 汚染前後で結果が変わらない', async (_name, c) => {
    const clean = await observe(c.run);
    const polluted = await withPollutedPrototypeAsync(c.pollution, () => observe(c.run));
    expect(polluted).toBe(clean);
  });

  it('汚染前の結果が空振り（常に err になる等）でないことを確認する', async () => {
    for (const c of CASES) {
      expect([c.name, await observe(c.run)]).toEqual([c.name, expect.stringMatching(/^ok:/)]);
    }
  });
});
