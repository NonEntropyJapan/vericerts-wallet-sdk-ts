/**
 * `Object.prototype` 汚染前後で結果が変わらないことの回帰テスト。
 * 各ケースは「汚染前の結果」と「省略したキーを汚染した後の結果」を `observe` で正規化して比較する。
 *
 * 許可リスト（`allowlist.ts`）に載せた読みが、実際に汚染下で動作を変えないことの確認（`consent scope` / `jws then`）も含む。
 */

import { describe, expect, it } from 'bun:test';
import { typedDataV4Payload } from '../../asset/eth-signing.js';
import { evaluateFormatCapability } from '../../credential/format-negotiation/capability.js';
import { verifyWithKey } from '../../credential/vc/jws.js';
import { VericertsError } from '../../errors.js';
import { withPresentedTo } from '../../gdpr/codec.js';
import {
  hasConsentTarget,
  resolveConsentTargetsByPresentation,
} from '../../gdpr/consent-scope-resolver.js';
import { extractFirstVerificationMethod } from '../../identity/jwt/jwt-codec.js';
import { readCorrelationContext } from '../../observability/correlation.js';
import { parsePresentationDefinition } from '../../presentation-exchange/definition.js';
import { validatePresentationSubmission } from '../../presentation-exchange/submission.js';
import { testSigner } from '../../wallet-migration/__tests__/fixtures.js';
import { exportBackup } from '../../wallet-migration/backup.js';
import { withPollutedPrototypeAsync } from '../prototype-pollution.fixtures.js';

/** 戻り値と例外コードを比較可能な形へ正規化する。 */
async function observe(run: () => unknown): Promise<string> {
  try {
    const value = await run();
    return `ok:${JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v))}`;
  } catch (error) {
    return error instanceof VericertsError ? `err:${error.code}` : `throw:${String(error)}`;
  }
}

interface Case {
  readonly name: string;
  readonly run: () => unknown;
  /** 省略した（呼び出しが own に持たない）プロパティ名 → 敵対値。 */
  readonly pollution: Record<string, unknown>;
  /** 汚染前の期待結果（正規化済み）。汚染後も同じでなければならない。 */
  readonly expected: string;
}

const JWK = { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' };
const VICTIM = `0x${'11'.repeat(20)}`;
const ATTACKER = `0x${'ee'.repeat(20)}`;
const PERMIT_TYPES = {
  Permit: [
    { name: 'owner', type: 'address' },
    { name: 'spender', type: 'address' },
    { name: 'value', type: 'uint256' },
  ],
};
const PERMIT = { types: PERMIT_TYPES, primaryType: 'Permit', domain: { name: 'T', chainId: 1 } };
const pd = parsePresentationDefinition({
  id: 'pd',
  input_descriptors: [{ id: 'a', constraints: { fields: [{ path: ['$.x'] }] } }],
} as never);
const submit = (submission: unknown) => () =>
  validatePresentationSubmission(submission as never, pd);
const GOOD_ENTRY = { id: 'a', format: 'jwt_vc_json', path: '$.verifiableCredential[0]' };

const CASES: readonly Case[] = [
  // validatePresentationSubmission は形不正でも例外を投げず false。必須キーの汚染で true にならない。
  {
    name: '正常な提出は true',
    run: submit({ id: 's', definition_id: 'pd', descriptor_map: [GOOD_ENTRY] }),
    pollution: { definition_id: 'x' },
    expected: 'ok:true',
  },
  {
    name: 'descriptor_map 欠落は false',
    run: submit({ id: 's', definition_id: 'pd' }),
    pollution: { descriptor_map: [GOOD_ENTRY] },
    expected: 'ok:false',
  },
  {
    name: 'descriptor_map に null 要素は false',
    run: submit({ id: 's', definition_id: 'pd', descriptor_map: [null] }),
    pollution: {},
    expected: 'ok:false',
  },
  {
    name: 'descriptor_map が非配列オブジェクトは false',
    run: submit({ id: 's', definition_id: 'pd', descriptor_map: { length: 1 } }),
    pollution: {},
    expected: 'ok:false',
  },
  {
    name: '要素の id が非文字列は false',
    run: submit({ id: 's', definition_id: 'pd', descriptor_map: [{ id: 1 }] }),
    pollution: {},
    expected: 'ok:false',
  },
  {
    name: '要素の id 欠落は汚染 id でも false',
    run: submit({ id: 's', definition_id: 'pd', descriptor_map: [{}] }),
    pollution: { id: 'a' },
    expected: 'ok:false',
  },
  {
    name: '空の提出 {} は汚染下でも false',
    run: submit({}),
    pollution: { definition_id: 'pd', descriptor_map: [GOOD_ENTRY] },
    expected: 'ok:false',
  },
  {
    name: 'null / 非オブジェクトの提出は false',
    run: submit(null),
    pollution: {},
    expected: 'ok:false',
  },
  { name: '数値の提出は false', run: submit(1), pollution: {}, expected: 'ok:false' },

  // typedDataV4Payload は message / types を own 限定で読む。欠落は 1020。
  {
    name: 'message の spender 欠落は汚染値で埋めず 1020',
    run: () => typedDataV4Payload({ ...PERMIT, message: { owner: VICTIM, value: '1' } } as never),
    pollution: { spender: ATTACKER, value: '99999999999' },
    expected: 'err:1020',
  },
  {
    name: 'message の全フィールド欠落は 1020',
    run: () => typedDataV4Payload({ ...PERMIT, message: {} } as never),
    pollution: { owner: VICTIM, spender: ATTACKER, value: '1' },
    expected: 'err:1020',
  },
  {
    name: 'types に無い primaryType は汚染定義でも 1020',
    run: () =>
      typedDataV4Payload({
        types: {},
        primaryType: 'Evil',
        domain: { name: 'T', chainId: 1 },
        message: { x: 1 },
      } as never),
    pollution: { Evil: [{ name: 'x', type: 'uint256' }] },
    expected: 'err:1020',
  },
  {
    name: 'ネスト struct 型が types に無いとき汚染定義でも 1020',
    run: () =>
      typedDataV4Payload({
        types: { Outer: [{ name: 'inner', type: 'Inner' }] },
        primaryType: 'Outer',
        domain: { name: 'T', chainId: 1 },
        message: { inner: { x: 1 } },
      } as never),
    pollution: { Inner: [{ name: 'x', type: 'uint256' }] },
    expected: 'err:1020',
  },
  {
    name: '最上位 message 欠落は汚染 message でも 1020',
    run: () => typedDataV4Payload({ ...PERMIT } as never),
    pollution: { message: { owner: VICTIM, spender: ATTACKER, value: '1' } },
    expected: 'err:1020',
  },
  {
    name: '最上位 domain 欠落は汚染 domain でも 1020',
    run: () =>
      typedDataV4Payload({
        types: PERMIT_TYPES,
        primaryType: 'Permit',
        message: { owner: VICTIM, spender: VICTIM, value: '1' },
      } as never),
    pollution: { domain: { name: 'T', chainId: 1 } },
    expected: 'err:1020',
  },

  // backup.ts の vc.format 鎖読み（VC が 2 → 1 件に落ちる）。
  {
    name: 'format を持たない VC は汚染 format が除外形式と一致してもバックアップに残る',
    run: async () =>
      (
        await exportBackup(
          {
            walletId: 'w',
            personas: [],
            dids: [],
            credentials: [
              { id: 'vc1', data: '{"a":1}' },
              { id: 'vc2', data: '{"b":2}', format: 'dc+sd-jwt' },
            ],
          },
          { ...testSigner(), sign: () => new Uint8Array(64) },
          {
            passphrase: 'correct horse battery staple 77!',
            excludeFormats: ['ephemeral-demo-vc'],
            iterations: 1000,
          },
        )
      ).credentials.length,
    pollution: { format: 'ephemeral-demo-vc' },
    expected: 'ok:2',
  },
  // capability.ts の descriptor.limitDisclosure（SD 非対応候補が汚染で絞り込まれる）。
  {
    name: 'limitDisclosure を省略した descriptor は汚染値 required で SD 非対応候補を落とさない',
    run: () => {
      const r = evaluateFormatCapability(
        [
          {
            id: 'pid',
            vpFormats: { jwt_vc_json: { alg: ['ES256'] } },
            candidates: [{ id: 'jwt-1', format: 'jwt_vc_json', alg: 'ES256' }],
          },
        ] as never,
        { randomTiebreak: () => 0.5 },
      );
      return {
        covered: r.fullyCovered,
        unmatched: r.unmatchedDescriptors,
        picked: r.selections.length,
      };
    },
    pollution: { limitDisclosure: 'required' },
    expected: 'ok:{"covered":true,"unmatched":[],"picked":1}',
  },
  // observability/correlation.ts の tracestate（省略しても汚染値が混ざらない）。
  {
    name: 'tracestate を省略した相関コンテキストに汚染 tracestate が混入しない',
    run: () =>
      readCorrelationContext({
        correlationContext: {
          requestId: 'req-1',
          traceparent: '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
        },
      }),
    pollution: { tracestate: 'evil=1' },
    expected:
      'ok:{"requestId":"req-1","traceparent":"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"}',
  },
  // jwt-codec の verificationMethod 必須キー。
  {
    name: 'id を欠く verificationMethod は id 汚染でも拒否',
    run: () =>
      extractFirstVerificationMethod({
        verificationMethod: [{ type: 'JsonWebKey2020', publicKeyJwk: JWK }],
      } as never),
    pollution: { id: 'did:key:z6Mk#evil' },
    expected: 'err:2001',
  },
  {
    name: 'type を欠く verificationMethod は type 汚染でも拒否',
    run: () =>
      extractFirstVerificationMethod({
        verificationMethod: [{ id: 'did:key:z#1', publicKeyJwk: JWK }],
      } as never),
    pollution: { type: 'JsonWebKey2020' },
    expected: 'err:2001',
  },
  {
    name: 'publicKeyJwk を欠く verificationMethod は汚染 JWK でも拒否',
    run: () =>
      extractFirstVerificationMethod({
        verificationMethod: [{ id: 'did:key:z#1', type: 'JsonWebKey2020' }],
      } as never),
    pollution: { publicKeyJwk: JWK },
    expected: 'err:2001',
  },

  {
    name: 'presentedTo を持たない記録に汚染履歴が混入しない',
    run: () =>
      withPresentedTo({ credential: 'c' } as never, { rpIdentifier: 'rp', presentedAt: 't' })
        .presentedTo,
    pollution: { presentedTo: [{ rpIdentifier: 'evil', presentedAt: 'x' }] },
    expected: 'ok:[{"rpIdentifier":"rp","presentedAt":"t"}]',
  },

  // 許可リスト（allowlist.ts）の読みが、汚染下で動作を変えないことの確認。
  {
    name: '許可: ownConsentScope の戻り値は省略キーを汚染値で読まない（hasConsentTarget）',
    run: () => hasConsentTarget({}),
    pollution: { rpIdentifier: 'rp', purpose: 'p', vcId: 'vc', pseudonym: 'ps' },
    expected: 'ok:false',
  },
  {
    name: '許可: ownConsentScope の戻り値は省略キーを汚染値で読まない（presentedTo 解決）',
    run: () =>
      resolveConsentTargetsByPresentation(
        { list: async () => ['k'], get: async () => null } as never,
        'k',
        {},
      ),
    pollution: { rpIdentifier: 'rp', purpose: 'p' },
    expected: 'ok:[]',
  },
  {
    name: '許可: verify の戻り値の汚染 then で署名検証結果は変わらない',
    run: () =>
      verifyWithKey(
        'ES256',
        {
          digest: new Uint8Array(32),
          signature: new Uint8Array(64),
          signingInput: new Uint8Array(1),
        },
        { verify: () => ({}) } as never,
      ),
    // biome-ignore lint/suspicious/noThenProperty: 汚染された Object.prototype.then を再現するために意図して thenable を作る
    pollution: { then: () => undefined },
    expected: 'ok:false',
  },
];

describe('Object.prototype 汚染前後で結果が変わらない', () => {
  for (const c of CASES) {
    it(c.name, async () => {
      const clean = await observe(c.run);
      expect(clean).toBe(c.expected);
      const polluted = await withPollutedPrototypeAsync(c.pollution, () => observe(c.run));
      expect(polluted).toBe(clean);
    });
  }
});
