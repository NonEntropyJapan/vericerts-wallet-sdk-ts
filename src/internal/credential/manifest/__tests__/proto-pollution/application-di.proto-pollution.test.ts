/**
 * `buildCredentialApplication` / `submitCredentialApplication` の DI・任意オプション
 * （`generateId` / `fetchImpl` / `presentationFormat` / `verifyReceived`）に関する回帰テスト
 *
 * - `presentationFormat`（純データ）: own 限定で読む。`Object.prototype` 汚染下で未指定の呼び出しが
 *   攻撃者の format 文字列を採用しないことを固定する。
 * - `generateId` / `fetchImpl` / `verifyReceived`（関数値 DI）: `nonObjectPrototypeProperty` で読む。
 *   1. `generateId` / `fetchImpl` は `Object.prototype` に仕込んだ関数が「未指定」として弾かれ、
 *      既定実装（`crypto.randomUUID()` / グローバル `fetch`）にフォールバックすること（own 限定に
 *      すると逆に prototype メソッド DI が弾かれてしまうため、両方向を固定する）。
 *      `verifyReceived` には既定実装が無いため、汚染関数へ委譲せず fail-closed（3022）になることを
 *      固定する。
 *   2. `class Deps { fetchImpl() {…} }` / `class Deps { verifyReceived() {…} }` のような
 *      プロトタイプメソッド DI は `this` 付きで呼ばれ、正しく動作すること（レシーバ束ね直しの固定。
 *      `refresh-receiver.proto-pollution.test.ts` と同水準）。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAsync,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes } from '../../../../errors.js';
import type { VerifiableCredential } from '../../../vc/vc.js';
import { buildCredentialApplication } from '../../application-build.js';
import { submitCredentialApplication } from '../../application-response.js';
import { parseCredentialManifest } from '../../parse.js';
import type { CredentialManifest, SubmitApplicationDependencies } from '../../types.js';

const SUPPORTED_SPEC_VERSION = 'https://identity.foundation/credential-manifest/spec/v1.0.0/';
const ISSUER_ENDPOINT = 'https://issuer.example/apply';

function manifestWithPd(): CredentialManifest {
  return parseCredentialManifest({
    id: 'manifest-1',
    spec_version: SUPPORTED_SPEC_VERSION,
    issuer: { id: ISSUER_ENDPOINT },
    output_descriptors: [{ id: 'od-1', schema: 'https://schema.example/IdCard' }],
    presentation_definition: { id: 'pd-1' },
  });
}

/** presentation_definition を持たない Manifest（submission 構築に answers を要求しない）。 */
function simpleManifest(): CredentialManifest {
  return parseCredentialManifest({
    id: 'manifest-1',
    spec_version: SUPPORTED_SPEC_VERSION,
    issuer: { id: ISSUER_ENDPOINT },
    output_descriptors: [{ id: 'od-1', schema: 'https://schema.example/IdCard' }],
  });
}

const VERIFIED_VC: VerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'IdentityCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { id: 'did:example:holder' },
  issuanceDate: '2026-01-01T00:00:00Z',
  id: 'urn:vc:issued',
};

describe('buildCredentialApplication: presentationFormat の Object.prototype 汚染耐性', () => {
  it('presentationFormat 未指定の呼び出しは汚染値を採用せず既定 jwt_vc_json を使う（データ汚染）', () => {
    withPollutedPrototype({ presentationFormat: 'attacker-format' }, () => {
      const app = buildCredentialApplication(
        manifestWithPd(),
        { 'in-1': 'answer' },
        { generateId: () => 'id-1' },
      );
      expect(app.presentation_submission?.descriptor_map[0]?.format).toBe('jwt_vc_json');
    });
  });

  it('presentationFormat を明示指定した場合は汚染下でも指定どおりになる（非退行）', () => {
    withPollutedPrototype({ presentationFormat: 'attacker-format' }, () => {
      const app = buildCredentialApplication(
        manifestWithPd(),
        { 'in-1': 'answer' },
        { generateId: () => 'id-1', presentationFormat: 'vc+sd-jwt' },
      );
      expect(app.presentation_submission?.descriptor_map[0]?.format).toBe('vc+sd-jwt');
    });
  });
});

describe('buildCredentialApplication: generateId の Object.prototype 汚染耐性', () => {
  it('generateId 未指定の呼び出しは Object.prototype の汚染関数へ委譲せず crypto.randomUUID にフォールバックする', () => {
    withPollutedPrototype({ generateId: () => 'attacker-id' }, () => {
      const app = buildCredentialApplication(simpleManifest(), {}, {});
      expect(app.id).not.toBe('attacker-id');
      expect(app.id).toMatch(/^urn:uuid:/);
    });
  });

  it('プロトタイプメソッドとして注入した generateId は this 付きで呼ばれる（レシーバ束ね直し）', () => {
    class OptsWithGenerator {
      readonly calls: unknown[] = [];
      private counter = 0;
      generateId(): string {
        this.calls.push(this);
        this.counter += 1;
        return `seq-${this.counter}`;
      }
    }
    const opts = new OptsWithGenerator();
    const app = buildCredentialApplication(manifestWithPd(), { 'in-1': 'answer' }, opts);
    expect(app.id).toBe('seq-1');
    expect(app.presentation_submission?.id).toBe('seq-2');
    // `this` 経由でインスタンス状態を積めた ＝ レシーバが `opts` に束ね直されている。
    expect(opts.calls).toEqual([opts, opts]);
  });
});

describe('submitCredentialApplication: fetchImpl の Object.prototype 汚染耐性', () => {
  it('fetchImpl 未指定の呼び出しは Object.prototype の汚染関数へ委譲せずグローバル fetch にフォールバックする', async () => {
    const original = globalThis.fetch;
    const seen: unknown[] = [];
    globalThis.fetch = function stubFetch(this: unknown): Promise<Response> {
      seen.push(this);
      return Promise.resolve(
        new Response(JSON.stringify({ transaction_id: 'tx-1' }), {
          status: 200,
        }),
      );
    } as unknown as typeof fetch;
    try {
      const attackerFetch = async () => {
        throw new Error('attacker fetch must not be called');
      };
      await withPollutedPrototypeAsync({ fetchImpl: attackerFetch }, async () => {
        const deps: SubmitApplicationDependencies = { verifyReceived: async () => VERIFIED_VC };
        const result = await submitCredentialApplication(simpleManifest(), {}, deps, {
          generateId: () => 'id-1',
        });
        expect(result.transactionId).toBe('tx-1');
      });
    } finally {
      globalThis.fetch = original;
    }
    // グローバル fetch にはレシーバを束ねない（ネイティブ fetch なら Illegal invocation になる）。
    expect(seen).toEqual([undefined]);
  });

  it('プロトタイプメソッドとして注入した fetchImpl は this 付きで呼ばれる（レシーバ束ね直し）', async () => {
    class DepsWithFetch {
      readonly requestedUrls: string[] = [];
      async fetchImpl(url: string): Promise<Response> {
        this.requestedUrls.push(url);
        return new Response(JSON.stringify({ transaction_id: 'tx-1' }), { status: 200 });
      }
      async verifyReceived(): Promise<VerifiableCredential> {
        return VERIFIED_VC;
      }
    }
    const deps = new DepsWithFetch();
    const result = await submitCredentialApplication(simpleManifest(), {}, deps, {
      generateId: () => 'id-1',
    });
    expect(result.transactionId).toBe('tx-1');
    // `this` 経由でインスタンス状態を積めた ＝ レシーバが `deps` に束ね直されている。
    expect(deps.requestedUrls).toEqual([ISSUER_ENDPOINT]);
  });
});

describe('submitCredentialApplication: verifyReceived の Object.prototype 汚染耐性', () => {
  it('verifyReceived 未指定の呼び出しは Object.prototype の汚染関数へ委譲せず fail-closed（3022）になる', async () => {
    const original = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ verifiableCredential: 'raw-vc-jwt' }), {
        status: 200,
      })) as unknown as typeof fetch;
    let attackerCallCount = 0;
    try {
      await withPollutedPrototypeAsync(
        {
          // 呼ばれてしまうと成功で解決する（例外に頼ると、fail-closed 側の別の例外と区別が
          // 付かなくなり「呼ばれていないこと」を検証できない）。
          verifyReceived: async () => {
            attackerCallCount += 1;
            return VERIFIED_VC;
          },
        },
        async () => {
          // `verifyReceived` を own プロパティとして持たない deps（呼び出し側の実装漏れを模す）。
          const deps = {} as SubmitApplicationDependencies;
          await expect(
            submitCredentialApplication(simpleManifest(), {}, deps, {
              generateId: () => 'id-1',
            }),
          ).rejects.toMatchObject({ code: ErrorCodes.REFRESHED_VC_VERIFICATION_FAILED });
        },
      );
      // 汚染された Object.prototype.verifyReceived が一度でも呼ばれていれば fail-closed になって
      // いない（攻撃者の検証器が受領 VC を検証したことになってしまう）。
      expect(attackerCallCount).toBe(0);
    } finally {
      globalThis.fetch = original;
    }
  });

  it('プロトタイプメソッドとして注入した verifyReceived は this 付きで呼ばれる（レシーバ束ね直し）', async () => {
    class DepsWithVerify {
      readonly receivedRaw: string[] = [];
      readonly receivers: unknown[] = [];
      async verifyReceived(raw: string): Promise<VerifiableCredential> {
        this.receivedRaw.push(raw);
        this.receivers.push(this);
        return VERIFIED_VC;
      }
    }
    const original = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ verifiableCredential: 'raw-vc-jwt' }), {
        status: 200,
      })) as unknown as typeof fetch;
    try {
      const deps = new DepsWithVerify();
      const result = await submitCredentialApplication(simpleManifest(), {}, deps, {
        generateId: () => 'id-1',
      });
      expect(result.accepted).toBe(true);
      expect(result.credential).toEqual(VERIFIED_VC);
      expect(deps.receivedRaw).toEqual(['raw-vc-jwt']);
      // `this` 経由でインスタンス状態を積めた ＝ レシーバが `deps` に束ね直されている。
      expect(deps.receivers).toEqual([deps]);
    } finally {
      globalThis.fetch = original;
    }
  });
});
