/**
 * VC リフレッシュの DI 依存を**レシーバ付きで呼ぶ**ことの回帰テスト。
 *
 * `refresh.ts` / `refresh-endpoint.ts` は `verifyRefreshed` / `requestConsent` / `fetchImpl` を
 * `nonObjectPrototypeProperty` で取り出す。取り出した関数を**裸で呼ぶ**と、`class Deps { … }` の
 * ように prototype メソッドで注入した正当な DI は `this` が `undefined` になって壊れる。取り出した関数は元のオブジェクトをレシーバとして呼ぶ。
 *
 * own 化しすぎ（prototype メソッドを「未指定」と誤判定する）とレシーバ喪失は別々の退行なので、
 * 本ファイルの DI はすべて **prototype メソッド** かつ **`this` 経由でインスタンス状態を参照** する。
 * `this` を参照しないスタブでは後者を検出できない（`catalogue.proto-pollution.test.ts` の
 * `CatalogueLoader` と同水準）。`refresh-fields.proto-pollution.test.ts` にあった `this` を
 * 参照しないクラス DI 正常系は、本ファイルが上位互換で置き換える。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import {
  createFailOpenWindow,
  type FailSafeAuditRecord,
  type FailSafeDecision,
} from '../../../../failsafe-policy/index.js';
import type { RefreshServiceConfig, VerifiableCredential } from '../../../vc/vc.js';
import { type RefreshDependencies, refreshCredential } from '../../refresh.js';

const MS_PER_DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse('2026-07-01T00:00:00Z');
const REFRESH_URL = 'https://issuer.example/refresh';

const SERVICE: RefreshServiceConfig = {
  id: 'refresh-1',
  type: 'OID4VCIRefreshService2025',
  url: REFRESH_URL,
};

/** 更新後の新 VC（`derivedFrom` は持たない ＝ Issuer 未設定）。 */
const NEW_VC: VerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'IdentityCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { id: 'did:example:holder' },
  issuanceDate: '2026-07-01T00:00:00Z',
  id: 'urn:vc:new',
};

/** しきい値内（exp まで 5 日）の旧 VC。 */
function makeVc(service: RefreshServiceConfig = SERVICE): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'IdentityCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:holder' },
    issuanceDate: '2026-01-01T00:00:00Z',
    expirationDate: new Date(NOW + 5 * MS_PER_DAY).toISOString(),
    id: 'urn:vc:old',
    refreshService: service,
  };
}

/**
 * 依存をすべて **prototype メソッド** で公開する DI（クラスベース DI の正当な形）。
 *
 * 各メソッドは `this` 経由でインスタンス状態を読み書きする。取り出した関数を裸で呼ばれると
 * `this` が `undefined` になり `TypeError` で失敗するため、レシーバ束ね直しの退行を検出できる。
 */
class RefreshDeps {
  readonly requestedUrls: string[] = [];
  readonly verifiedRaw: string[] = [];
  readonly consentedFor: string[] = [];

  constructor(private readonly body: string) {}

  async fetchImpl(url: string): Promise<Response> {
    this.requestedUrls.push(url);
    return new Response(this.body, { status: 200 });
  }

  async verifyRefreshed(raw: string): Promise<VerifiableCredential> {
    this.verifiedRaw.push(raw);
    return JSON.parse(raw) as VerifiableCredential;
  }

  async requestConsent(vc: VerifiableCredential): Promise<boolean> {
    this.consentedFor.push(vc.id ?? '');
    return true;
  }
}

/** refreshService の応答本文（新 VC を `credential` に載せた JSON）。 */
const RESPONSE_BODY = JSON.stringify({ credential: JSON.stringify(NEW_VC) });

describe('リフレッシュ DI のレシーバ束ね直し', () => {
  it('prototype メソッドの fetchImpl / verifyRefreshed が this 付きで呼ばれる', async () => {
    const deps = new RefreshDeps(RESPONSE_BODY);
    const result = await refreshCredential(
      makeVc(),
      { now: NOW },
      deps as unknown as RefreshDependencies,
    );

    expect(result.refreshed).toBe(true);
    expect(result.credential?.derivedFrom).toBe('urn:vc:old');
    // `this` 参照つきメソッドが動いた ＝ レシーバが `deps` に束ね直されている。
    expect(deps.requestedUrls).toEqual([REFRESH_URL]);
    expect(deps.verifiedRaw).toEqual([JSON.stringify(NEW_VC)]);
  });

  it('prototype メソッドの requestConsent が this 付きで呼ばれる', async () => {
    const deps = new RefreshDeps(RESPONSE_BODY);
    const vc = makeVc({ ...SERVICE, requireHolderConsent: true });
    const result = await refreshCredential(
      vc,
      { now: NOW },
      deps as unknown as RefreshDependencies,
    );

    expect(result.refreshed).toBe(true);
    // `this.consentedFor` に積めた ＝ 同意コールバックもレシーバ付きで呼ばれている。
    expect(deps.consentedFor).toEqual(['urn:vc:old']);
  });

  it('Object.create のプロトタイプに置いた依存でもレシーバが保たれる', async () => {
    // `class` 以外の prototype 委譲（`Object.create`）でも同じ経路を通ることを固定する。
    const base = new RefreshDeps(RESPONSE_BODY);
    const deps = Object.create(base) as RefreshDeps;
    const result = await refreshCredential(
      makeVc(),
      { now: NOW },
      deps as unknown as RefreshDependencies,
    );

    expect(result.refreshed).toBe(true);
    // レシーバは取り出し元（`deps`）。プロトタイプ経由で `base` の配列を共有する。
    expect(base.requestedUrls).toEqual([REFRESH_URL]);
  });

  it('fetchImpl 未指定のフォールバックではグローバル fetch にレシーバを束ねない', async () => {
    // ネイティブ `fetch` は `this` を差し替えると `Illegal invocation` で落ちるため、
    // 「注入されたときだけレシーバを渡す」分岐が要る。実ネットワークを叩かずに固定できるよう
    // グローバル `fetch` をスタブに差し替え、渡されたレシーバを記録して検証する。
    const original = globalThis.fetch;
    const seenThis: unknown[] = [];
    globalThis.fetch = function stubFetch(this: unknown): Promise<Response> {
      seenThis.push(this);
      return Promise.resolve(new Response(RESPONSE_BODY, { status: 200 }));
    } as unknown as typeof fetch;
    try {
      // `fetchImpl` はキーごと持たせない（`undefined` を置くとフォールバック経路が変わり得る）。
      const deps = {
        verifyRefreshed: async (raw: string) => JSON.parse(raw) as VerifiableCredential,
      };
      const result = await refreshCredential(
        makeVc(),
        { now: NOW },
        deps as unknown as RefreshDependencies,
      );
      expect(result.refreshed).toBe(true);
    } finally {
      globalThis.fetch = original;
    }
    // `deps` を `this` に束ねていないこと（ネイティブ fetch なら Illegal invocation になる）。
    expect(seenThis).toEqual([undefined]);
  });

  it('fetchImpl が null でもグローバル fetch にフォールバックしレシーバを束ねない', async () => {
    // `doFetch = fetchImpl ?? fetch`（null もグローバルへ倒れる）と `fetchImpl === undefined` の
    // レシーバ判定がずれていると、`deps.fetchImpl = null`（型のない JS 呼び出しでは有り得る）で
    // 「グローバル `fetch` に `deps` を束ねる」組み合わせが成立する。ブラウザでは
    // `Illegal invocation` の TypeError が 3004 に潰れ、FO-9 の `failOpenWindow` 未注入という
    // 既定挙動により **無言でリフレッシュが成立しなくなる**（例外がそのまま送出される）。
    // 判定は一箇所から導くこと。
    const original = globalThis.fetch;
    const seenThis: unknown[] = [];
    globalThis.fetch = function stubFetch(this: unknown): Promise<Response> {
      seenThis.push(this);
      return Promise.resolve(new Response(RESPONSE_BODY, { status: 200 }));
    } as unknown as typeof fetch;
    try {
      const deps = {
        fetchImpl: null,
        verifyRefreshed: async (raw: string) => JSON.parse(raw) as VerifiableCredential,
      };
      const result = await refreshCredential(
        makeVc(),
        { now: NOW },
        deps as unknown as RefreshDependencies,
      );
      expect(result.refreshed).toBe(true);
    } finally {
      globalThis.fetch = original;
    }
    expect(seenThis).toEqual([undefined]);
  });

  it('requestConsent が関数でなければ同意を得たことにしない（fail-closed / 3023）', async () => {
    // 同意が必要なサービスに対し `requestConsent` を注入しない。裸呼び出しの是正が
    // truthy 判定のままだと、非関数の継承値で `TypeError` に化けて経路が変わる。
    const deps = new RefreshDeps(RESPONSE_BODY);
    const { requestConsent: _omitted, ...withoutConsent } = {
      fetchImpl: deps.fetchImpl.bind(deps),
      verifyRefreshed: deps.verifyRefreshed.bind(deps),
      requestConsent: undefined,
    };
    const vc = makeVc({ ...SERVICE, requireHolderConsent: true });
    await expect(
      refreshCredential(vc, { now: NOW }, withoutConsent as unknown as RefreshDependencies),
    ).rejects.toMatchObject({ code: ErrorCodes.HOLDER_CONSENT_NOT_OBTAINED });
  });
});

/**
 * FO-9 の関数値 DI（`requestFailSafeConsent` / `onPolicyEvent`）を **prototype メソッド** かつ
 * `this` 経由でインスタンス状態を参照する形で実装したクラスベース deps（`refresh-fail-safe.ts` の
 * docstring が想定する形）。`nonObjectPrototypeProperty` で取り出した関数を裸で呼ぶと `this` が
 * `undefined` になり、`this.decisions.push(...)` 等が `TypeError` で落ちる。
 */
class FailSafeClassDeps {
  readonly decisions: FailSafeDecision[] = [];
  readonly records: FailSafeAuditRecord[] = [];
  readonly failOpenWindow = createFailOpenWindow();
  readonly verifyRefreshed: RefreshDependencies['verifyRefreshed'] = async (raw) =>
    JSON.parse(raw) as VerifiableCredential;
  readonly fetchImpl: RefreshDependencies['fetchImpl'] = async () =>
    new Response('{}', { status: 500 });

  requestFailSafeConsent(decision: FailSafeDecision): boolean {
    this.decisions.push(decision);
    return true;
  }

  onPolicyEvent(record: FailSafeAuditRecord): void {
    this.records.push(record);
  }
}

describe('FO-9 の関数値 DI のレシーバ束ね直し（プロトタイプメソッド実装）', () => {
  it('requestFailSafeConsent / onPolicyEvent が this 付きで呼ばれる（インスタンス状態へ記録できる）', async () => {
    // `failSafePolicy` 未指定 = `prompt` 相当（`keep-old` は同意プロンプトを省くため、
    // `requestFailSafeConsent` の receiver 束ね直しまでは検証できない）。
    const deps = new FailSafeClassDeps();
    const result = await refreshCredential(
      makeVc(),
      { now: NOW },
      deps as unknown as RefreshDependencies,
    );
    expect(result.warning?.policyEvent).toBe('FO-9');
    // `this.decisions` / `this.records` へ積めた＝レシーバが `deps` へ束ね直されている
    // （裸呼び出しなら `this` が `undefined` になり `TypeError` で落ちる）。
    expect(deps.decisions).toHaveLength(1);
    expect(deps.records).toHaveLength(1);
    expect(deps.records[0]).toMatchObject({ policy_event: 'FO-9' });
  });
});
