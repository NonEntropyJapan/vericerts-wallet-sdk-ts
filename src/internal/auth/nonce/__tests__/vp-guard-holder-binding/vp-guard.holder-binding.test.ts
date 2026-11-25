/**
 * `verifyPresentationWithReplayGuard` が実効 `aud` を内包 VC 検証へ中継することの回帰テスト
 *
 * **修正前の欠陥（PoC）**: 本ラッパは `aud` の不一致を 3012 ではなく 4012 として扱うため、内側の
 * `verifyPresentation` へ `expectedAudience: undefined` を明示的に渡している。その結果、内側が
 * 組み立てた `credentialResults` は audience 未指定で評価され、**内包 SD-JWT VC に付いた KB-JWT の
 * `aud` が一切照合されなかった**。攻撃者の Verifier（`https://evil.example/client`）宛に束縛された
 * KB-JWT を詰めた提示が、束縛照合も replay 検知も通ったうえで `valid: true` で返っていた。
 *
 * 本ラッパは公開プリミティブ（`exports/auth.ts`）であり、Wallet ファサードを経由しない直接呼び出しが
 * ある。ファサード側だけを直しても塞がらないため、guard 自身が実効値で組み直す。
 *
 * 実鍵のみを使う（モック禁止）。VP holder / KB-JWT は ES256、SD-JWT VC の issuer は ES256K。
 */

import { describe, expect, it } from 'bun:test';
import {
  FIXTURES,
  sampleVp,
  signerFor,
} from '../../../../credential/presentation/__tests__/presentation.fixtures.js';
import { issuePresentation } from '../../../../credential/presentation/issue.js';
import { createSdJwt } from '../../../../credential/sdjwt/sdjwt.js';
import { addKeyBinding } from '../../../../credential/sdjwt/verify.js';
import { createNonceStore } from '../../store.js';
import type { NonceContext, NonceStore } from '../../types.js';
import { verifyPresentationWithReplayGuard } from '../../vp-guard.js';

const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const AUD = 'https://verifier.example/client';
const EVIL_AUD = 'https://evil.example/client';
const IAT = 1_700_000_000;
const CTX: NonceContext = { flow: 'oid4vp', clientId: AUD };
const ISSUER_DID = 'did:example:issuer';
const VCT = 'https://example.com/credentials/identity';

/** VP 署名の検証鍵（holder = ES256）。 */
const HOLDER_KEY = { publicKeyJwk: FIXTURES.ES256.jwk } as const;
/** 内包 SD-JWT VC の正しい発行者鍵（ES256K）を返す DI。 */
const issuerKeyResolver = () => ({ publicKeyJwk: FIXTURES.ES256K.jwk });

/** 固定時刻の `NonceStore` を作る。 */
function makeStore(): NonceStore {
  return createNonceStore({ backend: 'memory', now: () => IAT * 1000 });
}

/** SD-JWT VC を発行する（`withCnf` 時は holder 鍵を `cnf` に載せる）。 */
function issueSdJwt(withCnf: boolean): string {
  return createSdJwt(signerFor('ES256K'), {
    vct: VCT,
    disclosureClaims: ['name'],
    claims: { name: 'Alice' },
    salts: { name: 'salt-name' },
    issuer: ISSUER_DID,
    nowSeconds: IAT,
    ...(withCnf ? { cnf: { jwk: FIXTURES.ES256.jwk } } : {}),
  });
}

/** 指定 audience に束縛した KB-JWT 付き SD-JWT VC を内包する JWT-VP を組み立てる。 */
function presentWithKb(kbAudience: string): string {
  const presentedVc = addKeyBinding(issueSdJwt(true), signerFor('ES256'), {
    audience: kbAudience,
    nonce: NONCE,
    iatSeconds: IAT,
  });
  return issuePresentation(sampleVp({ verifiableCredential: [presentedVc] }), signerFor('ES256'), {
    audience: AUD,
    nonce: NONCE,
    nowSeconds: IAT,
  });
}

/** `expectedAudience` を渡さない（束縛値は `nonceContext` 側）guard オプション。 */
function guardOpts(extra: Record<string, unknown> = {}) {
  return {
    key: HOLDER_KEY,
    nonce: NONCE,
    nonceStore: makeStore(),
    nonceContext: CTX,
    nowSeconds: IAT,
    credentialKey: issuerKeyResolver,
    ...extra,
  };
}

describe('replay 検知経路の実効 audience 中継', () => {
  it('攻撃者の Verifier 宛に束縛された KB-JWT は 3012 で弾かれる', async () => {
    // 中継前はこの提示が valid: true で返っていた（束縛照合も replay 検知も通るため）。
    const verified = await verifyPresentationWithReplayGuard(presentWithKb(EVIL_AUD), guardOpts());
    expect(verified.valid).toBe(false);
    expect(verified.credentialResults[0]?.errors).toEqual(['3012']);
    expect(verified.errors).toEqual(['3012']);
  });

  it('束縛値と同じ aud に束縛された KB-JWT は通る（過剰な拒否をしない）', async () => {
    const verified = await verifyPresentationWithReplayGuard(presentWithKb(AUD), guardOpts());
    expect(verified.valid).toBe(true);
    expect(verified.errors).toBeUndefined();
    expect(verified.credentialResults[0]).toMatchObject({ valid: true, format: 'dc+sd-jwt' });
  });

  it('requireHolderBinding: true も guard 経由で内包 VC へ中継される', async () => {
    // cnf も KB-JWT も持たない SD-JWT VC は、突合を要求されれば 3012 になる。
    const jwt = issuePresentation(
      sampleVp({ verifiableCredential: [issueSdJwt(false)] }),
      signerFor('ES256'),
      { audience: AUD, nonce: NONCE, nowSeconds: IAT },
    );
    const verified = await verifyPresentationWithReplayGuard(
      jwt,
      guardOpts({ requireHolderBinding: true }),
    );
    expect(verified.valid).toBe(false);
    expect(verified.credentialResults[0]?.errors).toEqual(['3012']);
  });

  it('requireHolderBinding 未指定なら KB-JWT を持たない SD-JWT VC は従来どおり受理される', async () => {
    const jwt = issuePresentation(
      sampleVp({ verifiableCredential: [issueSdJwt(false)] }),
      signerFor('ES256'),
      { audience: AUD, nonce: NONCE, nowSeconds: IAT },
    );
    const verified = await verifyPresentationWithReplayGuard(jwt, guardOpts());
    expect(verified.valid).toBe(true);
  });

  it('credentialKey は 1 エントリにつき 1 回だけ呼ばれる（内包 VC の二重検証をしない）', async () => {
    // 修正前は、内側の `verifyPresentation` が `{ ...opts }` を渡して credentialKey ごと引き継ぎ
    // 全内包 VC を暗号検証し、その結果を捨てて `withEffectiveBinding` が再検証していた
    // （1 エントリにつき 2 回）。VP レベルの検証には内包 VC を
    // 検証しない内部経路を使うようにして 1 パスへ畳んである。
    const seen: number[] = [];
    const countingResolver = (request: { index: number }) => {
      seen.push(request.index);
      return { publicKeyJwk: FIXTURES.ES256K.jwk };
    };
    const verified = await verifyPresentationWithReplayGuard(
      presentWithKb(AUD),
      guardOpts({ credentialKey: countingResolver }),
    );
    expect(verified.valid).toBe(true);
    expect(seen).toEqual([0]);
  });

  // 内包 VC ゼロの提示は `valid: false` / `3002`（`every([])` の空真を塞いだ）。
  // ここで固定するのは「guard の組み直しが下位層の判定をそのまま運ぶ」ことで、判定内容自体では
  // ない（guard 起因の拒否は例外として先に出る）。
  it('内包 VC を持たない提示は valid: false / 3002 を素通しする（組み直しで壊れない）', async () => {
    const jwt = issuePresentation(sampleVp({ verifiableCredential: [] }), signerFor('ES256'), {
      audience: AUD,
      nonce: NONCE,
      nowSeconds: IAT,
    });
    const verified = await verifyPresentationWithReplayGuard(jwt, guardOpts());
    expect(verified.holderDID).toBe('did:example:holder');
    expect(verified.valid).toBe(false);
    expect(verified.credentialResults).toEqual([]);
    expect(verified.errors).toEqual(['3002']);
  });
});
