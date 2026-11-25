/**
 * `key.verify`（検証関数の脱出ハッチ）の戻り値契約の回帰テスト。
 *
 * JWT-VC / JWT-VP の署名検証は同期 API のため、`verify` が返す `Promise`（`async` 実装）や
 * `'yes'` / `1` のような非 boolean 真値を truthiness で判定すると、署名が不正でも検証が通る
 * （fail-open）。厳密に `true` のときだけ成功とし、それ以外は 3010 に倒す。VC / VP の両経路と、
 * クラスインスタンス鍵の `this` 束縛が一致することも固定する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  FIXTURES,
  sampleVp,
  signerFor,
} from '../../presentation/__tests__/presentation.fixtures.js';
import { issuePresentation } from '../../presentation/issue.js';
import { verifyPresentation } from '../../presentation/presentation.js';
import { issueCredential } from '../issue.js';
import type { VerifiableCredential } from '../vc.js';
import { verifyCredential } from '../verify.js';

const NOW = 1_767_225_600;

type VerifyFn = (digest: Uint8Array, signature: Uint8Array, signingInput: Uint8Array) => unknown;

function sampleVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: '2025-12-01T00:00:00Z',
    expirationDate: '2027-01-01T00:00:00Z',
    id: 'urn:uuid:1234',
  };
}

/** 署名セグメントをゼロ埋め 64 バイトに差し替えた偽造 JWT。 */
function forge(jwt: string): string {
  const [h, p] = jwt.split('.');
  return `${h}.${p}.${Buffer.alloc(64).toString('base64url')}`;
}

function vcCall(jwt: string, verify: VerifyFn): () => unknown {
  return () => verifyCredential(jwt, { key: { verify: verify as never }, nowSeconds: NOW });
}

function vpCall(jwt: string, verify: VerifyFn): () => unknown {
  return () => verifyPresentation(jwt, { key: { verify: verify as never }, allowUnbound: true });
}

function expectSigInvalid(fn: () => unknown): void {
  let caught: unknown;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(ErrorCodes.SIG_INVALID);
}

const forgedVc = forge(issueCredential(sampleVc(), signerFor('ES256'), { nowSeconds: NOW }));
const forgedVp = forge(issuePresentation(sampleVp(), signerFor('ES256')));

const NON_STRICT_TRUE: ReadonlyArray<readonly [string, VerifyFn]> = [
  ['async () => true', async () => true],
  ['async () => false', async () => false],
  ["() => 'yes'", () => 'yes'],
  ["() => 'false'", () => 'false'],
  ['() => 1', () => 1],
  ['() => ({})', () => ({})],
  ['thenable', () => Object.defineProperty({}, 'then', { value: () => undefined })],
];

describe('key.verify の戻り値は厳密に true のときのみ成功', () => {
  it.each(NON_STRICT_TRUE)('JWT-VC: %s は 3010', (_name, verify) => {
    expectSigInvalid(vcCall(forgedVc, verify));
  });

  it.each(NON_STRICT_TRUE)('JWT-VP: %s は 3010', (_name, verify) => {
    expectSigInvalid(vpCall(forgedVp, verify));
  });

  it('拒否される Promise（reject）でも未処理 rejection を起こさず 3010', async () => {
    const rejecting: VerifyFn = () => Promise.reject(new Error('kms down'));
    expectSigInvalid(vcCall(forgedVc, rejecting));
    expectSigInvalid(vpCall(forgedVp, rejecting));
    await Promise.resolve();
  });

  it('同期 boolean true を返す検証関数は従来どおり成功する', () => {
    const fx = FIXTURES.ES256;
    const vc = issueCredential(sampleVc(), signerFor('ES256'), { nowSeconds: NOW });
    const vp = issuePresentation(sampleVp(), signerFor('ES256'));
    expect(vcCall(vc, fx.verify)()).toBeDefined();
    expect(vpCall(vp, fx.verify)()).toBeDefined();
  });
});

describe('クラスインスタンス鍵の this 束縛は VC / VP で一致する', () => {
  class StatefulKey {
    readonly calls: number[] = [];
    private readonly ok = true;
    verify(): boolean {
      this.calls.push(1);
      return this.ok;
    }
  }

  it('JWT-VC / JWT-VP ともに key をレシーバにして verify を呼ぶ', () => {
    const vcKey = new StatefulKey();
    const vpKey = new StatefulKey();
    const vc = issueCredential(sampleVc(), signerFor('ES256'), { nowSeconds: NOW });
    const vp = issuePresentation(sampleVp(), signerFor('ES256'));
    expect(verifyCredential(vc, { key: vcKey as never, nowSeconds: NOW })).toBeDefined();
    expect(verifyPresentation(vp, { key: vpKey as never, allowUnbound: true })).toBeDefined();
    expect(vcKey.calls).toHaveLength(1);
    expect(vpKey.calls).toHaveLength(1);
  });
});
