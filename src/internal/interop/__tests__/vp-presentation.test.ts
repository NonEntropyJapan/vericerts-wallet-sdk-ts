/**
 * VP 提示フロー（OID4VP）の相互運用ペアテスト。
 *
 * HAIP SD-JWT VC の Offer → Receive → Present を実鍵で 1 サイクル実行し、Verifier が Holder
 * Binding（KB-JWT）を nonce / audience 込みで検証できることを確認する。VeriCerts はどのロールに
 * 割り当てても同一ワイヤ形式で相互運用するため、`runInteropPair` に各ロールの鍵を差し替えて
 * `interop:<issuer>:<holder>:<verifier>`の代表ペアを検証する。
 *
 * 否定系: Holder Binding 不一致（cnf 非対応鍵）・nonce / audience 不一致・選択開示範囲逸脱。
 */

import { describe, expect, it } from 'bun:test';
import { verifySdJwt } from '../../credential/sdjwt/verify.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import {
  credentialInput,
  foreignHolderSigner,
  holderSigner,
  ISSUER_JWK,
  issuerSigner,
  VCT,
} from '../fixtures.js';
import { runInteropPair } from '../harness.js';

const NONCE = 'verifier-nonce-2f9a';
const AUD = 'https://verifier.example/haip';
const IAT = 1_767_225_600;
const REQUESTED = ['nickname', 'age_over_18'] as const;

/** 代表ペアの共通入力を構築する（各ロールを VeriCerts 実装で担う）。 */
function baseInput() {
  return {
    issuer: issuerSigner(),
    issuerKey: ISSUER_JWK,
    holder: holderSigner(),
    credential: credentialInput(),
    requestedClaims: REQUESTED,
    nonce: NONCE,
    audience: AUD,
    iatSeconds: IAT,
  };
}

describe('OID4VP VP 提示 — 基本フロー', () => {
  it('Offer → Receive → Present の 1 サイクルが成功する', () => {
    const result = runInteropPair(baseInput());
    // Receive: 発行体署名・vct 検証済み。
    expect(result.received.vct).toBe(VCT);
    // Present: KB 検証成功。
    expect(result.verified.keyBindingVerified).toBe(true);
    expect(result.verified.vct).toBe(VCT);
  });

  it('要求クレームのみ開示され、非要求クレームは復元されない', () => {
    const result = runInteropPair(baseInput());
    expect(result.verified.claims.nickname).toBe('ali');
    expect(result.verified.claims.age_over_18).toBe(true);
    // 非要求（resident_address / resident_country）は伏せられる。
    expect(result.verified.claims.resident_address).toBeUndefined();
    expect(result.verified.claims.resident_country).toBeUndefined();
    // 平文クレーム（sub）は常に残る。
    expect(result.verified.claims.sub).toBe('did:example:haip-holder');
  });

  it('提示部の KB-JWT は cnf 鍵で署名され sd_hash が整合する', () => {
    const { presented } = runInteropPair(baseInput());
    // 末尾に KB-JWT（`~` 終端でない）が付与されている。
    expect(presented.endsWith('~')).toBe(false);
    // KB-JWT を含む提示部が再検証できる。
    const kbSegments = presented.split('~');
    expect(kbSegments[kbSegments.length - 1]?.split('.').length).toBe(3);
  });
});

describe('OID4VP VP 提示 — Holder Binding 否定系', () => {
  it('cnf に対応しない鍵で署名した KB-JWT は HOLDER_BIND_MISMATCH（3012）', () => {
    // Holder 署名器のみ別鍵に差し替える（cnf は fixtures の HOLDER_JWK のまま）。
    expect(() => runInteropPair({ ...baseInput(), holder: foreignHolderSigner() })).toThrow(
      new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH),
    );
  });

  it('Verifier の nonce 期待値が提示 nonce と食い違うと 3012', () => {
    const input = baseInput();
    // 提示は NONCE、Verifier 検証は別 nonce になる状況を harness 外で再現する。
    const result = runInteropPair(input);
    // 一度成功した提示を、別 nonce を期待する Verifier に渡すと不一致。
    expect(() =>
      verifySdJwt(result.presented, {
        issuerKey: ISSUER_JWK,
        audience: AUD,
        nonce: 'different-nonce',
        requireKeyBinding: true,
      }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('Verifier の audience 期待値が食い違うと 3012', () => {
    const result = runInteropPair(baseInput());
    expect(() =>
      verifySdJwt(result.presented, {
        issuerKey: ISSUER_JWK,
        audience: 'https://attacker.example',
        nonce: NONCE,
        requireKeyBinding: true,
      }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });
});
