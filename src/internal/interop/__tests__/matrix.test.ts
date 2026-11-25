/**
 * 相互運用マトリクスのスコープ・命名テストと OID4VCI 発行フロー。
 *
 * 各 Peer の役割に基づく `supportsRole` の判定と `interopTestName` の命名、および
 * 代表的な Issuer / Holder ペアの OID4VCI 発行フローを 1 サイクル検証する。
 *
 * VeriCerts が全ロールを担うため、Issuer/Holder を VeriCerts 実装で回すペア（内部ループ、
 * PR 対象）を実鍵で実行し、他 Peer ペアはマトリクス上のスコープ判定のみを対象とする
 * （実接続は Nightly / Interop Event）。
 */

import { describe, expect, it } from 'bun:test';
import { verifySdJwt } from '../../credential/sdjwt/verify.js';
import { credentialInput, holderSigner, ISSUER_JWK, issuerSigner, VCT } from '../fixtures.js';
import { runInteropPair } from '../harness.js';
import { interopTestName, PEERS, supportsRole } from '../peers.js';

describe('相互運用マトリクス — Peer 役割カバレッジ', () => {
  it('VeriCerts は Issuer / Holder / Verifier を全て担える', () => {
    expect(supportsRole('vericerts', 'issuer')).toBe(true);
    expect(supportsRole('vericerts', 'holder')).toBe(true);
    expect(supportsRole('vericerts', 'verifier')).toBe(true);
  });

  it('EUDI RW は Holder のみ', () => {
    expect(supportsRole('eudi-rw', 'holder')).toBe(true);
    expect(supportsRole('eudi-rw', 'issuer')).toBe(false);
    expect(supportsRole('eudi-rw', 'verifier')).toBe(false);
  });

  it('walt.id / DIDKit は Issuer / Verifier', () => {
    for (const id of ['waltid', 'didkit'] as const) {
      expect(supportsRole(id, 'issuer')).toBe(true);
      expect(supportsRole(id, 'verifier')).toBe(true);
    }
  });

  it('Veramo は Holder だが EUDI RP との VP ペアはスコープ外', () => {
    // Veramo は Issuer / Holder。Verifier ロールは持たない。
    expect(supportsRole('veramo', 'verifier')).toBe(false);
    expect(supportsRole('veramo', 'holder')).toBe(true);
  });

  it('EBSI は OID4VCI Issuer（CT）として発行に参加し、Holder/Verifier は持たない', () => {
    // EBSI の適合テストは Issuer を対象とする。
    expect(supportsRole('ebsi', 'issuer')).toBe(true);
    // Wallet、RP、検証元としては EBSI を使わない。
    expect(supportsRole('ebsi', 'holder')).toBe(false);
    expect(supportsRole('ebsi', 'verifier')).toBe(false);
  });

  it('全 Peer が 7 実装（VeriCerts 含む）を網羅する', () => {
    expect(Object.keys(PEERS).sort()).toEqual([
      'didkit',
      'ebsi',
      'eudi-rw',
      'sphereon',
      'veramo',
      'vericerts',
      'waltid',
    ]);
  });
});

describe('相互運用テスト命名', () => {
  it('interop:<issuer>:<holder>:<verifier> 形式を組み立てる', () => {
    expect(interopTestName('sphereon', 'vericerts', 'waltid')).toBe(
      'interop:sphereon-issuer:vericerts-holder:waltid-verifier',
    );
  });
});

describe('OID4VCI 発行フロー — Issuer → Holder', () => {
  it('VeriCerts Issuer → VeriCerts Holder で受領検証まで成立する', () => {
    const result = runInteropPair({
      issuer: issuerSigner(),
      issuerKey: ISSUER_JWK,
      holder: holderSigner(),
      credential: credentialInput(),
      requestedClaims: ['nickname'],
      nonce: 'nonce-vci',
      audience: 'https://verifier.example/haip',
      iatSeconds: 1_767_225_600,
    });
    // Receive（発行受領）段階で Issuer 署名・vct が検証済みであること。
    expect(result.received.vct).toBe(VCT);
    expect(result.received.claims.nickname).toBe('ali');
  });

  it('別 Issuer 鍵（不正発行体）を期待する Holder は受領検証に失敗する', () => {
    const issued = runInteropPair({
      issuer: issuerSigner(),
      issuerKey: ISSUER_JWK,
      holder: holderSigner(),
      credential: credentialInput(),
      requestedClaims: ['nickname'],
      nonce: 'n',
      audience: 'a',
      iatSeconds: 1_767_225_600,
    }).issued;
    // 発行体鍵を別 JWK（Holder 鍵）で受領検証すると署名不一致。
    const foreignKey = holderSigner().publicKeyJwk;
    expect(() => verifySdJwt(issued, { issuerKey: foreignKey, expectedVct: VCT })).toThrow();
  });
});
