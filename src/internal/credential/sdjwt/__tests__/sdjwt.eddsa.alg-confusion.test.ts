/**
 * SD-JWT VC / KB-JWT の alg confusion 拒否テスト（実鍵・実署名、モック禁止）。
 *
 * 兄弟モジュール `sdjwt.eddsa.test.ts` から分離した異常系スイート（1 ファイル 300 行以下のため）。
 * フィクスチャは `sdjwt.eddsa.fixtures.ts` を共有する。
 *
 * 検証内容:
 * - `alg: none` は ALG_NONE（3011）。
 * - alg ↔ 鍵種別の不一致（EdDSA ヘッダ × EC 鍵 / ES256 ヘッダ × OKP 鍵）は、鍵解決時の
 *   INVALID_DID（2001）を漏らさず、Issuer 署名経路は SIG_INVALID（3010）・KB-JWT 経路は
 *   HOLDER_BIND_MISMATCH（3012）へ正規化される（`verifyWithJwkOrFalse`）。
 * - 不正な OKP `cnf.jwk`（`y` 混入 / 鍵合意専用の `crv: X25519`）は `validateCnf` が
 *   crypto 到達前に拒否する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { getEd25519PublicKey } from '../../../keymanager/ed25519.js';
import { selectDisclosures } from '../sdjwt.js';
import { addKeyBinding, verifySdJwt } from '../verify.js';
import {
  ALG_FIXTURES,
  AUD,
  b64u,
  ED_HOLDER_SEED,
  ED_OTHER_ISSUER_SEED,
  forgeIssuerHeader,
  IAT,
  issueSdJwt,
  NONCE,
  reissueWithPayload,
  toOkpJwk,
  VCT,
} from './sdjwt.eddsa.fixtures.js';

const ED = ALG_FIXTURES.EdDSA;
const EC = ALG_FIXTURES.ES256;

describe('受入条件 3: alg=none / alg confusion の拒否', () => {
  /** `fn` が投げた `VericertsError` のコードを返す（投げなければ undefined で assert を落とす）。 */
  function thrownCode(fn: () => unknown): string | undefined {
    try {
      fn();
    } catch (e) {
      return (e as VericertsError).code;
    }
    return undefined;
  }

  /** 指定 `cnf` を持つ（Disclosure なしの）EdDSA 署名済み SD-JWT を組み立てる。 */
  function issueWithCnf(cnf: Record<string, unknown>): string {
    return reissueWithPayload(ED.issuerSigner, 'EdDSA', {
      vct: VCT,
      _sd: [],
      _sd_alg: 'sha-256',
      cnf,
    });
  }

  it('Issuer ヘッダ alg=none は ALG_NONE（3011）', () => {
    const forged = forgeIssuerHeader(issueSdJwt(ED.issuerSigner), {
      alg: 'none',
      typ: 'vc+sd-jwt',
    });
    expect(thrownCode(() => verifySdJwt(forged, { issuerKey: ED.issuerJwk }))).toBe(
      ErrorCodes.ALG_NONE,
    );
  });

  it('alg: EdDSA を EC（P-256）Issuer 鍵で検証すると SIG_INVALID（3010）', () => {
    // EdDSA は OKP/Ed25519 にのみ束縛される。EC 鍵では検証できないため署名不一致として拒否する
    // （鍵解決時の 2001 が VC 検証 API の失敗面へ漏れないこと）。
    const code = thrownCode(() =>
      verifySdJwt(issueSdJwt(ED.issuerSigner), { issuerKey: EC.issuerJwk }),
    );
    expect(code).toBe(ErrorCodes.SIG_INVALID);
  });

  it('alg: ES256 を OKP（Ed25519）Issuer 鍵で検証すると SIG_INVALID（3010）', () => {
    const code = thrownCode(() =>
      verifySdJwt(issueSdJwt(EC.issuerSigner), { issuerKey: ED.issuerJwk }),
    );
    expect(code).toBe(ErrorCodes.SIG_INVALID);
  });

  it('ヘッダ alg を ES256 へ偽造しても OKP 鍵とは結び付かず SIG_INVALID（3010）', () => {
    const forged = forgeIssuerHeader(issueSdJwt(ED.issuerSigner), {
      alg: 'ES256',
      typ: 'vc+sd-jwt',
    });
    expect(thrownCode(() => verifySdJwt(forged, { issuerKey: ED.issuerJwk }))).toBe(
      ErrorCodes.SIG_INVALID,
    );
  });

  it('EdDSA 署名を別の Ed25519 公開鍵で検証すると SIG_INVALID（3010）', () => {
    const otherJwk = toOkpJwk(getEd25519PublicKey(ED_OTHER_ISSUER_SEED));
    const code = thrownCode(() =>
      verifySdJwt(issueSdJwt(ED.issuerSigner), { issuerKey: otherJwk }),
    );
    expect(code).toBe(ErrorCodes.SIG_INVALID);
  });

  it('y を持つ OKP cnf.jwk は KB 必須で 3012 / 非必須で 3010', () => {
    // OKP 鍵は `y` を持たない（RFC 8037）。EC JWK 偽装を crypto 到達前に弾く。
    const sdJwt = issueWithCnf({
      jwk: { ...toOkpJwk(getEd25519PublicKey(ED_HOLDER_SEED)), y: 'AAAA' },
    });
    expect(
      // audience / nonce は `requireKeyBinding: true` の必須入力。省略すると cnf 形状
      // ではなく期待値欠落を理由に 3012 になり、本ケースの検証にならない。
      thrownCode(() =>
        verifySdJwt(sdJwt, {
          issuerKey: ED.issuerJwk,
          audience: AUD,
          nonce: NONCE,
          requireKeyBinding: true,
        }),
      ),
    ).toBe(ErrorCodes.HOLDER_BIND_MISMATCH);
    expect(thrownCode(() => verifySdJwt(sdJwt, { issuerKey: ED.issuerJwk }))).toBe(
      ErrorCodes.SIG_INVALID,
    );
  });

  it('crv: X25519 の OKP cnf.jwk は validateCnf が拒否する（KB 必須で 3012 / 非必須で 3010）', () => {
    // X25519 は鍵合意専用であり署名鍵ではない。EdDSA は crv: Ed25519 にのみ束縛されるため、
    // crypto へ渡す前に cnf 形状検証で弾く。
    const sdJwt = issueWithCnf({
      jwk: { kty: 'OKP', crv: 'X25519', x: b64u(getEd25519PublicKey(ED_HOLDER_SEED)) },
    });
    const bound = addKeyBinding(sdJwt, ED.holderSigner, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    expect(
      thrownCode(() =>
        verifySdJwt(bound, {
          issuerKey: ED.issuerJwk,
          audience: AUD,
          nonce: NONCE,
          requireKeyBinding: true,
        }),
      ),
    ).toBe(ErrorCodes.HOLDER_BIND_MISMATCH);
    expect(
      thrownCode(() =>
        verifySdJwt(bound, { issuerKey: ED.issuerJwk, audience: AUD, nonce: NONCE }),
      ),
    ).toBe(ErrorCodes.SIG_INVALID);
  });
});

describe('回帰: KB-JWT の alg ↔ cnf.jwk 鍵種別の不一致', () => {
  /** EC（P-256）Holder 鍵を cnf に載せた EdDSA 発行の SD-JWT 提示部（name のみ開示）。 */
  function presentEcCnf(): string {
    return selectDisclosures(issueSdJwt(ED.issuerSigner, { jwk: EC.holderJwk }), ['name']);
  }

  it('cnf が EC 鍵の提示に EdDSA の KB-JWT を付けると HOLDER_BIND_MISMATCH（3012）', () => {
    // KB-JWT ヘッダ alg=EdDSA は OKP/Ed25519 にのみ束縛されるため、EC の cnf.jwk では検証できない。
    // 修正前はここで鍵解決の INVALID_DID（2001）が verifySdJwt の外へ漏れていた。
    const bound = addKeyBinding(presentEcCnf(), ED.holderSigner, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    expect(() =>
      verifySdJwt(bound, {
        issuerKey: ED.issuerJwk,
        audience: AUD,
        nonce: NONCE,
        requireKeyBinding: true,
      }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('cnf が OKP 鍵の提示に ES256 の KB-JWT を付けると HOLDER_BIND_MISMATCH（3012）', () => {
    const presented = selectDisclosures(issueSdJwt(ED.issuerSigner, { jwk: ED.holderJwk }), [
      'name',
    ]);
    const bound = addKeyBinding(presented, EC.holderSigner, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    expect(() =>
      verifySdJwt(bound, {
        issuerKey: ED.issuerJwk,
        audience: AUD,
        nonce: NONCE,
        requireKeyBinding: true,
      }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });
});
