/**
 * SD-JWT 検証のハードニングの回帰テスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - 未対応の `_sd_alg`（ハッシュアルゴリズムのダウングレード/混同）を 3010 で拒否する。
 * - Disclosure による平文クレーム隠蔽・重複 digest を 3010 で拒否する。
 * - 不正形状の `cnf`（3012/3010）・`status`（3010）を crypto/resolver 到達前に弾く。
 * - 構造不正な Issuer-signed JWT を 3010 へ正規化する。
 * - KB-JWT の `iat` 鮮度（`maxAgeSeconds`）を超えると 3012 で拒否する。
 *
 * KB-JWT の未来 `iat` 拒否と構造不正 KB-JWT のエラーコード正規化は
 * `sdjwt.hardening.edge-cases.test.ts` を参照（1 ファイル 300 行の Linterly 上限のため分離）。
 * 共有の鍵・定数・発行ヘルパは `shared.ts` に集約する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { encodeDisclosure } from '../../disclosure.js';
import { selectDisclosures } from '../../sdjwt.js';
import { addKeyBinding, verifySdJwt } from '../../verify.js';
import { HOLDER_SIGNER, ISSUER_JWK, issue, reissueWithPayload, VCT } from './shared.js';

describe('SD-JWT 検証のハードニング', () => {
  it('未対応の _sd_alg は SIG_INVALID（3010、ダウングレード防止）', () => {
    const sdJwt = reissueWithPayload({ vct: VCT, _sd: [], _sd_alg: 'sha-512' }, []);
    expect(() => verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK })).toThrow(
      new VericertsError(ErrorCodes.SIG_INVALID),
    );
  });

  it('対応する _sd_alg（sha-256）は受理する', () => {
    const sdJwt = reissueWithPayload({ vct: VCT, _sd: [], _sd_alg: 'sha-256' }, []);
    expect(verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK }).vct).toBe(VCT);
  });

  it('Disclosure が同名の平文クレームを隠蔽しようとすると SIG_INVALID（3010）', () => {
    const d = encodeDisclosure('sub', 'spoofed', 'salt-x');
    // sub は平文クレームとして存在し、かつ同名の Disclosure を _sd に載せる。
    const sdJwt = reissueWithPayload({ vct: VCT, sub: 'real', _sd: [d.digest] }, [d.encoded]);
    expect(() => verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK })).toThrow(
      new VericertsError(ErrorCodes.SIG_INVALID),
    );
  });

  it('同一 digest を指す重複 Disclosure は SIG_INVALID（3010）', () => {
    const d = encodeDisclosure('name', 'Alice', 'salt-name');
    const sdJwt = reissueWithPayload({ vct: VCT, _sd: [d.digest] }, [d.encoded, d.encoded]);
    expect(() => verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK })).toThrow(
      new VericertsError(ErrorCodes.SIG_INVALID),
    );
  });

  it('不正な cnf 形状（KB 必須）は HOLDER_BIND_MISMATCH（3012）', () => {
    const sdJwt = reissueWithPayload({ vct: VCT, _sd: [], cnf: { jwk: { kty: 'EC' } } }, []);
    // audience / nonce は `requireKeyBinding: true` の必須入力。省略すると cnf 形状
    // ではなく期待値欠落を理由に 3012 になり、本ケースの検証にならない。
    expect(() =>
      verifySdJwt(sdJwt, {
        issuerKey: ISSUER_JWK,
        audience: 'https://verifier.example',
        nonce: 'n',
        requireKeyBinding: true,
      }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('不正な cnf 形状（KB 非必須）は SIG_INVALID（3010）', () => {
    const sdJwt = reissueWithPayload({ vct: VCT, _sd: [], cnf: 'not-an-object' }, []);
    expect(() => verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK })).toThrow(
      new VericertsError(ErrorCodes.SIG_INVALID),
    );
  });

  it('不正な status 形状は SIG_INVALID（3010）', () => {
    const sdJwt = reissueWithPayload(
      { vct: VCT, _sd: [], status: { status_list: { idx: 'x', uri: 1 } } },
      [],
    );
    expect(() => verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK })).toThrow(
      new VericertsError(ErrorCodes.SIG_INVALID),
    );
  });

  it('構造不正な Issuer-signed JWT は SIG_INVALID（3010）に正規化される', () => {
    // 2 セグメントしかない不正な Issuer JWT。
    expect(() => verifySdJwt('aaa.bbb~', { issuerKey: ISSUER_JWK })).toThrow(
      new VericertsError(ErrorCodes.SIG_INVALID),
    );
  });

  it('maxAgeSeconds 超過の古い KB-JWT は HOLDER_BIND_MISMATCH（3012）', () => {
    const NONCE = 'n';
    const AUD = 'https://verifier.example';
    const IAT = 1_000_000;
    const bound = addKeyBinding(selectDisclosures(issue(), ['name']), HOLDER_SIGNER, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    expect(() =>
      verifySdJwt(bound, {
        issuerKey: ISSUER_JWK,
        audience: AUD,
        nonce: NONCE,
        maxAgeSeconds: 300,
        nowSeconds: IAT + 600,
      }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('maxAgeSeconds 範囲内の KB-JWT は検証成功する', () => {
    const NONCE = 'n';
    const AUD = 'https://verifier.example';
    const IAT = 1_000_000;
    const bound = addKeyBinding(selectDisclosures(issue(), ['name']), HOLDER_SIGNER, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    const result = verifySdJwt(bound, {
      issuerKey: ISSUER_JWK,
      audience: AUD,
      nonce: NONCE,
      maxAgeSeconds: 300,
      nowSeconds: IAT + 100,
    });
    expect(result.keyBindingVerified).toBe(true);
  });
});
