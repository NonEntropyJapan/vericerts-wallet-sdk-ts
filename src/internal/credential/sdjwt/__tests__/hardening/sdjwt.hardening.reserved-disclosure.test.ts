/**
 * 検証側が予約クレーム（`NON_DISCLOSABLE_CLAIMS`）名の Disclosure を拒否することの回帰テスト。
 *
 * 外部 Issuer が draft §2.2.2.3 に反して `exp` / `status` 等を Disclosure 化して発行すると、検証は
 * payload の own メンバだけを評価するため Holder が Disclosure を落とすだけで期限・失効・鍵束縛を回避できる。
 * 同梱の有無にかかわらず 3010 で拒否する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { encodeDisclosure } from '../../disclosure.js';
import { NON_DISCLOSABLE_CLAIMS } from '../../non-disclosable-claims.js';
import { verifySdJwt } from '../../verify.js';
import { ISSUER_JWK, reissueWithPayload, VCT } from './shared.js';

const NOW = 1_767_225_600;

describe('予約クレームの Disclosure 拒否', () => {
  for (const name of NON_DISCLOSABLE_CLAIMS) {
    it(`${name} の Disclosure は同梱有無にかかわらず 3010`, () => {
      const d = encodeDisclosure(name, name === 'exp' ? NOW - 86_400 : 'x', 'salt-r');
      const given = encodeDisclosure('given_name', 'Alice', 'salt-g');
      const payload = { vct: VCT, iat: NOW, _sd: [d.digest, given.digest] };
      const expected = new VericertsError(ErrorCodes.SIG_INVALID);

      // Holder が Disclosure を落とした提示でも、同梱した提示でも、Issuer の署名済み `_sd` は変わらない。
      // 落とした提示は digest 照合の対象が無いため拒否できないが、同梱された場合は必ず拒否する。
      const withReserved = reissueWithPayload(payload, [given.encoded, d.encoded]);
      expect(() => verifySdJwt(withReserved, { issuerKey: ISSUER_JWK, nowSeconds: NOW })).toThrow(
        expected,
      );
    });
  }

  it('vct#integrity（§2.2.2.3 で Disclosure 禁止）の Disclosure は 3010 で拒否する', () => {
    expect(NON_DISCLOSABLE_CLAIMS).toContain('vct#integrity');
  });

  it('予約クレームでない Disclosure は従来どおり復元される', () => {
    const given = encodeDisclosure('given_name', 'Alice', 'salt-g');
    const sdJwt = reissueWithPayload({ vct: VCT, iat: NOW, _sd: [given.digest] }, [given.encoded]);
    const verified = verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW });
    expect(verified.claims.given_name).toBe('Alice');
  });
});
