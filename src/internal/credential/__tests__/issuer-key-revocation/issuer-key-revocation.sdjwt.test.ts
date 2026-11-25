/**
 * SD-JWT VC 検証経路（`verifySdJwt`）における鍵無効化宣言の強制（FC-11）。
 *
 * Issuer の鍵無効化宣言（`revoked_keys`）と発行時刻に基づく拒否（FC-11）が対象。
 *
 * 回帰対象: `assertCredentialKeyNotRevoked` はどの検証経路からも呼ばれておらず、FC-11 の VC 側は
 * 完全に opt-in だった。JWT-VC 側（`issuer-key-revocation.jwtvc.test.ts`）と対称に、SD-JWT VC でも
 * **実際の `verifySdJwt` を通して**強制されることを検証する（フォーマット間の bypass を塞ぐ）。
 *
 * SD-JWT VC の発行時刻は `iat`（JWT-VC は `nbf`）である。どちらの経路でも同じ判定に到達すること
 * を確かめるため、ここでは `iat` を持つ VC を発行する。
 *
 * 検証内容:
 * - 宣言に該当する SD-JWT VC は `5012` FEDERATION_KEY_REVOKED。
 * - 漏洩前（`iat < revoked_at`）の VC は受理する（巻き添え防止）。
 * - 境界（`iat === revoked_at`）は拒否する。
 * - 突合 `kid` は上位が署名した JWKS を鍵素材で引いて決め、ヘッダや JWK の `kid` ラベルの詐称では
 *   素通りできない。
 * - `kid` 衝突: 別エンティティの同名 `kid` は巻き込まない（突合は `sub` で絞る）。
 * - `issuerTrust.issuer` の明示指定で leaf 以外のエンティティを対象にできる。
 * - `issuerTrust` 省略時は従来どおり（Federation を使わない検証経路に影響しない）。
 * - fail-closed: 宣言があるのに鍵素材の裏付け / `iat` が取れない VC は受理しない。
 * - 不成立チェーン（`valid: false`）は `5010` TRUST_CHAIN_INVALID。
 * - 発行時刻の第一候補は `iat`（JWT-VC の `nbf` 優先とは非対称。フォーマットごとの規定）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import {
  declaration,
  expectThrowCode,
  FORGED_KID,
  INTERMEDIATE_ID,
  ISSUER_ID,
  issueSdJwtVc,
  OTHER_ISSUER_ID,
  REVOKED_AT,
  SIGNING_KID,
  trustChain,
  UNRELATED_KID,
  verifySdJwtVc,
  verifySdJwtVcSignedByUnattestedKey,
  verifySdJwtVcWithKeyKid,
} from './issuer-key-revocation.fixtures.js';

/** 発行者（leaf）の署名鍵を無効化する宣言だけを載せたチェーン。 */
function compromisedChain() {
  return { trustChain: trustChain([declaration(ISSUER_ID)]) };
}

describe('verifySdJwt - 鍵無効化宣言の強制（FC-11）', () => {
  it('無効化された鍵で署名された SD-JWT VC は FEDERATION_KEY_REVOKED（5012）', () => {
    const sdJwt = issueSdJwtVc({ iat: REVOKED_AT + 1 }, SIGNING_KID);
    expectThrowCode(
      () => verifySdJwtVc(sdJwt, compromisedChain()),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
  });

  // 巻き添えの回帰: 漏洩前に正当に発行された VC まで無効化してはならない。
  it('漏洩前（iat < revoked_at）に発行された SD-JWT VC は受理する', () => {
    const sdJwt = issueSdJwtVc({ iat: REVOKED_AT - 1 }, SIGNING_KID);
    expect(() => verifySdJwtVc(sdJwt, compromisedChain())).not.toThrow();
  });

  it('境界（iat === revoked_at）は拒否する', () => {
    const sdJwt = issueSdJwtVc({ iat: REVOKED_AT }, SIGNING_KID);
    expectThrowCode(
      () => verifySdJwtVc(sdJwt, compromisedChain()),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
  });

  it('宣言対象外の kid で署名された SD-JWT VC は受理する', () => {
    const sdJwt = issueSdJwtVc({ iat: REVOKED_AT + 1 }, SIGNING_KID);
    const issuerTrust = { trustChain: trustChain([declaration(ISSUER_ID, UNRELATED_KID)]) };
    expect(() => verifySdJwtVc(sdJwt, issuerTrust)).not.toThrow();
  });
});

describe('verifySdJwt - 突合 kid の解決元（上位が署名した JWKS の鍵素材）', () => {
  // 最重要の回帰: FC-11 の脅威モデルでは署名者自身が失効鍵 K の保有者＝攻撃者である。JWS 保護
  // ヘッダも、DID Document 経由で解決される検証鍵 JWK の `kid` ラベルも攻撃者が決められるため、
  // そこから突合キーを取ると K で署名しつつ宣言外の別名を名乗るだけで素通りできてしまう。突合キーは
  // 上位（宣言と同じ権威）が署名した Subordinate Statement の JWKS を鍵素材で引いて決める。
  it('失効鍵で署名しヘッダに別の kid を詐称した SD-JWT VC は 5012 で拒否する', () => {
    const sdJwt = issueSdJwtVc({ iat: REVOKED_AT + 1 }, FORGED_KID);
    expectThrowCode(
      () => verifySdJwtVc(sdJwt, compromisedChain()),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
  });

  it('検証鍵 JWK の kid ラベルが宣言対象外でも、鍵素材が失効鍵なら 5012 で拒否する', () => {
    const sdJwt = issueSdJwtVc({ iat: REVOKED_AT + 1 }, FORGED_KID);
    expectThrowCode(
      () => verifySdJwtVcWithKeyKid(sdJwt, UNRELATED_KID, compromisedChain()),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
  });

  // 逆向きの対照。権威は上位の裏付けなので、ヘッダが宣言済み `kid` を名乗っても巻き添えにしない。
  it('ヘッダが宣言済み kid でも、上位の裏付けが宣言対象外なら受理する', () => {
    const sdJwt = issueSdJwtVc({ iat: REVOKED_AT + 1 }, SIGNING_KID);
    const issuerTrust = {
      trustChain: trustChain([declaration(ISSUER_ID)], { attestedKids: [UNRELATED_KID] }),
    };
    expect(() => verifySdJwtVc(sdJwt, issuerTrust)).not.toThrow();
  });
});

describe('verifySdJwt - 宣言の subject スコープ', () => {
  // kid 衝突の回帰: `kid` は JWKS 内でしか一意でない。エンティティ A の宣言が、同名 `kid` を使う
  // 別エンティティ B の VC を巻き添えで拒否してはならない。
  it('別エンティティ宛の宣言は同名 kid の SD-JWT VC を拒否しない', () => {
    const sdJwt = issueSdJwtVc({ iat: REVOKED_AT + 1 }, SIGNING_KID);
    const issuerTrust = {
      trustChain: trustChain([declaration(ISSUER_ID)]),
      issuer: OTHER_ISSUER_ID,
    };
    expect(() => verifySdJwtVc(sdJwt, issuerTrust)).not.toThrow();
  });

  it('leaf 以外を対象とする宣言も issuer の明示指定で強制される', () => {
    const sdJwt = issueSdJwtVc({ iat: REVOKED_AT + 1 }, SIGNING_KID);
    const issuerTrust = {
      trustChain: trustChain([declaration(INTERMEDIATE_ID)], { leaf: ISSUER_ID }),
      issuer: INTERMEDIATE_ID,
    };
    expectThrowCode(() => verifySdJwtVc(sdJwt, issuerTrust), ErrorCodes.FEDERATION_KEY_REVOKED);
  });
});

describe('verifySdJwt - issuerTrust 省略時の後方互換', () => {
  // FC-11 の判定は Federation 由来の信頼を使う経路にのみ適用する。did:web 単独など Trust Chain を
  // 持たない検証は従来どおり通る。
  it('issuerTrust を渡さなければ無効化鍵の SD-JWT VC も従来どおり受理する', () => {
    const sdJwt = issueSdJwtVc({ iat: REVOKED_AT + 1 }, SIGNING_KID);
    expect(() => verifySdJwtVc(sdJwt)).not.toThrow();
  });
});

describe('verifySdJwt - fail-closed（宣言はあるが突合材料が無い）', () => {
  // 上位が裏付けていない鍵で漏洩後に署名された VC を受理してはならない（ラベルに依存しない拒否）。
  it('裏付けの無い鍵で漏洩後に発行された SD-JWT VC は 5012（受理しない）', () => {
    expectThrowCode(
      () => verifySdJwtVcSignedByUnattestedKey({ iat: REVOKED_AT + 1 }, compromisedChain()),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
  });

  // 巻き添えの回帰: 失効鍵はチェーン成立時に JWKS へ残らないため、「裏付け無し = 即拒否」
  // にすると漏洩前の正当な VC まで巻き添えになる。最早 `revoked_at` との比較で判定する。
  it('裏付けの無い鍵でも漏洩前に発行された SD-JWT VC は受理する（巻き添え防止）', () => {
    expect(() =>
      verifySdJwtVcSignedByUnattestedKey({ iat: REVOKED_AT - 1 }, compromisedChain()),
    ).not.toThrow();
  });

  it('宣言があるのに iat / nbf を持たない SD-JWT VC は 5012（受理しない）', () => {
    const sdJwt = issueSdJwtVc({ iat: undefined }, SIGNING_KID);
    expectThrowCode(
      () => verifySdJwtVc(sdJwt, compromisedChain()),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
  });

  it('宣言があり iat / nbf が非数値の SD-JWT VC は 5012（受理しない）', () => {
    const sdJwt = issueSdJwtVc({ iat: null, nbf: 'not-a-number' }, SIGNING_KID);
    expectThrowCode(
      () => verifySdJwtVc(sdJwt, compromisedChain()),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
  });

  // 上 2 件の 5012 が FC-11 由来であることの対照。宣言が subject に無ければ FC-11 は何も判定せず、
  // 発行時刻を持たない SD-JWT VC はそのまま受理される（従来挙動）。
  it('subject 宛の宣言が無ければ発行時刻欠落を理由に拒否しない', () => {
    const sdJwt = issueSdJwtVc({ iat: undefined }, SIGNING_KID);
    const issuerTrust = { trustChain: trustChain([declaration(OTHER_ISSUER_ID)]) };
    expect(() => verifySdJwtVc(sdJwt, issuerTrust)).not.toThrow();
  });
});

describe('verifySdJwt - 不成立チェーン', () => {
  it('valid:false の Trust Chain は TRUST_CHAIN_INVALID（5010）', () => {
    const sdJwt = issueSdJwtVc({ iat: REVOKED_AT - 1 }, SIGNING_KID);
    const issuerTrust = { trustChain: trustChain([], { valid: false }) };
    expectThrowCode(() => verifySdJwtVc(sdJwt, issuerTrust), ErrorCodes.TRUST_CHAIN_INVALID);
  });
});

/**
 * 発行時刻の第一候補は `iat`（SD-JWT VC）である。
 *
 * JWT-VC は `nbf` を第一候補にする（`nbf` が `vc.issuanceDate` に束縛され詐称できないため）が、
 * SD-JWT VC には envelope ↔ body 整合という束縛が無く、`iat` が標準の発行時刻クレームである。
 * したがって優先順はフォーマットごとに異なる。ここでは SD-JWT VC 側が `iat` 優先のままである
 * ことを固定する（JWT-VC の是正が SD-JWT 側へ波及していないことの回帰）。
 */
describe('verifySdJwt - 発行時刻の第一候補は iat', () => {
  it('iat が漏洩後なら nbf が漏洩前でも拒否する（iat が優先されている証拠）', () => {
    const sdJwt = issueSdJwtVc({ iat: REVOKED_AT + 1, nbf: REVOKED_AT - 1 }, SIGNING_KID);
    expectThrowCode(
      () => verifySdJwtVc(sdJwt, compromisedChain()),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
  });

  it('iat が漏洩前なら nbf が漏洩後でも受理する（巻き添え防止）', () => {
    const sdJwt = issueSdJwtVc({ iat: REVOKED_AT - 1, nbf: REVOKED_AT + 1 }, SIGNING_KID);
    expect(() => verifySdJwtVc(sdJwt, compromisedChain())).not.toThrow();
  });

  // フォールバックの保持: `iat` が NumericDate として読めない場合に限り `nbf` を使う。
  it('iat が無ければ nbf へフォールバックする（拒否側）', () => {
    const sdJwt = issueSdJwtVc({ iat: undefined, nbf: REVOKED_AT + 1 }, SIGNING_KID);
    expectThrowCode(
      () => verifySdJwtVc(sdJwt, compromisedChain()),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
  });
});
