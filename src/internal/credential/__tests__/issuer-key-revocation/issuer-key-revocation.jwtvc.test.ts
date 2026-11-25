/**
 * JWT-VC 検証経路（`verifyCredential`）における鍵無効化宣言の強制（FC-11）。
 *
 * Issuer の鍵無効化宣言（`revoked_keys`）と発行時刻に基づく拒否（FC-11）が対象。
 *
 * 回帰対象: `assertCredentialKeyNotRevoked` はどの検証経路からも呼ばれておらず、FC-11 の VC 側は
 * 完全に opt-in（呼び忘れれば漏洩鍵で発行された VC が受理される）だった。ここでは helper を直接
 * 叩かず、**実際の `verifyCredential` を通して**強制されることを検証する。
 *
 * 検証内容:
 * - 宣言に該当する VC は `5012` FEDERATION_KEY_REVOKED。
 * - 漏洩前（`issuance < revoked_at`）の VC は受理する（巻き添え防止）。
 * - 境界（`issuance === revoked_at`）は拒否する。
 * - 突合 `kid` は上位が署名した JWKS を鍵素材で引いて決め、ヘッダや JWK の `kid` ラベルの詐称では
 *   素通りできない。
 * - `kid` 衝突: 別エンティティの同名 `kid` は巻き込まない（突合は `sub` で絞る）。
 * - `issuerTrust.issuer` の明示指定で leaf 以外のエンティティを対象にできる。
 * - `issuerTrust` 省略時は従来どおり（Federation を使わない検証経路に影響しない）。
 * - fail-closed: 宣言があるのに鍵素材の裏付け / 発行時刻が取れない VC は受理しない。
 * - 不成立チェーン（`valid: false`）は `5010` TRUST_CHAIN_INVALID。
 * - 発行時刻は `nbf` を第一候補にし、後付けの過去 `iat` でバックデートできない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import {
  AFTER_REVOKED,
  AFTER_REVOKED_ISO,
  BEFORE_REVOKED,
  BEFORE_REVOKED_ISO,
  declaration,
  expectThrowCode,
  FORGED_KID,
  INTERMEDIATE_ID,
  ISSUER_ID,
  issueJwtVc,
  OTHER_ISSUER_ID,
  REVOKED_AT_ISO,
  reissueJwtVcWithClaims,
  SIGNING_KID,
  signJwt,
  trustChain,
  UNRELATED_KID,
  verifyJwtVc,
  verifyJwtVcSignedByUnattestedKey,
  verifyJwtVcWithKeyKid,
} from './issuer-key-revocation.fixtures.js';

/** 発行者（leaf）の署名鍵を無効化する宣言だけを載せたチェーン。 */
function compromisedChain() {
  return { trustChain: trustChain([declaration(ISSUER_ID)]) };
}

describe('verifyCredential - 鍵無効化宣言の強制（FC-11）', () => {
  it('無効化された鍵で署名された JWT-VC は FEDERATION_KEY_REVOKED（5012）', () => {
    const jwt = issueJwtVc(AFTER_REVOKED_ISO, SIGNING_KID);
    expectThrowCode(() => verifyJwtVc(jwt, compromisedChain()), ErrorCodes.FEDERATION_KEY_REVOKED);
  });

  // 巻き添えの回帰: 漏洩前に正当に発行された VC まで無効化してはならない。
  it('漏洩前（issuance < revoked_at）に発行された JWT-VC は受理する', () => {
    const jwt = issueJwtVc(BEFORE_REVOKED_ISO, SIGNING_KID);
    expect(() => verifyJwtVc(jwt, compromisedChain())).not.toThrow();
  });

  it('境界（issuance === revoked_at）は拒否する', () => {
    const jwt = issueJwtVc(REVOKED_AT_ISO, SIGNING_KID);
    expectThrowCode(() => verifyJwtVc(jwt, compromisedChain()), ErrorCodes.FEDERATION_KEY_REVOKED);
  });

  it('宣言対象外の kid で署名された JWT-VC は受理する', () => {
    const jwt = issueJwtVc(AFTER_REVOKED_ISO, SIGNING_KID);
    const issuerTrust = { trustChain: trustChain([declaration(ISSUER_ID, UNRELATED_KID)]) };
    expect(() => verifyJwtVc(jwt, issuerTrust)).not.toThrow();
  });
});

describe('verifyCredential - 突合 kid の解決元（上位が署名した JWKS の鍵素材）', () => {
  // 最重要の回帰: FC-11 の脅威モデルでは署名者自身が失効鍵 K の保有者＝攻撃者である。JWS 保護
  // ヘッダも、DID Document 経由で解決される検証鍵 JWK の `kid` ラベルも攻撃者が決められるため、
  // そこから突合キーを取ると K で署名しつつ宣言外の別名を名乗るだけで素通りできてしまう。突合キーは
  // 上位（宣言と同じ権威）が署名した Subordinate Statement の JWKS を鍵素材で引いて決める。
  it('失効鍵で署名しヘッダに別の kid を詐称した JWT-VC は 5012 で拒否する', () => {
    const jwt = issueJwtVc(AFTER_REVOKED_ISO, FORGED_KID);
    expectThrowCode(() => verifyJwtVc(jwt, compromisedChain()), ErrorCodes.FEDERATION_KEY_REVOKED);
  });

  it('検証鍵 JWK の kid ラベルが宣言対象外でも、鍵素材が失効鍵なら 5012 で拒否する', () => {
    const jwt = issueJwtVc(AFTER_REVOKED_ISO, FORGED_KID);
    expectThrowCode(
      () => verifyJwtVcWithKeyKid(jwt, UNRELATED_KID, compromisedChain()),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
  });

  // 逆向きの対照。権威は上位の裏付けなので、ヘッダが宣言済み `kid` を名乗っても巻き添えにしない。
  it('ヘッダが宣言済み kid でも、上位の裏付けが宣言対象外なら受理する', () => {
    const jwt = issueJwtVc(AFTER_REVOKED_ISO, SIGNING_KID);
    const issuerTrust = {
      trustChain: trustChain([declaration(ISSUER_ID)], { attestedKids: [UNRELATED_KID] }),
    };
    expect(() => verifyJwtVc(jwt, issuerTrust)).not.toThrow();
  });

  it('同じ鍵素材が複数 kid で登録されていれば、1 つでも宣言に該当すれば拒否する', () => {
    const jwt = issueJwtVc(AFTER_REVOKED_ISO, UNRELATED_KID);
    const issuerTrust = {
      trustChain: trustChain([declaration(ISSUER_ID)], {
        attestedKids: [UNRELATED_KID, SIGNING_KID],
      }),
    };
    expectThrowCode(() => verifyJwtVc(jwt, issuerTrust), ErrorCodes.FEDERATION_KEY_REVOKED);
  });
});

describe('verifyCredential - 宣言の subject スコープ', () => {
  // kid 衝突の回帰: `kid` は JWKS 内でしか一意でない。エンティティ A の宣言が、同名 `kid` を使う
  // 別エンティティ B の VC を巻き添えで拒否してはならない。
  it('別エンティティ宛の宣言は同名 kid の JWT-VC を拒否しない', () => {
    const jwt = issueJwtVc(AFTER_REVOKED_ISO, SIGNING_KID);
    // 宣言は leaf（A）宛だが、この VC を署名したのは B である。
    const issuerTrust = {
      trustChain: trustChain([declaration(ISSUER_ID)]),
      issuer: OTHER_ISSUER_ID,
    };
    expect(() => verifyJwtVc(jwt, issuerTrust)).not.toThrow();
  });

  it('leaf 以外を対象とする宣言も issuer の明示指定で強制される', () => {
    const jwt = issueJwtVc(AFTER_REVOKED_ISO, SIGNING_KID);
    const issuerTrust = {
      trustChain: trustChain([declaration(INTERMEDIATE_ID)], { leaf: ISSUER_ID }),
      issuer: INTERMEDIATE_ID,
    };
    expectThrowCode(() => verifyJwtVc(jwt, issuerTrust), ErrorCodes.FEDERATION_KEY_REVOKED);
  });
});

describe('verifyCredential - issuerTrust 省略時の後方互換', () => {
  // FC-11 の判定は Federation 由来の信頼を使う経路にのみ適用する。did:web 単独など Trust Chain を
  // 持たない検証は従来どおり通る。
  it('issuerTrust を渡さなければ無効化鍵の JWT-VC も従来どおり受理する', () => {
    const jwt = issueJwtVc(AFTER_REVOKED_ISO, SIGNING_KID);
    expect(() => verifyJwtVc(jwt)).not.toThrow();
  });
});

describe('verifyCredential - fail-closed（宣言はあるが突合材料が無い）', () => {
  /** envelope binding を満たさない最小 payload（FC-11 を通過すれば 3002 で落ちる）。 */
  const bareHeader = { alg: 'ES256', kid: SIGNING_KID, typ: 'JWT' };

  // 上位が裏付けていない鍵で漏洩後に署名された VC を受理してはならない。受理すると、失効鍵の
  // 保有者は上位の JWKS に無い別名を名乗るだけで本検査を素通りできる（ラベルに依存しない拒否）。
  it('裏付けの無い鍵で漏洩後に発行された JWT-VC は 5012（受理しない）', () => {
    expectThrowCode(
      () => verifyJwtVcSignedByUnattestedKey(AFTER_REVOKED_ISO, compromisedChain()),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
  });

  // 巻き添えの回帰: 失効した鍵はチェーンが成立する限り JWKS に残っていないため、
  // 「裏付けが無ければ発行時刻によらず拒否」にすると、漏洩前に正当に発行されローテートで JWKS から
  // 外れた鍵の VC が全て拒否される。裏付けを引けない場合は最早 `revoked_at` との比較で判定する。
  it('裏付けの無い鍵でも漏洩前に発行された JWT-VC は受理する（巻き添え防止）', () => {
    expect(() =>
      verifyJwtVcSignedByUnattestedKey(BEFORE_REVOKED_ISO, compromisedChain()),
    ).not.toThrow();
  });

  it('宣言があるのに iat / nbf を持たない JWT-VC は 5012（受理しない）', () => {
    const jwt = signJwt(bareHeader, { iss: 'did:example:issuer' });
    expectThrowCode(() => verifyJwtVc(jwt, compromisedChain()), ErrorCodes.FEDERATION_KEY_REVOKED);
  });

  it('宣言があり iat / nbf が非数値の JWT-VC は 5012（受理しない）', () => {
    const jwt = signJwt(bareHeader, { iss: 'did:example:issuer', iat: null, nbf: 'not-a-number' });
    expectThrowCode(() => verifyJwtVc(jwt, compromisedChain()), ErrorCodes.FEDERATION_KEY_REVOKED);
  });

  // 上 2 件の 5012 が FC-11 由来であることの対照。宣言が subject に無ければ FC-11 は何も判定せず、
  // 同じ JWT は後段の envelope 検証（3002）まで進む。
  it('subject 宛の宣言が無ければ発行時刻欠落を理由に拒否しない', () => {
    const jwt = signJwt(bareHeader, { iss: 'did:example:issuer' });
    const issuerTrust = { trustChain: trustChain([declaration(OTHER_ISSUER_ID)]) };
    expectThrowCode(() => verifyJwtVc(jwt, issuerTrust), ErrorCodes.VC_SCHEMA_INVALID);
  });
});

describe('verifyCredential - 不成立チェーン', () => {
  it('valid:false の Trust Chain は TRUST_CHAIN_INVALID（5010）', () => {
    const jwt = issueJwtVc(BEFORE_REVOKED_ISO, SIGNING_KID);
    const issuerTrust = { trustChain: trustChain([], { valid: false }) };
    expectThrowCode(() => verifyJwtVc(jwt, issuerTrust), ErrorCodes.TRUST_CHAIN_INVALID);
  });
});

/**
 * 発行時刻の第一候補は `nbf`（JWT-VC）である。
 *
 * 注意: これはバックデート耐性そのものではない。`nbf` と `vc.issuanceDate` は同じ失効鍵で署名される
 * ため、両者を揃えて過去に詐称するバックデートは依然として通る。ここで塞ぐのは
 * 「束縛されていない `iat` を 1 つ後付けするだけ」という最も安価な迂回である。
 *
 * 回帰対象: 発行時刻を「`iat` を第一候補、無ければ `nbf`」で解決していた頃は、失効鍵の保有者が
 * JWT-VC に**任意の過去 `iat` を後付けする**だけで本検査を素通りできた。JWT-VC は本来 `iat` を
 * 持たず（`vc/issue.ts` は `nbf` のみを設定）、`iat` は何にも束縛されていないため、`nbf` /
 * `vc.issuanceDate` を現在時刻に保ったまま `iat` だけ過去に置いても `assertTimeClaims` も
 * `assertEnvelopeBinding` も通過し、バックデートの痕跡が VC に残らない。
 *
 * JWT-VC の `nbf` は `assertEnvelopeBinding` が `vc.issuanceDate` との一致を強制するため単独では
 * 動かせず、かつ JWT-VC では `nbf` がそのまま発行時刻なので、`nbf` 優先による巻き添えも起きない。
 */
describe('verifyCredential - 発行時刻の第一候補は nbf', () => {
  it('nbf を漏洩後に保ったまま過去の iat を後付けした JWT-VC は 5012', () => {
    // nbf = issuanceDate = revoked_at より後。iat だけ revoked_at より前に詐称する。
    const jwt = reissueJwtVcWithClaims(issueJwtVc(AFTER_REVOKED_ISO, SIGNING_KID), {
      iat: BEFORE_REVOKED,
    });
    expectThrowCode(() => verifyJwtVc(jwt, compromisedChain()), ErrorCodes.FEDERATION_KEY_REVOKED);
  });

  // 対照: 巻き添え防止側も `nbf` 基準のまま。漏洩前に発行された VC は、`iat` が漏洩後を指していても
  // 受理する（`iat` が優先されていたなら 5012 になる）。
  it('nbf が漏洩前なら iat が漏洩後でも受理する（nbf が優先されている証拠）', () => {
    const jwt = reissueJwtVcWithClaims(issueJwtVc(BEFORE_REVOKED_ISO, SIGNING_KID), {
      iat: AFTER_REVOKED,
    });
    expect(() => verifyJwtVc(jwt, compromisedChain())).not.toThrow();
  });

  // フォールバックの保持: `nbf` が NumericDate として読めない場合に限り `iat` を使う。
  it('nbf が非数値なら iat へフォールバックする（拒否側）', () => {
    const jwt = signJwt(
      { alg: 'ES256', kid: SIGNING_KID, typ: 'JWT' },
      { iss: 'did:example:issuer', nbf: 'not-a-number', iat: AFTER_REVOKED },
    );
    expectThrowCode(() => verifyJwtVc(jwt, compromisedChain()), ErrorCodes.FEDERATION_KEY_REVOKED);
  });

  it('nbf が無ければ iat へフォールバックする（受理側）', () => {
    const jwt = signJwt(
      { alg: 'ES256', kid: SIGNING_KID, typ: 'JWT' },
      { iss: 'did:example:issuer', iat: BEFORE_REVOKED },
    );
    // FC-11 は通過し、後段の envelope ↔ body 整合（3002）まで進む。
    expectThrowCode(() => verifyJwtVc(jwt, compromisedChain()), ErrorCodes.VC_SCHEMA_INVALID);
  });
});
