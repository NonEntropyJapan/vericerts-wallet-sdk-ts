/**
 * `Object.prototype` 汚染下でも `runInteropPair` が必須フィールドの継承値を拾わないことの
 * 回帰テスト。
 *
 * 各ペアで Offer → Receive → Present を 1 サイクル実行する。
 *
 * 欠陥時の挙動: `iatSeconds` / `nonce` / `audience` / `issuerKey` は own 限定で読むのに、
 * `credential` / `requestedClaims` / `issuer` / `holder` はプロトタイプ鎖越しに読んでいた。
 * 本ハーネスは `exports/interop.ts` から公開されており、型のない JS 呼び出しがこれらを省略すると
 *
 * - `credential`: 攻撃者が選んだ `vct` / `claims` が **正規の Issuer 鍵で署名されて発行**される
 *   （`expectedVct` も同じ汚染値を読むため受領検証まで通ってしまう）、
 * - `requestedClaims`: Verifier が要求していないクレーム（住所など）が**選択開示**される、
 * - `issuer`: 攻撃者が差し込んだ署名器の `sign` が呼ばれる、
 *
 * という結果になる。`harness.ts` の読み取り規律（純データは own 限定、`CredentialSigner` は
 * `Object.prototype` 由来のみ排除）をここで固定する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../__tests__/prototype-pollution.fixtures.js';
import { type CreateSdJwtOptions, parseSdJwt } from '../../../credential/sdjwt/sdjwt.js';
import { type CredentialSigner, createPrivateKeySigner } from '../../../credential/vc/signer.js';
import {
  credentialInput,
  HOLDER_CNF,
  holderSigner,
  ISSUER_JWK,
  issuerSigner,
  VCT,
} from '../../fixtures.js';
import { type InteropPairInput, runInteropPair } from '../../harness.js';

const NONCE = 'nonce-745';
const AUD = 'https://verifier.example/haip';
const IAT = 1_767_225_600;

/** 攻撃者が汚染値として仕込む別鍵（正規 Issuer 鍵とは別物）。 */
const ATTACKER_PRIVATE_KEY = new Uint8Array(32).fill(66);
/** 攻撃者が発行させたい型識別子。 */
const ATTACKER_VCT = 'https://attacker.example/credentials/admin';

/**
 * 攻撃者が `Object.prototype.credential` に仕込む発行入力。
 *
 * `cnf` は正規 Holder のものにしてある。汚染値を拾う実装では KB-JWT 検証まで通り、
 * **例外なしで**攻撃者の `vct` / `claims` が正規 Issuer 鍵で発行されてしまうため。
 */
function attackerCredential(): CreateSdJwtOptions {
  return {
    vct: ATTACKER_VCT,
    issuer: 'did:example:attacker',
    cnf: HOLDER_CNF,
    disclosureClaims: ['role'],
    claims: { sub: 'did:example:attacker', role: 'admin' },
    salts: { role: 'salt-role' },
  };
}

/** `sign` の signing-input を記録する `CredentialSigner` ラッパ（実鍵で実署名する）。 */
function recordingSigner(base: CredentialSigner): CredentialSigner & { readonly signed: string[] } {
  const signed: string[] = [];
  return {
    alg: base.alg,
    publicKeyJwk: base.publicKeyJwk,
    signed,
    sign(signingInput: Uint8Array): Uint8Array {
      signed.push(new TextDecoder().decode(signingInput));
      return base.sign(signingInput);
    },
  };
}

/** 記録した signing-input（`b64(header).b64(payload)`）の payload から `vct` を取り出す。 */
function signedVcts(signingInputs: readonly string[]): (string | undefined)[] {
  return signingInputs.map((input) => {
    const segment = input.split('.')[1] as string;
    const payload = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as {
      vct?: string;
    };
    return payload.vct;
  });
}

/** 提示 SD-JWT に残っている Disclosure のクレーム名。 */
function disclosedClaimNames(presented: string): string[] {
  return parseSdJwt(presented).disclosures.flatMap((d) => d.claimName ?? []);
}

/** 全フィールドを明示した正当な入力。 */
function baseInput(): InteropPairInput {
  return {
    issuer: issuerSigner(),
    issuerKey: ISSUER_JWK,
    holder: holderSigner(),
    credential: credentialInput(),
    requestedClaims: ['nickname'],
    nonce: NONCE,
    audience: AUD,
    iatSeconds: IAT,
  };
}

/** 必須フィールドを 1 つ省略した入力（型のない JS からの渡し忘れ相当）。 */
function inputWithout(
  key: keyof InteropPairInput,
  overrides: Readonly<Record<string, unknown>> = {},
): InteropPairInput {
  const input: Record<string, unknown> = { ...baseInput(), ...overrides };
  delete input[key];
  return input as unknown as InteropPairInput;
}

describe('runInteropPair: Object.prototype 汚染', () => {
  it('credential を省略した呼び出しで汚染値が発行入力に採用されない', () => {
    const issuer = recordingSigner(issuerSigner());
    expect(() =>
      withPollutedPrototype({ credential: attackerCredential() }, () =>
        runInteropPair(inputWithout('credential', { issuer })),
      ),
    ).toThrow();
    // 正規 Issuer 鍵が攻撃者の `vct` に署名していないこと（署名済み payload で直接確認する）。
    expect(signedVcts(issuer.signed)).not.toContain(ATTACKER_VCT);
  });

  it('requestedClaims を省略した提示で汚染値のクレームが開示されない', () => {
    // `selectDisclosures` は `new Set(claimsToDisclose)` で読むため `undefined` でも例外にならず
    // 「開示ゼロ」になる。汚染値を拾う実装だけが未要求クレームを開示する。
    const result = withPollutedPrototype({ requestedClaims: ['resident_address'] }, () =>
      runInteropPair(inputWithout('requestedClaims')),
    );
    expect(disclosedClaimNames(result.presented)).not.toContain('resident_address');
    expect(disclosedClaimNames(result.presented)).toEqual([]);
    expect(result.verified.keyBindingVerified).toBe(true);
  });

  it('issuer を省略した発行で汚染値の署名器が呼ばれない', () => {
    const attacker = recordingSigner(createPrivateKeySigner(ATTACKER_PRIVATE_KEY, 'ES256'));
    expect(() =>
      withPollutedPrototype({ issuer: attacker }, () => runInteropPair(inputWithout('issuer'))),
    ).toThrow();
    expect(attacker.signed).toEqual([]);
  });

  it('正常系: credential / requestedClaims / issuer を明示した提示は汚染下でも成功する', () => {
    // 受理集合を狭める変更のため、正当な入力が落ちていないことを確認する。
    const attacker = recordingSigner(createPrivateKeySigner(ATTACKER_PRIVATE_KEY, 'ES256'));
    const result = withPollutedPrototype(
      {
        credential: attackerCredential(),
        requestedClaims: ['resident_address'],
        issuer: attacker,
      },
      () => runInteropPair(baseInput()),
    );
    expect(result.received.vct).toBe(VCT);
    expect(result.received.claims.nickname).toBe('ali');
    expect(result.verified.keyBindingVerified).toBe(true);
    expect(disclosedClaimNames(result.presented)).toEqual(['nickname']);
    expect(attacker.signed).toEqual([]);
  });
});
