/**
 * `Object.prototype` 汚染下でも `runInteropTxPair` が必須フィールドの継承値を拾わないことの
 * 回帰テスト。
 *
 * OID4VP 提示で KB-JWT に `transaction_data_hashes` を格納して署名する。
 *
 * 欠陥時の挙動: `harness.ts` と同型で、`credential` / `requestedClaims` / `transactionData` /
 * `issuer` / `holder` をプロトタイプ鎖越しに読んでいた。Transaction Data 経路では
 * `transactionData` の汚染値がそのまま **Holder が署名する同意ハッシュ** になるため、
 * 「Holder が同意していない取引に署名済みの同意証跡が付く」状態を作れる。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
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
import { type InteropTxPairInput, runInteropTxPair } from '../../tx-harness.js';

const NONCE = 'tx-nonce-745';
const AUD = 'https://rp.example/pay';
const IAT = 1_767_225_600;

/** 攻撃者が汚染値として仕込む別鍵（正規 Issuer 鍵とは別物）。 */
const ATTACKER_PRIVATE_KEY = new Uint8Array(32).fill(66);
/** 攻撃者が発行させたい型識別子。 */
const ATTACKER_VCT = 'https://attacker.example/credentials/admin';

/** payment 種別の Transaction Data を base64url JSON として組み立てる。 */
function paymentTransactionData(payee: string, amount: string): string {
  const payload = {
    type: 'payment',
    credential_ids: ['haip-cred-1'],
    amount,
    currency: 'EUR',
    payee,
  };
  return base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(payload)));
}

/** Holder が同意した正規の取引。 */
const CONSENTED_TX = paymentTransactionData('Merchant BVBA', '42.00');
/** 攻撃者が汚染で差し込む取引（Holder は同意していない）。 */
const ATTACKER_TX = paymentTransactionData('Attacker BVBA', '9999.00');

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
function baseInput(): InteropTxPairInput {
  return {
    issuer: issuerSigner(),
    issuerKey: ISSUER_JWK,
    holder: holderSigner(),
    credential: credentialInput(),
    requestedClaims: ['nickname'],
    nonce: NONCE,
    audience: AUD,
    transactionData: [CONSENTED_TX],
    iatSeconds: IAT,
  };
}

/** 必須フィールドを 1 つ省略した入力（型のない JS からの渡し忘れ相当）。 */
function inputWithout(
  key: keyof InteropTxPairInput,
  overrides: Readonly<Record<string, unknown>> = {},
): InteropTxPairInput {
  const input: Record<string, unknown> = { ...baseInput(), ...overrides };
  delete input[key];
  return input as unknown as InteropTxPairInput;
}

describe('runInteropTxPair: Object.prototype 汚染', () => {
  it('credential を省略した呼び出しで汚染値が発行入力に採用されない', () => {
    const issuer = recordingSigner(issuerSigner());
    expect(() =>
      withPollutedPrototype({ credential: attackerCredential() }, () =>
        runInteropTxPair(inputWithout('credential', { issuer })),
      ),
    ).toThrow();
    // 正規 Issuer 鍵が攻撃者の `vct` に署名していないこと（署名済み payload で直接確認する）。
    expect(signedVcts(issuer.signed)).not.toContain(ATTACKER_VCT);
  });

  it('requestedClaims を省略した提示で汚染値のクレームが開示されない', () => {
    const result = withPollutedPrototype({ requestedClaims: ['resident_address'] }, () =>
      runInteropTxPair(inputWithout('requestedClaims')),
    );
    expect(disclosedClaimNames(result.presented)).not.toContain('resident_address');
    expect(disclosedClaimNames(result.presented)).toEqual([]);
    expect(result.verified.keyBindingVerified).toBe(true);
  });

  it('issuer を省略した発行で汚染値の署名器が呼ばれない', () => {
    const attacker = recordingSigner(createPrivateKeySigner(ATTACKER_PRIVATE_KEY, 'ES256'));
    expect(() =>
      withPollutedPrototype({ issuer: attacker }, () => runInteropTxPair(inputWithout('issuer'))),
    ).toThrow();
    expect(attacker.signed).toEqual([]);
  });

  it('transactionData を省略した提示で汚染値の取引が Holder に署名されない', () => {
    // 汚染値を拾うと Holder が同意していない取引の `transaction_data_hashes` が KB-JWT に載る。
    // 継承値を採らなければ抽出結果が空になり、Transaction Data 付き KB-JWT は組み立てられない。
    const holder = recordingSigner(holderSigner());
    expect(() =>
      withPollutedPrototype({ transactionData: [ATTACKER_TX] }, () =>
        runInteropTxPair(inputWithout('transactionData', { holder })),
      ),
    ).toThrow();
    expect(holder.signed).toEqual([]);
  });

  it('正常系: credential / requestedClaims / issuer を明示した提示は汚染下でも成功する', () => {
    // 受理集合を狭める変更のため、正当な入力が落ちていないことを確認する。
    const attacker = recordingSigner(createPrivateKeySigner(ATTACKER_PRIVATE_KEY, 'ES256'));
    const result = withPollutedPrototype(
      {
        credential: attackerCredential(),
        requestedClaims: ['resident_address'],
        transactionData: [ATTACKER_TX],
        issuer: attacker,
      },
      () => runInteropTxPair(baseInput()),
    );
    expect(result.verified.vct).toBe(VCT);
    expect(result.verified.keyBindingVerified).toBe(true);
    expect(result.extracted.map((e) => e.encoded)).toEqual([CONSENTED_TX]);
    expect(disclosedClaimNames(result.presented)).toEqual(['nickname']);
    expect(attacker.signed).toEqual([]);
  });
});
