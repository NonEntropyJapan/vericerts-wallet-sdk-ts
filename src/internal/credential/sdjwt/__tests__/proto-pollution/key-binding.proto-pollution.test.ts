/**
 * `Object.prototype` 汚染下でも KB-JWT の署名検証が省略されないことの回帰テスト。
 *
 * Key Binding は既定で `cnf.jwk` を使って検証する。
 *
 * 欠陥時の挙動: `opts.verifySignature !== false` はプロトタイプ鎖を辿るため、
 * `Object.prototype.verifySignature = false` の汚染下では **オプションを省略した既定
 * （検証あり）の呼び出しでも署名検証がまるごとスキップされ、`cnf` の鍵で署名されていない
 * KB-JWT が提示部に連結される**。`disclosedClaims` / `iatSeconds` の汚染も、署名対象
 * （sd_hash / iat）を呼び出し側の意図と無関係に変える。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { attachKeyBindingSignature, createKeyBindingTemplate } from '../../key-binding.js';
import { createSdJwt, parseSdJwt } from '../../sdjwt.js';
import {
  AUD,
  IAT,
  ISSUER_JWK,
  ISSUER_SIGNER,
  issue,
  NONCE,
  OTHER_SIGNER,
  SESSION_ALG,
  SESSION_JWK,
  SESSION_SIGNER,
  VCT,
} from '../key-binding.fixtures.js';

/** Session 鍵で署名した正当な KB-JWT テンプレートを作る（オプションは最小限）。 */
function template(sdJwt: string = issue()) {
  return createKeyBindingTemplate(sdJwt, {
    alg: SESSION_ALG,
    nonce: NONCE,
    audience: AUD,
    iatSeconds: IAT,
  });
}

describe('attachKeyBindingSignature: Object.prototype 汚染', () => {
  it('verifySignature の汚染で署名検証がスキップされない', () => {
    const tmpl = template();
    // `cnf` に載っていない鍵（なりすまし）で署名した KB-JWT。
    const forged = OTHER_SIGNER.sign(new TextEncoder().encode(tmpl.signingInput));

    const error = withPollutedPrototype({ verifySignature: false }, () => {
      try {
        // opts を省略 = 既定（検証あり）。汚染値を拾えば検証が消えて連結が成功してしまう。
        attachKeyBindingSignature(tmpl, forged);
        return undefined;
      } catch (e: unknown) {
        return e;
      }
    });
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.HOLDER_BIND_MISMATCH);
  });

  it('正常系: 汚染下でも正当な署名は従来どおり受理される', () => {
    const tmpl = template();
    const signature = SESSION_SIGNER.sign(new TextEncoder().encode(tmpl.signingInput));
    const combined = withPollutedPrototype({ verifySignature: false }, () =>
      attachKeyBindingSignature(tmpl, signature),
    );
    expect(parseSdJwt(combined).keyBinding).toBeDefined();
  });

  it('正常系: verifySignature: false を明示した呼び出しは従来どおり検証を省略する', () => {
    const tmpl = template();
    const forged = OTHER_SIGNER.sign(new TextEncoder().encode(tmpl.signingInput));
    const combined = attachKeyBindingSignature(tmpl, forged, { verifySignature: false });
    expect(parseSdJwt(combined).keyBinding).toBeDefined();
  });
});

describe('createKeyBindingTemplate: Object.prototype 汚染', () => {
  it('disclosedClaims の汚染で提示部が絞り込まれない', () => {
    const sdJwt = issue();
    const all = parseSdJwt(sdJwt).disclosures.length;
    const tmpl = withPollutedPrototype({ disclosedClaims: ['name'] }, () =>
      createKeyBindingTemplate(sdJwt, { alg: SESSION_ALG, nonce: NONCE, audience: AUD }),
    );
    // 汚染値を拾えば 1 件に絞られてしまう（= 署名対象 sd_hash が変わる）。
    expect(parseSdJwt(tmpl.presentation).disclosures.length).toBe(all);
  });

  it('iatSeconds の汚染が KB-JWT の署名対象 iat に載らない', () => {
    const before = Math.floor(Date.now() / 1000);
    const tmpl = withPollutedPrototype({ iatSeconds: 4_000_000_000 }, () =>
      createKeyBindingTemplate(issue(), { alg: SESSION_ALG, nonce: NONCE, audience: AUD }),
    );
    expect(tmpl.payload.iat).toBeGreaterThanOrEqual(before);
    expect(tmpl.payload.iat).toBeLessThan(4_000_000_000);
  });

  it('正常系: disclosedClaims / iatSeconds を明示した呼び出しは従来どおり反映される', () => {
    const tmpl = createKeyBindingTemplate(issue(), {
      alg: SESSION_ALG,
      nonce: NONCE,
      audience: AUD,
      disclosedClaims: ['name'],
      iatSeconds: IAT,
    });
    expect(parseSdJwt(tmpl.presentation).disclosures.length).toBe(1);
    expect(tmpl.payload.iat).toBe(IAT);
  });
});

describe('extractCnfJwk: issuer payload の cnf 汚染', () => {
  /** `cnf` クレームを持たない SD-JWT（Holder バインドを宣言していない VC）。 */
  function issueWithoutCnf(): string {
    return createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      issuer: 'did:example:issuer',
      disclosureClaims: ['name'],
      claims: { name: 'Alice' },
      salts: { name: 'salt-name' },
      nowSeconds: IAT,
    });
  }

  it('cnf を持たない SD-JWT の汚染値が Holder バインド鍵に採用されない', () => {
    const tmpl = createKeyBindingTemplate(issueWithoutCnf(), {
      alg: SESSION_ALG,
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    // 汚染 cnf（Session 公開鍵）を拾えば、この署名で検証が通り KB-JWT が連結されてしまう。
    const signature = SESSION_SIGNER.sign(new TextEncoder().encode(tmpl.signingInput));
    const error = withPollutedPrototype({ cnf: { jwk: SESSION_JWK } }, () => {
      try {
        attachKeyBindingSignature(tmpl, signature);
        return undefined;
      } catch (e: unknown) {
        return e;
      }
    });
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.HOLDER_BIND_MISMATCH);
  });

  it('正常系: cnf を持つ SD-JWT は汚染下でも自身の cnf で検証される', () => {
    const tmpl = createKeyBindingTemplate(issue(), {
      alg: SESSION_ALG,
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    const signature = SESSION_SIGNER.sign(new TextEncoder().encode(tmpl.signingInput));
    // 汚染値（曲線不一致の JWK）を拾えば 3012 になる。自身の cnf が優先されれば従来どおり成功する。
    const combined = withPollutedPrototype({ cnf: { jwk: ISSUER_JWK } }, () =>
      attachKeyBindingSignature(tmpl, signature),
    );
    expect(parseSdJwt(combined).keyBinding).toBeDefined();
  });
});
