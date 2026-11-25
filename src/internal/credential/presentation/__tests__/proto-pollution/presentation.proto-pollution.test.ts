/**
 * `Object.prototype` 汚染下でも VP の Verifier バインド検証が省略されないことの回帰テスト
 *
 * `aud` または `nonce` の不一致は 3012 になる。既定は束縛必須で、
 * `expectedAudience` / `expectedNonce` の未指定（バインド未検証）も拒否する。
 *
 * 欠陥時の挙動:
 * - `opts.allowUnbound !== true` がプロトタイプ鎖を辿るため、`Object.prototype.allowUnbound
 *   = true` の汚染下では **既定（束縛必須）で呼んだ検証が無言で unbound モードへ落ち、
 *   aud / nonce の照合がまるごと省略される**（リプレイ・対象者取り違えを検出できない）。
 * - `payload.aud` / `payload.nonce` は `JSON.parse` 直後の生オブジェクトから読むため、
 *   **`aud` を持たない VP でも汚染値が「payload に入っていた値」として照合に使われる**。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { issuePresentation } from '../../issue.js';
import { verifyPresentation } from '../../presentation.js';
import { FIXTURES, sampleVp, signerFor } from '../presentation.fixtures.js';

const AUDIENCE = 'https://verifier.example';
const NONCE = 'n-abc';
const fx = FIXTURES.ES256;

/**
 * 任意の payload で JWT-VP を組み立てて署名する。
 *
 * `issuePresentation` は `iss` を必ず出力するため、「`iss` クレームを持たない VP」は
 * ここでコンパクト JWS を直接組み立てて作る。
 */
function signJwtVp(payload: Record<string, unknown>): string {
  const b64u = (value: unknown): string =>
    Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
  const signingInput = `${b64u({ alg: 'ES256', typ: 'JWT' })}.${b64u(payload)}`;
  const signature = signerFor('ES256').sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${Buffer.from(signature).toString('base64url')}`;
}

/** 例外を投げずに `VericertsError` を取り出す。 */
function captureError(fn: () => unknown): unknown {
  try {
    fn();
    return undefined;
  } catch (e: unknown) {
    return e;
  }
}

/** 3012（HOLDER_BIND_MISMATCH）であることを表明する。 */
function expectBindMismatch(error: unknown): void {
  expect(error).toBeInstanceOf(VericertsError);
  expect((error as VericertsError).code).toBe(ErrorCodes.HOLDER_BIND_MISMATCH);
}

describe('verifyPresentation: Object.prototype 汚染', () => {
  it('allowUnbound の汚染で束縛検証がスキップされない', () => {
    // aud / nonce を持たない VP を、束縛モード（既定）で検証する。
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'));
    const error = withPollutedPrototype({ allowUnbound: true }, () =>
      // allowUnbound を渡していない = 既定（束縛必須）。汚染値を拾えば無検証で通ってしまう。
      captureError(() => verifyPresentation(jwt, { key: { publicKeyJwk: fx.jwk } })),
    );
    expectBindMismatch(error);
  });

  it('expectedAudience / expectedNonce の汚染がバインド未指定を埋め合わせない', () => {
    // 呼び出し側は期待値を渡していないため、payload と一致していても拒否されねばならない。
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'), {
      audience: AUDIENCE,
      nonce: NONCE,
    });
    const error = withPollutedPrototype({ expectedAudience: AUDIENCE, expectedNonce: NONCE }, () =>
      captureError(() => verifyPresentation(jwt, { key: { publicKeyJwk: fx.jwk } })),
    );
    expectBindMismatch(error);
  });

  it('payload.aud / payload.nonce の汚染が「VP に入っていた値」として照合されない', () => {
    // aud / nonce を持たない VP。汚染値を payload から読むと期待値と一致して通ってしまう。
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'));
    const error = withPollutedPrototype({ aud: AUDIENCE, nonce: NONCE }, () =>
      captureError(() =>
        verifyPresentation(jwt, {
          key: { publicKeyJwk: fx.jwk },
          expectedAudience: AUDIENCE,
          expectedNonce: NONCE,
        }),
      ),
    );
    expectBindMismatch(error);
  });

  it('payload.iss の汚染が holder バインドを成立させない', () => {
    // `iss` クレームを持たない JWT-VP。汚染値を payload から読むと holder と一致して通ってしまう。
    const jwt = signJwtVp({ iat: 1_700_000_000, vp: sampleVp() });
    const error = withPollutedPrototype({ iss: 'did:example:holder' }, () =>
      captureError(() =>
        verifyPresentation(jwt, { key: { publicKeyJwk: fx.jwk }, allowUnbound: true }),
      ),
    );
    expectBindMismatch(error);
  });

  it('正常系: iss を持つ JWT-VP は同じ組み立てで従来どおり検証できる', () => {
    // 直前のテストが「iss 欠落」だけを突いていることを担保する対照ケース。
    const jwt = signJwtVp({ iss: 'did:example:holder', iat: 1_700_000_000, vp: sampleVp() });
    const result = verifyPresentation(jwt, { key: { publicKeyJwk: fx.jwk }, allowUnbound: true });
    expect(result.presentation.holder).toBe('did:example:holder');
  });

  it('正常系: 汚染下でも期待値を明示した束縛検証は従来どおり成功する', () => {
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'), {
      audience: AUDIENCE,
      nonce: NONCE,
    });
    const result = withPollutedPrototype({ allowUnbound: true, aud: 'x', nonce: 'y' }, () =>
      verifyPresentation(jwt, {
        key: { publicKeyJwk: fx.jwk },
        expectedAudience: AUDIENCE,
        expectedNonce: NONCE,
      }),
    );
    expect(result.payload.aud).toBe(AUDIENCE);
    expect(result.payload.nonce).toBe(NONCE);
  });

  it('正常系: allowUnbound: true を明示した検証は従来どおり照合を省略する', () => {
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'));
    const result = verifyPresentation(jwt, { key: { publicKeyJwk: fx.jwk }, allowUnbound: true });
    expect(result.presentation.holder).toBe('did:example:holder');
  });
});

describe('verifyPresentation: key / vp / nowSeconds の汚染', () => {
  it('key.publicKeyJwk の汚染で verify コールバックが無視されない', () => {
    // `{ verify }` だけを渡した正当な呼び出し。`key.publicKeyJwk` を直接読むと汚染 JWK 分岐に入り、
    // **コールバックが `false` を返しても署名が有効と判定される**（署名検証バイパス）。
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'));
    const error = withPollutedPrototype({ publicKeyJwk: fx.jwk }, () =>
      captureError(() =>
        verifyPresentation(jwt, { key: { verify: () => false }, allowUnbound: true }),
      ),
    );
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.SIG_INVALID);
  });

  it('正常系: 汚染下でも verify コールバックの結果がそのまま採用される', () => {
    // 汚染 JWK では検証に失敗する組み合わせ。コールバックが尊重されていれば受理される。
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'));
    const result = withPollutedPrototype({ publicKeyJwk: FIXTURES.ES256K.jwk }, () =>
      verifyPresentation(jwt, { key: { verify: () => true }, allowUnbound: true }),
    );
    expect(result.presentation.holder).toBe('did:example:holder');
  });

  it('payload.vp の汚染が VP として受理されない', () => {
    // `vp` クレームを持たない署名済み JWT。汚染値を拾うと攻撃者制御の VP が返り値になる。
    const jwt = signJwtVp({ iss: 'did:example:holder', iat: 1_700_000_000 });
    const error = withPollutedPrototype(
      { vp: sampleVp({ verifiableCredential: ['attacker-vc'] }) },
      () =>
        captureError(() =>
          verifyPresentation(jwt, { key: { publicKeyJwk: fx.jwk }, allowUnbound: true }),
        ),
    );
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
  });

  it('nowSeconds の汚染で失効済み VP が受理されない', () => {
    // exp を大きく超過した VP。汚染された「現在時刻」を拾うと期限内と判定されて通ってしまう。
    const now = Math.floor(Date.now() / 1000);
    const jwt = signJwtVp({
      iss: 'did:example:holder',
      iat: now - 4000,
      exp: now - 2000,
      vp: sampleVp(),
    });
    const error = withPollutedPrototype({ nowSeconds: now - 3000 }, () =>
      captureError(() =>
        verifyPresentation(jwt, { key: { publicKeyJwk: fx.jwk }, allowUnbound: true }),
      ),
    );
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.VC_EXPIRED);
  });

  it('clockSkewSeconds の汚染が未指定の検証を 4015 で落とさない', () => {
    // 上限（30s）超過の汚染値を拾うと、オプションを渡していない正当な検証が
    // CLOCK_SKEW_OPTION_INVALID で失敗する（可用性の fail-open ならぬ巻き添え拒否）。
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'));
    const result = withPollutedPrototype({ clockSkewSeconds: 999 }, () =>
      verifyPresentation(jwt, { key: { publicKeyJwk: fx.jwk }, allowUnbound: true }),
    );
    expect(result.presentation.holder).toBe('did:example:holder');
  });

  it('正常系: nowSeconds を明示した検証は従来どおりその時刻で評価される', () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = signJwtVp({
      iss: 'did:example:holder',
      iat: now - 4000,
      exp: now - 2000,
      vp: sampleVp(),
    });
    const result = verifyPresentation(jwt, {
      key: { publicKeyJwk: fx.jwk },
      allowUnbound: true,
      nowSeconds: now - 3000,
    });
    expect(result.presentation.holder).toBe('did:example:holder');
  });
});
