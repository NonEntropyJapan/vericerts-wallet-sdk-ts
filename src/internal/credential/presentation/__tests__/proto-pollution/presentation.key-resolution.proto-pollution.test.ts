/**
 * `verifyPresentation` の検証鍵・`alg` 解決が `Object.prototype` 汚染に影響されないことの
 * 回帰テスト。
 *
 * `opts.key.publicKeyJwk` は自身のプロパティだけを読む。`verify` にはプロトタイプメソッドも使える。署名を検証できなければ 3010 となる。
 *
 * ここで担保する 3 点:
 * - 鍵素材 `publicKeyJwk` は own 限定のまま（署名検証バイパスを塞いだ状態を維持する）だが、
 *   `verify` を**プロトタイプメソッド**として持つクラスインスタンス鍵（KMS / HSM ラッパ）は
 *   正当な入力として受理される。own 限定にすると全 VP が無言で 3010 に落ちる。
 * - `header.alg` を直接読むと、`alg` を持たないヘッダの JWT-VP が `Object.prototype.alg` の
 *   汚染値で検証を通過する（本来 3010 で fail-close）。
 * - 必須の `opts.key` を渡し忘れた呼び出しは、修正前は TypeError（fail-close）だったが、
 *   `Object.prototype.key` 汚染下では攻撃者が選んだ鍵での署名検証に変わる。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { issuePresentation } from '../../issue.js';
import { type PresentationVerifierKey, verifyPresentation } from '../../presentation.js';
import { FIXTURES, sampleVp, signerFor } from '../presentation.fixtures.js';

const fx = FIXTURES.ES256;

/** `verify` を**プロトタイプメソッド**として持つ鍵（KMS / HSM をクラスでラップした統合の縮図）。 */
class KmsVerifierKey {
  constructor(private readonly result: boolean) {}

  verify(_digest: Uint8Array, _signature: Uint8Array, _signingInput: Uint8Array): boolean {
    return this.result;
  }
}

/** 任意のヘッダ・payload で JWT-VP を組み立てて実署名する。 */
function signJwtVp(header: Record<string, unknown>, payload: Record<string, unknown>): string {
  const b64u = (value: unknown): string =>
    Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
  const signingInput = `${b64u(header)}.${b64u(payload)}`;
  const signature = signerFor('ES256').sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${Buffer.from(signature).toString('base64url')}`;
}

/** 例外を投げずに送出値を取り出す。 */
function captureError(fn: () => unknown): unknown {
  try {
    fn();
    return undefined;
  } catch (e: unknown) {
    return e;
  }
}

/** 3010（SIG_INVALID）であることを表明する。 */
function expectSigInvalid(error: unknown): void {
  expect(error).toBeInstanceOf(VericertsError);
  expect((error as VericertsError).code).toBe(ErrorCodes.SIG_INVALID);
}

describe('verifyPresentation: プロトタイプメソッドの verify 鍵（指摘 2）', () => {
  it('正常系: 汚染下でもクラスインスタンス鍵の verify が受理される', () => {
    // `verify` は own プロパティではなく `KmsVerifierKey.prototype` 上にある。own 限定にすると
    // この正当な鍵が一律 3010 になる。汚染 JWK（別曲線）は無視され、コールバックが採用される。
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'));
    const key = new KmsVerifierKey(true) as unknown as PresentationVerifierKey;
    const result = withPollutedPrototype({ publicKeyJwk: FIXTURES.ES256K.jwk }, () =>
      verifyPresentation(jwt, { key, allowUnbound: true }),
    );
    expect(result.presentation.holder).toBe('did:example:holder');
  });

  it('正常系: 汚染のない環境でもクラスインスタンス鍵の verify が受理される', () => {
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'));
    const key = new KmsVerifierKey(true) as unknown as PresentationVerifierKey;
    const result = verifyPresentation(jwt, { key, allowUnbound: true });
    expect(result.presentation.holder).toBe('did:example:holder');
  });

  it('クラスインスタンス鍵が false を返せば 3010 になる（結果が本当に参照されている）', () => {
    // 直前の 2 件が「常に受理」ではなくコールバックの戻り値を見ていることの対照ケース。
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'));
    const key = new KmsVerifierKey(false) as unknown as PresentationVerifierKey;
    expectSigInvalid(captureError(() => verifyPresentation(jwt, { key, allowUnbound: true })));
  });

  it('Object.prototype.verify の汚染は検証関数として採用されない', () => {
    // `publicKeyJwk` も `verify` も持たない不正な `key`。汚染関数を拾えば任意の VP が受理される。
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'));
    const key = {} as unknown as PresentationVerifierKey;
    const error = withPollutedPrototype({ verify: () => true }, () =>
      captureError(() => verifyPresentation(jwt, { key, allowUnbound: true })),
    );
    expectSigInvalid(error);
  });
});

describe('verifyPresentation: header.alg の汚染（指摘 5）', () => {
  it('alg を持たないヘッダの JWT-VP が汚染値で検証を通過しない', () => {
    // 署名自体は ES256 で正当。`header.alg` を直接読むと汚染値 'ES256' が採用され受理される。
    const jwt = signJwtVp(
      { typ: 'JWT' },
      { iss: 'did:example:holder', iat: 1_700_000_000, vp: sampleVp() },
    );
    const error = withPollutedPrototype({ alg: 'ES256' }, () =>
      captureError(() =>
        verifyPresentation(jwt, { key: { publicKeyJwk: fx.jwk }, allowUnbound: true }),
      ),
    );
    expectSigInvalid(error);
  });

  it('正常系: alg を持つ同じ組み立ての JWT-VP は従来どおり検証できる', () => {
    // 直前のテストが「alg 欠落」だけを突いていることを担保する対照ケース。
    const jwt = signJwtVp(
      { alg: 'ES256', typ: 'JWT' },
      { iss: 'did:example:holder', iat: 1_700_000_000, vp: sampleVp() },
    );
    const result = verifyPresentation(jwt, {
      key: { publicKeyJwk: fx.jwk },
      allowUnbound: true,
    });
    expect(result.presentation.holder).toBe('did:example:holder');
  });
});

describe('verifyPresentation: opts.key の汚染（指摘 6）', () => {
  it('key を渡し忘れた呼び出しが汚染鍵で署名検証されない', () => {
    // 型の無い JS からの呼び出しで `key` が欠落したケース。`opts.key` を直接読むと
    // `Object.prototype.key` の汚染鍵で署名検証が成立してしまう。
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'));
    const opts = { allowUnbound: true } as unknown as Parameters<typeof verifyPresentation>[1];
    const error = withPollutedPrototype({ key: { publicKeyJwk: fx.jwk } }, () =>
      captureError(() => verifyPresentation(jwt, opts)),
    );
    expectSigInvalid(error);
  });

  it('opts は渡したが key を欠く呼び出しは 3010', () => {
    const opts = {} as unknown as Parameters<typeof verifyPresentation>[1];
    expectSigInvalid(captureError(() => verifyPresentation('a.b.c', opts)));
  });

  it('opts ごと省略した呼び出しは TypeError のまま', () => {
    // 3010 へ正規化されるのは「`opts` を渡したが `key` を欠く」呼び出しに限る。`opts` 自体は
    // 実装上の必須引数であり、省略した呼び出しは TypeError で fail-close する。
    const error = captureError(() =>
      (verifyPresentation as unknown as (jwt: string) => unknown)('a.b.c'),
    );
    expect(error).toBeInstanceOf(TypeError);
  });

  it('key に非オブジェクトを渡した呼び出しは 3010 に正規化される', () => {
    const jwt = issuePresentation(sampleVp(), signerFor('ES256'));
    const opts = { key: 'not-a-key', allowUnbound: true } as unknown as Parameters<
      typeof verifyPresentation
    >[1];
    expectSigInvalid(captureError(() => verifyPresentation(jwt, opts)));
  });
});
