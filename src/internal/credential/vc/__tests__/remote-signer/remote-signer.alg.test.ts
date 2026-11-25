/**
 * `createRemoteSigner` の未対応 alg 拒否のテスト（実鍵・モック禁止）。
 *
 * 正常系は `remote-signer.test.ts`（ECDSA）/ `remote-signer.eddsa.test.ts`（EdDSA）が担当し、
 * 本ファイルは「対応表に無い alg を構築時点で `UNSUPPORTED_ALGORITHM`（1030）として弾く」
 * 契約だけを固定する。
 *
 * 検証内容:
 * - 未対応 alg（`RS256` / `HS256` / `none`）は 1030。
 * - `Object.prototype` 由来の alg（`constructor` / `toString` / `valueOf` / `hasOwnProperty`）も 1030。
 *   回帰: `ALG_CURVES` が通常のオブジェクトリテラルだとこれらがプロトタイプにヒットし、
 *   `curve === undefined` のガードをすり抜けて signer が返っていた（検証不能な VC を発行し得る）。
 * - 文字列でない alg も 1030。回帰: 添字アクセス `ALG_CURVES[alg]` は `toString()` で暗黙変換
 *   するため、`toString` が対応 alg を返すオブジェクトはガードを通過し、そのまま signer の
 *   `alg` に載って JWS ヘッダ生成時に `JSON.stringify`（`toJSON`）で別の値へ化けられた。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { createRemoteSigner } from '../../../../keymanager/jws/remote-signer.js';
import type { CredentialAlg } from '../../jws.js';

/** 構築時に弾かれるため中身は評価されない、形だけの EC 公開鍵 JWK。 */
const DUMMY_JWK: PublicKeyJwk = { kty: 'EC', crv: 'P-256', x: 'AAAA', y: 'BBBB' };

/** 構築時に弾かれるため呼ばれてはならない署名関数。 */
function neverSign(): Uint8Array {
  throw new Error('sign must not be called for an unsupported alg');
}

describe('createRemoteSigner の未対応 alg 拒否', () => {
  it.each([
    'RS256',
    'HS256',
    'none',
    'constructor',
    'toString',
    'valueOf',
    'hasOwnProperty',
  ])('未対応 alg（%s）は UNSUPPORTED_ALGORITHM（1030）', (alg) => {
    expect(() =>
      createRemoteSigner({
        alg: alg as CredentialAlg,
        publicKeyJwk: DUMMY_JWK,
        sign: neverSign,
      }),
    ).toThrow(new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM));
  });
});

describe('createRemoteSigner の非文字列 alg 拒否', () => {
  it.each([
    ['toString が対応 alg を返すオブジェクト', { toString: (): string => 'ES256' }],
    [
      'toString と toJSON が食い違うオブジェクト',
      { toString: (): string => 'ES256', toJSON: (): string => 'EdDSA' },
    ],
    ['Number', 256],
    ['null', null],
    ['Symbol', Symbol('ES256')],
  ])('非文字列 alg（%s）は UNSUPPORTED_ALGORITHM（1030）', (_name, alg) => {
    expect(() =>
      createRemoteSigner({
        alg: alg as unknown as CredentialAlg,
        publicKeyJwk: DUMMY_JWK,
        sign: neverSign,
      }),
    ).toThrow(new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM));
  });

  it('alg が toString / toJSON で食い違っても JWS ヘッダへ載る前に弾かれる', () => {
    // 弾かれずに signer が返ると、照合は ES256・ヘッダは EdDSA という不整合な JWS を生む。
    let toJsonCalls = 0;
    const alg = {
      toString: (): string => 'ES256',
      toJSON: (): string => {
        toJsonCalls += 1;
        return 'EdDSA';
      },
    };
    expect(() =>
      createRemoteSigner({
        alg: alg as unknown as CredentialAlg,
        publicKeyJwk: DUMMY_JWK,
        sign: neverSign,
      }),
    ).toThrow(new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM));
    expect(toJsonCalls).toBe(0);
  });
});
