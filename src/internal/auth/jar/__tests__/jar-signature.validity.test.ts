/**
 * `verifyJarSignature` の Request Object 型・有効期間検査の回帰テスト。
 *
 * 従来、JAR 経路は `exp` / `nbf` / `typ` を一切見ていなかった。そのため
 * (a) 一度発行された Request Object は無期限に有効で、取得結果・ログに残ったディープリンク・
 * 共有端末から入手した攻撃者がいつでも提示フローを再駆動でき、(b) RP が同じ Access Certificate
 * 鍵で署名した任意の JWS が Request Object として構造上受理され得た（型混同）。
 * 本ファイルはその 2 つの穴が塞がったことを固定する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import { verifyJarSignature } from '../jar-signature.js';
import { jarClaims, makeJarSigner, signJar } from './jar-fixtures.js';

const VERIFIER = makeJarSigner();
const TRUST = { trustAnchors: VERIFIER.anchors } as const;
const NOW = Math.floor(Date.now() / 1000);

async function expectReason(promise: Promise<unknown>, reason: string): Promise<void> {
  try {
    await promise;
    throw new Error('should have thrown');
  } catch (err) {
    const error = err as VericertsError;
    expect(error.code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    expect(error.context).toMatchObject({ reason });
  }
}

describe('verifyJarSignature: Request Object の有効期間', () => {
  it('`exp` が過去の Request Object を拒否する（署名済み要求の無期限再利用を止める）', async () => {
    // スキュー（30s）を超えて過去。署名そのものは正当なので、時刻検査が無ければ通っていた。
    const jar = signJar(VERIFIER, { claims: jarClaims({ exp: NOW - 3600 }) });
    await expectReason(verifyJarSignature(jar, TRUST), 'jar_request_expired');
  });

  it('`exp` を持たない Request Object を拒否する（期限なし = 常に有効と読み替えない）', async () => {
    const claims = jarClaims();
    delete claims.exp;
    await expectReason(
      verifyJarSignature(signJar(VERIFIER, { claims }), TRUST),
      'jar_request_expired',
    );
  });

  it('`nbf` が未来の Request Object を拒否する', async () => {
    const jar = signJar(VERIFIER, { claims: jarClaims({ nbf: NOW + 3600 }) });
    await expectReason(verifyJarSignature(jar, TRUST), 'jar_request_expired');
  });

  it('`exp` が非数値の Request Object を拒否する（型不正を「期限なし」に倒さない）', async () => {
    const jar = signJar(VERIFIER, { claims: jarClaims({ exp: `${NOW + 300}` }) });
    await expectReason(verifyJarSignature(jar, TRUST), 'jar_request_expired');
  });

  it('`now` オプションを検証基準時刻として使う（期限切れ要求を過去時刻で再現できる）', async () => {
    const jar = signJar(VERIFIER, { claims: jarClaims({ exp: NOW + 300 }) });
    await expectReason(
      verifyJarSignature(jar, { ...TRUST, now: NOW + 3600 }),
      'jar_request_expired',
    );
    await expect(verifyJarSignature(jar, { ...TRUST, now: NOW })).resolves.toBeUndefined();
  });
});

describe('verifyJarSignature: Request Object の型', () => {
  it('`typ` が `oauth-authz-req+jwt` 以外の JWS を拒否する（型混同）', async () => {
    // RP の Access Certificate 鍵で署名された「Request Object ではない」JWS。
    const jar = signJar(VERIFIER, { header: { typ: 'dpop+jwt' } });
    await expectReason(verifyJarSignature(jar, TRUST), 'jar_typ_mismatch');
  });

  it('`typ` を持たない JWS を拒否する（型を名乗らない JWS は他用途と区別できない）', async () => {
    const jar = signJar(VERIFIER, { header: { typ: undefined } });
    await expectReason(verifyJarSignature(jar, TRUST), 'jar_typ_mismatch');
  });

  it('RFC 9101 §10.8 の互換値 `JWT` は受理する', async () => {
    const jar = signJar(VERIFIER, { header: { typ: 'JWT' } });
    await expect(verifyJarSignature(jar, TRUST)).resolves.toBeUndefined();
  });
});
