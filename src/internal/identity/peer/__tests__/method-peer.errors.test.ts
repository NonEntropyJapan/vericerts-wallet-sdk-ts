/**
 * did:peer の異常系・境界テスト。
 *
 * 形式不正は INVALID_DID（2001）、更新系は METHOD_NOT_SUPPORTED（2002）に正規化されることを
 * 確認する。入力データが例外メッセージに漏れないことも併せて確認する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { MethodPeer, resolveDidPeer } from '../method-peer.js';
import { p256Key } from './numalgo2-keys.fixtures.js';

/** 与えた DID が INVALID_DID で reject されることを検証するヘルパ。 */
function expectInvalidDid(did: string): void {
  try {
    resolveDidPeer(did);
    throw new Error('did not throw');
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    // 入力 DID 文字列がメッセージに漏れていないこと。
    expect((e as VericertsError).message).not.toContain(did);
  }
}

describe('resolveDidPeer 異常系', () => {
  it('did:peer プレフィックス無し', () => {
    expectInvalidDid('did:key:z6MkExample');
  });

  it('未対応 numalgo（1）', () => {
    expectInvalidDid('did:peer:1zabc');
  });

  it('numalgo 0 で鍵が空', () => {
    expectInvalidDid('did:peer:0');
  });

  it('numalgo 0 で multibase 不正（z 始まりでない）', () => {
    expectInvalidDid('did:peer:0Qabc');
  });

  it('numalgo 2 で先頭が . でない', () => {
    expectInvalidDid('did:peer:2Vz6MkExample');
  });

  it('numalgo 2 で未対応 purpose code', () => {
    expectInvalidDid('did:peer:2.Xz6MkExample');
  });

  it('numalgo 2 で V が 1 つも無い（E のみ）', () => {
    // V が無いと verificationMethod が空になり INVALID_DID。
    expectInvalidDid(`did:peer:2.E${p256Key(3)}`);
  });

  it('numalgo 2 で空エレメント', () => {
    expectInvalidDid('did:peer:2.V');
  });

  it('numalgo 4 で区切り : が無い（短縮形のみ）', () => {
    expectInvalidDid('did:peer:4zHashOnly');
  });

  it('numalgo 4 で encodedDocument が空', () => {
    expectInvalidDid('did:peer:4zHash:');
  });
});

describe('MethodPeer ライフサイクル', () => {
  const method = new MethodPeer();

  it('method() は "peer"', () => {
    expect(method.method()).toBe('peer');
  });

  it('update は METHOD_NOT_SUPPORTED', async () => {
    await expect(method.update('did:peer:0zx', {})).rejects.toMatchObject({
      code: ErrorCodes.METHOD_NOT_SUPPORTED,
    });
  });

  it('deactivate は METHOD_NOT_SUPPORTED', async () => {
    await expect(method.deactivate('did:peer:0zx')).rejects.toMatchObject({
      code: ErrorCodes.METHOD_NOT_SUPPORTED,
    });
  });
});
