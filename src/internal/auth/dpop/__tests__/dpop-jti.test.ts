/**
 * `createDpopProof` が呼び出し側指定の `jti` を署名前に検査するテスト
 * （実鍵・モック禁止）。
 *
 * 仕様は `jti` を UUIDv4 必須とし、不適合を `4013 NONCE_MALFORMED` とする。拒否は署名より前に起きる
 * （不適合な `jti` を載せた proof が一切出力されない）ことと、適合値は検証器まで通ることを固定する。
 */

import { describe, expect, it } from 'bun:test';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { createDpopProof } from '../dpop.js';
import { verifyDpopProof } from '../dpop-verify.js';

const SIGNER = createPrivateKeySigner(new Uint8Array(32).fill(7), 'ES256');
const HTM = 'POST';
const HTU = 'https://api.example.com/mcp';
const NOW = 1_767_225_600;
const V4 = '3b241101-e2bb-4255-8caf-4136c566a962';

function codeOf(run: () => unknown): string | undefined {
  try {
    run();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    return (e as VericertsError).code;
  }
  return undefined;
}

describe('createDpopProof の jti 検査', () => {
  it.each([
    ['空文字', ''],
    ['固定の短い値', 'jti-1'],
    ['nil UUID', '00000000-0000-0000-0000-000000000000'],
    ['UUIDv1', 'c232ab00-9414-11ec-b3c8-9f6bdeced846'],
    ['base64url(16B) の 22 文字', 'AbCdEfGhIjKlMnOpQrStUv'],
    ['37 文字', `${V4}0`],
  ])('指定した jti が %s なら 4013 で署名しない', (_label, jti) => {
    expect(
      codeOf(() => createDpopProof({ htm: HTM, htu: HTU, jti, nowSeconds: NOW }, SIGNER)),
    ).toBe(ErrorCodes.NONCE_MALFORMED);
  });

  it('文字列以外の jti も 4013 で拒否する', () => {
    const bad = { htm: HTM, htu: HTU, jti: 123, nowSeconds: NOW } as unknown as {
      htm: string;
      htu: string;
    };
    expect(codeOf(() => createDpopProof(bad, SIGNER))).toBe(ErrorCodes.NONCE_MALFORMED);
  });

  it.each([
    ['正準形', V4],
    ['ハイフンなし', V4.replaceAll('-', '')],
  ])('UUIDv4（%s）は payload.jti にそのまま載り、検証を通る', (_label, jti) => {
    const proof = createDpopProof({ htm: HTM, htu: HTU, jti, nowSeconds: NOW }, SIGNER);
    expect(verifyDpopProof(proof, { htm: HTM, htu: HTU, nowSeconds: NOW }).jti).toBe(jti);
  });

  it('jti を明示的に undefined で渡したときは省略と同じく UUIDv4 を生成する', () => {
    const proof = createDpopProof({ htm: HTM, htu: HTU, jti: undefined, nowSeconds: NOW }, SIGNER);
    const { jti } = verifyDpopProof(proof, { htm: HTM, htu: HTU, nowSeconds: NOW });
    expect(jti).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });
});
