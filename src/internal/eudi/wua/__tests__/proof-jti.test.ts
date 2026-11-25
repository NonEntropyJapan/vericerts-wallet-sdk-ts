/**
 * `buildWuaProofOfPossession` が呼び出し側指定の `jti` を署名前に検査するテスト。
 *
 * 仕様は `jti` を UUIDv4 必須とし、不適合を `4013 NONCE_MALFORMED` とする。省略時は SDK が UUIDv4 を
 * 生成する。
 */

import { describe, expect, test } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { buildWuaProofOfPossession } from '../proof.js';
import { parseWalletUnitAttestation } from '../wua.js';
import { makeWuaJwt, wscdSigner } from './wua-fixtures.js';

const NOW = 1_712_400_000;
const V4 = '3b241101-e2bb-4255-8caf-4136c566a962';
const WUA = parseWalletUnitAttestation(makeWuaJwt(new Uint8Array(32).fill(3)));

function popWith(jti: unknown): string {
  return buildWuaProofOfPossession(
    WUA,
    { aud: 'https://as.example', nonce: 'c_nonce_123', jti } as { aud: string; nonce: string },
    wscdSigner(),
    NOW,
  );
}

function jtiClaim(jwt: string): unknown {
  const payload = JSON.parse(
    new TextDecoder().decode(base64urlnopad.decode(jwt.split('.')[1] ?? '')),
  );
  return payload.jti;
}

describe('buildWuaProofOfPossession の jti 検査', () => {
  test.each([
    ['空文字', ''],
    ['固定の短い値', 'fixed-jti'],
    ['nil UUID', '00000000-0000-0000-0000-000000000000'],
    ['UUIDv1', 'c232ab00-9414-11ec-b3c8-9f6bdeced846'],
    ['base64url(16B) の 22 文字', 'AbCdEfGhIjKlMnOpQrStUv'],
    ['37 文字', `${V4}0`],
    ['null', null],
    ['数値', 123],
  ])('指定した jti が %s なら 4013 で署名しない', (_label, jti) => {
    try {
      popWith(jti);
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.NONCE_MALFORMED);
    }
  });

  test.each([
    ['正準形', V4],
    ['ハイフンなし', V4.replaceAll('-', '')],
  ])('UUIDv4（%s）は payload.jti にそのまま載る', (_label, jti) => {
    expect(jtiClaim(popWith(jti))).toBe(jti);
  });

  test('省略時は呼び出しごとに異なる UUIDv4 を生成する', () => {
    const a = jtiClaim(popWith(undefined));
    const b = jtiClaim(popWith(undefined));
    expect(a).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(a).not.toBe(b);
  });
});
