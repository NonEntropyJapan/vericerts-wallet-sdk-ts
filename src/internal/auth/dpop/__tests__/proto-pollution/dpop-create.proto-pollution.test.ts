/**
 * DPoP proof 生成の `Object.prototype` 汚染耐性テスト。
 *
 * `options.jti` / `nonce` / `accessToken` / `nowSeconds` をプロトタイプ鎖で読むと、これらを
 * **省略した**正当な生成でも汚染値が **署名済み DPoP proof の claims** に載る。
 *
 * とりわけ `jti` は深刻で、継承値だと生成のたびに同じ値へ固定される。サーバ側の jti ベースの
 * リプレイ検知は「同じ jti を 2 度見たら拒否」で動くため、正規の proof が 2 回目以降すべて
 * リプレイ扱いになる（可用性の破壊）一方、ランダム UUID による一意性という設計上の前提が
 * 失われる。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { createPrivateKeySigner } from '../../../../credential/vc/signer.js';
import { VericertsError } from '../../../../errors.js';
import { createDpopProof } from '../../dpop.js';

const KEY = new Uint8Array(32).fill(7);
const SIGNER = createPrivateKeySigner(KEY, 'ES256');
const HTM = 'POST';
const HTU = 'https://api.example.com/mcp';

/** DPoP proof の claims をデコードする（署名検証はしない）。 */
function claimsOf(proof: string): Record<string, unknown> {
  const segment = proof.split('.')[1] ?? '';
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
}

describe('createDpopProof の Object.prototype 汚染耐性', () => {
  it('継承した jti は採用せず、proof ごとに一意な jti を生成する', () => {
    const [first, second] = withPollutedPrototype({ jti: 'attacker-fixed-jti' }, () => [
      createDpopProof({ htm: HTM, htu: HTU }, SIGNER),
      createDpopProof({ htm: HTM, htu: HTU }, SIGNER),
    ]);
    const a = claimsOf(first ?? '').jti;
    const b = claimsOf(second ?? '').jti;
    expect(a).not.toBe('attacker-fixed-jti');
    expect(b).not.toBe('attacker-fixed-jti');
    // ランダム UUID による一意性が保たれていること。
    expect(a).not.toBe(b);
  });

  it('継承した nonce は署名済み proof に載らない', () => {
    const proof = withPollutedPrototype({ nonce: 'attacker-nonce' }, () =>
      createDpopProof({ htm: HTM, htu: HTU }, SIGNER),
    );
    expect(claimsOf(proof).nonce).toBeUndefined();
  });

  it('継承した accessToken は ath を生やさない', () => {
    const proof = withPollutedPrototype({ accessToken: 'attacker-token' }, () =>
      createDpopProof({ htm: HTM, htu: HTU }, SIGNER),
    );
    expect(claimsOf(proof).ath).toBeUndefined();
  });

  it('継承した nowSeconds は署名済み proof の iat に載らない', () => {
    const attackerIat = 1_000_000;
    const proof = withPollutedPrototype({ nowSeconds: attackerIat }, () =>
      createDpopProof({ htm: HTM, htu: HTU }, SIGNER),
    );
    expect(claimsOf(proof).iat).not.toBe(attackerIat);
  });

  it('明示的に渡したオプションは従来どおり claims に載る（正常系）', () => {
    const proof = createDpopProof(
      {
        htm: HTM,
        htu: HTU,
        jti: '3b241101-e2bb-4255-8caf-4136c566a962',
        nonce: 'nonce-1',
        nowSeconds: 1_767_225_600,
      },
      SIGNER,
    );
    const claims = claimsOf(proof);
    expect(claims.jti).toBe('3b241101-e2bb-4255-8caf-4136c566a962');
    expect(claims.nonce).toBe('nonce-1');
    expect(claims.iat).toBe(1_767_225_600);
    expect(claims.htm).toBe(HTM);
  });
});

describe('createDpopProof の htm / htu 汚染耐性', () => {
  it('継承した htm は採用せず 4080 で拒否する', () => {
    // 鎖読みだと htm を省いた呼び出しが汚染値で通り、攻撃者が選んだメソッドに束縛された
    // proof が**署名済み**で出力される。
    expect(() =>
      withPollutedPrototype({ htm: 'GET' }, () =>
        createDpopProof({ htu: HTU } as unknown as { htm: string; htu: string }, SIGNER),
      ),
    ).toThrow(VericertsError);
  });

  it('継承した htu は採用せず 4080 で拒否する', () => {
    expect(() =>
      withPollutedPrototype({ htu: 'https://attacker.example.com/' }, () =>
        createDpopProof({ htm: HTM } as unknown as { htm: string; htu: string }, SIGNER),
      ),
    ).toThrow(VericertsError);
  });

  it('汚染下でも明示的に渡した htm / htu がそのまま claims に載る（正常系）', () => {
    const proof = withPollutedPrototype({ htm: 'GET', htu: 'https://attacker.example.com/' }, () =>
      createDpopProof({ htm: HTM, htu: HTU }, SIGNER),
    );
    const claims = claimsOf(proof);
    expect(claims.htm).toBe(HTM);
    expect(claims.htu).toBe(HTU);
  });
});
