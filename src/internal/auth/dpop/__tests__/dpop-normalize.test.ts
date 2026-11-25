/**
 * `htu` 正規化（`normalizeHtu`）の境界値・回帰テスト（実鍵・モック禁止）。
 *
 * 検証内容（RFC 9449 §4.2 / §4.3 step 9、RFC 9110 §4.2.4 / §7.1）:
 * - userinfo（`user:pass@`）が除去される（MAJOR 回帰）。除去しないと、userinfo の有無だけで
 *   正規の proof が束縛不一致（4083）になり、さらに `VerifiedDpopProof.htu` 経由で資格情報が
 *   呼び出し側のログへ伝播する。
 * - `user@host` 形式のホスト偽装表記が、userinfo 除去後も**実ホスト**へ正規化される
 *   （`https://evil.example.com@api.example.com/` のホストは `api.example.com`）。
 * - 既存の正規化（クエリ・フラグメント除去、既定ポート省略、スキーム / ホストの小文字化）が
 *   維持される。
 * - 過剰正規化していないこと: ホスト・パス・ポートが異なる `htu` は依然として不一致になる。
 *
 * `verifyDpopProof` の他の検証段階は `dpop-verify.test.ts` / `dpop-verify-jwk.test.ts` が担う。
 */

import { describe, expect, it } from 'bun:test';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { createDpopProof } from '../dpop.js';
import { normalizeHtu } from '../dpop-common.js';
import { verifyDpopProof } from '../dpop-verify.js';

/** テスト用の固定秘密鍵。 */
const PRIVATE_KEY = new Uint8Array(32).fill(7);

/** 固定現在時刻（エポック秒）。 */
const NOW = 1_767_225_600;

const HTM = 'POST';

/** userinfo を含まない正規形。 */
const HTU = 'https://api.example.com/mcp';

const signer = createPrivateKeySigner(PRIVATE_KEY, 'ES256');

/** base64url セグメントを JSON object にデコードする。 */
function decodeSeg(seg: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(seg, 'base64url').toString('utf8'));
}

/** proof の payload を取り出す。 */
function payloadOf(proof: string): Record<string, unknown> {
  return decodeSeg(proof.split('.')[1] as string);
}

describe('normalizeHtu が userinfo を除去する（RFC 9110 §4.2.4）', () => {
  it.each([
    ['user と password', 'https://user:pass@api.example.com/mcp'],
    ['user のみ', 'https://user@api.example.com/mcp'],
    ['password のみ', 'https://:pass@api.example.com/mcp'],
    ['userinfo にホスト風の文字列', 'https://evil.example.com@api.example.com/mcp'],
    ['userinfo + クエリ + フラグメント', 'https://user:pass@api.example.com/mcp?q=1#frag'],
    ['userinfo + 既定ポート', 'https://user:pass@api.example.com:443/mcp'],
  ])('%s を含む htu が userinfo なしの正規形になる', (_label, uri) => {
    expect(normalizeHtu(uri)).toBe(HTU);
  });

  it('正規化結果に資格情報の痕跡（@ / パスワード）が残らない', () => {
    const normalized = normalizeHtu('https://user:s3cret@api.example.com/mcp') as string;
    expect(normalized).not.toContain('@');
    expect(normalized).not.toContain('s3cret');
    expect(normalized).not.toContain('user');
  });
});

describe('normalizeHtu の既存正規化が維持される', () => {
  it.each([
    ['クエリ・フラグメント除去', 'https://api.example.com/mcp?x=1#f', HTU],
    ['既定ポート省略', 'https://api.example.com:443/mcp', HTU],
    ['スキーム / ホストの小文字化', 'HTTPS://API.Example.COM/mcp', HTU],
  ])('%s', (_label, uri, expected) => {
    expect(normalizeHtu(uri)).toBe(expected);
  });

  it('パース不能な htu は undefined（例外は投げない）', () => {
    expect(normalizeHtu('not a uri')).toBeUndefined();
  });

  it.each([
    ['ホストが異なる', 'https://user:pass@evil.example.com/mcp'],
    ['パスが異なる', 'https://user:pass@api.example.com/other'],
    ['非既定ポート', 'https://user:pass@api.example.com:8443/mcp'],
  ])('%s 場合は userinfo 除去後も正規形と一致しない', (_label, uri) => {
    expect(normalizeHtu(uri)).not.toBe(HTU);
  });
});

describe('createDpopProof は htu の userinfo を proof に載せない', () => {
  it('payload.htu から userinfo が除去される', () => {
    const proof = createDpopProof(
      { htm: HTM, htu: 'https://user:s3cret@api.example.com/mcp', nowSeconds: NOW },
      signer,
    );
    const htu = payloadOf(proof).htu as string;
    expect(htu).toBe(HTU);
    expect(htu).not.toContain('s3cret');
  });
});

describe('verifyDpopProof の htu 束縛は userinfo の有無に影響されない', () => {
  const options = { htm: HTM, htu: HTU, nowSeconds: NOW } as const;

  it('proof 側の htu に userinfo があっても検証を通り、返る htu は正規形', () => {
    const proof = createDpopProof(
      {
        htm: HTM,
        htu: 'https://user:s3cret@api.example.com/mcp',
        jti: '3b241101-e2bb-4255-8caf-4136c566a962',
        nowSeconds: NOW,
      },
      signer,
    );
    const verified = verifyDpopProof(proof, options);
    expect(verified.htu).toBe(HTU);
    expect(verified.htu).not.toContain('s3cret');
  });

  it('期待値側の htu に userinfo があっても検証を通る', () => {
    const proof = createDpopProof(
      { htm: HTM, htu: HTU, jti: '3b241101-e2bb-4255-8caf-4136c566a962', nowSeconds: NOW },
      signer,
    );
    const verified = verifyDpopProof(proof, {
      ...options,
      htu: 'https://user:pass@api.example.com/mcp',
    });
    expect(verified.htu).toBe(HTU);
  });

  it('userinfo を除いたホストが異なる場合は 4083（過剰正規化していない）', () => {
    const proof = createDpopProof(
      {
        htm: HTM,
        htu: 'https://api.example.com@evil.example.com/mcp',
        jti: '3b241101-e2bb-4255-8caf-4136c566a962',
        nowSeconds: NOW,
      },
      signer,
    );
    try {
      verifyDpopProof(proof, options);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.DPOP_HTTP_BINDING_MISMATCH);
    }
  });
});
