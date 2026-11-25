/**
 * JWT-VC ヘッダ `alg` の own 限定読み取りの回帰テスト。
 *
 * `verify.ts` の `assertAlg` だけが `header.alg`（プロトタイプ鎖読み）のまま残り、同じ
 * `decodeCompactJwsOrThrow` の出力を扱う `sdjwt/verify.ts` の `assertAlg`と
 * 非対称になっていた。このリポジトリは「パース境界での `null` プロトタイプ化」と
 * 「読み取り時点の own 限定」を**意図的に重畳**させる方針なので、後段だけが欠けた状態は
 * 将来 header の生成経路が変わった時点で `Object.prototype.alg` 汚染を拾う穴になる。
 *
 * ## fail-first をどこで取るか（重要）
 *
 * `verifyCredential` の header は**必ず** `decodeCompactJwsOrThrow` →
 * `identity/jwt/jwt-codec.ts` の `parseJson` → `parse-json.ts` の `parseJsonWithoutPrototype` を
 * 通るため `null` プロトタイプであり、鎖読みでも `Object.prototype.alg` には到達しない。つまり
 * **公開 API 経由では own 読みと鎖読みの差を観測できない**（Issue 本文の「即座には悪用できない」
 * はこの意味）。したがって本ファイルの役割は 2 層に分かれる。
 *
 * - 振る舞いテスト（`describe` 1 つ目）: 汚染下で保たれるべき**契約**を固定する。パース境界が
 *   効いているため是正の前後どちらでも通る（fail-first にはならない）。パース境界が将来
 *   外れた／別経路が生えた場合にここが落ちる。
 * - 構造テスト（`describe` 2 つ目）: own 限定読みが**コードとして**存在することを固定する。
 *   是正前は落ち、是正後に通る。同ディレクトリ系列の
 *   `proto-pollution-shape/vc-member-single-read.toctou.test.ts` が、同じく公開 API から
 *   観測できない多層防御に対して採っている手法に揃える。
 */

import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getP256PublicKey } from '../../../../keymanager/signer.js';
import { issueCredential } from '../../issue.js';
import { createPrivateKeySigner } from '../../signer.js';
import type { VerifiableCredential } from '../../vc.js';
import { verifyCredential } from '../../verify.js';

const b64uText = (text: string): string => Buffer.from(text).toString('base64url');

function toJwk(pub: Uint8Array): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_KEY = new Uint8Array(32).fill(7);
const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false));
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const NOW = Math.floor(Date.parse('2026-01-01T00:00:00Z') / 1000);

const baseOpts = { key: { publicKeyJwk: ISSUER_JWK }, nowSeconds: NOW } as const;

function makeVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:holder' },
    issuanceDate: new Date((NOW - 100) * 1000).toISOString(),
  };
}

/**
 * 任意のヘッダを手組みし、実 issuer 鍵で署名したコンパクト JWS を作る。
 *
 * `assertAlg` は署名検証より**前**に走るため、payload の自己整合は作り込まない（alg 判定で
 * 例外が飛ぶ経路だけを切り分ける）。
 */
function credentialJwtWithRawHeader(header: Record<string, unknown>): string {
  const payload = { iss: 'did:example:issuer', nbf: NOW - 100 };
  const signingInput = `${b64uText(JSON.stringify(header))}.${b64uText(JSON.stringify(payload))}`;
  const sig = ISSUER_SIGNER.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${Buffer.from(sig).toString('base64url')}`;
}

describe('verifyCredential: JWT-VC ヘッダ alg の汚染耐性', () => {
  it('alg を持たないヘッダは Object.prototype.alg の汚染下でも 3010 で閉じる', () => {
    // 汚染値 'none' が「ヘッダに入っていた alg」として採用されると 3011（ALG_NONE）へ分岐する。
    // own 読み（およびパース境界）が効いていれば alg は undefined のままで 3010。
    const jwt = credentialJwtWithRawHeader({ typ: 'JWT' });

    const error = withPollutedPrototype({ alg: 'none' }, () => {
      try {
        verifyCredential(jwt, baseOpts);
        return null;
      } catch (e) {
        return e;
      }
    });

    expect(error).toEqual(new VericertsError(ErrorCodes.SIG_INVALID));
  });

  it('own な alg を持つ正当な JWT-VC は Object.prototype.alg の汚染下でも検証できる', () => {
    // 汚染が「未対応 alg」として先に採用されると、正当な VC が一律 3010 になる（可用性の欠陥）。
    const jwt = issueCredential(makeVc(), ISSUER_SIGNER, { nowSeconds: NOW });

    const result = withPollutedPrototype({ alg: 'HS256' }, () => verifyCredential(jwt, baseOpts));

    expect(result.header.alg).toBe('ES256');
    expect(result.payload.iss).toBe('did:example:issuer');
  });

  it('汚染が無い通常の検証は退行しない（正常系）', () => {
    const jwt = issueCredential(makeVc(), ISSUER_SIGNER, { nowSeconds: NOW });

    const result = verifyCredential(jwt, baseOpts);

    expect(result.header.alg).toBe('ES256');
    expect(result.payload.iss).toBe('did:example:issuer');
  });

  it('ヘッダに own で alg=none を持つ JWT-VC は従来どおり 3011（正常系）', () => {
    const jwt = credentialJwtWithRawHeader({ alg: 'none', typ: 'JWT' });

    expect(() => verifyCredential(jwt, baseOpts)).toThrow(new VericertsError(ErrorCodes.ALG_NONE));
  });
});

describe('assertAlg は own 限定で alg を読む（構造検査）', () => {
  // `assertAlg` は `verify.ts` / `sdjwt/verify.ts` / `presentation-signature.ts` の
  // 重複実装を `vc/jws.ts` の単一実装へ統合した。own 限定読みの構造検査もその SSOT を対象にする。
  /** `credential/vc/jws.ts`（`assertAlg` の実体）のソース。 */
  const source = readFileSync(new URL('../../jws.ts', import.meta.url), 'utf8');

  it('own 限定読みを使う', () => {
    expect(source).toContain("const alg = ownProperty<unknown>(header, 'alg');");
  });

  it('是正前の鎖読み（header.alg）が復活していない', () => {
    // JSDoc / コメント中の `header.alg` への言及は許容し、**コードとしての形**だけを禁止する。
    expect(source).not.toMatch(/const alg = header\.alg/);
  });
});
