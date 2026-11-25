/**
 * `decodeCompactJws` が返す header / payload が入れ子まで `null` プロトタイプであることの
 * 回帰テスト。
 *
 * `verify.ts` / `key-binding.ts` / `claims.ts` / `presentation/vp-claims.ts` の own 限定読みには
 * 「この値は `JSON.parse` した生オブジェクトで、プロトタイプは `Object.prototype`」という根拠が
 * 書かれていたが、実際には `decodeCompactJws` → `identity/jwt/jwt-codec.ts` の `parseJson`
 * → `parse-json.ts` の `parseJsonWithoutPrototype` を通るため **`null` プロトタイプ**である。自身のプロパティだけを読むことで、パース境界に加えて読み取り時にも継承値を除外する。
 *
 * コメントを実態へ是正しただけでは同じ陳腐化が再発するため、その実態をテストで固定する。
 * ここが `Object.prototype` へ戻る変更（パース境界を通らない経路の追加など）が入れば落ちる。
 *
 * 親ディレクトリ `sdjwt/__tests__/` は Linterly のディレクトリ行数上限（2000 行）を既に超過している
 * ため、本ファイルはサブディレクトリに置く。
 */

import { describe, expect, it } from 'bun:test';
import { decodeCompactJws } from '../../../vc/jws.js';
import { createPrivateKeySigner } from '../../../vc/signer.js';

const ISSUER_KEY = new Uint8Array(32).fill(7);
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');

const b64uText = (text: string): string => Buffer.from(text).toString('base64url');

/** 任意の header / payload を実鍵で署名したコンパクト JWS にする。 */
function signCompactJws(header: Record<string, unknown>, payload: Record<string, unknown>): string {
  const signingInput = `${b64uText(JSON.stringify(header))}.${b64uText(JSON.stringify(payload))}`;
  const sig = ISSUER_SIGNER.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${Buffer.from(sig).toString('base64url')}`;
}

describe('decodeCompactJws の戻り値は入れ子まで null プロトタイプ', () => {
  it('header / payload のプロトタイプは null である', () => {
    const jws = signCompactJws(
      { alg: 'ES256', typ: 'dc+sd-jwt' },
      { iss: 'did:example:issuer', vct: 'https://example.com/vct' },
    );

    const decoded = decodeCompactJws(jws);

    expect(Object.getPrototypeOf(decoded.header)).toBe(null);
    expect(Object.getPrototypeOf(decoded.payload)).toBe(null);
  });

  it('入れ子のオブジェクト（cnf / cnf.jwk / status.status_list）も null プロトタイプである', () => {
    const jwk = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' };
    const jws = signCompactJws(
      { alg: 'ES256', typ: 'dc+sd-jwt' },
      {
        iss: 'did:example:issuer',
        cnf: { jwk },
        status: { status_list: { idx: 3, uri: 'https://example.com/sl' } },
      },
    );

    const payload = decodeCompactJws(jws).payload as Record<string, unknown>;
    const cnf = payload.cnf as Record<string, unknown>;
    const status = payload.status as Record<string, unknown>;

    expect(Object.getPrototypeOf(cnf)).toBe(null);
    expect(Object.getPrototypeOf(cnf.jwk as object)).toBe(null);
    expect(Object.getPrototypeOf(status.status_list as object)).toBe(null);
  });

  it('配列は配列のまま保たれ、要素のオブジェクトは null プロトタイプになる', () => {
    const jws = signCompactJws(
      { alg: 'ES256', typ: 'dc+sd-jwt' },
      { iss: 'did:example:issuer', _sd: ['digest-1'], evidence: [{ type: 'DocumentCheck' }] },
    );

    const payload = decodeCompactJws(jws).payload as Record<string, unknown>;

    expect(Array.isArray(payload._sd)).toBe(true);
    const evidence = payload.evidence as readonly object[];
    expect(Array.isArray(evidence)).toBe(true);
    expect(Object.getPrototypeOf(evidence[0] as object)).toBe(null);
  });

  it('null プロトタイプなのでデコード結果にアクセサは存在しえない（2 度読みが安全）', () => {
    const jws = signCompactJws(
      { alg: 'ES256', typ: 'dc+sd-jwt' },
      { iss: 'did:example:issuer', cnf: { jwk: { kty: 'EC' } } },
    );

    const payload = decodeCompactJws(jws).payload as Record<string, unknown>;

    for (const key of Reflect.ownKeys(payload)) {
      const descriptor = Object.getOwnPropertyDescriptor(payload, key);
      expect(descriptor).toBeDefined();
      expect('value' in (descriptor as PropertyDescriptor)).toBe(true);
    }
  });
});
