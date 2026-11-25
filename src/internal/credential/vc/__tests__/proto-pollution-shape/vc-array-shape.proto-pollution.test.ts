/**
 * `assertVerifiableCredential` が**配列**および**継承値**を構造検証で素通りさせないことの
 * 回帰テスト（`assertVerifiablePresentation` 側の兄弟）。
 *
 * 是正前の欠陥:
 * - `typeof value !== 'object'` でしかゲートしておらず、`typeof [] === 'object'` のため
 *   **配列を受理**していた。`parse-json.ts` の reviver は配列を素通しするので、配列は
 *   `Array.prototype` → `Object.prototype` を保持したまま構造検証へ進む。
 * - 5 つの構造検査（`@context` / `type` / `issuer` / `issuanceDate` / `credentialSubject`）は
 *   すべて**鎖読み**だったため、`Object.prototype` 汚染だけで全部満たせた。
 *
 * 成立していた fail-open: `assertVerifiableCredential([])` が `[]` を「構造検証済み VC」として
 * 返し、`issuer` / `credentialSubject` が丸ごと `Object.prototype` 由来になる。署名経路からも
 * 到達し、payload が `{"iss":"<発行者 DID>","vc":[]}` の**署名済み** JWT-VC が
 * `verify.ts` の `assertEnvelopeBinding` 経由で同型に到達した。
 *
 * 是正は `assertVerifiablePresentation` と同じ形（配列を fail-closed で弾く + 全メンバを
 * `ownProperty` で own 限定に読む）。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getP256PublicKey } from '../../../../keymanager/signer.js';
import {
  assertVerifiableCredential,
  parseVerifiableCredential,
} from '../../../presentation/vc-assert.js';
import { createPrivateKeySigner } from '../../signer.js';
import { verifyCredential } from '../../verify.js';

/** テスト用の固定秘密鍵（ES256 / P-256）。 */
const P256_KEY = new Uint8Array(32).fill(7);
/** テスト用の固定現在時刻。 */
const NOW = 1_767_225_600;
/** 発行者 DID。 */
const ISSUER = 'did:example:issuer';
/** 発行日時 ISO（NOW より十分前）。 */
const ISSUANCE = '2025-12-01T00:00:00Z';

const SCHEMA_INVALID = ErrorCodes.VC_SCHEMA_INVALID;

/** VC の 5 つの構造メンバを `Object.prototype` へ仕込む汚染セット。 */
const VC_SHAPE_POLLUTION = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: ISSUER,
  issuanceDate: ISSUANCE,
  credentialSubject: { id: 'did:example:attacker', role: 'admin' },
} as const;

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array): PublicKeyJwk {
  const enc = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: enc(pub.subarray(1, 33)), y: enc(pub.subarray(33, 65)) };
}

const jwk = toJwk(getP256PublicKey(P256_KEY, false));
const signer = createPrivateKeySigner(P256_KEY, 'ES256');

/** 任意の payload を ES256 で署名してコンパクト JWS を組み立てる。 */
function signPayload(payload: Record<string, unknown>): string {
  const b64u = (text: string): string => base64urlnopad.encode(new TextEncoder().encode(text));
  const signingInput = `${b64u(JSON.stringify({ alg: 'ES256', typ: 'JWT' }))}.${b64u(JSON.stringify(payload))}`;
  const signature = signer.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${base64urlnopad.encode(signature)}`;
}

/** 送出された `VericertsError` のコードを取り出す（送出が無ければ `undefined`）。 */
function codeOf(fn: () => unknown): unknown {
  try {
    fn();
    return undefined;
  } catch (e: unknown) {
    return e instanceof VericertsError ? e.code : e;
  }
}

describe('配列の VC は構造検証を素通りしない', () => {
  it('汚染下の assertVerifiableCredential([]) は 3002 で拒否される', () => {
    const code = withPollutedPrototype(VC_SHAPE_POLLUTION, () =>
      codeOf(() => assertVerifiableCredential([])),
    );

    expect(code).toBe(SCHEMA_INVALID);
  });

  it('汚染由来の issuer / credentialSubject を持つ「検証済み VC」が返らない', () => {
    const result = withPollutedPrototype(VC_SHAPE_POLLUTION, () => {
      try {
        return assertVerifiableCredential([]);
      } catch {
        return undefined;
      }
    });

    // 是正前はここで `[]` が返り、`issuer` / `credentialSubject` が丸ごと汚染由来だった。
    expect(result).toBeUndefined();
  });

  it('公開 API parseVerifiableCredential も配列を受理しない', () => {
    const code = withPollutedPrototype(VC_SHAPE_POLLUTION, () =>
      codeOf(() => parseVerifiableCredential('[]')),
    );

    expect(code).toBe(SCHEMA_INVALID);
  });

  it('署名経路: vc が配列の署名済み JWT-VC は汚染下でも 3002 で拒否される', () => {
    const jwt = signPayload({ iss: ISSUER, vc: [] });

    const code = withPollutedPrototype(VC_SHAPE_POLLUTION, () =>
      codeOf(() => verifyCredential(jwt, { key: { publicKeyJwk: jwk }, nowSeconds: NOW })),
    );

    expect(code).toBe(SCHEMA_INVALID);
  });

  it('対照: 汚染なしでも配列の VC は 3002（配列は VC ではない）', () => {
    expect(codeOf(() => assertVerifiableCredential([]))).toBe(SCHEMA_INVALID);
  });
});

describe('VC の構造メンバは own 限定で読む（継承値で満たせない）', () => {
  it('空オブジェクトは汚染下でも 3002（全メンバが継承値のため）', () => {
    const code = withPollutedPrototype(VC_SHAPE_POLLUTION, () =>
      codeOf(() => assertVerifiableCredential({})),
    );

    expect(code).toBe(SCHEMA_INVALID);
  });

  it('credentialSubject だけを継承値に頼る VC も 3002', () => {
    const partial = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: ISSUER,
      issuanceDate: ISSUANCE,
    };

    const code = withPollutedPrototype(VC_SHAPE_POLLUTION, () =>
      codeOf(() => assertVerifiableCredential(partial)),
    );

    expect(code).toBe(SCHEMA_INVALID);
  });

  it('対照: 全メンバを own で持つ正当な VC は汚染下でも通る', () => {
    const vc = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: ISSUER,
      issuanceDate: ISSUANCE,
      credentialSubject: { id: 'did:example:subject' },
    };

    const result = withPollutedPrototype(VC_SHAPE_POLLUTION, () => assertVerifiableCredential(vc));

    expect(result.issuer).toBe(ISSUER);
    expect(result.credentialSubject.id).toBe('did:example:subject');
  });
});
