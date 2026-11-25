/**
 * `vp` クレームが**配列**の署名済み JWT-VP が構造検証を素通りしないことの回帰テスト
 *
 * payload はパース境界（`parse-json.ts`）で `null` プロトタイプになるが、**reviver は配列を
 * 素通しする**（同モジュールの JSDoc が明記）ため、配列は `Array.prototype` →
 * `Object.prototype` を保持する。`assertVerifiablePresentation` は `typeof value !== 'object'`
 * でしかゲートしておらず**配列を受理**し、その 4 つの構造検査（`@context` / `type` / `holder` /
 * `verifiableCredential`）はすべて鎖読みだったため、`Object.prototype` 汚染で満たせた。
 *
 * 成立していた fail-open: payload が `{"iss":"<提示者 DID>","vp":[]}` の**署名済み** JWT-VP が
 * 構造検証を通り、`Object.prototype.holder` を `iss` と同じ DID にすれば Holder Binding ゲートも
 * 通る。返る `verifiableCredential` は丸ごと `Object.prototype` 由来で、**JWT 署名に一切
 * 覆われていない内包 VC リスト**が「検証済み」として呼び出し側へ渡っていた。
 *
 * 兄弟の `delegation/subject-binding/subject-binding-verify.ts` の `extractAndAssert` は同型の
 * 形（配列が `typeof === 'object'` を通る）を持ちながら全メンバを `ownProperty` で読むため元から
 * fail-closed で、そちらへ揃えた。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { verifyPresentation } from '../../presentation.js';
import { parseVerifiablePresentation } from '../../vp.js';
import { FIXTURES, signerFor } from '../presentation.fixtures.js';

const fx = FIXTURES.ES256;
const HOLDER = 'did:example:holder';

/** 任意の payload で JWT-VP を組み立てて実鍵で署名する。 */
function signJwtVp(payload: Record<string, unknown>): string {
  const b64u = (value: unknown): string =>
    Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
  const signingInput = `${b64u({ alg: 'ES256', typ: 'JWT' })}.${b64u(payload)}`;
  const signature = signerFor('ES256').sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${Buffer.from(signature).toString('base64url')}`;
}

/** VP の 4 つの構造メンバを `Object.prototype` へ仕込む汚染セット。 */
const VP_SHAPE_POLLUTION = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiablePresentation'],
  holder: HOLDER,
  verifiableCredential: ['eyJhbGciOiJFUzI1NiJ9.attacker.injected'],
} as const;

const SCHEMA_INVALID = ErrorCodes.VC_SCHEMA_INVALID;

/** 送出された `VericertsError` のコードを取り出す。 */
function codeOf(fn: () => unknown): unknown {
  try {
    fn();
    return undefined;
  } catch (e: unknown) {
    return e instanceof VericertsError ? e.code : e;
  }
}

describe('配列の vp クレームは構造検証を素通りしない', () => {
  it('vp が空配列の署名済み JWT-VP は汚染下でも 3002 で拒否される', () => {
    const jwt = signJwtVp({ iss: HOLDER, vp: [] });

    const code = withPollutedPrototype(VP_SHAPE_POLLUTION, () =>
      codeOf(() => verifyPresentation(jwt, { key: { publicKeyJwk: fx.jwk }, allowUnbound: true })),
    );

    expect(code).toBe(SCHEMA_INVALID);
  });

  it('汚染された内包 VC リストが検証結果として返らない', () => {
    const jwt = signJwtVp({ iss: HOLDER, vp: [] });

    const result = withPollutedPrototype(VP_SHAPE_POLLUTION, () => {
      try {
        return verifyPresentation(jwt, {
          key: { publicKeyJwk: fx.jwk },
          allowUnbound: true,
        });
      } catch {
        return undefined;
      }
    });

    // 修正前はここで攻撃者の VC 文字列を含む「検証済み」VP が返っていた。
    expect(result).toBeUndefined();
  });

  it('公開 API parseVerifiablePresentation も配列を受理しない', () => {
    const code = withPollutedPrototype(VP_SHAPE_POLLUTION, () =>
      codeOf(() => parseVerifiablePresentation('[]')),
    );

    expect(code).toBe(SCHEMA_INVALID);
  });

  it('対照: 汚染なしでも配列の vp は 3002（配列は VP ではない）', () => {
    const jwt = signJwtVp({ iss: HOLDER, vp: [] });

    expect(
      codeOf(() => verifyPresentation(jwt, { key: { publicKeyJwk: fx.jwk }, allowUnbound: true })),
    ).toBe(SCHEMA_INVALID);
  });

  it('対照: 正当なオブジェクトの vp は汚染下でも従来どおり検証を通る', () => {
    const jwt = signJwtVp({
      iss: HOLDER,
      vp: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiablePresentation'],
        holder: HOLDER,
        verifiableCredential: [],
      },
    });

    const result = withPollutedPrototype(VP_SHAPE_POLLUTION, () =>
      verifyPresentation(jwt, { key: { publicKeyJwk: fx.jwk }, allowUnbound: true }),
    );

    expect(result.presentation.holder).toBe(HOLDER);
    expect(result.presentation.verifiableCredential).toEqual([]);
  });
});
