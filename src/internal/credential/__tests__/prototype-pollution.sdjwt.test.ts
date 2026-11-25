/**
 * `addKeyBinding` が prototype 継承の `kid` を KB-JWT ヘッダへ載せないことの回帰テスト
 *
 * `signer.kid !== undefined` はプロトタイプ鎖を辿るため、`Object.prototype.kid` が汚染された
 * 環境では **`kid` を持たない signer が署名した KB-JWT のヘッダに攻撃者が選んだ鍵 ID が載る**。
 * Verifier の鍵解決を誤導できるため、判定は `buildJwsHeader` と同じく `Object.hasOwn` に揃える。
 */

import { describe, expect, it } from 'bun:test';
import {
  AUD,
  IAT,
  issue,
  NONCE,
  SESSION_ALG,
  SESSION_SIGNER,
} from '../sdjwt/__tests__/key-binding.fixtures.js';
import { parseSdJwt, selectDisclosures } from '../sdjwt/sdjwt.js';
import { addKeyBinding } from '../sdjwt/verify.js';
import type { CredentialSigner } from '../vc/signer.js';

/** 攻撃者が `Object.prototype` 経由で載せようとする鍵 ID。 */
const ATTACKER_KID = 'did:web:attacker.example#key-1';

/** SD-JWT presentation の末尾 KB-JWT から、生ヘッダセグメントとデコード結果を取り出す。 */
function kbHeaderOf(presentation: string): { raw: string; decoded: unknown } {
  const keyBinding = parseSdJwt(presentation).keyBinding;
  if (keyBinding === undefined) {
    throw new Error('KB-JWT が付与されていない');
  }
  const raw = keyBinding.split('.')[0] as string;
  return { raw, decoded: JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')) };
}

/** `SESSION_SIGNER` で KB-JWT を付与する。 */
function present(signer: CredentialSigner): string {
  return addKeyBinding(selectDisclosures(issue(), ['name']), signer, {
    nonce: NONCE,
    audience: AUD,
    iatSeconds: IAT,
  });
}

describe('addKeyBinding: prototype 継承の kid を KB-JWT ヘッダへ載せない', () => {
  it('Object.prototype 汚染下でも kid 未設定 signer のヘッダは従来どおりのバイト列', () => {
    const polluted = Object.prototype as unknown as Record<string, unknown>;
    polluted.kid = ATTACKER_KID;
    try {
      // 前提: signer は kid を自身のプロパティとして持たない。
      expect(Object.hasOwn(SESSION_SIGNER, 'kid')).toBe(false);
      const expected = Buffer.from(JSON.stringify({ alg: SESSION_ALG, typ: 'kb+jwt' })).toString(
        'base64url',
      );
      expect(kbHeaderOf(present(SESSION_SIGNER)).raw).toBe(expected);
    } finally {
      delete polluted.kid;
    }
  });

  it('プロトタイプに kid を持つ signer でも KB-JWT ヘッダに kid が出ない', () => {
    const signer = Object.assign(
      Object.create({ kid: ATTACKER_KID }) as object,
      SESSION_SIGNER,
    ) as CredentialSigner;
    expect(Object.hasOwn(signer, 'kid')).toBe(false);
    expect(kbHeaderOf(present(signer)).decoded).toEqual({ alg: SESSION_ALG, typ: 'kb+jwt' });
  });

  it('自身のプロパティの kid は従来どおりヘッダへ載る（後方互換）', () => {
    const kid = 'did:example:agent#session-1';
    const signer: CredentialSigner = { ...SESSION_SIGNER, kid };
    expect(kbHeaderOf(present(signer)).decoded).toEqual({ alg: SESSION_ALG, kid, typ: 'kb+jwt' });
  });
});
