/**
 * ES256K-R（標準外の例外）の検証側と署名鍵の経路の境界。
 *
 * - 検証はアドレス鍵（`{ ethereumAddress }`）だけ。公開鍵 JWK・検証関数 DI・標準の alg の差し替えでは通らない。
 * - 受理するのは自分の DID の経路だけ（`assertAlg` の `allowEs256kR`）。許可リストにも含めない。
 * - 署名鍵は `requireStandardSigner` で標準の alg に限れる（許可していない経路へ渡す前の関門）。
 * - `Object.prototype` 汚染で条件は緩まない。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { MethodPkh } from '../../../../identity/pkh/method-pkh.js';
import { ethereumAddressOfJwk } from '../../../../keymanager/eip191.js';
import { assertAlg, SUPPORTED_CREDENTIAL_ALGS, verifyWithKey } from '../../../vc/jws.js';
import { createPrivateKeySigner, requireStandardSigner } from '../../../vc/signer.js';
import { didDocumentToVerifierKey } from '../../../vc/verifier-key.js';
import { importPersonaFromDid } from '../../import-persona.js';
import { findHeldKeyInDocument } from '../../key-binding.js';
import { resolvePersonaSigner } from '../../persona-signer.js';
import { signMessageJws, verifyMessageJws } from '../../sign-message.js';
import { externalKey, newWorld } from '../fixtures.js';

const SECP = externalKey('secp256k1', 41);
const ADDRESS = ethereumAddressOfJwk(SECP.publicKeyJwk.x, SECP.publicKeyJwk.y) as string;
const PKH_DID = `did:pkh:eip155:1:${ADDRESS}`;
const OTHER_ADDRESS = '0xb9c5714089478a327f09197987f16f9e5d936e8a';

async function pkhWorld() {
  const world = await newWorld({ methods: [new MethodPkh()] });
  const deps = { personas: world.personas, keymanager: world.km, resolver: world.resolver };
  return { world, deps };
}

describe('ES256K-R の検証は address 鍵だけ・自分の DID の経路だけ', () => {
  async function signedMessage() {
    const { world, deps } = await pkhWorld();
    const persona = await importPersonaFromDid(deps, {
      did: PKH_DID,
      key: { external: SECP.privateKeyJwk },
    });
    const { signer } = await resolvePersonaSigner(world.km, persona, {
      resolver: world.resolver,
      externalKey: SECP.privateKeyJwk,
    });
    return { world, persona, signer, message: 'login nonce 123' };
  }

  it('did_signMessage: 署名者のアドレスの DID だけが検証に通る。メッセージ・DID を替えると通らない', async () => {
    const { world, signer, message } = await signedMessage();
    const jws = await signMessageJws(message, signer);
    expect(
      await verifyMessageJws(jws, { message, resolver: world.resolver, expectedDid: PKH_DID }),
    ).toMatchObject({ did: PKH_DID, alg: 'ES256K-R' });
    await expect(
      verifyMessageJws(jws, {
        message: `${message}!`,
        resolver: world.resolver,
        expectedDid: PKH_DID,
      }),
    ).rejects.toMatchObject({ code: ErrorCodes.SIG_INVALID });
    // 同じ署名を別アドレスの did:pkh の署名として提示しても通らない（kid の DID が不一致）。
    await expect(
      verifyMessageJws(jws, {
        message,
        resolver: world.resolver,
        expectedDid: `did:pkh:eip155:1:${OTHER_ADDRESS}`,
      }),
    ).rejects.toBeInstanceOf(VericertsError);
  });

  it('ES256K-R の署名は公開鍵 JWK の検証鍵・検証関数では検証されない（アドレス鍵だけ）', async () => {
    const { world, signer } = await signedMessage();
    const jws = await signMessageJws('x', signer);
    const decodedHeader = JSON.parse(
      Buffer.from(jws.split('.')[0] as string, 'base64url').toString(),
    );
    expect(decodedHeader.alg).toBe('ES256K-R');
    const decoded = {
      signingInput: new Uint8Array(),
      digest: new Uint8Array(32),
      signature: new Uint8Array(65),
    };
    expect(verifyWithKey('ES256K-R', decoded, { publicKeyJwk: SECP.publicKeyJwk })).toBe(false);
    expect(verifyWithKey('ES256K-R', decoded, { verify: () => true })).toBe(false);
    expect(verifyWithKey('ES256K', decoded, { ethereumAddress: ADDRESS })).toBe(false);
    const document = await world.resolver.resolve(PKH_DID);
    expect(didDocumentToVerifierKey(document)).toEqual({ ethereumAddress: ADDRESS });
  });

  it('assertAlg は ES256K-R を既定で拒否し、自分の DID の経路が明示したときだけ受理する（SD-JWT などは標準の alg だけ）', () => {
    const header = { alg: 'ES256K-R' };
    expect(() => assertAlg(header)).toThrow(VericertsError);
    expect(assertAlg(header, { allowEs256kR: true })).toBe('ES256K-R');
    expect(assertAlg({ alg: 'ES256K' })).toBe('ES256K');
    expect(() => assertAlg({ alg: 'none' }, { allowEs256kR: true })).toThrow(VericertsError);
  });

  it('ES256K-R は検証経路の許可リスト（SD-JWT・Status List・Federation・WUA が直接参照する）に含まれない', () => {
    expect(SUPPORTED_CREDENTIAL_ALGS.has('ES256K-R')).toBe(false);
  });

  it('requireStandardSigner は ES256K-R の署名鍵を 1030 で拒否し、標準の alg は kid を保ったまま通す', async () => {
    const { signer } = await signedMessage();
    expect(signer.alg).toBe('ES256K-R');
    expect(() => requireStandardSigner(signer)).toThrow(
      expect.objectContaining({
        code: ErrorCodes.UNSUPPORTED_ALGORITHM,
        context: { reason: 'es256k_r_not_allowed' },
      }),
    );
    const standard = createPrivateKeySigner(
      base64urlnopad.decode(SECP.privateKeyJwk.d as string),
      'ES256K',
    );
    const passed = requireStandardSigner({ ...standard, kid: 'did:example:1#k' });
    expect(passed).toMatchObject({ alg: 'ES256K', kid: 'did:example:1#k' });
    expect(passed.sign(new Uint8Array([1]))).toHaveLength(64);
  });

  it('Object.prototype 汚染で ES256K-R の受理条件・アドレス鍵・取り込み許可は緩まない', async () => {
    const pollute = (name: string, value: unknown) =>
      Object.defineProperty(Object.prototype, name, { value, configurable: true, writable: true });
    const names = ['allowEs256kR', 'allowAddressKey', 'ethereumAddress'] as const;
    try {
      pollute('allowEs256kR', true);
      pollute('allowAddressKey', true);
      pollute('ethereumAddress', ADDRESS);
      expect(() => assertAlg({ alg: 'ES256K-R' })).toThrow(VericertsError);
      const decoded = {
        signingInput: new Uint8Array([1]),
        digest: new Uint8Array(32),
        signature: new Uint8Array(65),
      };
      expect(verifyWithKey('ES256K-R', decoded, {})).toBe(false);
      const world = await newWorld({ methods: [new MethodPkh()] });
      const document = await world.resolver.resolve(PKH_DID);
      expect(() => findHeldKeyInDocument(document, SECP.publicKeyJwk)).toThrow(VericertsError);
    } finally {
      for (const name of names) {
        Reflect.deleteProperty(Object.prototype, name);
      }
    }
  });

  it('標準の ES256K の JWS を pkh の address 検証メソッドで通せない（alg の差し替え）', async () => {
    const { world, persona } = await signedMessage();
    const es256k = createPrivateKeySigner(
      base64urlnopad.decode(SECP.privateKeyJwk.d as string),
      'ES256K',
    );
    const jws = await signMessageJws('x', { ...es256k, kid: persona.kid as string });
    // 公開鍵を持たない address 鍵の検証メソッドに、標準の alg（ES256K）の JWS を提示する alg の差し替えは、署名不正として拒否する。
    await expect(
      verifyMessageJws(jws, { message: 'x', resolver: world.resolver, expectedDid: PKH_DID }),
    ).rejects.toMatchObject({ code: ErrorCodes.SIG_INVALID, context: { reason: 'signature' } });
  });
});
