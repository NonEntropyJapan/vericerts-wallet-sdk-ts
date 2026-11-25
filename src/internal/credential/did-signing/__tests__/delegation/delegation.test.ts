/**
 * 委任 DID: controller 検証と署名鍵の解決（標準 = DID Core だけ）。
 *
 * 委任先 `D`（did:web。`did.json` を可変にした実 Resolver、キャッシュなし）を、ペルソナ（P-256 / secp256k1）が
 * controller として使えるかを `D` の DID Document だけから判定する。成功系（controller / capabilityDelegation の 2 通り、
 * `authentication` に埋め込み / 他 DID への参照の 2 通り）と、fail-closed の拒否系（controller 関係なし・失効後・
 * 鍵不一致・検証メソッド削除・参照先不明）を確かめる。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import {
  resolveDelegatedSigner,
  verifyDelegatedKey,
  verifyDelegationControl,
} from '../../delegation.js';
import { externalKey } from '../fixtures.js';
import {
  DELEGATED_DID,
  type Delegation,
  EMBEDDED_KID,
  failureOf,
  newDelegation,
} from './delegation.fixtures.js';

const KEY_TYPES = ['P-256', 'secp256k1'] as const;

describe.each([...KEY_TYPES])('委任 DID の controller 検証と署名鍵の解決（%s）', (keyType) => {
  async function resolveSigner(d: Delegation) {
    return resolveDelegatedSigner(d.world.km, d.persona, {
      delegatedDid: DELEGATED_DID,
      resolver: d.world.resolver,
    });
  }

  it('controller に含まれる: basis=controller、kid は D の検証メソッド（埋め込み）、署名はペルソナの鍵', async () => {
    const d = await newDelegation(keyType);
    const control = await verifyDelegationControl(d.world.resolver, DELEGATED_DID, d.persona.did);
    expect(control.basis).toBe('controller');
    const delegated = await resolveSigner(d);
    expect(delegated.did).toBe(DELEGATED_DID);
    expect(delegated.kid).toBe(EMBEDDED_KID);
    expect(delegated.signer.kid).toBe(EMBEDDED_KID);
    expect(delegated.alg).toBe(d.own.alg);
    expect(delegated.signer.publicKeyJwk).toEqual(d.own.signer.publicKeyJwk);
    expect(delegated.basis).toBe('controller');
    expect((await delegated.signer.sign(new TextEncoder().encode('x'))).length).toBe(64);
  });

  it('controller が文字列（単数形）でも成立する', async () => {
    const d = await newDelegation(keyType);
    d.publish({ controller: d.persona.did });
    expect(
      (await verifyDelegationControl(d.world.resolver, DELEGATED_DID, d.persona.did)).basis,
    ).toBe('controller');
  });

  it('authentication が他 DID（ペルソナ）の検証メソッドを DID URL 参照している: kid はその DID URL、署名主体は D', async () => {
    const d = await newDelegation(keyType);
    d.publish({ verificationMethod: [], authentication: [d.own.kid] });
    const delegated = await resolveSigner(d);
    expect(delegated.did).toBe(DELEGATED_DID);
    expect(delegated.kid).toBe(d.own.kid);
    expect(delegated.signer.kid).toBe(d.own.kid);
  });

  it('capabilityDelegation（埋め込み）: controller が空でも、ペルソナが controller の検証メソッドが載っていれば成立する', async () => {
    const d = await newDelegation(keyType);
    d.publish({
      controller: [],
      capabilityDelegation: [
        {
          id: `${DELEGATED_DID}#delegate`,
          type: 'JsonWebKey2020',
          controller: d.persona.did,
          publicKeyJwk: d.own.signer.publicKeyJwk,
        },
      ],
    });
    expect(
      (await verifyDelegationControl(d.world.resolver, DELEGATED_DID, d.persona.did)).basis,
    ).toBe('capabilityDelegation');
    expect((await resolveSigner(d)).basis).toBe('capabilityDelegation');
  });

  it('capabilityDelegation（ペルソナの検証メソッドを DID URL 参照）でも成立する', async () => {
    const d = await newDelegation(keyType);
    d.publish({ controller: [], capabilityDelegation: [d.own.kid] });
    expect(
      (await verifyDelegationControl(d.world.resolver, DELEGATED_DID, d.persona.did)).basis,
    ).toBe('capabilityDelegation');
  });

  it('毎回 D を解決し直す（キャッシュなし）: controller を外すと次の検証は 2006', async () => {
    const d = await newDelegation(keyType);
    await resolveSigner(d);
    d.publish({ controller: [] });
    expect(await failureOf(resolveSigner(d))).toEqual({
      code: ErrorCodes.CONTROLLER_NOT_AUTHORIZED,
      reason: 'not_a_controller',
    });
  });

  it('controller が別 DID だけなら 2006（controller 関係が無い）', async () => {
    const d = await newDelegation(keyType, { controller: ['did:key:zSomeoneElse'] });
    expect(
      await failureOf(verifyDelegationControl(d.world.resolver, DELEGATED_DID, d.persona.did)),
    ).toEqual({
      code: ErrorCodes.CONTROLLER_NOT_AUTHORIZED,
      reason: 'not_a_controller',
    });
  });

  it('capabilityDelegation の検証メソッドの controller が他人なら 2006', async () => {
    const d = await newDelegation(keyType);
    d.publish({
      controller: [],
      capabilityDelegation: [
        {
          id: `${DELEGATED_DID}#delegate`,
          type: 'JsonWebKey2020',
          controller: 'did:key:zSomeoneElse',
          publicKeyJwk: d.own.signer.publicKeyJwk,
        },
      ],
    });
    expect(
      (await failureOf(verifyDelegationControl(d.world.resolver, DELEGATED_DID, d.persona.did)))
        ?.code,
    ).toBe(ErrorCodes.CONTROLLER_NOT_AUTHORIZED);
  });

  it('D が失効（deactivated）していれば 2006', async () => {
    const d = await newDelegation(keyType, { deactivated: true });
    expect(
      await failureOf(verifyDelegationControl(d.world.resolver, DELEGATED_DID, d.persona.did)),
    ).toEqual({
      code: ErrorCodes.CONTROLLER_NOT_AUTHORIZED,
      reason: 'deactivated',
    });
  });

  it('Resolver が別 DID の文書を返したら 2010 document_id_mismatch（Resolver 実装を信用しない）', async () => {
    const d = await newDelegation(keyType);
    const other = await d.world.resolver.resolve(d.persona.did);
    const resolver = { resolve: async () => other };
    expect(
      await failureOf(verifyDelegationControl(resolver, DELEGATED_DID, d.persona.did)),
    ).toEqual({
      code: ErrorCodes.DID_DOC_INVALID,
      reason: 'document_id_mismatch',
    });
  });

  it('D を解決できない（ネットワーク失敗相当）: 解決の失敗がそのまま伝播し、署名鍵は返らない', async () => {
    const d = await newDelegation(keyType);
    for (const key of Object.keys(d.files)) {
      delete d.files[key];
    }
    const failure = await failureOf(resolveSigner(d));
    expect(failure?.code).toBeDefined();
    expect(failure?.code).not.toBe(ErrorCodes.CONTROLLER_NOT_AUTHORIZED);
  });

  it('鍵不一致（D の authentication の検証メソッドが別の鍵）は 2017 no_matching_verification_method', async () => {
    const d = await newDelegation(keyType);
    d.publish({
      verificationMethod: [
        {
          id: EMBEDDED_KID,
          type: 'JsonWebKey2020',
          controller: DELEGATED_DID,
          publicKeyJwk: externalKey('P-256', 77).publicKeyJwk,
        },
      ],
    });
    expect(await failureOf(resolveSigner(d))).toEqual({
      code: ErrorCodes.DID_KEY_MISMATCH,
      reason: 'no_matching_verification_method',
    });
  });

  it('検証メソッドが authentication から外されると 2017 relationship_not_granted（controller は成立したまま）', async () => {
    const d = await newDelegation(keyType);
    d.publish({ authentication: [] });
    expect(
      (await verifyDelegationControl(d.world.resolver, DELEGATED_DID, d.persona.did)).basis,
    ).toBe('controller');
    expect(await failureOf(resolveSigner(d))).toEqual({
      code: ErrorCodes.DID_KEY_MISMATCH,
      reason: 'relationship_not_granted',
    });
  });

  it('assertionMethod には載っていない: relationship=assertionMethod は 2017', async () => {
    const d = await newDelegation(keyType);
    expect(
      await failureOf(
        resolveDelegatedSigner(d.world.km, d.persona, {
          delegatedDid: DELEGATED_DID,
          resolver: d.world.resolver,
          relationship: 'assertionMethod',
        }),
      ),
    ).toEqual({ code: ErrorCodes.DID_KEY_MISMATCH, reason: 'relationship_not_granted' });
  });

  it('参照先（ペルソナの文書）に無い検証メソッドへの参照は 2010 external_method_unresolvable', async () => {
    const d = await newDelegation(keyType);
    d.publish({ verificationMethod: [], authentication: [`${d.persona.did}#nonexistent`] });
    expect(await failureOf(resolveSigner(d))).toEqual({
      code: ErrorCodes.DID_DOC_INVALID,
      reason: 'external_method_unresolvable',
    });
  });

  it('verifyDelegatedKey: 保持鍵を引数で渡しても同じ判定（鍵が違えば 2017）', async () => {
    const d = await newDelegation(keyType);
    const input = { delegatedDid: DELEGATED_DID, controllerDid: d.persona.did };
    const match = await verifyDelegatedKey(d.world.resolver, input, d.own.signer.publicKeyJwk);
    expect(match.kid).toBe(EMBEDDED_KID);
    expect(
      (
        await failureOf(
          verifyDelegatedKey(d.world.resolver, input, externalKey('P-256', 5).publicKeyJwk),
        )
      )?.code,
    ).toBe(ErrorCodes.DID_KEY_MISMATCH);
  });
});
