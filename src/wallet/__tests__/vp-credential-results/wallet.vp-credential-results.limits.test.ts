/**
 * Wallet ファサードの `verifyPresentation` が内包 VC の発行者 DID 解決ファンアウトを
 * 上限で抑えることの回帰テスト。
 *
 * 修正前は `vp.verifiableCredential` の全要素について DID 解決を無制限に同時実行していたため、
 * VC 件数ぶんの外部 I/O が一斉に発行された（正当な holder でも増幅を起こせる）。修正後は
 * 相異なる発行者 DID を `DEFAULT_MAX_DISTINCT_RESOLUTIONS` 件までに絞り、超過分は解決せず
 * fail-closed（当該 VC が `valid: false`）にする。
 *
 * ここでは did:key の自己発行・自己検証（実署名・ネット非依存）で上限の効き方を確認する。
 */

import { describe, expect, it } from 'bun:test';
import {
  VC_V2_CONTEXT,
  type VerifiableCredential,
  type VerifiablePresentation,
} from '../../../internal/credential/index.js';
import { DEFAULT_MAX_DISTINCT_RESOLUTIONS } from '../../../internal/identity/bounded-resolver.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import {
  assertPresentationInvalid,
  assertPresentationValid,
  issueCodes,
} from '../verification-result.fixtures.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** 上限を 1 件だけ超える発行者数。 */
const ISSUER_COUNT = DEFAULT_MAX_DISTINCT_RESOLUTIONS + 1;

function sampleVc(issuer: string, index: number): VerifiableCredential {
  return {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer,
    credentialSubject: { id: issuer, name: 'Alice' },
    issuanceDate: '2025-01-01T00:00:00Z',
    expirationDate: '2030-01-01T00:00:00Z',
    id: `urn:uuid:vc-${index}`,
  } satisfies VerifiableCredential;
}

describe('Wallet.verifyPresentation の発行者 DID 解決ファンアウト上限', () => {
  it('相異なる発行者 DID が上限を超える VP は超過分だけ fail-closed になる', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC);

    // 相異なる did:key 発行者を ISSUER_COUNT 件（= 上限 + 1）用意し、各自が 1 件ずつ VC を発行する。
    const jwtVcs: string[] = [];
    const issuerDids: string[] = [];
    let holderKeyID = '';
    let holderDid = '';
    for (let index = 0; index < ISSUER_COUNT; index += 1) {
      const keyPair = await wallet.deriveKey(ethereumPath(0, index));
      const document = await wallet.createDID('key', { keyID: keyPair.id });
      if (index === 0) {
        holderKeyID = keyPair.id;
        holderDid = document.id;
      }
      issuerDids.push(document.id);
      jwtVcs.push(await wallet.issueCredential(sampleVc(document.id, index), keyPair.id));
    }
    // 発行者 DID が実際に全て異なることを確認する（同じなら重複排除で上限に届かない）。
    expect(new Set(issuerDids).size).toBe(ISSUER_COUNT);

    const vp: VerifiablePresentation = {
      '@context': [VC_V2_CONTEXT],
      type: ['VerifiablePresentation'],
      holder: holderDid,
      verifiableCredential: jwtVcs,
    };
    const jwt = await wallet.issuePresentation(vp, holderKeyID);

    // 上限超過は VP 全体の例外にはせず、fail-closed で VP を無効にする。
    const verified = assertPresentationInvalid(
      await wallet.verifyPresentation(jwt, { allowUnbound: true }),
    );

    expect(verified.presentationValid).toBe(true);
    expect(verified.credentialResults).toHaveLength(ISSUER_COUNT);
    // どの VC が超過扱いになるかは解決順序に依存するため件数で判定する。
    const validCount = verified.credentialResults.filter((result) => result.valid).length;
    expect(validCount).toBe(DEFAULT_MAX_DISTINCT_RESOLUTIONS);
    expect(verified.credentialResults.length - validCount).toBe(1);
    expect(issueCodes(verified.errors)).toEqual(['3010']);
  });

  it('上限ちょうどの発行者数なら全ての内包 VC が検証される', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC);

    const jwtVcs: string[] = [];
    let holderKeyID = '';
    let holderDid = '';
    for (let index = 0; index < DEFAULT_MAX_DISTINCT_RESOLUTIONS; index += 1) {
      const keyPair = await wallet.deriveKey(ethereumPath(0, index));
      const document = await wallet.createDID('key', { keyID: keyPair.id });
      if (index === 0) {
        holderKeyID = keyPair.id;
        holderDid = document.id;
      }
      jwtVcs.push(await wallet.issueCredential(sampleVc(document.id, index), keyPair.id));
    }

    const vp: VerifiablePresentation = {
      '@context': [VC_V2_CONTEXT],
      type: ['VerifiablePresentation'],
      holder: holderDid,
      verifiableCredential: jwtVcs,
    };
    const jwt = await wallet.issuePresentation(vp, holderKeyID);

    const verified = assertPresentationValid(
      await wallet.verifyPresentation(jwt, { allowUnbound: true }),
    );

    expect(verified.warnings).toEqual([]);
    expect(verified.credentialResults).toHaveLength(DEFAULT_MAX_DISTINCT_RESOLUTIONS);
    expect(verified.credentialResults.every((result) => result.valid)).toBe(true);
  });

  it('同一発行者の VC は何件あっても重複排除され上限に当たらない', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC);
    const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
    const document = await wallet.createDID('key', { keyID: keyPair.id });

    // 相異なる DID は 1 件だけなので、VC 件数が上限を大きく超えても全件が検証される。
    const jwtVcs: string[] = [];
    for (let index = 0; index < DEFAULT_MAX_DISTINCT_RESOLUTIONS * 2; index += 1) {
      jwtVcs.push(await wallet.issueCredential(sampleVc(document.id, index), keyPair.id));
    }
    const vp: VerifiablePresentation = {
      '@context': [VC_V2_CONTEXT],
      type: ['VerifiablePresentation'],
      holder: document.id,
      verifiableCredential: jwtVcs,
    };
    const jwt = await wallet.issuePresentation(vp, keyPair.id);

    const verified = assertPresentationValid(
      await wallet.verifyPresentation(jwt, { allowUnbound: true }),
    );

    expect(verified.credentialResults).toHaveLength(DEFAULT_MAX_DISTINCT_RESOLUTIONS * 2);
    expect(verified.credentialResults.every((result) => result.valid)).toBe(true);
  });
});
