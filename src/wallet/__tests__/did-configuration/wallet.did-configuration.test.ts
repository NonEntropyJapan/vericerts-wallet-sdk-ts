/**
 * Wallet ファサードの Well Known DID Configuration 配線（統合）テスト。
 *
 * `generateDIDConfiguration` / `verifyDIDConfiguration` を `createWallet`
 * 経由（実 storage / 実鍵）で検証する。DID メソッドの登録は
 * `wallet.register-did-method.test.ts` が担う。
 *
 * - generateDIDConfiguration: アクティブペルソナ由来の鍵で self-issued DLC を発行し、指定 DID の
 *   鍵が使えない場合（未設定 / DID 不一致）は 2007 で失敗する。
 * - verifyDIDConfiguration: 生成した文書の往復検証に加え、取得失敗・形式不正・origin 不一致・
 *   署名改ざん・非 self-issued が**例外にならず**結果へ畳み込まれることを確認する。
 *
 * ネットワークは**グローバル `fetch` を差し替えず**、`createWallet` の `didConfigurationFetchImpl`
 * で注入する（`wallet/__tests__/eudi/eudi-fixtures.ts` と同じ方針）。
 */

import { describe, expect, it } from 'bun:test';
import { issueCredential, VC_TYPE, VC_V2_CONTEXT } from '../../../internal/credential/index.js';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import type { FetchLike } from '../../../internal/fetch-di.js';
import { createP256CredentialSigner } from '../../../internal/keymanager/credential-signer.js';
import { deriveSlip10Nist256p1 } from '../../../internal/keymanager/derivation/slip10.js';
import { mnemonicToSeed } from '../../../internal/keymanager/hd.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { MAX_LINKED_DIDS } from '../../did/facade.js';
import { createWallet } from '../../factory.js';
import type { WalletOptions } from '../../options.js';
import type { Wallet } from '../../types.js';

// BIP-39 公式オールゼロ・エントロピーのニーモニック（passphrase なし）。
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** 検証対象ドメイン（`fetchWellKnownJson` は HTTPS 以外を取得せずに拒否する）。 */
const ORIGIN = 'https://example.com';

/** DIF Well Known DID Configuration のコンテキスト。 */
const DID_CONFIGURATION_CONTEXT = 'https://identity.foundation/.well-known/did-configuration/v1';

/** 差し替え可能な本文を返すスタブ fetch。 */
interface StubFetch {
  /** `didConfigurationFetchImpl` として注入する実装。 */
  readonly fetchImpl: FetchLike;
  /** 200 で返す本文を設定する（未設定のままなら 404 を返す）。 */
  serve(body: string): void;
  /** 要求された URL の記録。 */
  readonly urls: string[];
}

function stubFetch(): StubFetch {
  let body: string | null = null;
  const urls: string[] = [];
  return {
    fetchImpl: (url) => {
      urls.push(url);
      return Promise.resolve(
        body === null
          ? new Response('', { status: 404 })
          : new Response(body, { status: 200, headers: { 'content-type': 'application/json' } }),
      );
    },
    serve: (next) => {
      body = next;
    },
    urls,
  };
}

/** ニーモニック import + アクティブペルソナ設定済みの Wallet を用意する。 */
async function setupWithActivePersona(
  options?: Omit<WalletOptions, 'storage'>,
): Promise<{ wallet: Wallet; did: string; derivationPath: string }> {
  const wallet = await createWallet({ storage: new MemoryStorage(), ...options });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const persona = await wallet.createPersona();
  await wallet.setActivePersona(persona.id);
  return { wallet, did: persona.did, derivationPath: persona.derivationPath };
}

/** JWT の署名部だけを改変した文字列を返す（署名検証失敗の再現）。 */
function tamperSignature(jwt: string): string {
  const [header, payload, signature] = jwt.split('.');
  const flipped = `${signature?.startsWith('A') === true ? 'B' : 'A'}${signature?.slice(1) ?? ''}`;
  return `${header}.${payload}.${flipped}`;
}

describe('Wallet.generateDIDConfiguration', () => {
  it('DLC を 1 件含む DID Configuration を返す', async () => {
    const { wallet, did } = await setupWithActivePersona();
    const config = await wallet.generateDIDConfiguration(did, ORIGIN);
    expect(config['@context']).toBe(DID_CONFIGURATION_CONTEXT);
    expect(config.linked_dids).toHaveLength(1);
    // コンパクト JWS（header.payload.signature）である。
    expect(config.linked_dids[0]?.split('.')).toHaveLength(3);
  });

  it.each([
    ['http スキーム', 'http://example.com'],
    ['パス付き', 'https://example.com/x'],
    ['末尾スラッシュ', 'https://example.com/'],
    ['クエリ付き', 'https://example.com?a=1'],
    ['userinfo 付き', 'https://user@example.com'],
    ['既定ポート明示', 'https://example.com:443'],
    ['非 origin 文字列', 'foo'],
    ['空文字', ''],
    ['非公開ホスト', 'https://localhost'],
    ['非文字列', 5],
  ])('origin が%sなら署名せず RP_IDENTIFIER_INVALID(10201) で拒否する', async (_name, bad) => {
    const { wallet, did } = await setupWithActivePersona();
    await expect(wallet.generateDIDConfiguration(did, bad as unknown as string)).rejects.toThrow(
      new VericertsError(ErrorCodes.RP_IDENTIFIER_INVALID),
    );
  });

  it('非既定ポート付きの正規形 origin は受理し、検証側と文字列一致する', async () => {
    const stub = stubFetch();
    const { wallet, did } = await setupWithActivePersona({
      didConfigurationFetchImpl: stub.fetchImpl,
    });
    const origin = 'https://example.com:8443';
    const config = await wallet.generateDIDConfiguration(did, origin);
    expect(config.linked_dids).toHaveLength(1);

    // 「検証側と文字列一致」を往復で pin する: 受理した origin で生成した DLC を verifyDIDConfiguration が
    // 同じ origin に対して valid にする（DLC の origin が正規形から外れると検証側で落ちる）。
    stub.serve(JSON.stringify(config));
    const result = await wallet.verifyDIDConfiguration(origin);
    expect(result.valid).toBe(true);
    expect(result.linkedDIDs).toEqual([{ did, valid: true }]);
    expect(result.errors).toBeUndefined();
    expect(stub.urls).toEqual([`${origin}/.well-known/did-configuration.json`]);
  });

  it('アクティブペルソナ未設定は DID_SIGNING_KEY_UNAVAILABLE(2007)', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC);
    const persona = await wallet.createPersona();
    // アクティブ化していないため署名鍵を解決できない（2005 ではなく 2007 に正規化する）。
    await expect(wallet.generateDIDConfiguration(persona.did, ORIGIN)).rejects.toThrow(
      new VericertsError(ErrorCodes.DID_SIGNING_KEY_UNAVAILABLE),
    );
  });

  it('マスターシード未投入も DID_SIGNING_KEY_UNAVAILABLE(2007) に正規化する', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await expect(wallet.generateDIDConfiguration('did:key:zNonExistent', ORIGIN)).rejects.toThrow(
      new VericertsError(ErrorCodes.DID_SIGNING_KEY_UNAVAILABLE),
    );
  });

  it('アクティブペルソナと異なる DID の要求は DID_SIGNING_KEY_UNAVAILABLE(2007)', async () => {
    const { wallet } = await setupWithActivePersona();
    await expect(wallet.generateDIDConfiguration('did:key:zOtherDid', ORIGIN)).rejects.toThrow(
      new VericertsError(ErrorCodes.DID_SIGNING_KEY_UNAVAILABLE),
    );
  });
});

describe('Wallet.verifyDIDConfiguration', () => {
  it('generateDIDConfiguration の出力を検証できる', async () => {
    const stub = stubFetch();
    const { wallet, did } = await setupWithActivePersona({
      didConfigurationFetchImpl: stub.fetchImpl,
    });
    stub.serve(JSON.stringify(await wallet.generateDIDConfiguration(did, ORIGIN)));

    const result = await wallet.verifyDIDConfiguration(ORIGIN);
    expect(result.valid).toBe(true);
    expect(result.linkedDIDs).toEqual([{ did, valid: true }]);
    expect(result.errors).toBeUndefined();
    expect(stub.urls).toEqual([`${ORIGIN}/.well-known/did-configuration.json`]);
  });

  it('did 指定で一致する DLC があれば valid: true', async () => {
    const stub = stubFetch();
    const { wallet, did } = await setupWithActivePersona({
      didConfigurationFetchImpl: stub.fetchImpl,
    });
    stub.serve(JSON.stringify(await wallet.generateDIDConfiguration(did, ORIGIN)));

    expect((await wallet.verifyDIDConfiguration(ORIGIN, did)).valid).toBe(true);
  });

  it('did 指定で一致する DLC が無ければ did_not_linked で valid: false', async () => {
    const stub = stubFetch();
    const { wallet, did } = await setupWithActivePersona({
      didConfigurationFetchImpl: stub.fetchImpl,
    });
    stub.serve(JSON.stringify(await wallet.generateDIDConfiguration(did, ORIGIN)));

    const result = await wallet.verifyDIDConfiguration(ORIGIN, 'did:key:zOtherDid');
    expect(result.valid).toBe(false);
    expect(result.errors).toEqual(['did_not_linked']);
    // 同居する DLC 自体は有効なので、結果にはそのまま有効として現れる。
    expect(result.linkedDIDs).toEqual([{ did, valid: true }]);
  });

  it('別 origin 向けの DLC は origin_mismatch で valid: false', async () => {
    const stub = stubFetch();
    const { wallet, did } = await setupWithActivePersona({
      didConfigurationFetchImpl: stub.fetchImpl,
    });
    // 別ドメイン向けに発行した DLC を ORIGIN の文書として配信する（ドメイン紐づけの詐称）。
    stub.serve(JSON.stringify(await wallet.generateDIDConfiguration(did, 'https://other.example')));

    const result = await wallet.verifyDIDConfiguration(ORIGIN);
    expect(result.valid).toBe(false);
    expect(result.linkedDIDs).toEqual([{ did, valid: false, error: 'origin_mismatch' }]);
  });

  it('署名が改ざんされた DLC は verification_failed で valid: false', async () => {
    const stub = stubFetch();
    const { wallet, did } = await setupWithActivePersona({
      didConfigurationFetchImpl: stub.fetchImpl,
    });
    const config = await wallet.generateDIDConfiguration(did, ORIGIN);
    const jwt = config.linked_dids[0];
    expect(jwt).toBeDefined();
    stub.serve(
      JSON.stringify({
        '@context': DID_CONFIGURATION_CONTEXT,
        linked_dids: [tamperSignature(jwt ?? '')],
      }),
    );

    const result = await wallet.verifyDIDConfiguration(ORIGIN);
    expect(result.valid).toBe(false);
    // 検証を通っていない payload は事実として扱わないため did は空にする。
    expect(result.linkedDIDs).toEqual([{ did: '', valid: false, error: 'verification_failed' }]);
  });

  it('self-issued でない DLC は not_self_issued で valid: false', async () => {
    const stub = stubFetch();
    const { wallet, did, derivationPath } = await setupWithActivePersona({
      didConfigurationFetchImpl: stub.fetchImpl,
    });
    // 公開 API は秘密鍵を返さないため、ペルソナと同じニーモニック・パス（SLIP-0010 P-256）から署名鍵を組み立てる。
    const { privateKey } = deriveSlip10Nist256p1(mnemonicToSeed(TEST_MNEMONIC), derivationPath);
    // 署名は正当（iss はペルソナ DID で解決できる）だが、対象 DID が別人の DLC。
    const jwt = await issueCredential(
      {
        '@context': [VC_V2_CONTEXT, DID_CONFIGURATION_CONTEXT],
        type: [VC_TYPE, 'DomainLinkageCredential'],
        issuer: did,
        credentialSubject: { id: 'did:key:zOtherDid', origin: ORIGIN },
        issuanceDate: new Date().toISOString(),
      },
      createP256CredentialSigner(privateKey),
    );
    stub.serve(JSON.stringify({ '@context': DID_CONFIGURATION_CONTEXT, linked_dids: [jwt] }));

    const result = await wallet.verifyDIDConfiguration(ORIGIN);
    expect(result.valid).toBe(false);
    expect(result.linkedDIDs).toEqual([
      { did: 'did:key:zOtherDid', valid: false, error: 'not_self_issued' },
    ]);
  });

  it('取得失敗（404）は例外にせず http_error を返す', async () => {
    const stub = stubFetch();
    const { wallet } = await setupWithActivePersona({ didConfigurationFetchImpl: stub.fetchImpl });

    const result = await wallet.verifyDIDConfiguration(ORIGIN);
    expect(result).toEqual({ valid: false, linkedDIDs: [], errors: ['http_error'] });
  });

  it('HTTPS でない origin は取得せずに non_https_issuer を返す', async () => {
    const stub = stubFetch();
    const { wallet } = await setupWithActivePersona({ didConfigurationFetchImpl: stub.fetchImpl });

    const result = await wallet.verifyDIDConfiguration('http://example.com');
    expect(result).toEqual({ valid: false, linkedDIDs: [], errors: ['non_https_issuer'] });
    // fetch は 1 度も発生しない（SSRF / 平文降格の防止）。
    expect(stub.urls).toEqual([]);
  });

  it('JSON として壊れた文書は invalid_json を返す', async () => {
    const stub = stubFetch();
    const { wallet } = await setupWithActivePersona({ didConfigurationFetchImpl: stub.fetchImpl });
    stub.serve('{');

    expect(await wallet.verifyDIDConfiguration(ORIGIN)).toEqual({
      valid: false,
      linkedDIDs: [],
      errors: ['invalid_json'],
    });
  });

  it.each([
    ['{}'],
    ['{"linked_dids":[]}'],
    ['{"linked_dids":"x"}'],
  ])('linked_dids を持たない / 空の文書は invalid_did_configuration（%s）', async (body) => {
    const stub = stubFetch();
    const { wallet } = await setupWithActivePersona({ didConfigurationFetchImpl: stub.fetchImpl });
    stub.serve(body);

    expect(await wallet.verifyDIDConfiguration(ORIGIN)).toEqual({
      valid: false,
      linkedDIDs: [],
      errors: ['invalid_did_configuration'],
    });
  });

  it('linked_dids が上限を超えると 1 件も解決せず invalid_did_configuration', async () => {
    const stub = stubFetch();
    const { wallet } = await setupWithActivePersona({ didConfigurationFetchImpl: stub.fetchImpl });
    stub.serve(
      JSON.stringify({ linked_dids: Array.from({ length: MAX_LINKED_DIDS + 1 }, () => 'x') }),
    );

    expect(await wallet.verifyDIDConfiguration(ORIGIN)).toEqual({
      valid: false,
      linkedDIDs: [],
      errors: ['invalid_did_configuration'],
    });
  });

  it('linked_dids の非文字列要素は invalid_linked_did_entry で valid: false', async () => {
    const stub = stubFetch();
    const { wallet } = await setupWithActivePersona({ didConfigurationFetchImpl: stub.fetchImpl });
    stub.serve(JSON.stringify({ '@context': DID_CONFIGURATION_CONTEXT, linked_dids: [{}] }));

    const result = await wallet.verifyDIDConfiguration(ORIGIN);
    expect(result.valid).toBe(false);
    expect(result.linkedDIDs).toEqual([
      { did: '', valid: false, error: 'invalid_linked_did_entry' },
    ]);
  });
});
