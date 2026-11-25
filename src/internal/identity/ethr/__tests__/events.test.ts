/**
 * buildDidEthrDocument の検証（純関数・モック不要）。
 *
 * 空イベント / OwnerChange による controller 更新 / Secp256k1 veriKey / sigAuth /
 * service 追加 / validTo 期限切れ除外 / revoke(validTo=0) 除外 / 同一属性集約 /
 * blockNumber+logIndex 順 / owner=0x0 deactivated / 複合シナリオのスナップショットを確認する。
 */

import { describe, expect, it } from 'bun:test';
import { base64 } from '@scure/base';
import type { AttributeChangeEvent, Erc1056Events, OwnerChangeEvent } from '../events.js';
import { buildDidEthrDocument } from '../events.js';

const IDENTITY = '0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb';
const NEW_OWNER = '0x1111111111111111111111111111111111111111';
const ZERO = '0x0000000000000000000000000000000000000000';
const DID = `did:ethr:1:${IDENTITY}`;
/** DID の chainId（Mainnet）。buildDidEthrDocument に直接渡す。 */
const CHAIN_ID = 1;
const NOW = 1_700_000_000;

/** secp256k1 圧縮公開鍵（33 バイト）の hex 例。 */
const SECP_PUBKEY_HEX = '0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71';
/** Ed25519 公開鍵（32 バイト）のバイト列例。 */
const ED_PUBKEY_BYTES = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const ED_PUBKEY_HEX = `0x${Buffer.from(ED_PUBKEY_BYTES).toString('hex')}`;

const noEvents: Erc1056Events = { ownerChanges: [], attributeChanges: [] };

function owner(o: string, blockNumber: number, logIndex: number): OwnerChangeEvent {
  return { owner: o, blockNumber, logIndex };
}

function attr(
  name: string,
  value: string,
  validTo: number,
  blockNumber: number,
  logIndex: number,
): AttributeChangeEvent {
  return { name, value, validTo, blockNumber, logIndex };
}

/** UTF-8 文字列を `0x` 付き hex に変換する（service エンドポイント value 生成用）。 */
function utf8ToHex(text: string): string {
  return `0x${Buffer.from(text, 'utf-8').toString('hex')}`;
}

describe('buildDidEthrDocument', () => {
  it('イベントが無い場合は #controller のみを含む', () => {
    const doc = buildDidEthrDocument(DID, IDENTITY, CHAIN_ID, noEvents, NOW);
    expect(doc.id).toBe(DID);
    expect(doc.controller).toBe(`did:ethr:1:${IDENTITY}`);
    expect(doc.verificationMethod).toEqual([
      {
        id: `${DID}#controller`,
        type: 'EcdsaSecp256k1RecoveryMethod2020',
        controller: `did:ethr:1:${IDENTITY}`,
        blockchainAccountId: `eip155:1:${IDENTITY}`,
      },
    ]);
    expect(doc.authentication).toEqual([`${DID}#controller`]);
    expect(doc.assertionMethod).toEqual([`${DID}#controller`]);
    expect(doc.service).toBeUndefined();
    expect(doc.deactivated).toBeUndefined();
    expect(doc['@context']).toEqual([
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/secp256k1recovery-2020/v2',
    ]);
  });

  it('OwnerChange で controller を新 owner に更新する', () => {
    const doc = buildDidEthrDocument(
      DID,
      IDENTITY,
      CHAIN_ID,
      { ownerChanges: [owner(NEW_OWNER, 10, 0)], attributeChanges: [] },
      NOW,
    );
    expect(doc.controller).toBe(`did:ethr:1:${NEW_OWNER}`);
    expect(doc.verificationMethod[0]?.blockchainAccountId).toBe(`eip155:1:${NEW_OWNER}`);
    expect(doc.verificationMethod[0]?.controller).toBe(`did:ethr:1:${NEW_OWNER}`);
  });

  it('Secp256k1 veriKey は VM + assertionMethod を追加する', () => {
    const doc = buildDidEthrDocument(
      DID,
      IDENTITY,
      CHAIN_ID,
      {
        ownerChanges: [],
        attributeChanges: [
          attr('did/pub/Secp256k1/veriKey/hex', SECP_PUBKEY_HEX, NOW + 1000, 5, 0),
        ],
      },
      NOW,
    );
    const vmId = `${DID}#delegate-1`;
    expect(doc.verificationMethod).toContainEqual({
      id: vmId,
      type: 'EcdsaSecp256k1VerificationKey2019',
      controller: DID,
      publicKeyHex: SECP_PUBKEY_HEX,
    });
    expect(doc.assertionMethod).toContain(vmId);
    expect(doc.authentication).not.toContain(vmId);
  });

  it('Secp256k1 sigAuth は authentication を追加する', () => {
    const doc = buildDidEthrDocument(
      DID,
      IDENTITY,
      CHAIN_ID,
      {
        ownerChanges: [],
        attributeChanges: [
          attr('did/pub/Secp256k1/sigAuth/hex', SECP_PUBKEY_HEX, NOW + 1000, 5, 0),
        ],
      },
      NOW,
    );
    const vmId = `${DID}#delegate-1`;
    expect(doc.authentication).toContain(vmId);
    expect(doc.assertionMethod).not.toContain(vmId);
  });

  it('Ed25519 veriKey は publicKeyBase64 と ed25519 context を追加する', () => {
    const doc = buildDidEthrDocument(
      DID,
      IDENTITY,
      CHAIN_ID,
      {
        ownerChanges: [],
        attributeChanges: [attr('did/pub/Ed25519/veriKey/base64', ED_PUBKEY_HEX, NOW + 1000, 5, 0)],
      },
      NOW,
    );
    const vmId = `${DID}#delegate-1`;
    expect(doc.verificationMethod).toContainEqual({
      id: vmId,
      type: 'Ed25519VerificationKey2018',
      controller: DID,
      publicKeyBase64: base64.encode(ED_PUBKEY_BYTES),
    });
    expect(doc['@context']).toContain('https://w3id.org/security/suites/ed25519-2018/v1');
  });

  it('did/svc/<Type> は service を追加する', () => {
    const endpoint = 'https://example.com/messaging';
    const doc = buildDidEthrDocument(
      DID,
      IDENTITY,
      CHAIN_ID,
      {
        ownerChanges: [],
        attributeChanges: [attr('did/svc/MessagingService', utf8ToHex(endpoint), NOW + 1000, 5, 0)],
      },
      NOW,
    );
    expect(doc.service).toEqual([
      {
        id: `${DID}#service-1`,
        type: 'MessagingService',
        serviceEndpoint: endpoint,
      },
    ]);
  });

  it('validTo <= now の属性は除外する', () => {
    const doc = buildDidEthrDocument(
      DID,
      IDENTITY,
      CHAIN_ID,
      {
        ownerChanges: [],
        attributeChanges: [attr('did/pub/Secp256k1/veriKey/hex', SECP_PUBKEY_HEX, NOW - 1, 5, 0)],
      },
      NOW,
    );
    expect(doc.verificationMethod).toHaveLength(1);
    expect(doc.assertionMethod).toEqual([`${DID}#controller`]);
  });

  it('revoke（validTo=0 で再発行）は当該属性を除外する', () => {
    const doc = buildDidEthrDocument(
      DID,
      IDENTITY,
      CHAIN_ID,
      {
        ownerChanges: [],
        attributeChanges: [
          attr('did/pub/Secp256k1/veriKey/hex', SECP_PUBKEY_HEX, NOW + 1000, 5, 0),
          // 同一 (name, value) を validTo=0 で再発行 → revoke。
          attr('did/pub/Secp256k1/veriKey/hex', SECP_PUBKEY_HEX, 0, 9, 0),
        ],
      },
      NOW,
    );
    expect(doc.verificationMethod).toHaveLength(1);
  });

  it('同一 (name, value) は最新 validTo に集約する', () => {
    const doc = buildDidEthrDocument(
      DID,
      IDENTITY,
      CHAIN_ID,
      {
        ownerChanges: [],
        attributeChanges: [
          attr('did/pub/Secp256k1/veriKey/hex', SECP_PUBKEY_HEX, NOW + 100, 5, 0),
          // 後勝ちで延長 → 有効。1 件に集約される。
          attr('did/pub/Secp256k1/veriKey/hex', SECP_PUBKEY_HEX, NOW + 5000, 12, 0),
        ],
      },
      NOW,
    );
    expect(doc.verificationMethod).toHaveLength(2);
    expect(
      doc.verificationMethod.filter((vm) => vm.type === 'EcdsaSecp256k1VerificationKey2019'),
    ).toHaveLength(1);
  });

  it('blockNumber + logIndex 昇順で安定適用する（owner は最終値）', () => {
    const doc = buildDidEthrDocument(
      DID,
      IDENTITY,
      CHAIN_ID,
      {
        // 順不同で渡しても (blockNumber, logIndex) 昇順で適用される。
        ownerChanges: [owner(ZERO, 20, 1), owner(NEW_OWNER, 20, 0)],
        attributeChanges: [],
      },
      NOW,
    );
    // (20,0)=NEW_OWNER → (20,1)=ZERO の順で適用され、最終 owner は ZERO。
    expect(doc.controller).toBe(`did:ethr:1:${ZERO}`);
    expect(doc.deactivated).toBe(true);
  });

  it('owner = ゼロアドレスは deactivated = true', () => {
    const doc = buildDidEthrDocument(
      DID,
      IDENTITY,
      CHAIN_ID,
      { ownerChanges: [owner(ZERO, 10, 0)], attributeChanges: [] },
      NOW,
    );
    expect(doc.deactivated).toBe(true);
  });

  it('owner = ゼロアドレスでは有効な委任鍵と service を載せない', () => {
    const doc = buildDidEthrDocument(
      DID,
      IDENTITY,
      CHAIN_ID,
      {
        ownerChanges: [owner(ZERO, 10, 0)],
        attributeChanges: [
          attr('did/pub/Secp256k1/veriKey/hex', SECP_PUBKEY_HEX, NOW + 1000, 11, 0),
          attr('did/svc/MessagingService', utf8ToHex('https://example.com/msg'), NOW + 1000, 12, 0),
        ],
      },
      NOW,
    );
    expect(doc.deactivated).toBe(true);
    expect(doc.verificationMethod).toEqual([]);
    expect(doc.authentication).toEqual([]);
    expect(doc.assertionMethod).toEqual([]);
    expect(doc.service).toBeUndefined();
  });

  it('value のデコード失敗（奇数長 hex / 非 hex）は throw せず当該属性をスキップする', () => {
    // 奇数長 hex（Ed25519 base64 鍵）と非 hex（service）は hex.decode が throw するが、
    // 純関数は throw せず当該属性のみスキップする。正常な secp256k1 鍵は残る。
    const events: Erc1056Events = {
      ownerChanges: [],
      attributeChanges: [
        // 奇数長 hex（`0x` 除いて 3 文字）→ デコード失敗 → スキップ。
        attr('did/pub/Ed25519/veriKey/base64', '0xabc', NOW + 1000, 5, 0),
        // 非 hex 文字（`zz`）→ デコード失敗 → スキップ。
        attr('did/svc/MessagingService', '0xzz', NOW + 1000, 6, 0),
        // 正常な secp256k1 veriKey は VM に含まれる。
        attr('did/pub/Secp256k1/veriKey/hex', SECP_PUBKEY_HEX, NOW + 1000, 7, 0),
      ],
    };
    let doc: ReturnType<typeof buildDidEthrDocument> | undefined;
    expect(() => {
      doc = buildDidEthrDocument(DID, IDENTITY, CHAIN_ID, events, NOW);
    }).not.toThrow();
    // #controller + 正常な secp256k1 鍵の 2 件のみ（不正な 2 属性はスキップ）。
    expect(doc?.verificationMethod).toHaveLength(2);
    expect(doc?.service).toBeUndefined();
    expect(doc?.verificationMethod[1]).toEqual({
      id: `${DID}#delegate-1`,
      type: 'EcdsaSecp256k1VerificationKey2019',
      controller: DID,
      publicKeyHex: SECP_PUBKEY_HEX,
    });
  });

  it('複合シナリオのスナップショット', () => {
    const events: Erc1056Events = {
      ownerChanges: [owner(NEW_OWNER, 100, 0)],
      attributeChanges: [
        attr('did/pub/Secp256k1/veriKey/hex', SECP_PUBKEY_HEX, NOW + 10000, 101, 0),
        attr('did/pub/Secp256k1/sigAuth/hex', SECP_PUBKEY_HEX, NOW + 10000, 102, 0),
        attr('did/svc/MessagingService', utf8ToHex('https://example.com/msg'), NOW + 10000, 103, 0),
        // 期限切れは除外される。
        attr('did/pub/Ed25519/veriKey/base64', ED_PUBKEY_HEX, NOW - 1, 104, 0),
      ],
    };
    const doc = buildDidEthrDocument(DID, IDENTITY, CHAIN_ID, events, NOW);
    expect(doc).toMatchSnapshot();
  });
});
