/**
 * DIDComm 連携を想定したラウンドトリップテスト。
 *
 * 署名鍵（V）・暗号鍵（E）・DIDComm v2 サービス（S）を含む did:peer numalgo 2 を
 * 生成 → 解決し、鍵・サービスが欠落・改変なく往復することを確認する。numalgo 4 についても
 * 完全ドキュメントの往復を確認する。
 */

import { describe, expect, it } from 'bun:test';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import type { Service } from '../../did.js';
import { multibaseBase58Decode } from '../../multibase.js';
import {
  createDidPeer2,
  createDidPeer4,
  encodePublicKeyMultibase,
  MethodPeer,
  resolveDidPeer,
} from '../method-peer.js';
import { p256Key } from './numalgo2-keys.fixtures.js';

describe('numalgo 2 DIDComm ラウンドトリップ', () => {
  it('V/E 鍵と DIDComm v2 サービスが往復で保存される', () => {
    const signKey = encodePublicKeyMultibase(
      'secp256k1',
      getSecp256k1PublicKey(new Uint8Array(32).fill(11), true),
    );
    const encKey = p256Key(12);
    const service: Service = {
      id: '#didcomm',
      type: 'DIDCommMessaging',
      serviceEndpoint: {
        uri: 'https://mediator.example.com',
        accept: ['didcomm/v2'],
        routingKeys: ['did:key:z6MkRoutingKey'],
      },
    };

    const did = createDidPeer2({
      verificationKeys: [signKey],
      keyAgreementKeys: [encKey],
      services: [service],
    });
    const doc = resolveDidPeer(did);

    // 署名鍵: verificationMethod に保存され、authentication / assertionMethod から参照される。
    const vmSign = doc.verificationMethod.find((vm) => vm.publicKeyMultibase === signKey);
    expect(vmSign).toBeDefined();
    expect(doc.authentication).toContain(vmSign?.id ?? '');
    expect(doc.assertionMethod).toContain(vmSign?.id ?? '');

    // 暗号鍵: keyAgreement から参照される。
    const vmEnc = doc.verificationMethod.find((vm) => vm.publicKeyMultibase === encKey);
    expect(vmEnc).toBeDefined();
    expect(doc.keyAgreement).toContain(vmEnc?.id ?? '');

    // 公開鍵が改変なく復元できる（multibase デコードで一致）。
    const decodedSign = multibaseBase58Decode(vmSign?.publicKeyMultibase ?? '');
    const original = multibaseBase58Decode(signKey);
    expect(Array.from(decodedSign)).toEqual(Array.from(original));

    // DIDComm v2 サービスが往復する。id は省略形に含めないため #service が再付与され、
    // type / serviceEndpoint（uri / accept / routingKeys）は改変なく復元される。
    expect(doc.service?.[0]).toEqual({
      id: `${did}#service`,
      type: 'DIDCommMessaging',
      serviceEndpoint: {
        uri: 'https://mediator.example.com',
        accept: ['didcomm/v2'],
        routingKeys: ['did:key:z6MkRoutingKey'],
      },
    });
  });

  it('MethodPeer.create → resolve で署名鍵が一致する', async () => {
    const method = new MethodPeer();
    const publicKey = getP256PublicKey(new Uint8Array(32).fill(13), true);
    const created = await method.create({ keyType: 'P-256', publicKey });
    const resolved = await method.resolve(created.id);
    expect(resolved.id).toBe(created.id);
    expect(resolved.verificationMethod[0]?.publicKeyMultibase).toBe(
      created.verificationMethod[0]?.publicKeyMultibase,
    );
    // create が返すドキュメントと resolve 結果は同一であること。
    expect(resolved).toEqual(created);
  });
});

describe('numalgo 4 完全ドキュメントのラウンドトリップ', () => {
  it('生成元ドキュメントの内容が解決結果に保存される', () => {
    const signKey = encodePublicKeyMultibase(
      'secp256k1',
      getSecp256k1PublicKey(new Uint8Array(32).fill(14), true),
    );
    const document = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [
        { id: '#key-1', type: 'Multikey', controller: '#id', publicKeyMultibase: signKey },
      ],
      authentication: ['#key-1'],
      assertionMethod: ['#key-1'],
      service: [
        {
          id: '#didcomm',
          type: 'DIDCommMessaging',
          serviceEndpoint: { uri: 'https://mediator.example.com', accept: ['didcomm/v2'] },
        },
      ],
    };

    const did = createDidPeer4(document);
    const doc = resolveDidPeer(did);

    expect(doc.id).toBe(did);
    expect(doc.verificationMethod).toEqual(document.verificationMethod);
    expect(doc.service).toEqual(document.service);
    // 短縮形 DID が alsoKnownAs に含まれる。
    const hash = did.slice('did:peer:4'.length).split(':')[0];
    expect(doc.alsoKnownAs).toContain(`did:peer:4${hash}`);
  });
});
