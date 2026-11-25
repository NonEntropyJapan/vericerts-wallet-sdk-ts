/**
 * `expandService`（`mapKeys` 経由）の `.S` ブロック展開の回帰テスト。
 *
 * `mapKeys` は展開結果を通常のオブジェクトリテラル（`{}`）で構築していたため、`Object.prototype`
 * を継承していた。`.S` ブロックが `type`（省略形 `t`）/ `serviceEndpoint`（省略形 `s`）を持たない
 * 場合、`decodeService` の `const { type, serviceEndpoint } = expanded;` はプロトタイプ鎖を辿り、
 * `Object.prototype.type` / `Object.prototype.serviceEndpoint` が汚染された環境では
 * 「本来 type/serviceEndpoint を持たないため拒否されるべき `.S` ブロック」が攻撃者の選んだ
 * `serviceEndpoint` を持つ DIDCommMessaging サービスとして採用されてしまう（fail-open）。
 *
 * **トートロジー回避**: 汚染値と own 値を食い違わせ、own を明示指定したブロックは own 値のまま
 * 解決されることまで検証する。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { Service } from '../../../did.js';
import { createDidPeer2, encodePublicKeyMultibase, resolveDidPeer } from '../../method-peer.js';

const ATTACKER_TYPE = 'DIDCommMessaging';
const ATTACKER_ENDPOINT = 'https://attacker.example';

/** 署名鍵（`.V` 要素）。DIDComm サービスの解決には無関係だが numalgo2 は署名鍵必須。 */
const VER_KEY = encodePublicKeyMultibase('Ed25519', new Uint8Array(32).fill(6));

/** `type` / `serviceEndpoint` を持たない `.S` 省略形ブロックを含む did:peer numalgo2 文字列。 */
function didWithServiceMissingTypeAndEndpoint(): string {
  const encoded = base64urlnopad.encode(new TextEncoder().encode(JSON.stringify({ foo: 'bar' })));
  return `did:peer:2.V${VER_KEY}.S${encoded}`;
}

describe('expandService の mapKeys は Object.prototype を継承しない', () => {
  it('type/serviceEndpoint を持たない .S はデータ汚染下でも INVALID_DID になる', () => {
    const did = didWithServiceMissingTypeAndEndpoint();
    expect(() =>
      withPollutedPrototype({ type: ATTACKER_TYPE, serviceEndpoint: ATTACKER_ENDPOINT }, () =>
        resolveDidPeer(did),
      ),
    ).toThrow(VericertsError);
    try {
      withPollutedPrototype({ type: ATTACKER_TYPE, serviceEndpoint: ATTACKER_ENDPOINT }, () =>
        resolveDidPeer(did),
      );
      throw new Error('unreachable: resolveDidPeer は例外を投げるはず');
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    }
  });

  it('type/serviceEndpoint を持たない .S はアクセサ汚染下でも INVALID_DID になる', () => {
    // getter は呼ばれるたびに新しい値を返せるため、同一性比較による除外を素通りしうる非対称性を突く。
    const did = didWithServiceMissingTypeAndEndpoint();
    expect(() =>
      withPollutedPrototypeAccessor(
        { type: () => ATTACKER_TYPE, serviceEndpoint: () => ATTACKER_ENDPOINT },
        () => resolveDidPeer(did),
      ),
    ).toThrow(VericertsError);
    try {
      withPollutedPrototypeAccessor(
        { type: () => ATTACKER_TYPE, serviceEndpoint: () => ATTACKER_ENDPOINT },
        () => resolveDidPeer(did),
      );
      throw new Error('unreachable: resolveDidPeer は例外を投げるはず');
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    }
  });

  it('type/serviceEndpoint を明示指定した .S は汚染下でも own 値のまま解決される（回帰なし）', () => {
    const service: Service = {
      id: '',
      type: 'DIDCommMessaging',
      serviceEndpoint: 'https://real.example',
    };
    const did = createDidPeer2({ verificationKeys: [VER_KEY], services: [service] });

    const doc = withPollutedPrototype(
      { type: ATTACKER_TYPE, serviceEndpoint: ATTACKER_ENDPOINT },
      () => resolveDidPeer(did),
    );

    expect(doc.service).toEqual([
      { id: `${did}#service`, type: 'DIDCommMessaging', serviceEndpoint: 'https://real.example' },
    ]);
  });

  it('対照: 汚染なしでも type/serviceEndpoint を持たない .S は従来どおり INVALID_DID', () => {
    const did = didWithServiceMissingTypeAndEndpoint();
    expect(() => resolveDidPeer(did)).toThrow(VericertsError);
    try {
      resolveDidPeer(did);
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    }
  });
});
