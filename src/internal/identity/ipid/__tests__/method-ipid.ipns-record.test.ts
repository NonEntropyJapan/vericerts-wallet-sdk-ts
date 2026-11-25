/**
 * did:ipid:<ipns-name> の解決は IPNS レコードの署名と解決先 CID の本文ハッシュを検証する。
 *
 * 以前は Gateway の `/ipns/<name>` 応答を署名検証も CID 照合もなしに DID Document として採用していたため、
 * Gateway（またはその前段）が任意の検証鍵を含む偽造文書を返せた。実時間ではなく、拒否の `reason`・
 * Gateway への要求回数・予算計上で pin する。攻撃形状（署名鍵 / 名前 / 期限 / Value / 署名外フィールド /
 * 本文差し替え / 検証不能な名前）を変えて確かめる。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ed25519 } from '@noble/curves/ed25519.js';
import { base58 } from '@scure/base';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import { createResolutionWorkBudget, WORK_UNITS_PER_SIGNATURE } from '../../resolution-budget.js';
import { MethodIpid } from '../method-ipid.js';
import { toBase36 } from './cid-fixture.js';
import { type IpnsRecordSpec, ipnsGateway, ipnsNameOf } from './ipns-fixture.js';

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});

const SEED = 21;
const NAME = ipnsNameOf(SEED);
const DID = `did:ipid:${NAME}`;
const docWith = (key: string, id: string = DID): string =>
  JSON.stringify({
    '@context': ['https://www.w3.org/ns/did/v1'],
    id,
    verificationMethod: [
      { id: `${id}#k`, type: 'Multikey', controller: id, publicKeyMultibase: key },
    ],
    authentication: [`${id}#k`],
    assertionMethod: [`${id}#k`],
  });
const GENUINE = docWith('zGENUINE');
const FORGED = docWith('zFORGEDBYGATEWAY');

async function failureOf(promise: Promise<unknown>): Promise<VericertsError> {
  try {
    await promise;
  } catch (error) {
    return error as VericertsError;
  }
  throw new Error('should have thrown');
}

describe('did:ipid:<ipns-name>: レコード署名と解決先 CID の検証', () => {
  it('正規のレコードと本文は解決でき、Gateway へはレコード→本文の 2 要求だけ送る', async () => {
    const gateway = ipnsGateway(SEED, GENUINE);
    globalThis.fetch = gateway.fetch;
    const doc = await new MethodIpid().resolve(DID);
    expect(doc.verificationMethod[0]?.publicKeyMultibase).toBe('zGENUINE');
    expect(gateway.urls).toHaveLength(2);
  });

  it('PeerID 表記（12D3Koo… = base58 の identity multihash）も同じ検証を通る', async () => {
    const proto = Uint8Array.from([
      0x08,
      0x01,
      0x12,
      0x20,
      ...ed25519.getPublicKey(new Uint8Array(32).fill(SEED)),
    ]);
    const peerId = base58.encode(Uint8Array.from([0x00, proto.length, ...proto]));
    expect(peerId.startsWith('12D3Koo')).toBe(true);
    const did = `did:ipid:${peerId}`;
    const gateway = ipnsGateway(SEED, docWith('zGENUINE', did));
    // 名前は PeerID 表記なので、レコード応答の経路だけを差し替える。
    const served = gateway.fetch;
    globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) =>
      served(String(input).replace(peerId, NAME), init)) as typeof fetch;
    const doc = await new MethodIpid().resolve(did);
    expect(doc.id).toBe(did);
  });

  it('再現手順の攻撃: Gateway が /ipns/ で偽造 DID Document(JSON) を返しても採用しない', async () => {
    globalThis.fetch = (async () =>
      new Response(FORGED, {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })) as unknown as typeof fetch;
    const error = await failureOf(new MethodIpid().resolve(DID));
    expect(error.code).toBe(ErrorCodes.DID_DOC_INVALID);
  });

  it('偽造 JSON を IPNS レコードの Content-Type で返しても protobuf として不正なので拒否する', async () => {
    globalThis.fetch = (async () =>
      new Response(FORGED, {
        status: 200,
        headers: { 'content-type': 'application/vnd.ipfs.ipns-record' },
      })) as unknown as typeof fetch;
    const error = await failureOf(new MethodIpid().resolve(DID));
    expect(error.code).toBe(ErrorCodes.DID_DOC_INVALID);
    expect(error.context?.reason).toBe('ipns_record_malformed');
  });

  const attacks: ReadonlyArray<readonly [string, IpnsRecordSpec, string]> = [
    [
      '別の鍵で署名したレコード（名前の所有者でない）',
      { signerSeed: SEED + 1 },
      'ipns_signature_invalid',
    ],
    ['期限切れのレコード', { validity: '2020-01-01T00:00:00.000000000Z' }, 'ipns_record_expired'],
    ['署名後に data を 1 ビット改ざん', { tamperData: true }, 'ipns_signature_invalid'],
    ['Value が /ipns/ を指す（連鎖）', { value: `/ipns/${NAME}` }, 'ipns_value_invalid'],
    ['Value が /ipfs/ 以外', { value: 'https://evil.example/doc.json' }, 'ipns_value_invalid'],
    [
      '署名外の protobuf Value だけを差し替え',
      { outsideValue: '/ipfs/bafyattacker' },
      'ipns_record_malformed',
    ],
    ['有効期限の書式不正', { validity: 'tomorrow' }, 'ipns_record_malformed'],
  ];

  it.each(attacks)('%s は拒否する', async (_name, spec, reason) => {
    const gateway = ipnsGateway(SEED, GENUINE, spec);
    globalThis.fetch = gateway.fetch;
    const error = await failureOf(new MethodIpid().resolve(DID));
    expect(error.code).toBe(ErrorCodes.DID_DOC_INVALID);
    expect(error.context?.reason).toBe(reason);
    // レコード検証に失敗したら本文（/ipfs/）は取りに行かない。
    expect(gateway.urls).toHaveLength(1);
  });

  it('別名のレコードの再送（他者が署名した有効なレコードを流用）は拒否する', async () => {
    const other = ipnsGateway(SEED + 2, GENUINE);
    // 他者の名前宛のレコードを、こちらの名前の要求への応答として返す。
    globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) =>
      other.fetch(String(input).replace(NAME, ipnsNameOf(SEED + 2)), init)) as typeof fetch;
    const error = await failureOf(new MethodIpid().resolve(DID));
    expect(error.context?.reason).toBe('ipns_signature_invalid');
  });

  it('署名済みレコードが指す CID の本文を Gateway が差し替えたら cid_mismatch で拒否する', async () => {
    const gateway = ipnsGateway(SEED, GENUINE, {}, FORGED);
    globalThis.fetch = gateway.fetch;
    const error = await failureOf(new MethodIpid().resolve(DID));
    expect(error.code).toBe(ErrorCodes.DID_DOC_INVALID);
    expect(error.context?.reason).toBe('cid_mismatch');
    expect(gateway.urls).toHaveLength(2);
  });

  it('公開鍵を名前に持たない libp2p-key（sha2-256 形式）は Gateway へ要求を送らず拒否する', async () => {
    const name = toBase36(Uint8Array.from([0x01, 0x72, 0x12, 0x20, ...new Uint8Array(32).fill(7)]));
    const requested: string[] = [];
    globalThis.fetch = (async (input: string | URL | Request) => {
      requested.push(String(input));
      return new Response(FORGED, { status: 200, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;
    const error = await failureOf(new MethodIpid().resolve(`did:ipid:${name}`));
    expect(error.code).toBe(ErrorCodes.DID_DOC_INVALID);
    expect(error.context?.reason).toBe('ipns_key_unsupported');
    expect(requested).toHaveLength(0);
  });

  it('Ed25519 以外の鍵（secp256k1 の identity multihash）の名前も拒否する', async () => {
    const proto = [0x08, 0x02, 0x12, 0x21, ...new Uint8Array(33).fill(2)];
    const name = toBase36(Uint8Array.from([0x01, 0x72, 0x00, proto.length, ...proto]));
    globalThis.fetch = (async () => {
      throw new Error('must not fetch');
    }) as unknown as typeof fetch;
    const error = await failureOf(new MethodIpid().resolve(`did:ipid:${name}`));
    expect(error.context?.reason).toBe('ipns_key_unsupported');
  });

  it('10 KiB を超えるレコードは読み切らずに 2003 で拒否する', async () => {
    globalThis.fetch = (async () =>
      new Response(new Uint8Array(10 * 1024 + 1), {
        status: 200,
        headers: { 'content-type': 'application/vnd.ipfs.ipns-record' },
      })) as unknown as typeof fetch;
    const error = await failureOf(new MethodIpid().resolve(DID));
    expect(error.code).toBe(ErrorCodes.DID_NOT_FOUND);
    expect(error.context?.reason).toBe('oversized_body');
  });

  it('署名検証 1 回ぶんの仕事量が残っていないスコープは、レコード取得後・署名検証の前に拒否する', async () => {
    const gateway = ipnsGateway(SEED, GENUINE);
    globalThis.fetch = gateway.fetch;
    const scope = createResolutionWorkBudget(WORK_UNITS_PER_SIGNATURE - 1);
    const error = await failureOf(new MethodIpid().resolve(DID, scope));
    expect(error.code).toBe(ErrorCodes.INVALID_DID);
    expect(error.context?.reason).toBe('resolution_work_limit');
    expect(gateway.urls).toHaveLength(1);
  });

  it('署名検証 1 回ぶんちょうどの仕事量があれば解決でき、ちょうど使い切る', async () => {
    globalThis.fetch = ipnsGateway(SEED, GENUINE).fetch;
    const scope = createResolutionWorkBudget(WORK_UNITS_PER_SIGNATURE);
    await new MethodIpid().resolve(DID, scope);
    expect(scope.remaining).toBe(0);
  });

  it('本文量が尽きたスコープでは、レコード取得の要求自体を送らない', async () => {
    const gateway = ipnsGateway(SEED, GENUINE);
    globalThis.fetch = gateway.fetch;
    const scope = createResolutionWorkBudget(WORK_UNITS_PER_SIGNATURE, 0);
    const error = await failureOf(new MethodIpid().resolve(DID, scope));
    expect(error.context?.reason).toBe('resolution_work_limit');
    expect(gateway.urls).toHaveLength(0);
  });
});
