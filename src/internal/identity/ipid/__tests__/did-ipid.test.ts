/**
 * parseDidIpid の DID 形式パース検証。
 *
 * CID 形式 / IPNS 名形式の分類、および形式不正（プレフィックス不正・空・不正文字）の
 * `INVALID_DID`（2001）を検証する。
 */

import { describe, expect, it } from 'bun:test';
import { base32nopad, base58 } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { parseDidIpid } from '../did-ipid.js';
import { cidV0Of, ipnsNameOf, rawCidBase36Of, rawCidOf } from './cid-fixture.js';

describe('parseDidIpid', () => {
  it('CIDv1 raw（base32 b...）は kind=cid に分類する', () => {
    const cid = rawCidOf('doc');
    const parsed = parseDidIpid(`did:ipid:${cid}`);
    expect(parsed.kind).toBe('cid');
    expect(parsed.identifier).toBe(cid);
  });

  it('CIDv1 raw（base36 k...）は ipns ではなく kind=cid に分類する', () => {
    const cid = rawCidBase36Of('doc');
    expect(cid.startsWith('k')).toBe(true);
    expect(parseDidIpid(`did:ipid:${cid}`).kind).toBe('cid');
  });

  it('CIDv0（Qm...）は ipns ではなく kind=cid に分類する', () => {
    const cid = cidV0Of('doc');
    expect(cid.startsWith('Qm')).toBe(true);
    expect(parseDidIpid(`did:ipid:${cid}`).kind).toBe('cid');
  });

  it('dag-pb の CIDv1（base32 bafybei...）は kind=cid に分類する', () => {
    const dagPb = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi';
    expect(parseDidIpid(`did:ipid:${dagPb}`).kind).toBe('cid');
  });

  it('IPNS 名（libp2p-key の CIDv1 base36 k51...）は kind=ipns に分類する', () => {
    const name = ipnsNameOf(3);
    expect(name.startsWith('k51')).toBe(true);
    const parsed = parseDidIpid(`did:ipid:${name}`);
    expect(parsed.kind).toBe('ipns');
    expect(parsed.identifier).toBe(name);
  });

  it('IPNS 名（libp2p-key の CIDv1 base32 bafzaa...）も multicodec で ipns に分類する', () => {
    const libp2pKey = new Uint8Array([0x01, 0x72, 0x00, 0x04, 0x08, 0x01, 0x12, 0x00]);
    const id = `b${base32nopad.encode(libp2pKey).toLowerCase()}`;
    expect(parseDidIpid(`did:ipid:${id}`).kind).toBe('ipns');
  });

  it('IPNS 名（Ed25519 PeerID 12D3Koo...）は kind=ipns に分類する', () => {
    const peerId = base58.encode(
      new Uint8Array([0x00, 0x24, 0x08, 0x01, 0x12, 0x20, ...new Uint8Array(32).fill(1)]),
    );
    expect(peerId.startsWith('12D3Koo')).toBe(true);
    expect(parseDidIpid(`did:ipid:${peerId}`).kind).toBe('ipns');
  });

  it.each([
    ['CID としても PeerID としても復号できない k...', 'k51qzi5uqu5dexampleipnsname'],
    ['先頭 0 の非正準 base36', 'k0'],
    ['復号できない Qm...', 'QmExampleName'],
    ['未知の multibase プレフィックスで復号不能', 'bafybeigdyrexamplecid'],
    [
      'sha2-256 以外の multihash の PeerID 形',
      base58.encode(new Uint8Array([0x11, 0x20, ...new Uint8Array(32)])),
    ],
  ])('%s は 2001', (_name, id) => {
    expect(() => parseDidIpid(`did:ipid:${id}`)).toThrow(
      new VericertsError(ErrorCodes.INVALID_DID),
    );
  });

  it('プレフィックス不正は 2001', () => {
    expect(() => parseDidIpid('did:web:example.com')).toThrow(
      new VericertsError(ErrorCodes.INVALID_DID),
    );
  });

  it('識別子が空は 2001', () => {
    expect(() => parseDidIpid('did:ipid:')).toThrow(new VericertsError(ErrorCodes.INVALID_DID));
  });

  it('経路偽装になり得る不正文字（/）を含むと 2001', () => {
    let caught: unknown;
    try {
      parseDidIpid('did:ipid:bafy/../secret');
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
  });
});
