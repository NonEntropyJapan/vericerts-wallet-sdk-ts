/**
 * `didcomm/oob.ts`（OOB Invitation 生成・エンコード・デコード・処理）のテスト
 */

import { describe, expect, it } from 'bun:test';
import type { ErrorCode } from '../../errors.js';
import { VericertsError } from '../../errors.js';
import {
  createOutOfBandInvitation,
  decodeOutOfBandInvitationUrl,
  encodeOutOfBandInvitationUrl,
  OUT_OF_BAND_INVITATION_TYPE,
  processOutOfBandInvitation,
} from '../oob.js';

function expectThrowsCode(fn: () => unknown, code: ErrorCode): void {
  expect(fn).toThrow(VericertsError);
  try {
    fn();
    expect.unreachable();
  } catch (error) {
    expect((error as VericertsError).code).toBe(code);
  }
}

function base64urlEncodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8')
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
}

describe('createOutOfBandInvitation / encode / decode', () => {
  it('生成した Invitation を URL へ埋め込み、往復でデコードできる', () => {
    const invitation = createOutOfBandInvitation({
      inviterDid: 'did:peer:2.inviter',
      goalCode: 'issue-vc',
      goal: 'Issue a diploma credential',
      accept: ['didcomm/v2'],
      handshakeProtocols: ['https://didcomm.org/didexchange/1.0'],
    });
    expect(invitation.type).toBe(OUT_OF_BAND_INVITATION_TYPE);
    expect(invitation.from).toBe('did:peer:2.inviter');

    const url = encodeOutOfBandInvitationUrl(invitation, 'https://issuer.example.com/invite');
    expect(url).toContain('https://issuer.example.com/invite?');
    expect(url).toContain('_oob=');

    const decoded = decodeOutOfBandInvitationUrl(url);
    expect(decoded).toEqual(invitation);
  });

  it('ベース URL が不正な形式の場合 OOB_INVITATION_PARSE_FAILED を送出する', () => {
    const invitation = createOutOfBandInvitation({ inviterDid: 'did:peer:2.inviter' });
    expectThrowsCode(() => encodeOutOfBandInvitationUrl(invitation, 'not a url'), '9005');
  });

  it('`_oob` パラメータが無い URL は OOB_INVITATION_PARSE_FAILED', () => {
    expectThrowsCode(
      () => decodeOutOfBandInvitationUrl('https://issuer.example.com/invite'),
      '9005',
    );
  });

  it('`_oob` の base64url デコードに失敗する場合 OOB_INVITATION_PARSE_FAILED', () => {
    expectThrowsCode(
      () =>
        decodeOutOfBandInvitationUrl('https://issuer.example.com/invite?_oob=%25not-base64url%25'),
      '9005',
    );
  });

  it('デコードした JSON が Invitation として不正（`type` 不一致）な場合 OOB_INVITATION_INVALID', () => {
    const notAnInvitation = {
      id: 'x',
      type: 'https://didcomm.org/basicmessage/2.0/message',
      from: 'did:peer:2.x',
      body: {},
    };
    const encoded = base64urlEncodeJson(notAnInvitation);
    expectThrowsCode(
      () => decodeOutOfBandInvitationUrl(`https://issuer.example.com/invite?_oob=${encoded}`),
      '9010',
    );
  });

  it('`from` を欠く Invitation は OOB_INVITATION_INVALID', () => {
    const invalid = { id: 'x', type: OUT_OF_BAND_INVITATION_TYPE, body: {} };
    const encoded = base64urlEncodeJson(invalid);
    expectThrowsCode(
      () => decodeOutOfBandInvitationUrl(`https://issuer.example.com/invite?_oob=${encoded}`),
      '9010',
    );
  });
});

describe('processOutOfBandInvitation', () => {
  it('Invitation を処理し invited 状態の DIDCommConnection を構築する', () => {
    const invitation = createOutOfBandInvitation({ inviterDid: 'did:peer:2.inviter' });
    const url = encodeOutOfBandInvitationUrl(invitation, 'https://issuer.example.com/invite');

    const result = processOutOfBandInvitation(url, 'did:peer:2.me');
    expect(result.connection.state).toBe('invited');
    expect(result.connection.myDID).toBe('did:peer:2.me');
    expect(result.connection.theirDID).toBe('did:peer:2.inviter');
    expect(result.invitation).toEqual(invitation);
  });

  it('connectionId を指定した場合、その ID が使われる', () => {
    const invitation = createOutOfBandInvitation({ inviterDid: 'did:peer:2.inviter' });
    const url = encodeOutOfBandInvitationUrl(invitation, 'https://issuer.example.com/invite');

    const result = processOutOfBandInvitation(url, 'did:peer:2.me', {
      connectionId: 'conn-fixed-id',
    });
    expect(result.connection.id).toBe('conn-fixed-id');
  });
});
