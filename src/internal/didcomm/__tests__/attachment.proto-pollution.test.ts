/**
 * 受信 DIDComm メッセージから JWT-VC / JWT-VP を取り出す読み（`extractIssuedCredentialJwt` /
 * `extractPresentationJwt`）が `Object.prototype` の汚染値を拾わないことの回帰テスト。
 *
 * `type` / `attachments[].data` / `data.base64` は型上は必須だが実体は受信 JSON で、省略したメッセージが汚染値
 * （攻撃者の JWT・種別）を継承すると、取り出した資格情報が攻撃者の値になる。
 */

import { describe, expect, it } from 'bun:test';
import { base64 } from '@scure/base';
import { withPollutedPrototype } from '../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes } from '../../errors.js';
import { extractIssuedCredentialJwt, ISSUE_CREDENTIAL_ISSUE_TYPE } from '../issue-credential.js';
import { extractPresentationJwt, PRESENT_PROOF_PRESENTATION_TYPE } from '../present-proof.js';
import type { DIDCommPlaintextMessage } from '../types.js';

const EVIL_JWT = base64.encode(new TextEncoder().encode('evil.jwt.value'));
const OK_JWT = base64.encode(new TextEncoder().encode('ok.jwt.value'));

const targets = [
  ['issue-credential', ISSUE_CREDENTIAL_ISSUE_TYPE, extractIssuedCredentialJwt],
  ['present-proof', PRESENT_PROOF_PRESENTATION_TYPE, extractPresentationJwt],
] as const;

function message(type: string | undefined, attachments: unknown): DIDCommPlaintextMessage {
  return {
    id: 'm',
    ...(type === undefined ? {} : { type }),
    body: {},
    ...(attachments === undefined ? {} : { attachments }),
  } as unknown as DIDCommPlaintextMessage;
}

for (const [name, type, extract] of targets) {
  describe(`${name}: 添付の取り出しは own 限定`, () => {
    it('own の添付は汚染下でも own の値を返す', () => {
      const own = message(type, [{ id: 'a', data: { base64: OK_JWT } }]);
      const polluted = withPollutedPrototype({ data: { base64: EVIL_JWT } }, () => extract(own));
      expect(polluted).toBe('ok.jwt.value');
    });

    it('type を省略したメッセージは汚染 type で受理しない', () => {
      const noType = message(undefined, [{ data: { base64: OK_JWT } }]);
      expect(() => extract(noType)).toThrow(
        expect.objectContaining({ code: ErrorCodes.DIDCOMM_UNPACKING_FAILED }),
      );
      expect(() => withPollutedPrototype({ type }, () => extract(noType))).toThrow(
        expect.objectContaining({ code: ErrorCodes.DIDCOMM_UNPACKING_FAILED }),
      );
    });

    it('attachments を省略したメッセージは汚染 attachments を使わない', () => {
      const none = message(type, undefined);
      expect(() =>
        withPollutedPrototype({ attachments: [{ data: { base64: EVIL_JWT } }] }, () =>
          extract(none),
        ),
      ).toThrow(expect.objectContaining({ code: ErrorCodes.DIDCOMM_UNPACKING_FAILED }));
    });

    it('data を省略した添付は汚染 data を拾わない（生 TypeError も漏らさない）', () => {
      const noData = message(type, [{ id: 'a' }]);
      expect(() =>
        withPollutedPrototype({ data: { base64: EVIL_JWT } }, () => extract(noData)),
      ).toThrow(expect.objectContaining({ code: ErrorCodes.DIDCOMM_UNPACKING_FAILED }));
    });

    it('data.base64 を省略した添付は汚染 base64 を拾わない', () => {
      const noBase64 = message(type, [{ id: 'a', data: { json: {} } }]);
      expect(() => withPollutedPrototype({ base64: EVIL_JWT }, () => extract(noBase64))).toThrow(
        expect.objectContaining({ code: ErrorCodes.DIDCOMM_UNPACKING_FAILED }),
      );
    });
  });
}
