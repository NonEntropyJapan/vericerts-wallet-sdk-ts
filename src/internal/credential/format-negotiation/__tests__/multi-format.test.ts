/**
 * format-negotiation `buildMultiFormatVP` のユニットテスト。
 */

import { describe, expect, test } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { buildMultiFormatVP, type MultiFormatAuditEntry } from '../multi-format.js';
import type { NegotiableCredential, VCSelection } from '../types.js';

function selection(id: string, format: string): VCSelection {
  const chosen: NegotiableCredential = { id, format, alg: 'ES256' };
  return { descriptorId: `desc-${id}`, chosen, alternatives: [] };
}

/** テストで参照しないケース向けの no-op 監査ログ（挙動確認は専用テストで行う）。 */
const noopRecordAudit = () => {};

function sha256Base64url(value: string): string {
  return base64urlnopad.encode(sha256(new TextEncoder().encode(value)));
}

describe('buildMultiFormatVP', () => {
  test('case 4: sd-jwt + mdoc の 2 形式を並行提示。descriptor_map に path_nested', async () => {
    const nonceUsed: string[] = [];
    const token = await buildMultiFormatVP(
      [selection('sd', 'vc+sd-jwt'), selection('md', 'mso_mdoc')],
      {
        definitionId: 'def-1',
        nonce: 'nonce-xyz',
        generateId: () => 'submission-1',
        buildVpFor: async (sel, nonce) => {
          nonceUsed.push(nonce);
          return `vp-${sel.chosen.id}`;
        },
        recordAudit: noopRecordAudit,
      },
    );

    expect(token.vp_token).toEqual(['vp-sd', 'vp-md']);
    // 全 VP で同一 nonce を使用。
    expect(nonceUsed).toEqual(['nonce-xyz', 'nonce-xyz']);
    expect(token.presentation_submission.id).toBe('submission-1');
    expect(token.presentation_submission.definition_id).toBe('def-1');
    expect(token.presentation_submission.descriptor_map).toHaveLength(2);
    const [d0, d1] = token.presentation_submission.descriptor_map;
    expect(d0).toMatchObject({ id: 'desc-sd', format: 'vc+sd-jwt', path: '$[0]' });
    expect(d0?.path_nested).toEqual({ format: 'vc+sd-jwt', path: '$.verifiableCredential[0]' });
    expect(d1).toMatchObject({ id: 'desc-md', format: 'mso_mdoc', path: '$[1]' });
  });

  test('3 形式までは許容される', async () => {
    const token = await buildMultiFormatVP(
      [selection('a', 'vc+sd-jwt'), selection('b', 'mso_mdoc'), selection('c', 'jwt_vc_json')],
      {
        definitionId: 'def',
        nonce: 'n',
        buildVpFor: async (sel) => `vp-${sel.chosen.id}`,
        recordAudit: noopRecordAudit,
      },
    );
    expect(token.vp_token).toHaveLength(3);
  });

  test('4 形式は上限超過で VP_FORMATS_NOT_SUPPORTED', async () => {
    const sels = [
      selection('a', 'vc+sd-jwt'),
      selection('b', 'mso_mdoc'),
      selection('c', 'jwt_vc_json'),
      selection('d', 'ldp_vc'),
    ];
    let thrown: unknown;
    try {
      await buildMultiFormatVP(sels, {
        definitionId: 'd',
        nonce: 'n',
        buildVpFor: async () => 'x',
        recordAudit: noopRecordAudit,
      });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(VericertsError);
    expect((thrown as VericertsError).code).toBe(ErrorCodes.VP_FORMATS_NOT_SUPPORTED);
  });

  test('同一フォーマットが複数 descriptor でも distinct カウントで上限内', async () => {
    const token = await buildMultiFormatVP(
      [
        selection('a', 'vc+sd-jwt'),
        selection('b', 'vc+sd-jwt'),
        selection('c', 'vc+sd-jwt'),
        selection('d', 'vc+sd-jwt'),
      ],
      {
        definitionId: 'd',
        nonce: 'n',
        buildVpFor: async (s) => `vp-${s.chosen.id}`,
        recordAudit: noopRecordAudit,
      },
    );
    expect(token.vp_token).toHaveLength(4);
  });

  test('selection が空なら VP_FORMATS_NOT_SUPPORTED', async () => {
    let thrown: unknown;
    try {
      await buildMultiFormatVP([], {
        definitionId: 'd',
        nonce: 'n',
        buildVpFor: async () => 'x',
        recordAudit: noopRecordAudit,
      });
    } catch (e) {
      thrown = e;
    }
    expect((thrown as VericertsError).code).toBe(ErrorCodes.VP_FORMATS_NOT_SUPPORTED);
  });

  // 各 VP のハッシュが監査ログに個別に記録されることを確認する。
  test('各 VP の SHA-256 ハッシュを個別に監査ログへ記録する', async () => {
    const recorded: MultiFormatAuditEntry[] = [];
    const token = await buildMultiFormatVP(
      [selection('sd', 'vc+sd-jwt'), selection('md', 'mso_mdoc')],
      {
        definitionId: 'def-1',
        nonce: 'nonce-xyz',
        buildVpFor: async (sel) => `vp-${sel.chosen.id}`,
        recordAudit: (entry) => {
          recorded.push(entry);
        },
      },
    );

    expect(recorded).toHaveLength(2);
    expect(recorded).toEqual([
      { descriptorId: 'desc-sd', format: 'vc+sd-jwt', hash: sha256Base64url('vp-sd') },
      { descriptorId: 'desc-md', format: 'mso_mdoc', hash: sha256Base64url('vp-md') },
    ]);
    // VP 本文はハッシュ化されて記録されるだけで、記録される文字列そのものではない。
    expect(recorded[0]?.hash).not.toBe(token.vp_token[0]);
  });

  test('recordAudit が Promise を返す非同期実装でも各 VP のハッシュ記録を待ち合わせる', async () => {
    const recorded: string[] = [];
    await buildMultiFormatVP([selection('a', 'jwt_vc_json')], {
      definitionId: 'def',
      nonce: 'n',
      buildVpFor: async (sel) => `vp-${sel.chosen.id}`,
      recordAudit: async (entry) => {
        await Promise.resolve();
        recorded.push(entry.hash);
      },
    });

    expect(recorded).toEqual([sha256Base64url('vp-a')]);
  });
});
