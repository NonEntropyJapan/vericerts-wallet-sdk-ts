/**
 * OID4VP Transaction Data による Human Approval の表現と検証。
 *
 * 承認内容を Transaction Data に含め、元の base64url 文字列のハッシュで照合できることを確認する。
 *
 * 検証内容:
 * - `claims` は任意 JSON のため tool 名・引数ダイジェスト・承認プロンプトを同時に運べる。
 * - ハッシュは生 base64url 文字列に対して決定的で、承認内容と 1:1 に対応する。
 * - 承認内容の改竄は `expectedHashes` 突合で 10402 として検知される（暗号的束縛）。
 * - Verifier / Gateway 側の `transaction_data_hashes` 突合は SDK が提供する。
 */

import { describe, expect, it } from 'bun:test';
import * as eudiExports from '../../../../exports/eudi.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { extractTransactionData } from '../extract.js';
import { addKeyBindingWithTransactionData, computeTransactionDataHashes } from '../hashes.js';

/** Authorization Request 上の `transaction_data` 要素（base64url JSON）を作る。 */
function encodeEntry(obj: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

/** MCP Gateway が tool 実行前の人間承認を要求する Transaction Data。 */
const APPROVAL_CLAIMS = {
  type: 'mcp-tool-invocation',
  credential_ids: ['agent-authorization-vc'],
  tool_name: 'delete_file',
  tool_arguments_digest: 'sha256-2f8a1c',
  approval_prompt: 'エージェントが delete_file を実行します。承認しますか？',
  requires_human_approval: true,
};

describe('Transaction Data の claims は tool 情報と承認要求を同時に運べる', () => {
  it('任意フィールドが型を保ったまま claims に復元される', () => {
    const [entry] = extractTransactionData([encodeEntry(APPROVAL_CLAIMS)]);
    expect(entry?.type).toBe('mcp-tool-invocation');
    expect(entry?.credentialIds).toEqual(['agent-authorization-vc']);
    // termsOfUse の UsageContext（4 フィールド固定）と違い、任意のキーを追加できる。
    expect(entry?.claims.tool_name).toBe('delete_file');
    expect(entry?.claims.tool_arguments_digest).toBe('sha256-2f8a1c');
    expect(entry?.claims.requires_human_approval).toBe(true);
    expect(entry?.claims.approval_prompt).toBe(
      'エージェントが delete_file を実行します。承認しますか？',
    );
  });

  it('hashAlgorithms は省略時 sha-256 に正規化される', () => {
    const [entry] = extractTransactionData([encodeEntry(APPROVAL_CLAIMS)]);
    expect(entry?.hashAlgorithms).toEqual(['sha-256']);
  });
});

describe('承認内容とハッシュは 1:1 に対応する', () => {
  it('同一内容は同一ハッシュ、tool 名が変われば別ハッシュになる', () => {
    const approve = extractTransactionData([encodeEntry(APPROVAL_CLAIMS)]);
    const again = extractTransactionData([encodeEntry(APPROVAL_CLAIMS)]);
    const other = extractTransactionData([
      encodeEntry({ ...APPROVAL_CLAIMS, tool_name: 'read_file' }),
    ]);
    expect(computeTransactionDataHashes(approve)).toEqual(computeTransactionDataHashes(again));
    expect(computeTransactionDataHashes(approve)).not.toEqual(computeTransactionDataHashes(other));
  });
});

describe('承認内容の差し替えは 10402 として検知される', () => {
  const signer = createPrivateKeySigner(new Uint8Array(32).fill(3), 'ES256');
  const sdJwt = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3MifQ.c2ln~';

  it('UI で承認した内容のハッシュと KB-JWT 格納分が一致すれば KB-JWT を付与できる', () => {
    const entries = extractTransactionData([encodeEntry(APPROVAL_CLAIMS)]);
    const presented = addKeyBindingWithTransactionData(sdJwt, signer, {
      nonce: 'n-1',
      audience: 'did:example:mcp-gateway',
      transactionData: entries,
      expectedHashes: computeTransactionDataHashes(entries),
      iatSeconds: 1_767_225_600,
    });
    expect(presented.startsWith(sdJwt)).toBe(true);
    const kbPayload = JSON.parse(
      Buffer.from(presented.slice(sdJwt.length).split('.')[1] ?? '', 'base64url').toString(),
    );
    expect(kbPayload.transaction_data_hashes).toEqual(computeTransactionDataHashes(entries));
    expect(kbPayload.transaction_data_hashes_alg).toBe('sha-256');
  });

  it('承認後に tool 名を差し替えると 10402 で拒否される', () => {
    const approved = extractTransactionData([encodeEntry(APPROVAL_CLAIMS)]);
    const tampered = extractTransactionData([
      encodeEntry({ ...APPROVAL_CLAIMS, tool_name: 'exfiltrate' }),
    ]);
    expect(() =>
      addKeyBindingWithTransactionData(sdJwt, signer, {
        nonce: 'n-1',
        audience: 'did:example:mcp-gateway',
        transactionData: tampered,
        // 人間が承認したのは delete_file の方。
        expectedHashes: computeTransactionDataHashes(approved),
        iatSeconds: 1_767_225_600,
      }),
    ).toThrow(new VericertsError(ErrorCodes.TRANSACTION_DATA_HASH_MISMATCH));
  });
});

describe('Verifier 側のハッシュ突合は SDK が提供する', () => {
  const signer = createPrivateKeySigner(new Uint8Array(32).fill(3), 'ES256');
  const sdJwt = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3MifQ.c2ln~';

  /** Gateway が承認内容を要求し、Holder が同意して KB-JWT を付与した提示を作る。 */
  function presentApproval(): string {
    return addKeyBindingWithTransactionData(sdJwt, signer, {
      nonce: 'n-1',
      audience: 'did:example:mcp-gateway',
      transactionData: extractTransactionData([encodeEntry(APPROVAL_CLAIMS)]),
      iatSeconds: 1_767_225_600,
    });
  }

  it('eudi の公開 API に transaction_data_hashes を突合する関数がある', () => {
    const names = Object.keys(eudiExports).filter((n) => /transaction_?data/i.test(n));
    // 抽出・計算・付与・同意記録に加え、受領側突合（verify）も SDK が提供する。
    expect(names.sort()).toEqual([
      'TRANSACTION_DATA_CONSENT_LOG_TYPE',
      'TRANSACTION_DATA_HASH_ALG',
      'addKeyBindingWithTransactionData',
      'buildTransactionDataConsentPayload',
      'computeTransactionDataHashes',
      'computeTransactionDataHashesWithAlg',
      'extractTransactionData',
      'recordTransactionDataConsent',
      'verifyTransactionDataHashes',
    ]);
  });

  it('Gateway は要求した承認内容と受領提示のハッシュを突合できる', () => {
    expect(() =>
      eudiExports.verifyTransactionDataHashes({
        requested: extractTransactionData([encodeEntry(APPROVAL_CLAIMS)]),
        presentation: presentApproval(),
      }),
    ).not.toThrow();
  });

  it('Gateway の要求した tool 名と受領提示が食い違えば 10402 で拒否される', () => {
    expect(() =>
      eudiExports.verifyTransactionDataHashes({
        // Gateway が要求したのは read_file だが、提示は delete_file の承認に束縛されている。
        requested: extractTransactionData([
          encodeEntry({ ...APPROVAL_CLAIMS, tool_name: 'read_file' }),
        ]),
        presentation: presentApproval(),
      }),
    ).toThrow(VericertsError);
    try {
      eudiExports.verifyTransactionDataHashes({
        requested: extractTransactionData([
          encodeEntry({ ...APPROVAL_CLAIMS, tool_name: 'read_file' }),
        ]),
        presentation: presentApproval(),
      });
      throw new Error('unreachable');
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.TRANSACTION_DATA_HASH_MISMATCH);
    }
  });
});
