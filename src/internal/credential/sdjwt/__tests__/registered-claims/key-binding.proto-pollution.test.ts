/**
 * KB-JWT 生成の残存プロトタイプ読み取りの回帰テスト。
 *
 * `createKeyBindingTemplate` の `nonce` / `audience` は型上必須だが、型の無い JS から渡し忘れると
 * プロトタイプ鎖の汚染値が「指定された値」に化け、`assertBindingValue`（空文字・非文字列を弾く）
 * を素通りして **KB-JWT の署名対象 payload** に載る。Verifier 側のリプレイ対策（`nonce`）と
 * audience バインド（`aud`）が攻撃者の選んだ値になる。
 *
 * `addKeyBindingWithTransactionData` の `iatSeconds` も同じ経路で、署名済み KB-JWT の `iat` が
 * 攻撃者の選んだ時刻に固定される（鮮度判定の無効化）。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { extractTransactionData } from '../../../../eudi/transaction-data/extract.js';
import { addKeyBindingWithTransactionData } from '../../../../eudi/transaction-data/hashes.js';
import { createPrivateKeySigner } from '../../../vc/signer.js';
import { createKeyBindingTemplate } from '../../key-binding.js';
import { AUD, issue, NONCE, SESSION_ALG } from '../key-binding.fixtures.js';

describe('createKeyBindingTemplate の残存汚染読み取り', () => {
  it('継承した nonce / audience は KB-JWT の署名対象に載らず 3012 で拒否する', () => {
    expect(() =>
      withPollutedPrototype({ nonce: 'attacker-nonce', audience: 'https://attacker.example' }, () =>
        // `nonce` / `audience` を渡していない呼び出し（型の無い JS からの渡し忘れ相当）。
        createKeyBindingTemplate(issue(), { alg: SESSION_ALG } as Parameters<
          typeof createKeyBindingTemplate
        >[1]),
      ),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('継承した iatSeconds は KB-JWT の署名対象に載らない', () => {
    // `iatSeconds` を**明示指定しない**こと。明示すると own 値が汚染値を隠してしまい、
    // 修正前でも pass するトートロジーになる。汚染値が `iat` になっていないことで検出する。
    const attackerIat = 1_000_000;
    const template = withPollutedPrototype({ iatSeconds: attackerIat }, () =>
      createKeyBindingTemplate(issue(), { alg: SESSION_ALG, nonce: NONCE, audience: AUD }),
    );
    expect(template.payload.iat).not.toBe(attackerIat);
  });

  it('明示的に渡した nonce / audience は従来どおり payload に載る（正常系）', () => {
    const template = createKeyBindingTemplate(issue(), {
      alg: SESSION_ALG,
      nonce: NONCE,
      audience: AUD,
      iatSeconds: 1_700_000_000,
    });
    expect(template.payload.nonce).toBe(NONCE);
    expect(template.payload.aud).toBe(AUD);
    expect(template.payload.iat).toBe(1_700_000_000);
  });
});

describe('addKeyBindingWithTransactionData の iatSeconds 汚染耐性', () => {
  const signer = createPrivateKeySigner(new Uint8Array(32).fill(3), 'ES256');
  const sdJwt = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3MifQ.c2ln~';
  const entries = extractTransactionData([
    Buffer.from(
      JSON.stringify({ type: 'mcp_tool_approval_v1', credential_ids: ['vc-1'], tool_name: 'ls' }),
    ).toString('base64url'),
  ]);

  it('継承した iatSeconds は署名済み KB-JWT の iat に載らない', () => {
    const attackerIat = 1_000_000;
    const presented = withPollutedPrototype({ iatSeconds: attackerIat }, () =>
      addKeyBindingWithTransactionData(sdJwt, signer, {
        nonce: 'n-1',
        audience: 'did:example:mcp-gateway',
        transactionData: entries,
      }),
    );
    const payload = JSON.parse(
      Buffer.from(presented.slice(sdJwt.length).split('.')[1] ?? '', 'base64url').toString('utf8'),
    ) as Record<string, unknown>;
    expect(payload.iat).not.toBe(attackerIat);
  });

  it('明示的に渡した iatSeconds は従来どおり反映される（正常系）', () => {
    const presented = addKeyBindingWithTransactionData(sdJwt, signer, {
      nonce: 'n-1',
      audience: 'did:example:mcp-gateway',
      transactionData: entries,
      iatSeconds: 1_767_225_600,
    });
    const payload = JSON.parse(
      Buffer.from(presented.slice(sdJwt.length).split('.')[1] ?? '', 'base64url').toString('utf8'),
    ) as Record<string, unknown>;
    expect(payload.iat).toBe(1_767_225_600);
  });
});
