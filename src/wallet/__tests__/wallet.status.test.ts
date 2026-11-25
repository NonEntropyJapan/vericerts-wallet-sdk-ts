/**
 * Wallet ファサードの `createStatusListResolver`の回帰テスト。
 *
 * `createDashboardLogAuditRecorder`（`internal/failsafe/dashboard-audit.ts`）は
 * 実装・単体テスト済みだったが、`createStatusListResolver` の `onPolicyEvent` へ実際に結線する呼び出し側が
 * SDK 内のどこにも無く、「Fail-open 判定を署名付きで Dashboard ログに追記する」が本番コード
 * パスでは一度も成立していなかった。本テストは `wallet.createStatusListResolver` 経由でその配線が実際に
 * 機能することを、`createWallet` で組み立てた本物の Wallet（実 storage / 実鍵）に対して検証する。
 *
 * 検証内容:
 * - `onPolicyEvent` 未指定で Fail-open（FO-1）が発生すると、Wallet の Dashboard ログへ
 *   `failOpenPolicy` エントリが JWS 署名付きで自動的に追記される（配線の主張）。
 * - `onPolicyEvent` を明示指定した場合はそちらが使われ、Dashboard ログには追記されない（上書き優先）。
 */

import { describe, expect, it } from 'bun:test';
import type { PublicKeyJwk } from '../../internal/identity/did.js';
import { MemoryStorage } from '../../storage/storage.js';
import { createWallet } from '../factory.js';
import type { Wallet } from '../types.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** 取得が必ず失敗するため署名検証には到達しない。形式だけ満たすダミー鍵。 */
const DUMMY_ISSUER_KEY: PublicKeyJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
};

/** import + アクティブペルソナ設定済みの Wallet と共有 storage を用意する。 */
async function setup(): Promise<{ wallet: Wallet; storage: MemoryStorage }> {
  const storage = new MemoryStorage();
  const wallet = await createWallet({ storage });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const persona = await wallet.createPersona();
  await wallet.setActivePersona(persona.id);
  return { wallet, storage };
}

/** storage 上のユーザー制御 Dashboard ログのキー数を数える（`wallet.gdpr-export.test.ts` と同じ手法）。 */
async function countDashboardLog(storage: MemoryStorage): Promise<number> {
  return (await storage.list('dashboard-log/')).length;
}

/** 常に失敗する fetchToken。 */
async function failingFetchToken(): Promise<never> {
  throw new Error('network unreachable');
}

describe('Wallet.createStatusListResolver', () => {
  it('onPolicyEvent 省略時、Fail-open（FO-1）で Dashboard ログへ署名付き追記される', async () => {
    const { wallet, storage } = await setup();
    expect(await countDashboardLog(storage)).toBe(0);

    const resolver = await wallet.createStatusListResolver({
      fetchToken: failingFetchToken,
      issuerPublicKey: DUMMY_ISSUER_KEY,
      purpose: 'revocation',
      failSafePolicy: { suppressPrompt: ['FO-1'] },
    });
    const result = await resolver.resolve({
      status_list: { idx: 0, uri: 'https://issuer.example/status/1' },
    });

    expect(result.valid).toBe(true);
    expect(result.warnings).toEqual([
      { policyEvent: 'FO-1', auditEvent: 'status_check_unreachable' },
    ]);
    // 配線が無ければ監査ログの件数は 0 のままになる。
    expect(await countDashboardLog(storage)).toBe(1);

    const blob = await wallet.exportDashboardLog();
    const [entry] = (await blob.text())
      .split('\n')
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(entry?.type).toBe('failOpenPolicy');
    expect(entry?.signature).toBeDefined();
  });

  it('onPolicyEvent を明示指定した場合はそちらが使われ、Dashboard ログには追記されない', async () => {
    const { wallet, storage } = await setup();
    const records: unknown[] = [];

    const resolver = await wallet.createStatusListResolver({
      fetchToken: failingFetchToken,
      issuerPublicKey: DUMMY_ISSUER_KEY,
      purpose: 'revocation',
      failSafePolicy: { suppressPrompt: ['FO-1'] },
      onPolicyEvent: (record) => {
        records.push(record);
      },
    });
    await resolver.resolve({ status_list: { idx: 0, uri: 'https://issuer.example/status/1' } });

    expect(records).toHaveLength(1);
    expect(await countDashboardLog(storage)).toBe(0);
  });
});
