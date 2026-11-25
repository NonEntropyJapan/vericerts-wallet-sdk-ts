import { describe, expect, setDefaultTimeout, test } from 'bun:test';
import { HEAVY_INPUT_TIMEOUT_MS } from '../../src/internal/__tests__/heavy-input-timeout.js';
import { main } from './monitor.mjs';
import { IDENTITY_PROVIDERS } from './monitor-core.mjs';

setDefaultTimeout(HEAVY_INPUT_TIMEOUT_MS);

const MONITOR = new URL('./monitor.mjs', import.meta.url).pathname;

/** 監視 CLI を別プロセスで実行する（`main()` が import 時に走るため）。 */
function runMonitor(env) {
  const result = Bun.spawnSync(['node', MONITOR], {
    env: { PATH: process.env.PATH, ...env },
    stdout: 'pipe',
    stderr: 'pipe',
  });
  return {
    code: result.exitCode,
    stdout: result.stdout.toString(),
    stderr: result.stderr.toString(),
  };
}

describe('jwk-registry-monitor CLI の環境変数正規化', () => {
  test('RPC URL / アドレスが空白のみ（未設定 secret 相当）ならスキップして exit 0', () => {
    const { code, stdout } = runMonitor({
      JWK_REGISTRY_RPC_URL: '  ',
      JWK_REGISTRY_ADDRESS: '',
    });
    expect(code).toBe(0);
    expect(stdout).toContain('スキップ');
  });

  test('RPC URL / アドレスの片方だけ設定（投入漏れ）は未デプロイ扱いにせず exit 1', () => {
    const address = `0x${'11'.repeat(20)}`;
    for (const env of [
      { JWK_REGISTRY_RPC_URL: 'http://127.0.0.1:1' },
      { JWK_REGISTRY_ADDRESS: address },
      { JWK_REGISTRY_ADDRESS: '', JWK_REGISTRY_SIGNER_KEY: `0x${'22'.repeat(32)}` },
    ]) {
      const { code, stdout, stderr } = runMonitor(env);
      expect(code).toBe(1);
      expect(stdout).not.toContain('スキップ');
      expect(stderr).toContain('JWK_REGISTRY_RPC_URL と JWK_REGISTRY_ADDRESS は両方設定');
    }
  });

  test('JWK_REGISTRY_FROM_BLOCK が不正値なら RPC に触れる前に明示エラーで exit 1', () => {
    const { code, stderr } = runMonitor({
      JWK_REGISTRY_RPC_URL: 'http://127.0.0.1:1',
      JWK_REGISTRY_ADDRESS: `0x${'11'.repeat(20)}`,
      JWK_REGISTRY_FROM_BLOCK: 'abc',
    });
    expect(code).toBe(1);
    expect(stderr).toContain('JWK_REGISTRY_FROM_BLOCK');
  });
});

const VALID_ENV = {
  JWK_REGISTRY_RPC_URL: 'http://127.0.0.1:1',
  JWK_REGISTRY_ADDRESS: `0x${'11'.repeat(20)}`,
};
const GOOD_JWKS = { keys: [{ kty: 'RSA', alg: 'RS256', kid: 'new-kid', n: 'AQAB' }] };

/** チェーン状態スタブ: 何も登録されていない（= JWKS の kid は全て新規）。 */
function stubChainClient({ canExecute }) {
  const executed = [];
  return {
    executed,
    canExecute,
    async getModulusStatus() {
      return { registered: false, notAfter: 0n };
    },
    async getRegisteredEvents() {
      return [];
    },
    async getKey() {
      return { registered: false, revoked: false, notAfter: 0n };
    },
    async registerKey(...args) {
      executed.push(args);
      return '0xtx';
    },
    async setNotAfter() {
      throw new Error('not expected');
    },
    async destroy() {},
  };
}

describe('jwk-registry-monitor main の通知・fail-closed', () => {
  test('署名者未設定で registerKey が必要なら DRY RUN の後に失敗して通知する', async () => {
    const chainClient = stubChainClient({ canExecute: false });
    await expect(
      main({
        env: VALID_ENV,
        fetchJwksImpl: async () => GOOD_JWKS,
        createChainClient: () => chainClient,
      }),
    ).rejects.toThrow('署名者（JWK_REGISTRY_SIGNER_KEY）が未設定');
    expect(chainClient.executed).toHaveLength(0);
  });

  test('署名者ありなら registerKey を実行して正常終了する', async () => {
    const chainClient = stubChainClient({ canExecute: true });
    await main({
      env: VALID_ENV,
      fetchJwksImpl: async () => GOOD_JWKS,
      createChainClient: () => chainClient,
    });
    expect(chainClient.executed).toHaveLength(IDENTITY_PROVIDERS.length);
  });

  test('一方の IdP が空 JWKS でも失敗にするが、他方の IdP の検知は続ける', async () => {
    const chainClient = stubChainClient({ canExecute: true });
    const [first] = IDENTITY_PROVIDERS;
    await expect(
      main({
        env: VALID_ENV,
        fetchJwksImpl: async (url) => (url === first.jwksUri ? { keys: [] } : GOOD_JWKS),
        createChainClient: () => chainClient,
      }),
    ).rejects.toThrow(first.iss);
    expect(chainClient.executed).toHaveLength(IDENTITY_PROVIDERS.length - 1);
  });
});
