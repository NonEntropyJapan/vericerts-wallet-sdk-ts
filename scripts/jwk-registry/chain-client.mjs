/**
 * 監視対象の `JwkRegistry` を ethers 経由で読み書きする。
 *
 * `monitor-core.mjs` の `planActionsForIdp` が要求する 3 メソッド
 * （`getModulusStatus` / `getRegisteredEvents` / `getKey`）と、実行系 2 メソッド
 * （`registerKey` / `setNotAfter`）を実装する。
 *
 * `signerPrivateKey` を渡さない場合は読み取り専用になり（`canExecute === false`）、
 * `registerKey` / `setNotAfter` は呼び出し側の判断で呼ばずログのみ出す運用（owner が
 * MultiSig の本番環境）を想定する。単一 EOA が owner のステージング環境等でだけ
 * `signerPrivateKey` を設定し、実行まで自動化する。
 */

import { Contract, FetchRequest, JsonRpcProvider, Wallet } from 'ethers';

// 監視に使うイベントと関数の ABI。keyOf の戻り値には、ethers でフィールド名を使えるよう名前を付ける。
const JWK_REGISTRY_ABI = [
  'event KeyRegistered(bytes32 indexed keyId, bytes32 indexed issHash, bytes32 indexed kidHash, bytes32 modulusHash, uint64 notAfter)',
  'function registerKey(bytes32 issHash, bytes32 kidHash, uint256[17] modulus, uint64 notAfter)',
  'function setNotAfter(bytes32 keyId, uint64 notAfter)',
  'function modulusStatusForIss(bytes32 issHash, uint256[17] modulus) view returns (bool registered, uint64 notAfter)',
  'function keyOf(bytes32 keyId) view returns (tuple(bytes32 issHash, bytes32 kidHash, uint64 notAfter, bool revoked, bool registered) key)',
];

/**
 * `fromBlock`（環境変数 `JWK_REGISTRY_FROM_BLOCK` 由来を含む）を走査開始ブロック番号へ正規化する。
 *
 * GitHub Actions は未設定 secret を「未設定の環境変数」ではなく空文字として渡すため、
 * `undefined` / `null` / 空文字 / 空白のみはいずれも未設定と見なして既定 `0` にする
 * （`??` や引数の既定値は空文字を置換しない）。それ以外は 10 進の非負整数のみ許可し、
 * 不正値は ethers の `invalid blockTag` に落とさず明示エラーで fail-closed にする。
 *
 * @param {number | string | null | undefined} value
 * @returns {number}
 */
export function parseFromBlock(value) {
  const normalized = typeof value === 'string' ? value.trim() : value;
  if (normalized === undefined || normalized === null || normalized === '') return 0;
  const block =
    typeof normalized === 'string' && /^\d+$/.test(normalized) ? Number(normalized) : normalized;
  if (!Number.isSafeInteger(block) || block < 0) {
    throw new Error(
      `jwk-registry-chain-client: JWK_REGISTRY_FROM_BLOCK / fromBlock は 0 以上の 10 進整数で指定する（受け取った値: ${JSON.stringify(value)}）`,
    );
  }
  return block;
}

/** JSON-RPC 1 リクエストあたりの待ち時間上限（ミリ秒）。 */
const NETWORK_TIMEOUT_MS = 30_000;

/**
 * @param {object} params
 * @param {string} params.rpcUrl JSON-RPC エンドポイント。
 * @param {string} params.registryAddress `JwkRegistry` のデプロイ先アドレス。
 * @param {string} [params.signerPrivateKey] owner の秘密鍵（16 進、`0x` 有無いずれも可）。
 *   省略時は読み取り専用（`canExecute === false`）。
 * @param {number | string} [params.fromBlock] `KeyRegistered` ログの走査開始ブロック
 *   （既定 `0`。デプロイブロック以降に絞るとログ量を抑えられる）。
 */
export function createChainClient({ rpcUrl, registryAddress, signerPrivateKey, fromBlock }) {
  const fromBlockNumber = parseFromBlock(fromBlock);
  // RPC がスローレスポンスで応答を返さないと cron が詰まる（cancel-in-progress: false）ため打ち切る。
  const request = new FetchRequest(rpcUrl);
  request.timeout = NETWORK_TIMEOUT_MS;
  const provider = new JsonRpcProvider(request);
  const readContract = new Contract(registryAddress, JWK_REGISTRY_ABI, provider);
  const wallet = signerPrivateKey ? new Wallet(signerPrivateKey, provider) : undefined;
  const writeContract = wallet ? readContract.connect(wallet) : undefined;

  return {
    canExecute: writeContract !== undefined,

    async getModulusStatus(issHash, limbs) {
      const [registered, notAfter] = await readContract.modulusStatusForIss(issHash, limbs);
      return { registered, notAfter };
    },

    async getKey(keyId) {
      const key = await readContract.keyOf(keyId);
      return {
        issHash: key.issHash,
        kidHash: key.kidHash,
        notAfter: key.notAfter,
        revoked: key.revoked,
        registered: key.registered,
      };
    },

    async getRegisteredEvents(issHash) {
      const filter = readContract.filters.KeyRegistered(null, issHash);
      const logs = await readContract.queryFilter(filter, fromBlockNumber, 'latest');
      return logs.map((log) => ({
        keyId: log.args.keyId,
        kidHash: log.args.kidHash,
        modulusHash: log.args.modulusHash,
      }));
    },

    /** @returns {Promise<string>} 送信した tx hash。 */
    async registerKey(issHash, kidHash, limbs, notAfter) {
      if (!writeContract)
        throw new Error(
          'jwk-registry-chain-client: signerPrivateKey が未設定のため registerKey を実行できない',
        );
      const tx = await writeContract.registerKey(issHash, kidHash, limbs, notAfter);
      await tx.wait();
      return tx.hash;
    },

    /** @returns {Promise<string>} 送信した tx hash。 */
    async setNotAfter(keyId, notAfter) {
      if (!writeContract)
        throw new Error(
          'jwk-registry-chain-client: signerPrivateKey が未設定のため setNotAfter を実行できない',
        );
      const tx = await writeContract.setNotAfter(keyId, notAfter);
      await tx.wait();
      return tx.hash;
    },

    // JSON-RPC のバッチ待ちタイマーを解放し、監視プロセスが終了できるようにする。
    async destroy() {
      provider.destroy();
    },
  };
}
