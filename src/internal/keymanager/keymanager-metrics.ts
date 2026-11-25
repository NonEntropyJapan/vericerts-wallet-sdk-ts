/**
 * `KeyManager.encrypt` の所要時間を `vericerts_storage_encrypt_duration_seconds` に記録するサブクラス。
 *
 * `wallet/factory.ts` が生成時にこのクラスへ差し替え、`wallet/wallet.ts`（薄いファサード）は
 * 通常の `KeyManager` として素通し委譲するだけで済む。`encrypt` 以外のメソッドは基底クラスの
 * 実装のまま変更しない。暗号方式（AES-256-GCM）・KDF には一切関与せず、既存の暗号化呼び出しの
 * 前後でレイテンシを計測するだけの計装専用サブクラスである。
 */

import { MetricNames, type Metrics } from '../observability/metrics.js';
import { safeEmit } from '../observability/safe-emit.js';
import type { Storage } from '../storage-port.js';
import type { KdfParams } from './kdf.js';
import { KeyManager } from './keymanager.js';

export class MetricsInstrumentedKeyManager extends KeyManager {
  constructor(
    options: { kdf?: KdfParams; storage?: Storage } | undefined,
    private readonly metrics: Metrics,
  ) {
    super(options);
  }

  override async encrypt(plaintext: Uint8Array, password: string): Promise<Uint8Array> {
    const startedAt = Date.now();
    const ciphertext = await super.encrypt(plaintext, password);
    // 暗号化は成功済み。メトリクス sink の失敗で ciphertext を失わない。
    safeEmit(() =>
      this.metrics
        .histogram(MetricNames.STORAGE_ENCRYPT_DURATION_SECONDS, { algorithm: 'aes-256-gcm' })
        .observe((Date.now() - startedAt) / 1000),
    );
    return ciphertext;
  }
}
