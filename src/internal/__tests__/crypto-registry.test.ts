/**
 * `crypto-registry.ts` の単体テスト。
 *
 * 検証内容:
 * - `getAlgorithmStatus` は各カテゴリの代表的なアルゴリズム ID について
 *   正しいステータスを返す（`recommended` / `acceptable` / `deprecated` / `prohibited` /
 *   `experimental` / `unsupported`）。
 * - 未登録の id には `undefined` を返す（不明を「安全側」として fail-open しない）。
 * - `CRYPTO_ALGORITHM_REGISTRY` は ID で検索でき、`ES256@1.0` は `signature` / `recommended` として登録されている。
 * - 全エントリの `status` が `AlgorithmStatus` の許容値のいずれかである（データ整合性）。
 * - モジュール読み込み自体が成功していること（`REGISTRY_ENTRIES` に `id` 重複があれば
 *   モジュール初期化時に throw するため、このファイルが実行できている時点で重複が無いことの
 *   回帰検知になる）。
 */

import { describe, expect, it } from 'bun:test';
import {
  type AlgorithmStatus,
  CRYPTO_ALGORITHM_REGISTRY,
  getAlgorithmStatus,
} from '../crypto-registry.js';

describe('getAlgorithmStatus はアルゴリズム ID に対応するステータスを返す', () => {
  it.each([
    ['ES256@1.0', 'recommended'],
    ['EdDSA-Ed25519@1.0', 'recommended'],
    ['ES256K@1.0', 'acceptable'],
    ['RSA-PSS-SHA256@0.9', 'deprecated'],
    ['SHA-1@1.0', 'prohibited'],
    ['ML-DSA-44@1.0', 'experimental'],
    ['ES384@1.0', 'unsupported'],
    ['BBS-2023@1.0', 'unsupported'],
    ['AES-256-GCM@1.0', 'recommended'],
    ['Argon2id@1.0', 'recommended'],
    ['SHA-256@1.0', 'recommended'],
  ] as const)('%s のステータスは %s', (id, expected) => {
    expect(getAlgorithmStatus(id)).toBe(expected);
  });

  it('未登録の id は undefined を返す（fail-open せず「不明」を表す）', () => {
    expect(getAlgorithmStatus('NOT-A-REGISTERED-ALGORITHM@9.9')).toBeUndefined();
  });
});

describe('CRYPTO_ALGORITHM_REGISTRY は id で引けるエントリ集合を提供する', () => {
  it('id からエントリを引くと category / status が一致する', () => {
    const entry = CRYPTO_ALGORITHM_REGISTRY['ES256@1.0'];
    expect(entry?.category).toBe('signature');
    expect(entry?.status).toBe('recommended');
    expect(entry?.id).toBe('ES256@1.0');
  });

  it.each([
    ['ES384@1.0', 'BSI TR-02102-1 推奨。SDK 未受理'],
    ['BBS-2023@1.0', '選択的開示 + Unlinkability。SDK 未受理'],
    ['RSA-PKCS1-SHA256@1.0', 'X.509 証明書署名専用'],
    ['ES256K-R@1.0', 'did:pkh / did:ethr の controller 鍵限定の標準外の例外'],
  ] as const)('%s の採用根拠と適用範囲を説明文だけで読める', (id, rationale) => {
    expect(CRYPTO_ALGORITHM_REGISTRY[id]?.rationale).toBe(rationale);
  });

  it('未登録の id には undefined を返す', () => {
    expect(CRYPTO_ALGORITHM_REGISTRY['NOT-A-REGISTERED-ALGORITHM@9.9']).toBeUndefined();
  });

  it('全エントリの status が AlgorithmStatus の許容値のいずれかである', () => {
    const validStatuses: ReadonlySet<AlgorithmStatus> = new Set([
      'recommended',
      'acceptable',
      'deprecated',
      'sunset',
      'prohibited',
      'experimental',
      'unsupported',
    ]);
    const statuses = Object.values(CRYPTO_ALGORITHM_REGISTRY).map((entry) => entry.status);
    expect(statuses.length).toBeGreaterThan(0);
    for (const status of statuses) {
      expect(validStatuses.has(status)).toBe(true);
    }
  });

  it('全エントリの id は自身のキーと一致する（Record 構築時の取り違え回帰検知）', () => {
    for (const [key, entry] of Object.entries(CRYPTO_ALGORITHM_REGISTRY)) {
      expect(entry.id).toBe(key);
    }
  });
});
