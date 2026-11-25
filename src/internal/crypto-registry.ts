/**
 * 全暗号アルゴリズムのステータスを一元管理するレジストリ。
 * SDK はこの表から各アルゴリズムの利用可否や移行状態を参照する。
 *
 * **本レジストリは「台帳」であり「受理範囲」ではない。** ここに `recommended` / `acceptable` として
 * 載っていても、個々の検証経路（JWS 署名検証・X.509 証明書検証等）が実際にそのアルゴリズムを
 * 受理するとは限らない（実受理範囲の SSOT は各経路の実装、例
 * `credential/vc/jws.ts` の `SUPPORTED_CREDENTIAL_ALGS`）。本レジストリの役割は、経路側が
 * 「技術的に検証できる」と判定した後で「ポリシー上まだ使ってよいか」（`deprecated` 警告 /
 * `prohibited` 拒否）を判定するための一元化されたステータス参照先を提供することに限られる。
 *
 * 横断ヘルパー（`src/internal` 直下）に置く: Domain 層の複数パッケージ（`credential` の VC/VP 検証、
 * `trust` の X.509 / ETSI TSL 証明書検証等）が将来ともに参照し得る、レイヤーに依存しない純粋な
 * データ + 参照関数のため。
 */

/** アルゴリズムの分類。 */
export type AlgorithmCategory = 'signature' | 'encryption' | 'kdf' | 'hash';

/**
 * アルゴリズムのライフサイクル上のステータス。
 *
 * `recommended` / `acceptable` / `deprecated` / `sunset` / `prohibited` の 5 値は
 * アルゴリズムの採用から廃止までの遷移段階。`experimental` / `unsupported` は「まだ SDK のどの経路でも
 * 受理していない」ことを表す 2 値で、いずれも現時点では検証を通らない。
 */
export type AlgorithmStatus =
  | 'recommended'
  | 'acceptable'
  | 'deprecated'
  | 'sunset'
  | 'prohibited'
  | 'experimental'
  | 'unsupported';

/** レジストリの 1 エントリ。 */
export interface CryptoRegistryEntry {
  /** `algorithm@version` 形式の識別子。 */
  readonly id: string;
  /** アルゴリズムの分類。 */
  readonly category: AlgorithmCategory;
  /** 準拠する外部規格。 */
  readonly standard: string;
  /** 採用根拠。 */
  readonly rationale: string;
  /** 現在のステータス。 */
  readonly status: AlgorithmStatus;
}

/**
 * 署名、暗号化、KDF、ハッシュの各アルゴリズムを収録する。
 * `id` の重複は無い（`CRYPTO_ALGORITHM_REGISTRY` 構築時に検出可能）。
 */
const REGISTRY_ENTRIES: readonly CryptoRegistryEntry[] = [
  // 署名アルゴリズム
  {
    id: 'ECDSA-secp256k1@1.0',
    category: 'signature',
    standard: 'SEC 2 / EIP-712',
    rationale: 'Ethereum 互換。ethers.js 標準',
    status: 'recommended',
  },
  {
    id: 'ES256@1.0',
    category: 'signature',
    standard: 'RFC 7518 (P-256)',
    rationale: 'HAIP / EUDI 必須。Web Crypto ネイティブ',
    status: 'recommended',
  },
  {
    id: 'ES384@1.0',
    category: 'signature',
    standard: 'RFC 7518 (P-384)',
    rationale: 'BSI TR-02102-1 推奨。SDK 未受理',
    status: 'unsupported',
  },
  {
    id: 'EdDSA-Ed25519@1.0',
    category: 'signature',
    standard: 'RFC 8032',
    rationale: 'CRYPTREC / NIST SP 800-186 推奨',
    status: 'recommended',
  },
  {
    id: 'BBS-2023@1.0',
    category: 'signature',
    standard: 'W3C Data Integrity CR',
    rationale: '選択的開示 + Unlinkability。SDK 未受理',
    status: 'unsupported',
  },
  {
    id: 'RSA-PKCS1-SHA256@1.0',
    category: 'signature',
    standard: 'RFC 8017 §8.2 (PKCS#1 v1.5)',
    rationale: 'X.509 証明書署名専用',
    status: 'acceptable',
  },
  {
    id: 'RSA-PSS-SHA256@1.0',
    category: 'signature',
    standard: 'RFC 8017 (PKCS#1 v2.2)',
    rationale: 'レガシー HSM 互換（3072 bit 以上）',
    status: 'acceptable',
  },
  {
    id: 'RSA-PSS-SHA256@0.9',
    category: 'signature',
    standard: 'PKCS#1 v2.1 (2048 bit)',
    rationale: 'レガシー（2030-01-01 廃止予定）',
    status: 'deprecated',
  },
  {
    id: 'ES256K@1.0',
    category: 'signature',
    standard: 'RFC 8812',
    rationale: 'did:ethr 互換',
    status: 'acceptable',
  },
  {
    id: 'ES256K-R@1.0',
    category: 'signature',
    standard: 'EIP-191（IANA JWS alg 登録外）',
    rationale: 'did:pkh / did:ethr の controller 鍵限定の標準外の例外',
    status: 'acceptable',
  },
  {
    id: 'ML-DSA-44@1.0',
    category: 'signature',
    standard: 'FIPS 204 (Dilithium2)',
    rationale: 'NIST PQC 標準（PQC Stage 2 以降）',
    status: 'experimental',
  },
  {
    id: 'ML-DSA-65@1.0',
    category: 'signature',
    standard: 'FIPS 204 (Dilithium3)',
    rationale: 'NIST PQC 標準',
    status: 'experimental',
  },
  {
    id: 'ML-DSA-87@1.0',
    category: 'signature',
    standard: 'FIPS 204 (Dilithium5)',
    rationale: 'NIST PQC 標準（最高強度）',
    status: 'experimental',
  },
  {
    id: 'SLH-DSA-SHA2-128s@1.0',
    category: 'signature',
    standard: 'FIPS 205 (SPHINCS+)',
    rationale: 'NIST PQC 標準（ハッシュベース）',
    status: 'experimental',
  },
  {
    id: 'ES256+ML-DSA-44@1.0',
    category: 'signature',
    standard: 'IETF pqt-hybrid (draft)',
    rationale: 'Hybrid（Classical + PQC、PQC Stage 2 以降）',
    status: 'experimental',
  },
  // 暗号化アルゴリズム
  {
    id: 'AES-256-GCM@1.0',
    category: 'encryption',
    standard: 'NIST SP 800-38D',
    rationale: 'CRYPTREC / BSI TR-02102-1 推奨',
    status: 'recommended',
  },
  {
    id: 'AES-128-GCM@1.0',
    category: 'encryption',
    standard: 'NIST SP 800-38D',
    rationale: 'Web Crypto 標準',
    status: 'acceptable',
  },
  {
    id: 'XChaCha20-Poly1305@1.0',
    category: 'encryption',
    standard: 'RFC 7539 拡張',
    rationale: 'libsodium 互換（将来の DIDComm）',
    status: 'acceptable',
  },
  {
    id: 'ML-KEM-768@1.0',
    category: 'encryption',
    standard: 'FIPS 203 (Kyber768)',
    rationale: 'NIST PQC 標準（鍵カプセル化、PQC Stage 2）',
    status: 'experimental',
  },
  {
    id: 'ECDH-ES+A256KW@1.0',
    category: 'encryption',
    standard: 'RFC 7518 / RFC 7520',
    rationale: 'DIDComm v2 Authcrypt',
    status: 'recommended',
  },
  // KDF / パスワード導出
  {
    id: 'HKDF-SHA256@1.0',
    category: 'kdf',
    standard: 'RFC 5869',
    rationale: 'NIST SP 800-56C 推奨',
    status: 'recommended',
  },
  {
    id: 'HKDF-SHA384@1.0',
    category: 'kdf',
    standard: 'RFC 5869',
    rationale: '高強度用途',
    status: 'acceptable',
  },
  {
    id: 'PBKDF2-SHA256@1.0',
    category: 'kdf',
    standard: 'RFC 8018',
    rationale: 'OWASP 推奨 600,000 iter',
    status: 'recommended',
  },
  {
    id: 'scrypt@1.0',
    category: 'kdf',
    standard: 'RFC 7914',
    rationale: 'N=2^17, r=8, p=1',
    status: 'recommended',
  },
  {
    id: 'Argon2id@1.0',
    category: 'kdf',
    standard: 'RFC 9106',
    rationale:
      'OWASP 第 1 推奨。低エントロピー入力（ウォレットパスワード等）の標準（m=19 MiB / t=2 / p=1）',
    status: 'recommended',
  },
  // ハッシュ関数
  {
    id: 'SHA-256@1.0',
    category: 'hash',
    standard: 'FIPS 180-4',
    rationale: '全体で使用',
    status: 'recommended',
  },
  {
    id: 'SHA-384@1.0',
    category: 'hash',
    standard: 'FIPS 180-4',
    rationale: 'HKDF-SHA384 とセット',
    status: 'recommended',
  },
  {
    id: 'SHA-512@1.0',
    category: 'hash',
    standard: 'FIPS 180-4',
    rationale: 'BBS+ / XOF 用',
    status: 'acceptable',
  },
  {
    id: 'SHAKE128@1.0',
    category: 'hash',
    standard: 'FIPS 202',
    rationale: '将来の PQC 併用',
    status: 'acceptable',
  },
  {
    id: 'SHA-1@1.0',
    category: 'hash',
    standard: 'FIPS 180-4',
    rationale: 'レガシー互換の検証のみ',
    status: 'prohibited',
  },
];

/**
 * `id` → エントリ。静的な文字列キーの参照表であり実行時の挿入・削除は無いため `Record` で持つ
 * （`ts-set-map` 規約）。重複 `id` があれば構築時に fail-closed で throw する。
 */
export const CRYPTO_ALGORITHM_REGISTRY: Readonly<Record<string, CryptoRegistryEntry>> =
  REGISTRY_ENTRIES.reduce<Record<string, CryptoRegistryEntry>>((registry, entry) => {
    if (entry.id in registry) {
      throw new Error(`crypto-registry: id が重複しています: ${entry.id}`);
    }
    registry[entry.id] = entry;
    return registry;
  }, {});

/**
 * `id`（`algorithm@version`）のレジストリ上のステータスを返す。
 *
 * @param id `algorithm@version` 形式の識別子（例 `ES256@1.0`）。
 * @returns 登録済みならそのステータス、未登録なら `undefined`。
 */
export function getAlgorithmStatus(id: string): AlgorithmStatus | undefined {
  return CRYPTO_ALGORITHM_REGISTRY[id]?.status;
}
