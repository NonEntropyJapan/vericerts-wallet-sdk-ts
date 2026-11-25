/**
 * content-addressed DID / VC `contentHash` で扱うハッシュアルゴリズムのレジストリ。
 *
 * アルゴリズム識別子は multicodec / multihash の規約に従い、canonical 名を multicodec の
 * ハッシュ関数名（`sha2-256`）とする。DID サブパスや VC claim では `sha256-` / `sha-256-` の
 * 表記も現れるため、alias 表で canonical 名へ正規化する。
 *
 * セキュリティ上の注意:
 * - 対応表は `Object.create(null)` 由来のプロトタイプなしオブジェクトで保持する。通常の
 *   オブジェクトリテラルだと `constructor` / `toString` / `__proto__` などの入力が
 *   `Object.prototype` 経由でヒットし、未対応アルゴリズムが「対応済み」と誤判定され得る。
 * - 未知・未対応のアルゴリズムは fail-closed で拒否する（既定へのフォールバックはしない）。
 * - 例外メッセージに入力文字列を含めない。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { ErrorCodes, VericertsError } from '../../errors.js';

/** 対応するハッシュアルゴリズムの canonical 名（multicodec のハッシュ関数名）。 */
export type ContentHashAlgorithm = 'sha2-256';

/** ストリーミング計算に使う逐次ハッシュ器。`@noble/hashes` の `create()` 戻り値に適合する。 */
export interface IncrementalHasher {
  update(chunk: Uint8Array): unknown;
  digest(): Uint8Array;
}

/** アルゴリズム 1 件の定義。 */
export interface ContentHashAlgorithmSpec {
  /** canonical 名（multicodec のハッシュ関数名）。 */
  readonly algorithm: ContentHashAlgorithm;
  /** multihash のハッシュ関数コード（`sha2-256` = 0x12）。 */
  readonly multihashCode: number;
  /** ダイジェストのバイト長。 */
  readonly digestLength: number;
  /** 逐次ハッシュ器を生成する。 */
  readonly createHasher: () => IncrementalHasher;
}

/**
 * canonical 名 → 定義。
 *
 * 新しいアルゴリズムを追加するときは、暗号ポリシー上で recommended または acceptable のものに限る。
 */
const ALGORITHM_SPECS: Record<string, ContentHashAlgorithmSpec | undefined> = Object.assign(
  Object.create(null),
  {
    'sha2-256': {
      algorithm: 'sha2-256',
      multihashCode: 0x12,
      digestLength: 32,
      createHasher: () => sha256.create(),
    } satisfies ContentHashAlgorithmSpec,
  },
);

/**
 * 表記ゆれ（小文字化済み）→ canonical 名。
 *
 * `sha256` / `sha-256` はいずれも multicodec 名の `sha2-256` として扱う。
 */
const ALGORITHM_ALIASES: Record<string, ContentHashAlgorithm | undefined> = Object.assign(
  Object.create(null),
  {
    'sha2-256': 'sha2-256',
    'sha-256': 'sha2-256',
    sha256: 'sha2-256',
  },
);

/**
 * 既知だが本 SDK が対応しないハッシュアルゴリズム名（小文字、alias 表記を含む）。
 *
 * `1030 UNSUPPORTED_ALGORITHM` と `2016 CONTENT_HASH_FORMAT_INVALID` の投げ分けにのみ使う。
 * 最終セグメントを contentHash として認識できない場合は、形式エラー（`2016`）として扱う。
 * `did:web:acme.example.com:docs:v1-2` のような **content-addressed でない普通のサブパス**を
 * 「未対応ハッシュアルゴリズム」と報告してはならない。そのため「ハイフンを含むか」のような
 * 形状ヒューリスティクスではなく、既知アルゴリズム名の明示リストで判定する。
 *
 * ここに載っていない未知のプレフィックスは 2016 に倒す。どちらのコードでも入力は必ず
 * 拒否されるため、この分類は fail-closed 性に影響しない（エラーの切り分け精度の問題）。
 */
const KNOWN_UNSUPPORTED_ALGORITHMS: Record<string, true | undefined> = Object.assign(
  Object.create(null),
  {
    md4: true,
    md5: true,
    md6: true,
    sha0: true,
    sha1: true,
    'sha-1': true,
    sha224: true,
    'sha-224': true,
    'sha2-224': true,
    sha384: true,
    'sha-384': true,
    'sha2-384': true,
    sha512: true,
    'sha-512': true,
    'sha2-512': true,
    'sha2-512-224': true,
    'sha2-512-256': true,
    'sha3-224': true,
    'sha3-256': true,
    'sha3-384': true,
    'sha3-512': true,
    'shake-128': true,
    'shake-256': true,
    blake3: true,
    'blake2b-256': true,
    'blake2b-512': true,
    'blake2s-256': true,
    keccak224: true,
    'keccak-224': true,
    keccak256: true,
    'keccak-256': true,
    'keccak-384': true,
    'keccak-512': true,
    ripemd: true,
    ripemd160: true,
    'ripemd-160': true,
    whirlpool: true,
    sm3: true,
  },
);

/**
 * `<name>-<digest>` の `<name>` 部が「既知だが未対応のアルゴリズム名」かどうかを判定する。
 *
 * アルゴリズム名自体がハイフンを含み得る（`sha3-256` / `blake2b-256` / `sha-1`）ため、
 * ハイフン位置ごとに前方部分を切り出して照合する。
 *
 * @param text contentHash 表記の候補文字列。
 * @returns 既知の未対応アルゴリズム名で始まるなら `true`。
 */
export function hasKnownUnsupportedAlgorithmPrefix(text: string): boolean {
  const lowered = text.toLowerCase();
  for (let index = lowered.indexOf('-'); index > 0; index = lowered.indexOf('-', index + 1)) {
    if (KNOWN_UNSUPPORTED_ALGORITHMS[lowered.slice(0, index)] === true) {
      return true;
    }
  }
  return false;
}

/** 対応アルゴリズムの canonical 名一覧（安定した順序で返す）。 */
export const SUPPORTED_CONTENT_HASH_ALGORITHMS: readonly ContentHashAlgorithm[] = ['sha2-256'];

/**
 * 表記ゆれを含むアルゴリズム名を canonical 名へ正規化する。
 *
 * @param name DID サブパス / VC claim に現れたアルゴリズム名。
 * @returns canonical 名。未対応なら `undefined`（呼び出し側で fail-closed に扱う）。
 */
export function normalizeAlgorithmName(name: string): ContentHashAlgorithm | undefined {
  return ALGORITHM_ALIASES[name.toLowerCase()];
}

/** 正規化済みの alias 一覧（長い順）。`<alg>-<digest>` の前方一致判定に使う。 */
export const ALGORITHM_ALIAS_NAMES: readonly string[] = Object.keys(ALGORITHM_ALIASES).sort(
  (a, b) => b.length - a.length,
);

/**
 * canonical 名から定義を取得する。
 *
 * @param algorithm canonical 名。
 * @returns 定義。
 * @throws 未対応アルゴリズムの場合（VericertsError、code `1030`）。
 */
export function getAlgorithmSpec(algorithm: ContentHashAlgorithm): ContentHashAlgorithmSpec {
  const spec = ALGORITHM_SPECS[algorithm];
  if (spec === undefined) {
    throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
  }
  return spec;
}

/**
 * multihash のハッシュ関数コードから定義を探す。
 *
 * 未対応コードは `undefined` を返す。呼び出し側で fail-closed に拒否すること
 * （既定アルゴリズムへフォールバックしない）。
 *
 * @param code multihash のハッシュ関数コード。
 * @returns 定義。未対応なら `undefined`。
 */
export function findAlgorithmSpecByMultihashCode(
  code: number,
): ContentHashAlgorithmSpec | undefined {
  for (const algorithm of SUPPORTED_CONTENT_HASH_ALGORITHMS) {
    const spec = getAlgorithmSpec(algorithm);
    if (spec.multihashCode === code) {
      return spec;
    }
  }
  return undefined;
}
