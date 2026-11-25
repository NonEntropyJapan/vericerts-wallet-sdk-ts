/**
 * did:webvh DID Log エントリの Data Integrity proof 検証。
 *
 * proof は `eddsa-jcs-2022`（Ed25519）。署名対象は spec: Data Integrity EdDSA Cryptosuites v1.0 の `eddsa-jcs-2022`
 * （`hashData` = `SHA-256(JCS(proofConfig)) || SHA-256(JCS(secured document))`）で、
 * - `proofConfig`: `proofValue` を除いた proof の全メンバ（`challenge` 等の追加メンバがあれば同じく署名される）、
 * - secured document: `proof` を除いたエントリ（確定済みの `versionId` を含む）。
 * 公式テストスイート（`decentralized-identity/didwebvh-test-suite`）のベクタで一致を確認している。
 *
 * proof の `verificationMethod` は `did:key:<multikey>#<multikey>`（本体とフラグメントが一致。spec: Witness DIDs and
 * Reputation の did:key 規則）。その Multikey が**有効な** `updateKeys` に逐語で含まれること。
 *
 * **ログ位置の束縛**: 署名は `versionId` を含むエントリ全体にかかる。`versionId` は `<番号>-<entryHash>` で、
 * entryHash は前版の `versionId`（初版は SCID）を含むので、署名が「この番号・この前版・この本体」に束縛される。
 * 過去の署名済みエントリを別の位置へ複製しても署名が合わない。このため旧方式の `proof.challenge === versionId`
 * 検査は持たない（DIF didwebvh version.md「Version 0.4」で `challenge` はエントリ全体への署名に置き換わった。
 * `challenge` は Authorized Keys の必須要素にない）。proof に `challenge` があっても proofConfig として署名され、検証できる。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` に DID 文字列・Log 本文・鍵バイトを含めない。
 * - `@scure` 由来の例外は入力を含み得るため `cause` を渡さず正規化する。
 * - Ed25519 検証は keymanager の `verifyEd25519`（RFC 8032 / `zip215: false`）に集約する。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { verifyEd25519 } from '../../keymanager/ed25519.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { multibaseBase58Decode } from '../multibase.js';
import { canonicalize, entryWithoutProof, type WebVhLogEntry, type WebVhProof } from './codec.js';
import {
  consumeSignatureBudget,
  createSignatureBudget,
  MAX_LOG_ENTRY_CHARS,
  MAX_PROOFS_PER_ENTRY,
  rejectDidLogOversized,
  type SignatureBudget,
} from './limits.js';

/** Ed25519 公開鍵の multicodec プレフィックス（`0xed01`、varint）。 */
const MULTIKEY_ED25519_PREFIX = Uint8Array.from([0xed, 0x01]);

/** Ed25519 raw 公開鍵長（バイト）。 */
const ED25519_PUBLIC_KEY_LENGTH = 32;

/** 受理する proof.type。 */
const PROOF_TYPE = 'DataIntegrityProof';

/** 受理する proof.cryptosuite。 */
const PROOF_CRYPTOSUITE = 'eddsa-jcs-2022';

/** 受理する proof.proofPurpose（did:webvh 1.0 / Data Integrity）。 */
const PROOF_PURPOSE = 'assertionMethod';

/**
 * proof の `verificationMethod`（`did:key:<multikey>#<multikey>`）から Multikey 文字列（`z...`）を取り出す。
 *
 * did:key の規則どおり、DID 本体の multibase と フラグメントは逐語で一致しなければならない（本体が鍵を定め、
 * フラグメントは検証メソッドの id。食い違う参照は拒否する）。DID 解決は行わない。
 *
 * @param verificationMethod proof.verificationMethod。
 * @returns Multikey 文字列。
 * @throws 形式が違う・本体とフラグメントが違う場合（VericertsError、code `2001`）。
 */
export function multikeyFromVerificationMethod(verificationMethod: string): string {
  const prefix = 'did:key:';
  const hash = verificationMethod.indexOf('#');
  if (!verificationMethod.startsWith(prefix) || hash < 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const body = verificationMethod.slice(prefix.length, hash);
  if (body.length === 0 || body !== verificationMethod.slice(hash + 1) || !body.startsWith('z')) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  return body;
}

/**
 * Ed25519 Multikey（`z` + base58btc(0xed01 || pubkey)）から raw 公開鍵を取り出す。
 *
 * @param multikey Multikey 文字列。
 * @returns 32 バイトの raw Ed25519 公開鍵。
 * @throws プレフィックス不一致・長さ不正の場合（VericertsError、code `2001`）。
 */
export function ed25519PublicKeyFromMultikey(multikey: string): Uint8Array {
  const decoded = multibaseBase58Decode(multikey);
  if (
    decoded.length !== MULTIKEY_ED25519_PREFIX.length + ED25519_PUBLIC_KEY_LENGTH ||
    decoded[0] !== MULTIKEY_ED25519_PREFIX[0] ||
    decoded[1] !== MULTIKEY_ED25519_PREFIX[1]
  ) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  return decoded.subarray(MULTIKEY_ED25519_PREFIX.length);
}

/** `SHA-256(JCS(value))`。 */
function hashJcs(value: unknown): Uint8Array {
  return sha256(new TextEncoder().encode(canonicalize(value)));
}

/**
 * `eddsa-jcs-2022` の署名対象（`hashData`）を作る: `SHA-256(JCS(proofConfig)) || SHA-256(JCS(document))`。
 *
 * @param proof 対象 proof（`proofValue` は除かれる）。
 * @param documentHash secured document の `SHA-256(JCS(...))`（文書ごとに 1 回だけ計算する）。
 * @returns 64 バイトの署名対象。
 */
export function eddsaJcs2022HashData(
  proof: Readonly<Record<string, unknown>>,
  documentHash: Uint8Array,
): Uint8Array {
  const { proofValue: _proofValue, ...proofConfig } = proof;
  const message = new Uint8Array(64);
  message.set(hashJcs(proofConfig), 0);
  message.set(documentHash, 32);
  return message;
}

/** secured document（`proof` を含まない JSON 値）の `SHA-256(JCS(...))`。 */
export function documentHashOf(document: unknown): Uint8Array {
  return hashJcs(document);
}

/**
 * 単一 proof の Ed25519 署名を検証する（署名対象は {@link eddsaJcs2022HashData}）。
 *
 * @param proof 対象 proof。
 * @param documentHash secured document のハッシュ（エントリごとに 1 回だけ作る）。
 * @param multikey 検証鍵 Multikey。
 * @returns 署名が有効なら `true`。
 */
export function verifyProofSignature(
  proof: WebVhProof,
  documentHash: Uint8Array,
  multikey: string,
): boolean {
  try {
    const publicKey = ed25519PublicKeyFromMultikey(multikey);
    const message = eddsaJcs2022HashData(proof, documentHash);
    const signature = multibaseBase58Decode(ownProperty<string>(proof, 'proofValue') as string);
    // keymanager の verifyEd25519 経由に統一する（引数順は (message, signature, publicKey)）。
    // @noble を直接呼ぶと既定の zip215: true になり、SDK 内で Ed25519 受理集合が分岐する。
    return verifyEd25519(message, signature, publicKey);
  } catch {
    // @scure 由来の例外・不正な鍵/署名は検証失敗として扱う。
    return false;
  }
}

/**
 * 署名対象の secured document（`proof` を除いたエントリ。確定した `versionId` を含む）の JCS 文字列を作る。
 *
 * @param entry 対象エントリ。
 * @returns 正規化済み文字列。
 */
export function proofPayloadCanonical(entry: WebVhLogEntry): string {
  return canonicalize(entryWithoutProof(entry));
}

/**
 * エントリの proof[] を許可された updateKeys のいずれかの Ed25519 鍵で検証する。
 *
 * proof のうち少なくとも 1 つが、`type` / `cryptosuite` / `proofPurpose` を満たし、許可鍵で有効であれば成功。
 *
 * 検証量は署名検証の前に縛る。`proof[]` 件数が `MAX_PROOFS_PER_ENTRY` を、payload 正規化文字列が
 * `MAX_LOG_ENTRY_CHARS` を超えるエントリは署名を 1 つも検証せず拒否する。同一の許可鍵（Multikey）の proof は
 * 1 つしか検証せず、payload のハッシュは 1 回だけ計算する（proof ごとの全量再ハッシュを避ける）。
 *
 * @param entry 対象エントリ。
 * @param allowedKeys この版で有効な updateKeys（Multikey 文字列）。
 * @param budget ログ全体の署名検証予算（`verifyChain` が全エントリで共有する）。尽きたら署名を検証せず拒否する。
 *        省略時は 1 エントリぶんの予算で単独検証する。
 * @throws proof 欠落・件数/サイズ超過・予算超過・許可鍵不一致・署名検証失敗の場合（VericertsError、code `2001`）。
 */
export function verifyEntryProof(
  entry: WebVhLogEntry,
  allowedKeys: ReadonlySet<string>,
  budget: SignatureBudget = createSignatureBudget(0),
): void {
  const proofs = ownProperty<unknown>(entry, 'proof') as WebVhLogEntry['proof'];
  if (!Array.isArray(proofs) || proofs.length === 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  rejectDidLogOversized(proofs.length, MAX_PROOFS_PER_ENTRY);
  const payloadCanonical = proofPayloadCanonical(entry);
  rejectDidLogOversized(payloadCanonical.length, MAX_LOG_ENTRY_CHARS);
  const documentHash = sha256(new TextEncoder().encode(payloadCanonical));
  const triedKeys = new Set<string>();
  for (const proof of proofs) {
    if (
      typeof proof !== 'object' ||
      proof === null ||
      typeof proof.verificationMethod !== 'string' ||
      typeof proof.proofValue !== 'string'
    ) {
      continue;
    }
    // 仕様が要求する proof の要素は `type` / `cryptosuite` / `proofPurpose` / `verificationMethod` だけ
    // （DIF didwebvh specification.md「Authorized Keys」）。`challenge` は見ず、あれば他のメンバと同じく
    // proofConfig として署名・ハッシュに入る。ログ位置への束縛は、`versionId` を含むエントリへの署名と
    // entryHash の連鎖が担う（上の注記）。
    if (
      proof.type !== PROOF_TYPE ||
      proof.cryptosuite !== PROOF_CRYPTOSUITE ||
      proof.proofPurpose !== PROOF_PURPOSE
    ) {
      continue;
    }
    let multikey: string;
    try {
      multikey = multikeyFromVerificationMethod(proof.verificationMethod);
    } catch {
      continue;
    }
    // 許可鍵でない proof、および同じ鍵で検証済みの proof は検証しない（鍵ごとに 1 回）。
    if (!allowedKeys.has(multikey) || triedKeys.has(multikey)) {
      continue;
    }
    consumeSignatureBudget(budget);
    triedKeys.add(multikey);
    if (verifyProofSignature(proof, documentHash, multikey)) {
      return;
    }
  }
  throw new VericertsError(ErrorCodes.INVALID_DID);
}
