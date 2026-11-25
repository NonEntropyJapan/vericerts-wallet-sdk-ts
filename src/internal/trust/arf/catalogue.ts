/**
 * ARF Trust Anchor Catalogue の取得・署名検証（Layer 3）。
 *
 * EU Commission 管理の Wallet Provider / Attestation Provider Registry（ARF Catalogue）を DI fetcher
 * 経由で取得し、ARF Trust Anchor の固定 Ed25519 鍵で署名を検証したうえで、登録エントリ集合を返す。
 * ネットワーク I/O は SDK コアに持ち込まず `ArfTrustAnchorFetcher` 経由で注入する（trust/etsi-tsl と
 * 同方針の依存隔離・テスト容易性）。
 *
 * 署名エンベロープ（detached・JWS ライク）:
 *   { "payload": "<base64url(UTF-8 JSON)>", "signature": "<base64(Ed25519 sig)>" }
 * 署名対象は `payload`（base64url 文字列）の ASCII バイト列。正規化揺れを避けるため、受信した
 * payload 文字列そのものを検証・デコードする。
 *
 * セキュリティ上の注意:
 * - fail-closed。取得失敗・エンベロープ不正・署名不一致・payload 構造不正はすべて 10305
 *   （ARF_TRUST_ANCHOR_NOT_REGISTERED）へ正規化する。
 * - 鮮度・世代: 署名は固定鍵で永続的に有効なので、登録解除前の旧 Catalogue の再生は署名検査
 *   だけでは落とせない。payload の任意項目 `nextUpdate`（期限切れを拒否）と `sequence` / `issuedAt`
 *   （`options.previous` より後退した世代を拒否。TSL の）を検査する。守れるのは
 *   Catalogue が項目を提供し、かつ呼び出し側が直前に受理した世代を渡す間だけ。
 * - 例外・戻り値・context に Catalogue 本文 / URL / 鍵素材を含めない。
 */

import { base64, base64urlnopad } from '@scure/base';
import { systemNowSeconds } from '../../cache/index.js';
import { parseIsoDateTimeMs } from '../../cache/iso-datetime.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { verifyEd25519 } from '../../keymanager/ed25519.js';
import { isNonEmptyString } from '../../prototype-safety/non-empty-string.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import type {
  ArfCatalogueEntry,
  ArfCatalogueGeneration,
  ArfEntryRole,
  ArfTrustAnchorFetcher,
  ArfTrustAnchorSet,
  LoadArfTrustAnchorOptions,
} from './arf-types.js';

/** Ed25519 raw 公開鍵の長さ（バイト）。 */
const ED25519_PUBLIC_KEY_LENGTH = 32;

/** 許可する ARF エントリ役割。 */
const ENTRY_ROLES = new Set<ArfEntryRole>([
  'wallet-provider',
  'issuer',
  'attestation-provider',
  'relying-party',
]);

/**
 * `null` でないオブジェクトか（`ownProperty` へ渡せるか）を判定する（
 * `auth/jar/jar-trust-arf.ts` / `auth/jar/jar-trust-evaluation.ts` の同名 `isObject` と
 * 完全同一のロジックがそれぞれ個別定義されていたのをここへ集約した。配列を除外しない
 * のは意図的で、`ownProperty` へ渡す前の「非 null か」だけを見る用途のため
 * `object-guards.ts` の `isPlainObject`（配列除外あり）とは別物として扱う）。
 */
export function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null;
}

/**
 * ARF Trust Anchor Catalogue を取得・署名検証し、登録エントリ集合を返す。
 *
 * @param url ARF Catalogue（Wallet Provider Registry JSON）の URL。
 * @param options 取得関数・固定 Ed25519 公開鍵。
 * @returns 署名検証済みの Trust Anchor 集合。
 * @throws 取得失敗・署名検証失敗・構造不正の場合（10305 ARF_TRUST_ANCHOR_NOT_REGISTERED）。
 */
export async function loadArfTrustAnchor(
  url: string,
  options: LoadArfTrustAnchorOptions,
): Promise<ArfTrustAnchorSet> {
  // ピン留め鍵は純データ（Uint8Array）なので own 限定で読む。継承値を拾うと、
  // `trustAnchorPublicKey` を**省略した**呼び出しが攻撃者の鍵で Catalogue 署名を検証してしまい、
  // Trust Anchor 集合を丸ごとすり替えられる。型・長さも明示的に検査して `as` で隠さない。
  const trustAnchorPublicKey = ownProperty<Uint8Array>(options, 'trustAnchorPublicKey');
  if (
    !(trustAnchorPublicKey instanceof Uint8Array) ||
    trustAnchorPublicKey.length !== ED25519_PUBLIC_KEY_LENGTH
  ) {
    // 不正な固定鍵は設定ミス。本文・鍵素材は載せない。
    throw new VericertsError(ErrorCodes.ARF_TRUST_ANCHOR_NOT_REGISTERED);
  }

  // `fetcher` は関数値の DI。own 限定で読むと `class Loader { async fetcher() {} }` のような
  // プロトタイプメソッド実装が「未指定」に化けるため、`Object.prototype` 由来だけを弾く
  // （trust/federation/subordinate.ts・credential/refresh と同じ読み方）。継承値を拾うと
  // `fetcher` を省略した呼び出しが攻撃者の関数へ委譲され、Catalogue をすり替えられる。
  const fetcher = nonObjectPrototypeProperty<ArfTrustAnchorFetcher>(options, 'fetcher');
  if (typeof fetcher !== 'function') {
    throw new VericertsError(ErrorCodes.ARF_TRUST_ANCHOR_NOT_REGISTERED);
  }

  let raw: string;
  try {
    // レシーバは `options` に束ね直す。取り出した関数を裸で呼ぶと、従来の `options.fetcher(url)`
    // では `this === options` だったクラスベース DI（`this` 参照つきメソッド）が壊れる。
    raw = await fetcher.call(options, url);
  } catch {
    throw new VericertsError(ErrorCodes.ARF_TRUST_ANCHOR_NOT_REGISTERED);
  }

  const payloadB64 = verifyEnvelope(raw, trustAnchorPublicKey);
  const payload = decodePayload(payloadB64);

  // 鮮度・世代の検査。署名は固定鍵で永続的に有効なので、署名検証だけでは旧世代の再生を
  // 落とせない。`nextUpdate` を過ぎた世代、直前に受理した世代より後退した世代は拒否する。
  const nowSeconds = ownProperty<unknown>(options, 'nowSeconds');
  const now =
    typeof nowSeconds === 'number' && Number.isFinite(nowSeconds) ? nowSeconds : systemNowSeconds();
  if (payload.nextUpdateMs !== undefined && payload.nextUpdateMs <= now * 1000) {
    throw new VericertsError(ErrorCodes.ARF_TRUST_ANCHOR_NOT_REGISTERED);
  }
  const previous = ownProperty<ArfCatalogueGeneration | undefined>(options, 'previous');
  if (previous !== undefined && !isGenerationMonotonic(previous, payload)) {
    throw new VericertsError(ErrorCodes.ARF_TRUST_ANCHOR_NOT_REGISTERED);
  }

  return {
    signatureValid: true,
    ...(payload.version !== undefined ? { version: payload.version } : {}),
    ...(payload.sequence !== undefined ? { sequence: payload.sequence } : {}),
    ...(payload.issuedAt !== undefined ? { issuedAt: payload.issuedAt } : {}),
    ...(payload.nextUpdate !== undefined ? { nextUpdate: payload.nextUpdate } : {}),
    entries: payload.entries,
  };
}

/**
 * 取得した世代が直前に受理した世代より古くないかを返す（TSL の `isTrustedListGenerationMonotonic` と同じ規則）。
 *
 * - 直前に `sequence` があれば、今回も持ち、かつそれ以上でなければならない。厳密に大きければ受理し、
 *   同値なら `issuedAt` の比較へ進む（同一世代の再取得は許す）。
 * - 直前に `issuedAt` があれば、今回も持ち、かつそれ以上でなければならない。
 * - 直前にどちらも無ければ比較できないので `true`。
 * 今回の側に項目が無いのに直前にはあった場合は `false`（項目を消した旧世代で比較を迂回させない）。
 */
function isGenerationMonotonic(
  previous: ArfCatalogueGeneration,
  current: { sequence: number | undefined; issuedAtMs: number | undefined },
): boolean {
  const previousSequence = ownProperty<unknown>(previous, 'sequence');
  if (typeof previousSequence === 'number') {
    if (current.sequence === undefined || current.sequence < previousSequence) {
      return false;
    }
    if (current.sequence > previousSequence) {
      return true;
    }
  }
  const previousIssuedAt = ownProperty<unknown>(previous, 'issuedAt');
  const previousIssuedAtMs =
    typeof previousIssuedAt === 'string' ? parseIsoDateTimeMs(previousIssuedAt) : Number.NaN;
  if (!Number.isNaN(previousIssuedAtMs)) {
    return current.issuedAtMs !== undefined && current.issuedAtMs >= previousIssuedAtMs;
  }
  return true;
}

/**
 * エンベロープをパースし Ed25519 署名を検証する。
 *
 * @returns 署名検証に成功した payload（base64url 文字列）。
 * @throws 署名不一致・エンベロープ不正時（10305）。
 */
function verifyEnvelope(raw: string, publicKey: Uint8Array): string {
  let envelope: unknown;
  try {
    envelope = parseJsonWithoutPrototype(raw);
  } catch {
    throw new VericertsError(ErrorCodes.ARF_TRUST_ANCHOR_NOT_REGISTERED);
  }
  if (!isObject(envelope)) {
    throw new VericertsError(ErrorCodes.ARF_TRUST_ANCHOR_NOT_REGISTERED);
  }
  // エンベロープは `parseJsonWithoutPrototype` 由来で `Object.prototype` を継承しないが、own 限定
  // 読みは多層防御として残す。鎖を辿ると `{}` のエンベロープでも
  // `Object.prototype.payload` / `.signature` が署名対象・署名として採用される。
  const payloadB64 = ownProperty<unknown>(envelope, 'payload');
  const signatureB64 = ownProperty<unknown>(envelope, 'signature');
  if (typeof payloadB64 !== 'string' || typeof signatureB64 !== 'string') {
    throw new VericertsError(ErrorCodes.ARF_TRUST_ANCHOR_NOT_REGISTERED);
  }

  let valid = false;
  try {
    const message = new TextEncoder().encode(payloadB64);
    const signature = base64.decode(signatureB64);
    // keymanager の verifyEd25519 経由に統一する（引数順は (message, signature, publicKey)）。
    // @noble を直接呼ぶと既定の zip215: true になり、SDK 内で Ed25519 受理集合が分岐する。
    valid = verifyEd25519(message, signature, publicKey);
  } catch {
    // 不正な署名エンコード / 鍵は改ざん相当として fail-closed。
    valid = false;
  }
  if (!valid) {
    throw new VericertsError(ErrorCodes.ARF_TRUST_ANCHOR_NOT_REGISTERED);
  }
  return payloadB64;
}

/** 署名検証済み payload（base64url）をデコードし構造を検証する。 */
function decodePayload(payloadB64: string): {
  version: string | undefined;
  sequence: number | undefined;
  issuedAt: string | undefined;
  issuedAtMs: number | undefined;
  nextUpdate: string | undefined;
  nextUpdateMs: number | undefined;
  entries: ArfCatalogueEntry[];
} {
  let parsed: unknown;
  try {
    const json = new TextDecoder().decode(base64urlnopad.decode(payloadB64));
    parsed = parseJsonWithoutPrototype(json);
  } catch {
    throw new VericertsError(ErrorCodes.ARF_TRUST_ANCHOR_NOT_REGISTERED);
  }
  if (!isObject(parsed)) {
    throw new VericertsError(ErrorCodes.ARF_TRUST_ANCHOR_NOT_REGISTERED);
  }
  // `entries` / `version` も own 限定で読む。鎖読みだと entries を持たない payload に
  // 汚染値の登録一覧が生え、署名検証済みの Catalogue として攻撃者のエントリが通る。
  const rawEntries = ownProperty<unknown>(parsed, 'entries');
  if (!Array.isArray(rawEntries)) {
    throw new VericertsError(ErrorCodes.ARF_TRUST_ANCHOR_NOT_REGISTERED);
  }
  const version = ownProperty<unknown>(parsed, 'version');
  const entries = rawEntries
    .map((value: unknown) => parseEntry(value))
    .filter((e): e is ArfCatalogueEntry => e !== undefined);
  // 鮮度・世代の項目は「提供されない」(undefined) と「提供されたが不正」(拒否) を区別する。
  // 不正値を黙って無視すると、項目を壊した旧世代で検査を迂回できる。
  const sequence = ownProperty<unknown>(parsed, 'sequence');
  if (sequence !== undefined && !(Number.isSafeInteger(sequence) && (sequence as number) >= 0)) {
    throw new VericertsError(ErrorCodes.ARF_TRUST_ANCHOR_NOT_REGISTERED);
  }
  const issuedAt = parseOptionalDateTime(ownProperty<unknown>(parsed, 'issuedAt'));
  const nextUpdate = parseOptionalDateTime(ownProperty<unknown>(parsed, 'nextUpdate'));
  return {
    version: typeof version === 'string' ? version : undefined,
    sequence: sequence as number | undefined,
    issuedAt: issuedAt?.text,
    issuedAtMs: issuedAt?.ms,
    nextUpdate: nextUpdate?.text,
    nextUpdateMs: nextUpdate?.ms,
    entries,
  };
}

/** 任意の ISO 8601 日時（オフセット必須）を読む。未提供は `undefined`、提供されたが不正なら 10305。 */
function parseOptionalDateTime(value: unknown): { text: string; ms: number } | undefined {
  if (value === undefined) {
    return undefined;
  }
  const ms = typeof value === 'string' ? parseIsoDateTimeMs(value) : Number.NaN;
  if (typeof value !== 'string' || Number.isNaN(ms)) {
    throw new VericertsError(ErrorCodes.ARF_TRUST_ANCHOR_NOT_REGISTERED);
  }
  return { text: value, ms };
}

/** 生エントリを検証し `ArfCatalogueEntry` へ変換する（不正なら undefined で除外・fail-closed）。 */
function parseEntry(value: unknown): ArfCatalogueEntry | undefined {
  if (!isObject(value)) {
    return undefined;
  }
  // エントリの各フィールドも own 限定で読む。鎖読みだと `role` を持たないエントリが
  // 汚染値で「登録済み wallet-provider」に化け、`id` / `country` / `spki` も差し替えられる。
  const id = ownProperty<unknown>(value, 'id');
  const role = ownProperty<unknown>(value, 'role');
  const country = ownProperty<unknown>(value, 'country');
  if (typeof id !== 'string' || id.length === 0) {
    return undefined;
  }
  if (typeof role !== 'string' || !ENTRY_ROLES.has(role as ArfEntryRole)) {
    return undefined;
  }
  const spki = decodeSpki(ownProperty<unknown>(value, 'spki'));
  return {
    id,
    role: role as ArfEntryRole,
    ...(isNonEmptyString(country) ? { country } : {}),
    ...(spki !== undefined ? { spki } : {}),
  };
}

/** SPKI（base64・任意）をデコードする。不正・欠落なら undefined。 */
function decodeSpki(value: unknown): Uint8Array | undefined {
  if (typeof value !== 'string' || value.length === 0) {
    return undefined;
  }
  try {
    return base64.decode(value.replace(/\s+/g, ''));
  } catch {
    return undefined;
  }
}
