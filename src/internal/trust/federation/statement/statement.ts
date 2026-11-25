/**
 * Entity Statement（OpenID Federation JWT）のデコード・構造検証・署名検証ヘルパ。
 *
 * OpenID Federation 1.0 §3.1 の Entity Statement を扱う。
 *
 * `entity-configuration.ts` / `trust-chain.ts` から共有される純粋関数群
 * （1 ファイル 300 行以下のため分割）。JWT 署名検証は既存の `credential/vc/jws.ts`
 * の `decodeCompactJws` / `verifyWithJwk` を再利用し、`jose` 等は導入しない。
 *
 * 対応署名アルゴリズム: `ES256`（P-256）/ `ES256K`（secp256k1）/ `EdDSA`（Ed25519）。
 * `alg=none` は拒否する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に JWT・URL・鍵などの入力データを含めない。
 */

import type { CredentialAlg, DecodedJws } from '../../../credential/vc/jws.js';
import {
  decodeCompactJws,
  SUPPORTED_CREDENTIAL_ALGS,
  verifyWithJwkOrFalse,
} from '../../../credential/vc/jws.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { isNonEmptyString } from '../../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { assertNoCriticalExtensions, parseConstraints } from '../constraints/parse.js';
import type { EntityStatement, JsonWebKeySet } from '../federation-types.js';
import { parseRevokedKeys } from '../revocation/key-revocation.js';

/**
 * 値が NumericDate（RFC 7519）として受理できるかを判定する。
 *
 * 非負整数のみを受理する。RFC 7519 の NumericDate 自体は非整数を許容するが、本 SDK では
 * `revoked_keys` の `revoked_at`（`key-revocation.ts` の `parseRevokedKey`）と規律を揃えて
 * 整数のみとする。理由は 2 つある:
 *
 * - **キャッシュ注入が検証結果を変えないため**。`statementCacheTtlSeconds` は `exp - now` を
 *   そのまま TTL に渡し、`TtlCache.set` は整数 TTL を要求する。ここで非整数 `exp` を通すと、
 *   キャッシュ未注入なら成立する Statement が `statementCache` を注入した途端 `3002` で
 *   落ちるという、キャッシュの有無で結果が変わる経路ができてしまう。
 * - 秒未満の精度は鍵無効化宣言の突合（`iat >= revoked_at`）にとって意味を持たず、
 *   取り違えの余地を増やすだけであるため。
 */
function isNumericDate(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

/**
 * Entity Statement の `jwks.keys` に許容する鍵数の上限。
 *
 * 自己署名 Entity Configuration の本文は攻撃者が自由に書ける。`kid` 無しヘッダでは全鍵に対して
 * ECDSA 検証を同期実行するため、鍵数に上限が無いと 1 MiB 未満の Statement 1 通で呼び出しスレッドを
 * 数十秒停止できる。実運用の Federation エンティティが公開する署名鍵は数本（ローテーション
 * 中でも 10 本未満）なので 32 で十分余裕がある。
 */
export const MAX_JWKS_KEYS = 32;

/**
 * `jwks` クレームを JsonWebKeySet として検証・正規化する。
 *
 * @param value payload の `jwks` 値（未検証）。
 * @returns 検証済み JsonWebKeySet。
 * @throws `keys` が非空配列でない / 要素がオブジェクトでない / 鍵数が `MAX_JWKS_KEYS` 超の場合
 *   （TRUST_CHAIN_INVALID）。
 */
function parseJwks(value: unknown): JsonWebKeySet {
  if (typeof value !== 'object' || value === null) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  const keys = (value as { keys?: unknown }).keys;
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > MAX_JWKS_KEYS) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  for (const key of keys) {
    if (typeof key !== 'object' || key === null) {
      throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
    }
  }
  return { keys: keys as readonly PublicKeyJwk[] };
}

/**
 * デコード済み payload を EntityStatement として構造検証する。
 *
 * 必須クレーム（`iss` / `sub` / `iat` / `exp` / `jwks`）の存在と型を確認し、任意クレーム
 * （`authority_hints` / `metadata` / `metadata_policy` / `revoked_keys`）は型が合う場合のみ引き継ぐ。
 * `iat` / `exp` は非負整数の NumericDate のみ受理する（`isNumericDate` の注記を参照）。
 * `revoked_keys`（鍵無効化宣言）は不正な宣言を黙って落とすと防御目的が
 * 崩れるため、`key-revocation.ts` の厳格パーサで検証する。
 *
 * @param payload デコード済み JWT payload。
 * @returns 構造検証済み EntityStatement。
 * @throws 必須クレーム欠落・型不正の場合（VericertsError、TRUST_CHAIN_INVALID）。
 */
export function parseEntityStatement(payload: Record<string, unknown>): EntityStatement {
  if (!isNonEmptyString(payload.iss) || !isNonEmptyString(payload.sub)) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  if (!isNumericDate(payload.iat) || !isNumericDate(payload.exp)) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  const jwks = parseJwks(payload.jwks);
  // 理解できない拡張を「理解必須」と宣言する Statement は拒否する。
  assertNoCriticalExtensions(payload);

  const statement: {
    iss: string;
    sub: string;
    iat: number;
    exp: number;
    jwks: JsonWebKeySet;
    authority_hints?: readonly string[];
    metadata?: EntityStatement['metadata'];
    metadata_policy?: EntityStatement['metadata_policy'];
    revoked_keys?: EntityStatement['revoked_keys'];
    constraints?: EntityStatement['constraints'];
  } = {
    iss: payload.iss,
    sub: payload.sub,
    iat: payload.iat,
    exp: payload.exp,
    jwks,
  };

  if (payload.authority_hints !== undefined) {
    if (
      !Array.isArray(payload.authority_hints) ||
      !payload.authority_hints.every((hint) => isNonEmptyString(hint))
    ) {
      throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
    }
    statement.authority_hints = payload.authority_hints as readonly string[];
  }
  if (payload.metadata !== undefined) {
    if (typeof payload.metadata !== 'object' || payload.metadata === null) {
      throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
    }
    statement.metadata = payload.metadata as EntityStatement['metadata'];
  }
  if (payload.metadata_policy !== undefined) {
    if (typeof payload.metadata_policy !== 'object' || payload.metadata_policy === null) {
      throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
    }
    statement.metadata_policy = payload.metadata_policy as EntityStatement['metadata_policy'];
  }
  if (payload.revoked_keys !== undefined) {
    statement.revoked_keys = parseRevokedKeys(payload.revoked_keys);
  }
  if (payload.constraints !== undefined) {
    statement.constraints = parseConstraints(payload.constraints);
  }

  return statement;
}

/**
 * compact JWS をデコードする（署名検証はしない）。JWT 1 通につき JSON パースはここで 1 回だけ行う。
 *
 * @param jwt compact JWS 文字列。
 * @returns デコード結果（ヘッダ・payload は未検証）。
 * @throws 3 セグメント不正 / base64url・JSON 不正の場合（VericertsError、TRUST_CHAIN_INVALID）。
 */
export function decodeStatementJws(jwt: string): DecodedJws {
  try {
    return decodeCompactJws(jwt);
  } catch {
    // 形式不正（3 セグメントでない / base64url / JSON 不正）は入力を含み得るため正規化する。
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
}

/**
 * 自己署名 Entity Configuration の鍵源として payload 内の `jwks` を取り出す。
 *
 * @param decoded `decodeStatementJws` の結果（payload は未検証。署名検証の鍵源として使う）。
 * @returns payload の `jwks`。
 * @throws `jwks` 欠落・型不正の場合（VericertsError、TRUST_CHAIN_INVALID）。
 */
export function selfJwksOf(decoded: DecodedJws): JsonWebKeySet {
  return parseJwks(decoded.payload.jwks);
}

/** 署名検証を通過した Entity Statement と、実際に署名を検証した鍵の `kid`。 */
export interface VerifiedStatement {
  /** 構造検証済みの Entity Statement。 */
  readonly statement: EntityStatement;
  /**
   * 署名の検証が成立した JWKS 内の鍵の `kid`（鍵が `kid` を持たなければ `undefined`）。
   *
   * 鍵無効化宣言（`revoked_keys`）との突合に使う。JOSE ヘッダの
   * `kid` ではなく**実際に検証が成立した鍵**の `kid` を返す。宣言は「subject の JWKS 内の鍵」を
   * 指すため、突合の相手は JWKS 側の鍵でなければ意味を持たない。
   */
  readonly signingKid?: string;
  /**
   * 検証対象となった生の compact JWT（`header.payload.signature`）。
   *
   * `FederationEntityCache`の `trustChain` のように、**検証済みクレームでは
   * なく JWT 自体**を必要とする呼び出し側のためだけに持たせる。`decodeAndVerifyStatementWithKey`
   * は設定せず、JWT を手元に持っている呼び出し側（`subordinate.ts`）が付与する。
   */
  readonly jwt?: string;
}

/**
 * Entity Statement JWT の署名を検証し、成立した鍵の `kid` も併せて返す。
 *
 * 署名検証の規則は `decodeAndVerifyStatement` と同一で、戻り値に `signingKid` が加わるだけである。
 * Trust Chain は各 Statement を「どの鍵が署名したか」を鍵無効化宣言と突合する必要があるため
 * （`trust-chain.ts` の `assertChainSignaturesNotRevoked`）、この情報を落とさない経路を用意する。
 *
 * @param jwt compact JWS（`header.payload.signature`）。
 * @param jwks 検証に用いる JWK Set。
 * @returns 署名検証を通過した Entity Statement と署名鍵の `kid`。
 * @throws 3 セグメント不正・alg 不正・署名不成立の場合（VericertsError、TRUST_CHAIN_INVALID）。
 */
export function decodeAndVerifyStatementWithKey(
  jwt: string,
  jwks: JsonWebKeySet,
): VerifiedStatement {
  return verifyDecodedStatement(decodeStatementJws(jwt), jwks);
}

/**
 * デコード済みの Entity Statement JWS の署名を検証し、成立した鍵の `kid` も併せて返す。
 *
 * `decodeAndVerifyStatementWithKey` の検証部。呼び出し側がデコード結果を持っている場合（自己署名
 * Entity Configuration の鍵源取得、Trust Anchor ピン検証の鍵ごとの再試行）に、同じ JWT を何度も
 * JSON パースしないために分けてある。
 *
 * @param decoded `decodeStatementJws` の結果。
 * @param jwks 検証に用いる JWK Set。
 * @returns 署名検証を通過した Entity Statement と署名鍵の `kid`。
 * @throws alg 不正・署名不成立の場合（VericertsError、TRUST_CHAIN_INVALID）。
 */
export function verifyDecodedStatement(
  decoded: DecodedJws,
  jwks: JsonWebKeySet,
): VerifiedStatement {
  const alg = decoded.header.alg;
  if (typeof alg !== 'string' || alg === 'none' || !SUPPORTED_CREDENTIAL_ALGS.has(alg)) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  const kid = typeof decoded.header.kid === 'string' ? decoded.header.kid : undefined;

  // ヘッダに kid が在れば kid 一致鍵**だけ**を試す。「一致が無ければ全鍵を試す」形のフォールバックは
  // 置かない — 発行者が指した鍵と違う鍵で検証を通してしまえば、kid を付ける意味（鍵の取り違えを
  // 検知すること）が無くなり、エンティティが JWKS で宣言した鍵用途の分離も破れる。一致鍵が無ければ
  // 候補が空になり、下の find が undefined を返して TRUST_CHAIN_INVALID になる。
  // kid が無い場合のみ全鍵を試行する（alg と鍵種別が食い違う鍵は不成立として次へ進む）。
  const keysToTry =
    kid !== undefined
      ? jwks.keys.filter((key) => ownProperty<unknown>(key, 'kid') === kid)
      : jwks.keys;

  const signingKey = keysToTry.find((key) =>
    verifyWithJwkOrFalse(alg as CredentialAlg, decoded, key),
  );
  if (signingKey === undefined) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }

  const statement = parseEntityStatement(decoded.payload);
  const signingKid = ownProperty<unknown>(signingKey, 'kid');
  return isNonEmptyString(signingKid) ? { statement, signingKid } : { statement };
}

/**
 * Entity Statement JWT の署名を、指定した JWK Set のいずれかの鍵で検証する。
 *
 * OpenID Federation では:
 * - Entity Configuration（自己署名）は自身の `jwks`（= payload 内）で検証する。
 * - Subordinate Statement は「発行者（上位）の JWKS」で検証する（呼び出し側が上位の鍵集合を渡す）。
 *
 * ヘッダ `kid` があれば一致する鍵**だけ**を試し（一致が無ければ拒否する）、`kid` が無ければ全鍵を
 * 順に試す。`alg=none` および未対応 alg は拒否する。
 *
 * 署名鍵の `kid` も必要な場合は `decodeAndVerifyStatementWithKey` を使う。
 *
 * @param jwt compact JWS（`header.payload.signature`）。
 * @param jwks 検証に用いる JWK Set。
 * @returns 署名検証を通過した EntityStatement。
 * @throws 3 セグメント不正・alg 不正・署名不成立の場合（VericertsError、TRUST_CHAIN_INVALID）。
 */
export function decodeAndVerifyStatement(jwt: string, jwks: JsonWebKeySet): EntityStatement {
  return decodeAndVerifyStatementWithKey(jwt, jwks).statement;
}

/**
 * Entity Statement の有効期間（`iat` / `exp`）を評価する。
 *
 * `now >= exp`（期限切れ）・`now < iat`（発行前）はいずれも不成立とする。
 *
 * @param statement 構造検証済み EntityStatement。
 * @param nowSeconds 現在時刻（エポック秒）。
 * @throws 期限切れ・発行前の場合（VericertsError、TRUST_CHAIN_INVALID）。
 */
export function assertStatementTimeValid(statement: EntityStatement, nowSeconds: number): void {
  // `nowSeconds` が NaN だと否定形の比較は常に false になり期限切れ Statement を通す。
  // 「有効期間内である」ことを肯定形で確認して fail-closed にする。
  if (!(nowSeconds < statement.exp && nowSeconds >= statement.iat)) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
}
