/**
 * Federation Trust Chain の `revoked_keys` を VC の署名検証後に照合する（FC-11）。
 * Federation に基づいて VC を受理する場合は、`verifyCredential` / `verifySdJwt` に
 * `issuerTrust` を渡す。省略時はこの照合を行わない。
 *
 * 照合時刻は VC の発行時刻（エポック秒）。JWT-VC は `nbf`、SD-JWT VC は `iat` を優先する。
 * 署名済みの発行時刻を使うため、失効前に発行された VC は引き続き検証できる。
 * 発行日時を独立に証明する仕組みは含まない。
 *
 * 対象の発行者について、署名検証に使った鍵素材を上位が署名した Subordinate Statement の JWKS と照合する。
 * 鍵素材に複数の `kid` が対応するときはすべて確認する。判定には発行者ごとの失効宣言を使う。
 * 該当する宣言があり発行時刻が不明なら拒否する。鍵を特定できない場合は、
 * その発行者の最も早い `revoked_at` 以降に発行された VC を拒否する。
 * この検査の失敗に fail-open は適用しない。例外には鍵 ID、エンティティ ID、URL、JWT を含めない。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import type { PublicKeyJwk } from '../identity/did.js';
import { isNonEmptyString } from '../prototype-safety/non-empty-string.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import type {
  ScopedRevokedKeyDeclaration,
  TrustChain,
} from '../trust/federation/federation-types.js';
import { assertCredentialKeyNotRevoked } from '../trust/federation/revocation/trust-chain-revocation.js';

/**
 * VC の発行者を Federation Trust Chain で信頼している場合に渡す、FC-11 判定用の入力。
 *
 * これを検証オプションに渡すと、署名検証を通った VC に対して
 * `assertCredentialKeyNotRevoked` が**自動的に**適用される。呼び出し側が別途この関数を
 * 呼ぶ必要は無い。
 */
export interface IssuerTrustOption {
  /** VC の発行者について構築済みの Trust Chain（`buildTrustChain` の戻り値）。 */
  readonly trustChain: TrustChain;
  /**
   * VC の署名鍵を保有するエンティティ。省略時は `trustChain.leaf`。
   *
   * 通常 VC の発行者は leaf なので既定で足りる。leaf 以外のエンティティが署名した VC を
   * 判定する場合のみ明示する。突合に subject が要るのは、`kid` が JWKS 内でしか一意でなく、
   * 別エンティティの同名 `kid` と衝突するためである。
   */
  readonly issuer?: string;
}

/**
 * FC-11 の突合に使う発行時刻の**第一候補クレーム**。
 *
 * VC フォーマットごとに標準の発行時刻クレームが異なるため、優先順は呼び出し側が指定する。
 * もう一方はフォールバックとしてのみ使う。
 * - `'nbf'`: JWT-VC（`vc.issuanceDate` に束縛される唯一の発行時刻クレーム。`iat` も出力されるが束縛されない）。
 * - `'iat'`: SD-JWT VC（標準の発行時刻クレーム）。
 */
export type IssuanceTimeClaim = 'nbf' | 'iat';

/**
 * 指定 subject を対象とする宣言のうち最も早い `revoked_at`。宣言が無ければ `undefined`。
 *
 * 最早を採るのは、後からより遅い時刻で再宣言しても既に無効化された署名を復活させられないように
 * するためである（`findKeyRevocation` の「最も早い `revoked_at` が勝つ」規則と同じ）。
 */
function earliestRevokedAt(
  revocations: readonly ScopedRevokedKeyDeclaration[],
  subject: string,
): number | undefined {
  let earliest: number | undefined;
  for (const revocation of revocations) {
    if (
      revocation.sub === subject &&
      (earliest === undefined || revocation.revoked_at < earliest)
    ) {
      earliest = revocation.revoked_at;
    }
  }
  return earliest;
}

/**
 * 鍵素材の同一性キー。`kid` ラベルは**含めない**（ラベルの正しさは署名検証が証明しない）。
 *
 * 対応する鍵型は EC（`x` / `y`）と OKP（`x` のみ）で、いずれも `x` を必ず持つ。`x` が非空文字列
 * として読めない JWK は同一性を判定できないため `undefined` を返し、呼び出し側が fail-closed に倒す
 * （`undefined` 同士が一致して別の鍵を同一視することを防ぐ）。
 */
function keyMaterialId(jwk: PublicKeyJwk): string | undefined {
  if (!isNonEmptyString(jwk.x)) {
    return undefined;
  }
  return JSON.stringify([jwk.kty, jwk.crv, jwk.x, jwk.y ?? null]);
}

/**
 * 突合に使う `kid` を、上位が署名した Subordinate Statement の JWKS から鍵素材で引く。
 *
 * 対象は `sub` が `subject` である Subordinate Statement のみ。Entity Configuration は自己署名で
 * あり、鍵を掌握した攻撃者が `kid` ラベルを自由に付け替えられるため権威にしない
 * （`collectRevokedKeys` が Entity Configuration を無視するのと同じ理由）。
 *
 * @returns 検証鍵と鍵素材が一致する登録鍵の `kid` 群（重複排除済み）。裏付けが引けなければ空配列。
 */
function resolveAuthenticatedKids(
  chain: TrustChain,
  subject: string,
  verificationKey: PublicKeyJwk | undefined,
): readonly string[] {
  if (verificationKey === undefined) {
    return [];
  }
  const wanted = keyMaterialId(verificationKey);
  if (wanted === undefined) {
    return [];
  }
  const kids: string[] = [];
  for (const node of chain.nodes) {
    if (node.kind !== 'subordinate-statement' || node.sub !== subject) {
      continue;
    }
    for (const key of node.statement.jwks.keys) {
      // `kid` は 1 度だけ読む（検査と採用で読み直すと、アクセサ実装で値が食い違い得る）。
      const kid = key.kid;
      if (!isNonEmptyString(kid) || keyMaterialId(key) !== wanted || kids.includes(kid)) {
        continue;
      }
      kids.push(kid);
    }
  }
  return kids;
}

/**
 * VC payload から発行時刻（エポック秒）を取り出す。
 *
 * 優先クレームは `preferred`（＝ VC フォーマット由来）で決まる。もう一方はフォールバックとしてのみ
 * 使い、優先クレームが NumericDate として読めた時点で確定させる（後付けクレームに上書きさせない）。
 * NumericDate は非負整数とする（`parseRevokedKey` の `revoked_at` と同じ厳しさ）。どちらも読めない
 * 場合は「発行時刻不明」として `undefined` を返し、呼び出し側が fail-closed に倒す。
 */
function resolveIssuanceSeconds(
  payload: Record<string, unknown>,
  preferred: IssuanceTimeClaim,
): number | undefined {
  const candidates = preferred === 'nbf' ? [payload.nbf, payload.iat] : [payload.iat, payload.nbf];
  for (const value of candidates) {
    if (typeof value === 'number' && Number.isInteger(value) && value >= 0) {
      return value;
    }
  }
  return undefined;
}

/**
 * 署名検証を通った VC の署名鍵が、Trust Chain 内の鍵無効化宣言に該当しないことを確認する（FC-11）。
 *
 * `issuerTrust` が未指定なら何もしない（Federation を使わない検証経路に影響を与えない）。
 * 指定された場合は `assertCredentialKeyNotRevoked` へ委譲し、該当する VC を `5012` で拒否する。
 *
 * 判定対象の subject について宣言が 1 件も無ければ、突合材料の欠落を理由に拒否しない
 * （鍵漏洩が宣言されていない発行者の VC を巻き添えにしないため）。宣言がある場合に限り、
 * 突合に必要な情報が欠けている VC を fail-closed に拒否する。
 *
 * **署名検証の後に呼ぶこと。** 署名が成立していない VC の検証鍵は「実際に署名した鍵」ではなく、
 * 鍵素材による裏付けの引き当てに意味が無い。
 *
 * @param payload 署名検証済み JWS payload（`iat` / `nbf` を読む）。
 * @param issuerTrust Federation Trust Chain（未指定なら判定しない）。
 * @param issuanceClaim 発行時刻の第一候補クレーム。JWT-VC は `'nbf'`、SD-JWT VC は `'iat'` を渡す。
 * @param verificationKey 署名検証が成立した公開鍵 JWK。この**鍵素材**で Subordinate Statement の
 *        JWKS を引き、突合するすべての `kid` を決める。JWK を取得できない場合は `undefined`。
 * @throws 無効な Trust Chain は `5010`（TRUST_CHAIN_INVALID）。対象の発行者に宣言があり、発行時点で
 *         署名鍵が失効済み、発行時刻が不明、または鍵を特定できず発行時刻がその発行者の最早
 *         `revoked_at` 以降なら `5012`（FEDERATION_KEY_REVOKED）。
 */
export function assertSigningKeyNotRevoked(
  payload: Record<string, unknown>,
  issuerTrust: IssuerTrustOption | undefined,
  issuanceClaim: IssuanceTimeClaim,
  verificationKey?: PublicKeyJwk,
): void {
  if (issuerTrust === undefined) {
    return;
  }
  // `issuerTrust` の中身も own 限定で読む。**省略が通常**の `issuer` を鎖読みすると、
  // 汚染値で突合対象が攻撃者の subject にすり替わって宣言が無くなり、下の早期 return に落ちて失効鍵の
  // VC が**無言で受理される**（`trustChain` 汚染は宣言 0 件の成立チェーンを掴ませる）。FC-11 は
  // fail-closed なので取得不能/不成立は 5010 へ倒す。
  const trustChain = ownProperty<TrustChain>(issuerTrust, 'trustChain');
  if (trustChain === null || typeof trustChain !== 'object' || !trustChain.valid) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);
  }
  const subject = ownProperty<string>(issuerTrust, 'issuer') ?? trustChain.leaf;
  const earliest = earliestRevokedAt(trustChain.revokedKeys, subject);
  // この発行者について宣言が無い以上、拒否し得る VC は存在しない。
  if (earliest === undefined) {
    return;
  }
  const issuedAt = resolveIssuanceSeconds(payload, issuanceClaim);
  if (issuedAt === undefined) {
    // 宣言があるのに発行時刻が取れない。受理すると iat / nbf を落とすだけで素通りできる。
    throw new VericertsError(ErrorCodes.FEDERATION_KEY_REVOKED);
  }
  const kids = resolveAuthenticatedKids(trustChain, subject, verificationKey);
  if (kids.length === 0) {
    // 上位が裏付けた JWKS からこの署名鍵を特定できない。ラベルに依存せず判定するため、当該 subject の
    // 最早 `revoked_at` 以降に発行された VC だけを拒否する（漏洩前の VC は巻き添えにしない）。
    if (issuedAt >= earliest) {
      throw new VericertsError(ErrorCodes.FEDERATION_KEY_REVOKED);
    }
    return;
  }
  for (const kid of kids) {
    assertCredentialKeyNotRevoked(trustChain, kid, issuedAt, subject);
  }
}
