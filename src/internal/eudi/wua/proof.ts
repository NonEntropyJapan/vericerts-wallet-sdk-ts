/**
 * WUA-PoP JWT 生成と OAuth2 client_assertion 組み立て。
 *
 * 提供機能:
 * - `buildWuaProofOfPossession`: WUA `cnf.jwk` にバインドされた WSCD 鍵で WUA-PoP JWT を生成
 * - `buildClientAttestation`: `<WUA>~<WUA-PoP>` と `client_assertion_type` を組み立て
 *
 * 署名鍵は WUA `cnf.jwk` に対応する WSCD（Passkey）由来鍵。生 privateKey を本モジュールへ
 * 渡さず、`credential/vc/signer.ts` の `CredentialSigner` で DI する（keymanager 等の鍵レジストリが
 * privateKey を露出せず署名できる seam）。コンパクト JWS 組み立ては本モジュールが担い、`jose` は
 * 導入しない。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` に鍵素材・JWT 本文を含めない。
 */

import { signCompactJws } from '../../credential/vc/compact-jws.js';
import { decodeCompactJws } from '../../credential/vc/jws.js';
import { buildJwsHeader, type CredentialSigner } from '../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { resolveProofJti } from '../../primitives/proof-jti.js';
import { isNonEmptyString } from '../../prototype-safety/non-empty-string.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import { publicKeyJwkMatches } from './jwk-match.js';
import {
  type ClientAttestation,
  type WalletUnitAttestation,
  WUA_CLIENT_ASSERTION_TYPE,
  type WuaPopClaims,
  type WuaPopOptions,
} from './types.js';

/** WUA-PoP の既定有効期間（秒）。 */
const DEFAULT_POP_LIFETIME_SECONDS = 300;

/** WUA-PoP JWT の JWS ヘッダ `typ`。 */
const WUA_POP_TYP = 'wuapop+jwt' as const;

/** 読み取った値がプロパティを引ける非 null オブジェクトのときだけ返す（`as` で流さないため）。 */
function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null
    ? (value as Record<string, unknown>)
    : undefined;
}

/**
 * signer の公開鍵が WUA `cnf.jwk` にバインドされているか（同一 WSCD 鍵か）検査する。
 *
 * WUA-PoP は WUA `cnf.jwk` に対応する鍵で署名しなければならない。
 * 不一致は Passkey Assertion 不正として拒否する。
 *
 * 鍵種別ごとの比較規則は `publicKeyJwkMatches`（`jwk-match.ts`）に集約している。
 *
 * 比較対象の読み取りはプロトタイプ鎖を辿らない。鎖経由で読むと、`cnf` を持たない
 * WUA でも `Object.prototype.cnf` の汚染値が比較基準になり、**攻撃者が選んだ鍵でバインド検査が
 * 成立する**（fail-open）。`cnf` / `cnf.jwk` は純データなので own 限定（`ownProperty`）で読み、
 * `signer.publicKeyJwk` は KMS / HSM 鍵ラッパが getter（プロトタイプアクセサ）で公開し得るため
 * `nonObjectPrototypeProperty` で読む（own 限定にすると正当なクラスベース署名器が壊れる）。
 * いずれかが欠落・型不正なら `as` で下流へ流さず fail-closed に拒否する。
 */
function assertSignerBoundToCnf(wua: WalletUnitAttestation, signer: CredentialSigner): void {
  const cnf = asRecord(ownProperty(wua, 'cnf'));
  const cnfJwk = cnf === undefined ? undefined : asRecord(ownProperty(cnf, 'jwk'));
  const signerJwk = asRecord(nonObjectPrototypeProperty(signer, 'publicKeyJwk'));
  if (cnfJwk === undefined || signerJwk === undefined || !publicKeyJwkMatches(cnfJwk, signerJwk)) {
    throw new VericertsError(ErrorCodes.PASSKEY_ASSERTION_INVALID);
  }
}

/**
 * WUA `sub`（Wallet Instance の識別子）を、`wua.jwt` を再デコードして取り出す。
 *
 * PoP `iss` に必要な Wallet Instance の識別子は `wua.jwt` の `sub` クレームを都度読む。
 * 署名検証は行わない（`parseWalletUnitAttestation` と同じ「デコードのみ」）。
 *
 * `wua.jwt` は own 限定で読む（`jwt` を持たない WUA へ
 * `Object.prototype.jwt` の汚染値が供給されるのを防ぐ）。`sub` は decode 結果（null プロトタイプ）
 * の own プロパティなので `ownProperty` で読む。
 *
 * @throws `wua.jwt` が自身のプロパティとして無い・デコードできない・`sub` が非空文字列でない
 *         場合（VericertsError、code `10104`）。
 */
function walletInstanceIdOf(wua: WalletUnitAttestation): string {
  const jwt = ownProperty<unknown>(wua, 'jwt');
  if (typeof jwt !== 'string' || jwt.length === 0) {
    throw new VericertsError(ErrorCodes.PASSKEY_ASSERTION_INVALID);
  }
  let sub: unknown;
  try {
    sub = ownProperty<unknown>(decodeCompactJws(jwt).payload, 'sub');
  } catch {
    throw new VericertsError(ErrorCodes.PASSKEY_ASSERTION_INVALID);
  }
  if (!isNonEmptyString(sub)) {
    throw new VericertsError(ErrorCodes.PASSKEY_ASSERTION_INVALID);
  }
  return sub;
}

/**
 * WUA-PoP JWT を生成する。
 *
 * payload には Wallet Instance ID を表す `iss` と `aud` / `iat` / `exp` / `jti` / `nonce` を含める。ヘッダの `typ` は `wuapop+jwt`。署名鍵は WUA `cnf.jwk` に対応する
 * WSCD 鍵でなければならず、`signer.publicKeyJwk` が `cnf.jwk` に一致しない場合は拒否する。
 *
 * `jti` はリプレイ防止に必須。`opts.jti` 未指定時は `crypto.randomUUID()` で生成する。指定時は
 * UUIDv4（32〜36 文字）だけを受け付ける。
 *
 * @param wua 添付対象の WUA。
 * @param opts `aud` / `nonce` と任意の有効期間・`jti`。
 * @param signer WUA `cnf.jwk` に対応する WSCD 鍵の署名抽象。
 * @param nowSeconds 現在時刻（NumericDate、秒）。
 * @returns WUA-PoP JWT（コンパクト JWS）。
 * @throws signer 鍵が `cnf.jwk` と不一致、または `cnf.jwk` / `signer.publicKeyJwk` /
 *         `opts.aud` / `opts.nonce` / `wua.jwt` の `sub` クレームを取得できない場合
 *         （code `10104`）、署名演算が失敗した場合（code `1020`）、`opts.jti` を指定し、
 *         それが UUIDv4（ハイフンなし 32 文字 / 正準形 36 文字）でない場合（code `4013`）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export function buildWuaProofOfPossession(
  wua: WalletUnitAttestation,
  opts: WuaPopOptions,
  signer: CredentialSigner,
  nowSeconds: number,
): string {
  assertSignerBoundToCnf(wua, signer);

  // 任意プロパティは自身のプロパティに限って読む。継承値を拾うと、その項目を
  // **省略した**正当な生成でも汚染値が**署名済み WUA-PoP JWT** に載る。`jti` の継承値は
  // proof ごとに同じ値へ固定され、jti ベースのリプレイ検知を無効化する。`lifetimeSeconds` の
  // 継承値は `exp` を伸ばし、実質無期限の PoP を作れる。
  const lifetime = ownProperty<number>(opts, 'lifetimeSeconds') ?? DEFAULT_POP_LIFETIME_SECONDS;
  const jti = resolveProofJti(ownProperty(opts, 'jti'));
  // 必須の署名対象クレームも同じ理由で own 限定に揃える。`aud` の継承値は
  // `aud` を**省略した**正当な生成で「攻撃者が選んだ Authorization Server 向けの PoP」を
  // 署名させ、`nonce` の継承値は AS の c_nonce を差し替えてリプレイ防止を無効化する。
  // `iss`（Wallet Instance ID）は `wua.jwt` の `sub` クレームから取る（`walletInstanceIdOf`）ため、
  // `wua` オブジェクト自身の継承値に汚染される経路はない。
  const aud = ownProperty(opts, 'aud');
  const nonce = ownProperty(opts, 'nonce');
  if (typeof aud !== 'string' || typeof nonce !== 'string') {
    // `as` で undefined を型検査から隠して下流へ流さず、ここで fail-closed に倒す。
    throw new VericertsError(ErrorCodes.PASSKEY_ASSERTION_INVALID);
  }
  const iss = walletInstanceIdOf(wua);
  const claims: WuaPopClaims = {
    iss,
    aud,
    iat: nowSeconds,
    exp: nowSeconds + lifetime,
    jti,
    nonce,
  };

  return signCompactJws(buildJwsHeader(signer, WUA_POP_TYP), claims, signer);
}

/**
 * OAuth2 Attestation-Based Client Authentication の client_assertion を組み立てる。
 *
 * `<WUA>~<WUA-PoP>` を `client_assertion`、`WUA_CLIENT_ASSERTION_TYPE` を
 * `client_assertion_type` として返す。OID4VCI Token Request /
 * PAR / OID4VP Authorization Response に添付する。
 *
 * `wua.jwt` は own 限定で読む。鎖経由で読むと `jwt` を持たない WUA でも
 * `Object.prototype.jwt` の汚染値が `client_assertion` の前半へ載り、AS へ**攻撃者が用意した
 * WUA** を提示してしまう。
 *
 * @param wua 添付する WUA。
 * @param pop `buildWuaProofOfPossession` が生成した WUA-PoP JWT。
 * @returns client_assertion（`clientAssertion` / `clientAssertionType`）。
 * @throws `wua.jwt` を自身のプロパティとして持たない場合（code `10102`）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export function buildClientAttestation(wua: WalletUnitAttestation, pop: string): ClientAttestation {
  const jwt = ownProperty(wua, 'jwt');
  if (typeof jwt !== 'string') {
    throw new VericertsError(ErrorCodes.WUA_VERIFICATION_FAILED);
  }
  return {
    clientAssertion: `${jwt}~${pop}`,
    clientAssertionType: WUA_CLIENT_ASSERTION_TYPE,
  };
}
