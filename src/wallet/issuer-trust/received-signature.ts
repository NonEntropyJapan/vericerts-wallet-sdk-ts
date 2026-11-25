/**
 * 受領した Credential の Issuer 署名を既定検証する共通ルール。
 *
 * `Wallet` メソッド層の受領経路は 2 つある。
 *
 * - `wallet.receiveCredential`
 * - `wallet.receivePID` / `wallet.receiveEAA`
 *
 * どちらも `Wallet` が持つ DID Resolver へ到達できる位置にあるため、**既定で Issuer 署名を検証する**
 * という契約を両者で揃える（揃えないと「同じ Wallet 層なのに受領経路ごとに検証の有無が
 * 違う」という非対称が残り、呼び出し側は経路ごとに責務を覚え直すことになる）。本モジュールはその
 * 共通規則 — 鍵解決と検証の分離・`3010` への正規化・明示フックの読み取り — を 1 箇所に集約する。
 * 規則を各ファサードへ複製すると、片方だけ fail-closed が緩む事故が起き得る。
 *
 * 規則は 3 つある（EUDI 経路にも適用する）。Issuer 鍵の**解決経路**
 * （`x5c` → ETSI TSL Trust Anchor / `iss` → JWT VC Issuer Metadata〔opt-in〕 / `iss` → DID）と
 * その分岐順序は `resolve.ts` が持ち、本モジュールはその結果を受け取るだけである
 * （解決の分岐と照合の規則を 1 ファイルに混ぜない）。
 *
 * 1. Issuer 鍵を解決できない場合は fail-closed（`3010` / `issuer_key_unresolved`）。JWK を持たない
 *    Issuer 鍵（did:pkh の `blockchainAccountId` 等）もここに含む。
 * 2. DID 解決失敗（DID 文字列不正・未対応メソッド・ネットワーク断・DID Document 不正）も、`x5c`
 *    経路の失敗（Trust Anchor 未設定・チェーン不成立・`iss` と SubjectAltName の不一致）
 * も、JWT VC Issuer Metadata 経路の失敗（metadata 取得失敗・`issuer` と `iss` の
 *    不一致・JWK Set 不正・`kid` で鍵を 1 つに絞れない）も、同じ `3010` /
 *    `issuer_key_unresolved` へ正規化する。理由コードを分けない — いずれも「検証に使える鍵が
 *    手に入らなかった」という同一の状態である。
 * 3. 呼び出し側が明示の検証フックを渡した場合、既定検証を**置換**する（併用しない）。
 *
 * 照合段の失敗（規則 2・3）で `3010` へ正規化するのは署名不一致（`3010`）と `VericertsError` 以外の例外
 * （VC 本文・署名を載せ得るため `cause` に渡さない）だけである。`3002` / `3024` / `3025` などそれ以外の
 * `VericertsError` は元のコードのまま返す。
 */

import type { ReceivedVerifiableCredential } from '../../internal/auth/oid4vci/facade/types.js';
import { preservedVerifyFailure } from '../../internal/auth/oid4vci/facade/verify-failure.js';
import {
  type CredentialVerifierKey,
  verifyCredential,
  verifySdJwt,
} from '../../internal/credential/index.js';
import { ErrorCodes, VericertsError } from '../../internal/errors.js';
import type { DidResolverLike } from '../../internal/identity/bounded-resolver.js';
import type { PublicKeyJwk } from '../../internal/identity/did.js';
import { nonObjectPrototypeProperty } from '../../internal/prototype-safety/own-property.js';
import { resolveIssuerVerifierKey } from '../issuer-key.js';
import { type ReceivedIssuerTrust, resolveReceivedIssuerKey } from './resolve.js';

/** 呼び出し側が渡せる明示の検証フック（受領した生 VC を受け取り、失敗時は throw する）。 */
export type VerifyReceivedHook = (received: string) => void | Promise<void>;

/**
 * Issuer 鍵を解決できなかったことを `3010`（`issuer_key_unresolved`）へ正規化する。
 *
 * 検証に使える鍵を取得できなければ、どの解決経路でも同じ理由コードを返す。
 *
 * - DID 経路: 「DID 文字列が不正」「未対応 DID メソッド」「DID 解決失敗（ネットワーク断・did:web
 *   到達不可）」「DID Document 不正」「解決できた鍵が JWK を持たない（did:pkh の
 *   `blockchainAccountId` 等）」。
 * - `x5c` 経路: 「`issuerTrustAnchors` 未設定」「`x5c` が不正」「Trust Anchor へ
 *   連鎖しない」「チェーン検証が課す RFC 5280 制約への違反（中間証明書の `cA:TRUE` /
 *   `keyCertSign` / `pathLenConstraint` / nameConstraints、leaf と中間の解釈できない critical 拡張、
 *   leaf の keyUsage が `digitalSignature` / `nonRepudiation` をいずれも持たない）」「チェーンが
 *   深すぎる（本経路では `maxDepth` を指定できず常に既定 5 段）」「`x5c[1..]`（中間証明書）が
 *   11 枚以上（`MAX_INTERMEDIATES` は 10 枚）」「`iss` が leaf 証明書の SubjectAltName と一致
 *   しない」「leaf 鍵が EC P-256 以外」。
 * - JWT VC Issuer Metadata 経路（`jwtVcIssuerMetadataResolution` 有効時のみ）:
 *   「非 HTTPS / query・fragment 付きの `iss`」「metadata 取得失敗・非 JSON Content-Type・本文
 *   1 MiB 超過」「`issuer` と `iss` の不一致」「`jwks` と `jwks_uri` の両方または欠落」「別 origin の
 *   `jwks_uri`」「リダイレクト後の最終 URL が別 origin」「`keys` に非オブジェクト要素を含む」
 *   「`kid` で鍵を 1 つに絞れない」「`kid` は在るが文字列でない / 空文字（`kid` 無し扱いへ格下げ
 *   しない）」。
 */
export function issuerKeyUnresolved(): VericertsError {
  return new VericertsError(ErrorCodes.SIG_INVALID, {
    context: { reason: 'issuer_key_unresolved' },
  });
}

/** 鍵は得られたが署名が合わなかったことを `3010` へ正規化する（署名不一致以外の失敗は含めない）。 */
export function receivedSignatureInvalid(): VericertsError {
  return new VericertsError(ErrorCodes.SIG_INVALID, {
    context: { reason: 'received_credential_signature_invalid' },
  });
}

/**
 * 受領した SD-JWT VC の Issuer 署名を既定検証する。
 *
 * **鍵解決と検証を別の try/catch に分ける**のが要点である。前段（Issuer 鍵の解決）の失敗は
 * 「そもそも照合する鍵が無い」、後段（`verifySdJwt`）の失敗は「鍵で照合したが一致しなかった /
 * 時刻条件を満たさない」であり、呼び出し側が取るべき対応が異なる。両者を 1 つの try/catch に
 * 畳むと理由の区別が付かなくなり、fail-closed の根拠（鍵が無いから拒否したのか、偽の VC だから
 * 拒否したのか）が失われる。
 *
 * @param trust Issuer 鍵解決の信頼材料（`ReceivedIssuerTrust`。DID Resolver・`x5c` 用 Issuer 側
 *        Trust Anchor・JWT VC Issuer Metadata 経路の opt-in と取得シーム）。
 * @param raw 受領した SD-JWT VC のコンパクト表現。
 * @param expectedVct 要求で選択した型。指定時は署名対象の vct と照合する。
 * @throws Issuer 鍵を解決できない場合（code `3010`、`reason: 'issuer_key_unresolved'`）、
 *         署名が合わない場合（code `3010`、`reason: 'received_credential_signature_invalid'`）。
 *         それ以外の `VericertsError`（`3002` / `3024` 等）は元のコード。
 */
export async function verifyReceivedSdJwt(
  trust: ReceivedIssuerTrust,
  raw: string,
  expectedVct?: string,
): Promise<void> {
  let issuerKey: PublicKeyJwk;
  try {
    issuerKey = await resolveReceivedIssuerKey(trust, raw);
  } catch {
    // DID・証明書・Metadata のいずれで鍵解決に失敗しても、呼び出し側には同じ理由コードを返す。
    throw issuerKeyUnresolved();
  }
  try {
    verifySdJwt(raw, { issuerKey, ...(expectedVct === undefined ? {} : { expectedVct }) });
  } catch (failure) {
    // 署名不一致（3010）だけを `received_credential_signature_invalid` へ正規化し、構造不正
    // （3002）・期限切れ（3024）等は元のコードで返す。
    throw preservedVerifyFailure(failure) ?? receivedSignatureInvalid();
  }
}

/**
 * 受領した VC の署名を `format` に応じて既定検証する（`wallet.receiveCredential` 用）。
 *
 * どちらの形式でも、鍵を解決できない場合と署名不一致は `3010` の `context.reason` で区別する。
 * 検証で生じた構造不正（`3002`）・期限切れ（`3024`）・有効化前（`3025`）など、
 * `3010` 以外の `VericertsError` は元のコードで返す。
 */
export async function verifyReceivedCredential(
  trust: ReceivedIssuerTrust,
  received: ReceivedVerifiableCredential,
): Promise<void> {
  if (received.format === 'sd-jwt') {
    await verifyReceivedSdJwt(trust, received.raw);
    return;
  }
  // `format: 'jwt'` 経路。内部ファサードの `facade/decode.ts`（`decodePayload`）が返す `format` は
  // `sd-jwt` / `jwt` の 2 値だけで、`data-integrity` / `cose` は現時点で生成されない。将来それらが
  // 生成されるようになったら、ここで専用の検証プリミティブへ分岐させる必要がある。
  // **`x5c` 経路は SD-JWT VC のみに入れている**。`x5c` を Issuer 鍵解決に使う運用は
  // ARF / SD-JWT VC の PID Provider の規定（draft-ietf-oauth-sd-jwt-vc）に由来し、JWT-VC 側には
  // 対応する `iss` ↔ 証明書の結び付け規定が無い。規定の無いまま同じ分岐を足すと、`iss` と無関係な
  // 証明書で JWT-VC が「検証済み」になる余地を作る。
  // `resolver` は DI 依存なので `nonObjectPrototypeProperty` で読む（`ReceivedIssuerTrust` の
  // 読み取り規律。`resolve.ts` の DID 解決経路と同じ）。`trust.resolver` の素の鎖読みだと
  // `Object.prototype.resolver` の汚染値が Resolver に化け、攻撃者が選んだ DID Document の鍵で
  // JWT-VC の署名が「検証済み」になる。`factory.ts` が常に own プロパティとして載せるため
  // 現状この分岐は到達しないが、規律は SD-JWT 経路と同じ形で 2 箇所とも強制しておく。
  const resolver = nonObjectPrototypeProperty<DidResolverLike>(trust, 'resolver');
  // 必須メンバだが、汚染値を掴むくらいなら鍵無しで倒す（fail-closed。`resolve.ts` と同じ扱い）。
  if (resolver === undefined) throw issuerKeyUnresolved();
  let key: CredentialVerifierKey;
  try {
    key = await resolveIssuerVerifierKey(resolver, received.raw);
  } catch {
    throw issuerKeyUnresolved();
  }
  try {
    verifyCredential(received.raw, { key });
  } catch (failure) {
    // 署名不一致（3010）だけを `received_credential_signature_invalid` へ正規化し、構造不正
    // （3002）・期限切れ（3024）等は元のコードで返す。
    throw preservedVerifyFailure(failure) ?? receivedSignatureInvalid();
  }
}

/** {@link readVerifyReceived} の戻り値。判定と実行で**同じ 1 回の読み**の結果を使う。 */
export interface ResolvedVerifyReceived {
  /** 明示フックが指定されていたか（既定検証を置換するかの判定に使う）。 */
  readonly hasCustomVerify: boolean;
  /** 実行する値（関数ならレシーバを束ねた関数、関数でなければ読んだ値そのまま）。 */
  readonly verifyReceived: VerifyReceivedHook | undefined;
}

/**
 * `opts.verifyReceived` を**1 回だけ**読み、「既定検証を置換するかどうかの判定」と「実際に実行する
 * 値」の両方に同じ結果を使う。
 *
 * 判定を `nonObjectPrototypeProperty(opts, 'verifyReceived')` で読む一方、実行側を `{...opts}`
 * （スプレッド。own enumerable プロパティのみコピー）経由で渡すと穴が開く。
 * `class Opts { verifyReceived() {…} }` のようにプロトタイプメソッドとして DI する
 * （`own-property.ts` の規約が正当な形として挙げているパターン）と、判定側はプロトタイプメソッドを
 * 正しく拾って `hasCustomVerify = true` になる一方、スプレッドはプロトタイプメソッドをコピーしない
 * ため実行側に渡る値は `undefined` になる。結果、既定検証はスキップされる（`hasCustomVerify=true`
 * のため）のにカスタム検証も呼ばれず、**署名検証が一切走らずに VC が受理される**（fail-open）。
 * `verifyReceived` をアクセサ（getter）で公開する `opts` を 2 回読む実装でも、副作用のある getter
 * により同じ穴が開く。
 *
 * 本関数はその読みを 1 箇所に集約する。関数値ならレシーバ（`opts`）を `bind` して確定させる
 * （プロトタイプメソッドはインスタンス状態を `this` で参照し得るため）。関数でない値はそのまま返し、
 * 型検査は呼び出し側（内部ファサードの `optionalFunction`、`invalid_receive_deps` / `8010`）または
 * {@link runVerifyReceivedHook} に委ねる。
 */
export function readVerifyReceived(opts: object | undefined): ResolvedVerifyReceived {
  if (opts === undefined) {
    return { hasCustomVerify: false, verifyReceived: undefined };
  }
  const raw = nonObjectPrototypeProperty<unknown>(opts, 'verifyReceived');
  if (raw === undefined) {
    return { hasCustomVerify: false, verifyReceived: undefined };
  }
  const verifyReceived =
    typeof raw === 'function'
      ? ((raw as VerifyReceivedHook).bind(opts) as VerifyReceivedHook)
      : (raw as VerifyReceivedHook);
  return { hasCustomVerify: true, verifyReceived };
}

/**
 * 明示の検証フックを実行し、署名不一致相当の throw を `3010` へ正規化する（EUDI 受領経路用）。
 *
 * 関数でない `verifyReceived` を渡された場合は「検証したことにしない」ため同じ `3010` で
 * fail-closed に落とす（`hasCustomVerify` が立っている以上、既定検証はもう走らないため、ここで
 * 素通しすると無検証で受理される）。
 *
 * @throws フックが関数でない場合、フックが `VericertsError` 以外・`3010` を throw した場合（code `3010`、
 *         `reason: 'received_credential_signature_invalid'`）。`3010` 以外の `VericertsError` は元のコード。
 */
export async function runVerifyReceivedHook(
  hook: VerifyReceivedHook | undefined,
  raw: string,
): Promise<void> {
  if (typeof hook !== 'function') {
    throw receivedSignatureInvalid();
  }
  try {
    await hook(raw);
  } catch (failure) {
    // 署名不一致以外の `VericertsError`（3002 / 3024 等）は元のコードを保つ。
    // VC 本文・署名を載せ得る素の例外は cause に渡さず 3010 へ畳む。
    throw preservedVerifyFailure(failure) ?? receivedSignatureInvalid();
  }
}
