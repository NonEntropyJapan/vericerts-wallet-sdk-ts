/**
 * DID Document から JWS 検証用の公開鍵（`CredentialVerifierKey`）を抽出するヘルパ。
 *
 * `verifyCredential` は検証鍵を DI で受け取る（発行者 DID 解決は credential の責務外）。本モジュールは
 * 解決済み DID Document（identity 側で取得済み）から、`verifyCredential` が受理する
 * `{ publicKeyJwk }` 形へ検証鍵を取り出す橋渡しを担う。
 *
 * 公開鍵表現（`publicKeyJwk` / `publicKeyMultibase` / `publicKeyHex`）から JWK への変換は
 * 兄弟モジュール `verifier-key-jwk.ts` が担う。対応する鍵タイプは `ES256`（EC P-256）/
 * `ES256K`（EC secp256k1）/ `EdDSA`（OKP Ed25519）で、それ以外（RSA・X25519 等）は
 * `UNSUPPORTED_ALGORITHM`（code `1030`）となる。
 *
 * 検証鍵の選択方針（JSDoc 明記）:
 * 候補は **`opts.relationship` に列挙された VerificationMethod だけ**（既定 `assertionMethod`。VC 検証は
 * assertion 用途、DIDComm の送信者認証は `authentication`）。`verificationMethod` 配列に在るだけで
 * relationship に宣言されていない鍵（`keyAgreement` 専用鍵など）は、署名鍵としては選ばない。
 * 文字列参照は `verificationMethod` から解決し、解決できない参照は `DID_DOC_INVALID`（2010）。
 * 1. `opts.verificationMethodId`（JWS ヘッダ `kid` 等）指定時は、候補の中でその id に一致する
 *    VerificationMethod を使う（`#frag` の相対 id は `doc.id` 基準で比較）。候補に無ければ 2010。
 * 2. 未指定時は候補の先頭を使う。候補が空なら 2010（`verificationMethod[0]` へのフォールバックは無い）。
 *
 * レイヤリング: 本モジュールは Domain（credential）に属し、鍵の低レベル変換は
 * `verifier-key-jwk.ts` 経由で Foundation（`identity/multibase.ts` / `@noble/curves`）に委ねる。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・公開鍵バイトなどの入力データを含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { DIDDocument, PublicKeyJwk, VerificationMethod } from '../../identity/did.js';
import { relationshipEntriesOf, verificationMethodsOf } from '../../identity/did-document-read.js';
import { ES256K_R_ALG, verifyEip191Address } from '../../keymanager/eip191.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { type CredentialSignerAlg, type DecodedJws, verifyWithJwkOrFalse } from './jws.js';
import { ethereumAddressOfMethod } from './verifier-key-ethereum.js';
import { verificationMethodToJwk } from './verifier-key-jwk.js';
import type { CredentialVerifierKey } from './verify.js';

/** `verifier-key` の選択オプション。 */
export interface VerifierKeyOptions {
  /**
   * 使用する VerificationMethod の id（完全一致）。
   * 指定時はこの id の鍵のみを使い、見つからなければエラー（`DID_DOC_INVALID` 2010）。
   */
  readonly verificationMethodId?: string;
  /**
   * 鍵を選ぶ検証関係（既定 `assertionMethod`）。VC / SD-JWT の発行者署名は `assertionMethod`、
   * DIDComm の送信者認証は `authentication`。
   */
  readonly relationship?: 'assertionMethod' | 'authentication';
}

/** 相対 id（`#frag`）を `doc.id` 基準の絶対 id に直して比較用に正規化する。 */
function absoluteVmId(docId: unknown, id: unknown): unknown {
  return typeof id === 'string' && id.startsWith('#') && typeof docId === 'string'
    ? `${docId}${id}`
    : id;
}

/**
 * 選択方針に従って DID Document から対象 VerificationMethod を決定する。
 *
 * @param doc DID Document。
 * @param opts 選択オプション。
 * @returns 選択された VerificationMethod。
 * @throws id 指定が見つからない / 候補がない場合（VericertsError、code `2010`）。
 */
function selectVerificationMethod(doc: DIDDocument, opts?: VerifierKeyOptions): VerificationMethod {
  // 失効済み DID の委任鍵では検証鍵を作らない（配列を空にした did:ethr 以外の経路の保険）。
  // own 限定で読む。`Object.prototype.deactivated = true` で自己完結メソッド（did:key / did:jwk 等）の
  // 全検証が 2010 になる DoS を防ぐ。
  if (ownProperty<unknown>(doc, 'deactivated') === true) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  // 欠落は空、配列でない値は 2010。素の `[0]` / `.find` は生 TypeError になる。
  const methods = verificationMethodsOf(doc);
  // 選択オプションも own 限定。継承値の relationship / verificationMethodId で選ばれる鍵が変わらない。
  const relationship =
    ownProperty<NonNullable<VerifierKeyOptions['relationship']>>(opts ?? {}, 'relationship') ??
    'assertionMethod';
  // 候補 = 指定 relationship に列挙された VM のみ。参照は verificationMethod から解決する。
  // 参照ごとに配列を走査すると O(R×M) になるため、id → VM を 1 回だけ畳む（重複 id は先頭が勝つ）。
  const methodById = new Map<string, VerificationMethod>();
  for (const vm of methods) {
    const id = ownProperty<string>(vm, 'id');
    if (id !== undefined && !methodById.has(id)) {
      methodById.set(id, vm);
    }
  }
  const candidates = (relationshipEntriesOf(doc, relationship) ?? []).map((entry) => {
    if (typeof entry !== 'string') {
      return entry;
    }
    const resolved = methodById.get(entry);
    if (resolved === undefined) {
      throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
    }
    return resolved;
  });
  const wantedId = ownProperty<string>(opts ?? {}, 'verificationMethodId');
  // `id` は VM・文書とも own 限定で読む。`id` を欠く文書が `Object.prototype.id` の汚染値を拾って
  // 「`#key` 参照の絶対化」や選択対象の同一性判定を乗っ取られない。
  const docId = ownProperty<string>(doc, 'id');
  const selected =
    wantedId === undefined
      ? candidates[0]
      : candidates.find(
          (vm) =>
            absoluteVmId(docId, ownProperty<string>(vm, 'id')) === absoluteVmId(docId, wantedId),
        );
  if (selected === undefined) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  return selected;
}

/**
 * DID Document から JWS 検証用の公開鍵 JWK を取り出し、`verifyCredential` が受理する
 * `CredentialVerifierKey`（`{ publicKeyJwk }`）として返す。
 *
 * 検証鍵の選択方針は本モジュール冒頭の JSDoc を参照（relationship の候補から
 * `opts.verificationMethodId` 一致 → 先頭。フォールバックなし）。
 *
 * @param doc 解決済みの DID Document。
 * @param opts 検証鍵の選択オプション。
 * @returns `verifyCredential` に渡せる検証鍵（`{ publicKeyJwk }`。公開鍵を持たない did:pkh / did:ethr の controller 鍵は
 *          `{ ethereumAddress }`で、`alg: "ES256K-R"` の署名だけを検証できる）。
 * @throws 候補がない / 公開鍵表現が不正な場合（VericertsError、code `2010`）、
 *         対応 alg（`ES256K-R` を除く `ES256` / `ES256K` / `EdDSA`）で検証できない鍵タイプの場合（code `1030`）、
 *         multibase 形式不正の場合（code `2001`）。ただし `EcdsaSecp256k1RecoveryMethod2020` + `eip155` の `blockchainAccountId` だけの
 *         検証メソッドは例外にせず `{ ethereumAddress }` を返す（上記。以前は `2010`）。
 */
export function didDocumentToVerifierKey(
  doc: DIDDocument,
  opts?: VerifierKeyOptions,
): CredentialVerifierKey {
  return verifierKeyOfMethod(selectVerificationMethod(doc, opts));
}

/**
 * 単一の検証メソッドを検証鍵にする（公開鍵を持つなら `{ publicKeyJwk }`、`blockchainAccountId` だけなら `{ ethereumAddress }`）。
 *
 * 公開鍵を持たず `blockchainAccountId` だけの検証メソッド（did:pkh / did:ethr の controller 鍵）は、署名から公開鍵を復元して
 * アドレスと照合する `ES256K-R`（IANA 登録外の標準外の例外）専用のアドレス鍵になる。
 *
 * @throws 公開鍵表現が不正（`2010`）・未対応の鍵種（`1030`）・multibase 形式不正（`2001`）で、アドレス鍵にもできない場合。
 */
export function verifierKeyOfMethod(vm: VerificationMethod): CredentialVerifierKey {
  try {
    return { publicKeyJwk: verificationMethodToJwk(vm) };
  } catch (error) {
    const ethereumAddress = ethereumAddressOfMethod(vm);
    if (ethereumAddress !== undefined && error instanceof VericertsError) {
      return { ethereumAddress };
    }
    throw error;
  }
}

/**
 * 検証メソッドの鍵で、デコード済み JWS の署名を検証する（SIOPv2 id_token / `did_signMessage` 用）。
 *
 * `alg: "ES256K-R"` はアドレス鍵（`blockchainAccountId`）の検証メソッドだけ、ほかの alg は公開鍵を持つ検証メソッドだけで検証する。
 * アドレス鍵だけの検証メソッドを標準の alg（`ES256K` など）で検証しようとした場合（alg の差し替え）は、公開鍵として読めないことによる
 * 文書不正（`2010`）ではなく署名不正（`false`）として扱う。
 *
 * @returns 署名が有効なら `true`。
 * @throws 検証メソッドが公開鍵として読めず、アドレス鍵でもない場合（`2010` / `1030` / `2001`。`verificationMethodToJwk` と同じ）。
 */
export function verifyWithMethod(
  alg: CredentialSignerAlg,
  decoded: Pick<DecodedJws, 'signingInput' | 'signature'>,
  method: VerificationMethod,
): boolean {
  if (alg === ES256K_R_ALG) {
    const address = ethereumAddressOfMethod(method);
    return (
      address !== undefined && verifyEip191Address(decoded.signingInput, decoded.signature, address)
    );
  }
  let jwk: PublicKeyJwk;
  try {
    jwk = verificationMethodToJwk(method);
  } catch (error) {
    if (error instanceof VericertsError && ethereumAddressOfMethod(method) !== undefined) {
      return false;
    }
    throw error;
  }
  return verifyWithJwkOrFalse(alg, decoded, jwk);
}
