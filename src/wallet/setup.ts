/**
 * Wallet 生成・委譲のための補助関数群。
 *
 * `createWallet`（`wallet.ts`）から検証鍵解決（`issuer-key.ts`）・createDID 用公開鍵取得・
 * controller Tx 依存組み立てといった詳細を分離し、ファサード本体を薄く保つ。DID メソッドの登録
 * （`buildDidResolver`）は公開 API として単独で使えるよう `did-resolver.ts` にある。
 */

import type { PrivateKeyJwk } from '../internal/credential/did-signing/external-key.js';
import {
  type PersonaSignerOptions,
  resolvePersonaSigner,
} from '../internal/credential/did-signing/persona-signer.js';
import type { CredentialAlg, CredentialSignerAlg } from '../internal/credential/vc/jws.js';
import { type CredentialSigner, requireStandardSigner } from '../internal/credential/vc/signer.js';
import type { AbiEncoder, ControllerTxDeps } from '../internal/delegation/index.js';
import { ErrorCodes, VericertsError } from '../internal/errors.js';
import type { DidResolverLike } from '../internal/identity/bounded-resolver.js';
import { DEFAULT_REGISTRY_ADDRESS } from '../internal/identity/ethr/registry.js';
import type { Resolver } from '../internal/identity/resolver.js';
import { p256DidPath } from '../internal/keymanager/derivation/slip10.js';
import type { KeyManager } from '../internal/keymanager/keymanager.js';
import type { PersonaManager } from '../internal/persona/persona.js';
import { personaFields } from '../internal/persona/persona-fields.js';
import type { PersonaMetadata } from '../internal/persona/types.js';
import { ownProperty } from '../internal/prototype-safety/own-property.js';

/**
 * createDID 用の did:key の鍵（種類と公開鍵）を取得する。
 *
 * - 省略時は P-256（ES256）の鍵を SLIP-0010 `m/9256'/0'/0'/0'`（`p256DidPath(0)`）で新規導出する。新規に作成する DID は
 *   P-256 のみ。ペルソナ index 0 と同じ鍵なので、同じ seed からは同じ DID になる。
 * - keyID 指定時は、呼び出し側が `deriveKey` で既に保持している鍵（secp256k1）の公開鍵をそのまま did:key にする
 *   （既存鍵の DID 化。`getSigner` 経由。P-256 の鍵 ID は `1030`）。新しい鍵は作らない。
 *
 * @param keymanager 鍵管理委譲先。
 * @param keyID 使用する保持済みの鍵の ID（省略時は P-256 を新規導出）。
 * @throws 指定 keyID が未登録の場合（VericertsError、code `1004`）。
 */
export async function resolveCreateDidKey(
  keymanager: KeyManager,
  keyID?: string,
): Promise<{ readonly keyType: 'P-256' | 'secp256k1'; readonly publicKey: Uint8Array }> {
  if (keyID !== undefined) {
    return { keyType: 'secp256k1', publicKey: keymanager.getSigner(keyID).publicKey() };
  }
  const keyPair = await keymanager.deriveP256Key(p256DidPath(0));
  return { keyType: 'P-256', publicKey: keyPair.publicKey };
}

/**
 * 取り込んだ DID のペルソナの外部秘密鍵（JWK）を、DID を指定して返すコールバック（`WalletOptions.externalKeyProvider`）。
 * 見つからなければ `undefined`。SDK は返された鍵を保存しない（署名のたびに呼び出し側から受け取る）。
 */
export type ExternalKeyProvider = (did: string) => Promise<PrivateKeyJwk | undefined>;

/** Wallet ファサードがアクティブペルソナの署名鍵を解決するときの共通設定（`createWallet` が 1 度だけ組み立てる）。 */
export interface ActiveSignerOptions extends PersonaSignerOptions {
  /** `keySource: 'external'` のペルソナの秘密鍵 JWK の提供元（`opts.externalKey` が無いとき、ペルソナの DID で呼ぶ）。 */
  readonly externalKeyProvider?: ExternalKeyProvider;
}

/**
 * 取り込んだ DID のペルソナの署名・照合に使う DID Resolver を、Wallet の Resolver から作る。
 *
 * 署名のたびに DID Document を解決し直して保持鍵との一致を確かめる設計（`resolvePersonaSigner`）なので、鍵を
 * ローテーション・削除した DID は直ちに署名できなくならなければならない。Wallet の Resolver の did:web は
 * `Cache-Control` に従って最長 600 秒（取得失敗は 30 秒）、did:ebsi / did:ion / did:cheqd は 600 秒記憶するため、
 * 解決結果を記憶するこの 4 メソッドは Resolver に添えたキャッシュなし版（`Resolver.resolveUncached`）で解決する。
 * それ以外のメソッドは記憶しないので Wallet の Resolver と同じプラグインで解決する。`registerDIDMethod` で差し替えた
 * メソッドはその差し替え後のプラグインが解決する（キャッシュの有無はそのプラグインの責務）。
 */
export function createPersonaSigningResolver(resolver: Resolver): DidResolverLike {
  return { resolve: (did, scope) => resolver.resolveUncached(did, scope) };
}

/**
 * ペルソナの `resolvePersonaSigner` へ渡すオプションを組み立てる。外部鍵のペルソナで `externalKey` が無ければ
 * `externalKeyProvider` から DID を指定して受け取る（無い・`undefined` なら渡さない = `2007`）。
 *
 * @throws プロバイダーが失敗した場合（code `2007`。原因の例外は秘密を含み得るので伝播しない）。
 */
async function signerOptionsFor(
  persona: PersonaMetadata,
  opts: ActiveSignerOptions | undefined,
): Promise<PersonaSignerOptions | undefined> {
  if (opts === undefined) {
    return undefined;
  }
  const { externalKeyProvider: _provider, ...rest } = opts;
  const provider = ownProperty<ExternalKeyProvider>(opts, 'externalKeyProvider');
  const { keySource, did } = personaFields(persona);
  if (
    provider === undefined ||
    keySource !== 'external' ||
    ownProperty<PrivateKeyJwk>(opts, 'externalKey') !== undefined
  ) {
    return rest;
  }
  let externalKey: PrivateKeyJwk | undefined;
  try {
    externalKey = await provider(did);
  } catch {
    throw new VericertsError(ErrorCodes.DID_SIGNING_KEY_UNAVAILABLE);
  }
  return externalKey === undefined ? rest : { ...rest, externalKey };
}

/**
 * アクティブペルソナから DID と署名鍵を導出する。
 *
 * アクティブペルソナの鍵（secp256k1 = BIP-32 / P-256 = SLIP-0010。`resolvePersonaSigner`）から
 * `CredentialSigner` を取得する。`alg` は鍵の種類で決まる（ES256K / ES256 / EdDSA）。返す署名鍵は従来どおり
 * `kid` を持たない（`kid` 付きの署名鍵が要る VP / VC / id_token は `resolveActiveHolder`）。Holder DID は
 * アクティブペルソナの DID を用いる。
 *
 * 取り込んだ DID のペルソナは DID Document との照合（`opts.resolver`）が要る。Resolver を渡さない呼び出しは、
 * 取り込んだ DID のペルソナを `2007` で拒否する（fail-closed）。外部鍵のペルソナの秘密鍵は `opts.externalKey` か
 * `opts.externalKeyProvider`（ペルソナの DID で呼ぶ）で渡す。どちらも無ければ `2007`。
 *
 * @param personas ペルソナ管理委譲先。
 * @param keymanager 鍵管理委譲先。
 * @param opts 検証関係・Resolver・外部秘密鍵（の提供元）。
 * @returns 署名鍵（CredentialSigner。IANA 登録済みの `alg` のみ）・Holder DID・検証メソッド id（`kid`）。
 * @throws アクティブペルソナ未設定の場合（VericertsError、code `2005`）。マスターシード未 import
 *   時は `deriveKey` が `1041` を投げる（そのまま伝播）。取り込んだ DID の照合失敗は `2007` / `2017`。
 *   did:pkh / did:ethr の controller 鍵（`ES256K-R`。標準外の例外で、自分の DID の VP / VC / id_token / signMessage だけに使う）を持つ
 *   ペルソナは `1030`（`context.reason: "es256k_r_not_allowed"`）。
 */
export async function resolveActiveSigner(
  personas: PersonaManager,
  keymanager: KeyManager,
  opts?: ActiveSignerOptions,
): Promise<{ signer: CredentialSigner<CredentialAlg>; did: string; kid: string }> {
  const persona = await personas.getActivePersona();
  if (persona === null) {
    throw new VericertsError(ErrorCodes.PERSONA_NOT_FOUND);
  }
  const {
    signer: keyed,
    did,
    kid,
  } = await resolvePersonaSigner(keymanager, persona, await signerOptionsFor(persona, opts));
  const standard = requireStandardSigner(keyed);
  const signer: CredentialSigner<CredentialAlg> = {
    alg: standard.alg,
    publicKeyJwk: standard.publicKeyJwk,
    sign: (signingInput) => standard.sign(signingInput),
  };
  return { signer, did, kid };
}

/** アクティブペルソナから解決した署名鍵・Holder DID・検証鍵 ID（`did#fragment` 形式）。 */
export interface ActiveHolder<A extends CredentialSignerAlg = CredentialAlg> {
  /** JWT Proof / KB-JWT の署名鍵（`kid` 付き）。 */
  readonly signer: CredentialSigner<A>;
  /** Holder DID（JWT Proof の `iss` / VP の `holder`）。 */
  readonly did: string;
  /** 検証鍵 ID（`did#fragment`）。 */
  readonly keyId: string;
}

/**
 * アクティブペルソナの署名鍵と Holder 識別子を、`kid` 付きの `CredentialSigner` として解決する。
 *
 * `kid` はペルソナの検証メソッド id（`persona.kid`。旧レコードは did:key の規則 `<did>#<multibase>`）。署名を
 * 検証する側（`presentPIDCredential` 等）は `kid` を持たない署名鍵を `missing_holder_key_id` 系のコードで
 * 拒否するため、必ず載せる。`EudiFacade`（`wallet/eudi/facade.ts`）の `receivePID` 等と
 * `receiveCredentialWith`（`wallet/credential/ops.ts`）が共有する。
 *
 * @param personas ペルソナ管理委譲先。
 * @param keymanager 鍵管理委譲先。
 * @param opts 検証関係・Resolver・外部秘密鍵（の提供元。`resolveActiveSigner` と同じ）。
 * @returns 署名鍵（IANA 登録済みの `alg` のみ）・Holder DID・検証鍵 ID。
 * @throws アクティブペルソナ未設定の場合（VericertsError、code `2005`）。did:pkh / did:ethr の controller 鍵（`ES256K-R`。
 *   標準外の例外で、自分の DID の VP / VC だけに使う）のペルソナは `1030`（`es256k_r_not_allowed`）。
 */
export async function resolveActiveHolder(
  personas: PersonaManager,
  keymanager: KeyManager,
  opts?: ActiveSignerOptions,
): Promise<ActiveHolder> {
  const holder = await resolveActiveOwnDidHolder(personas, keymanager, opts);
  return { ...holder, signer: requireStandardSigner(holder.signer) };
}

/**
 * `resolveActiveHolder` と同じだが、`ES256K-R`（did:pkh / did:ethr の controller 鍵。標準外の例外）の署名鍵も返す。
 * 自分の DID の署名（JWT-VP / JWT-VC / SIOPv2 id_token / `did_signMessage`）だけが使う。OID4VCI の proof・EUDI・KB-JWT など
 * 他の経路は `resolveActiveHolder`（標準の `alg` のみ）を使う。
 */
export async function resolveActiveOwnDidHolder(
  personas: PersonaManager,
  keymanager: KeyManager,
  opts?: ActiveSignerOptions,
): Promise<ActiveHolder<CredentialSignerAlg>> {
  const persona = await personas.getActivePersona();
  if (persona === null) {
    throw new VericertsError(ErrorCodes.PERSONA_NOT_FOUND);
  }
  const { signer, did, kid } = await resolvePersonaSigner(
    keymanager,
    persona,
    await signerOptionsFor(persona, opts),
  );
  return { signer, did, keyId: kid };
}

/**
 * 指定した DID に対応する署名鍵をアクティブペルソナから解決する（`generateDIDConfiguration` 用）。
 *
 * 対象は呼び出し側が指定した `did` に限定する。
 * `generateDIDConfiguration` は `keyID` を取らないため、署名鍵はアクティブペルソナからしか
 * 解決できず、「その鍵が本当に `did` のものか」を確かめないと**別 DID の鍵で署名した
 * Domain Linkage Credential** を返してしまう（検証側では self-issued にならず必ず落ちる）。
 *
 * 返す署名鍵は `kid`（ペルソナの検証メソッド id。取り込んだ DID は `assertionMethod` で保持鍵と一致した検証メソッド）
 * を持つ（`resolveActiveHolder` と同じ）。DLC の JWS ヘッダに `kid` が載らないと、検証側は `assertionMethod[0]` を
 * 検証鍵に選ぶため、保持鍵が先頭でない取り込み DID の DLC が `verifyDIDConfiguration` で落ちる。
 *
 * 失敗理由（アクティブペルソナ未設定 `2005` / マスターシード未投入 `1041` / 取り込んだ DID の照合失敗 `2017` /
 * 外部鍵・Resolver なし `2007` / DID 不一致）はすべて `DID_SIGNING_KEY_UNAVAILABLE`（`2007`）へ正規化する。
 * このコードは、指定した DID に使える署名鍵を得られなかったことを表す。
 *
 * @param personas ペルソナ管理委譲先。
 * @param keymanager 鍵管理委譲先。
 * @param did 署名主体として要求された DID。
 * @param opts 取り込んだ DID のペルソナで署名するための Resolver・外部秘密鍵の提供元。
 * @returns `did` のものであることを確認した、`kid` 付きの署名鍵。
 * @throws 指定 `did` の署名鍵が利用できない場合（VericertsError、code `2007`）。
 */
export async function resolveSignerForDid(
  personas: PersonaManager,
  keymanager: KeyManager,
  did: string,
  opts?: ActiveSignerOptions,
): Promise<CredentialSigner<CredentialSignerAlg>> {
  let holder: ActiveHolder<CredentialSignerAlg>;
  try {
    // DLC は VC（self-issued）なので、取り込んだ DID は `assertionMethod` に載った鍵だけで署名できる。
    holder = await resolveActiveOwnDidHolder(personas, keymanager, {
      ...opts,
      relationship: 'assertionMethod',
    });
  } catch {
    // 呼び出し元は指定した DID で署名できるかを判定するため、失敗理由を 2007 に統一する。
    throw new VericertsError(ErrorCodes.DID_SIGNING_KEY_UNAVAILABLE);
  }
  if (holder.did !== did) {
    throw new VericertsError(ErrorCodes.DID_SIGNING_KEY_UNAVAILABLE);
  }
  return holder.signer;
}

/**
 * controller Tx 構築用の依存を組み立てる。registryAddress 省略時は ERC-1056 標準アドレスを使う。
 *
 * @param encoder ERC-1056 書き込み Tx の ABI エンコーダ。
 * @param registryAddress ERC-1056 レジストリアドレス（省略時は標準アドレス）。
 */
export function buildControllerTxDeps(
  encoder: AbiEncoder,
  registryAddress?: string,
): ControllerTxDeps {
  return { registryAddress: registryAddress ?? DEFAULT_REGISTRY_ADDRESS, encoder };
}
