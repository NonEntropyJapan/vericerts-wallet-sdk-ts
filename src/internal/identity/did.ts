/**
 * DID（Decentralized Identifier）共通の型定義とプラグインインターフェース。
 *
 * 本モジュールは型のみを提供し、実装は持たない。
 */

import type { ResolutionWorkBudget } from './resolution-budget.js';

/**
 * 本 SDK の did:key が対応する鍵タイプ。
 */
export type DidKeyType = 'Ed25519' | 'secp256k1' | 'P-256';

/**
 * JWK（JSON Web Key）の公開鍵表現。
 *
 * did:jwk / did:jwt / did:webvh など JWK 形式の鍵を扱うメソッド用。
 * 具体的なメンバ（kty / crv / x / y など）はメソッド側で検証するため、
 * ここでは任意のメンバを許容する汎用オブジェクト型とする。秘密鍵パラメータ
 * （`d` 等）は公開鍵表現には含めない。
 */
export type PublicKeyJwk = Readonly<Record<string, unknown>>;

/**
 * W3C DID Core の Service エントリ。
 *
 * did:web / did:peer（DIDCommMessaging）/ did:webvh などで利用する。
 * `serviceEndpoint` は文字列・オブジェクト・配列のいずれも取り得る（DID Core 準拠）。
 */
export interface Service {
  /** Service の ID（`<did>#<fragment>`）。 */
  readonly id: string;
  /** Service の type（例: `DIDCommMessaging`）。 */
  readonly type: string;
  /** サービスエンドポイント（URI 文字列、オブジェクト、またはその配列）。 */
  readonly serviceEndpoint: string | Readonly<Record<string, unknown>> | readonly unknown[];
}

/**
 * W3C DID Core の VerificationMethod。
 *
 * 公開鍵の表現はメソッドにより異なるため、各 `publicKey*` は optional とする:
 * - did:key: `publicKeyMultibase`（multibase base58btc）
 * - did:jwk / did:jwt / did:webvh: `publicKeyJwk`
 * - did:peer 等の一部: `publicKeyBase58`
 * - did:pkh: `blockchainAccountId`（CAIP-10）
 *
 * 少なくとも 1 つの公開鍵表現を持つことが期待されるが、型レベルでは強制しない
 * （メソッド実装側で保証する）。
 */
export interface VerificationMethod {
  /** VerificationMethod の ID（例: `<did>#<fragment>`）。 */
  readonly id: string;
  /** VerificationMethod の type（例: `Ed25519VerificationKey2020`）。 */
  readonly type: string;
  /** この鍵の controller（通常は所属 DID）。 */
  readonly controller: string;
  /** multibase base58btc 表現の公開鍵（`z...`）。did:key 等で使用。 */
  readonly publicKeyMultibase?: string;
  /** JWK 表現の公開鍵。did:jwk / did:jwt / did:webvh 等で使用。 */
  readonly publicKeyJwk?: PublicKeyJwk;
  /** base58btc 表現の公開鍵。一部の suite / did:peer で使用。 */
  readonly publicKeyBase58?: string;
  /** hex 表現の公開鍵（`0x` 付き）。did:ethr の Secp256k1 検証鍵で使用。 */
  readonly publicKeyHex?: string;
  /** base64 表現の公開鍵。did:ethr の Ed25519 検証鍵で使用。 */
  readonly publicKeyBase64?: string;
  /** CAIP-10 形式のブロックチェーンアカウント ID。did:pkh 等で使用。 */
  readonly blockchainAccountId?: string;
}

/**
 * W3C DID Core の DID Document。
 *
 * 標準で登録する DID メソッド（did:key / did:web / did:jwk / did:peer /
 * did:jwt / did:webvh）が返せる superset として定義する。
 *
 * 後方互換のため `verificationMethod` / `authentication` / `assertionMethod` は
 * 従来どおり必須（既存の did:key 実装・テストが直接添字アクセスするため）。
 * 全 DID メソッドはこれらを必ず埋める。relationship 値は参照（string）に加え、
 * VerificationMethod の埋め込みも許容する。
 */
export interface DIDDocument {
  /** JSON-LD コンテキスト。 */
  readonly '@context': readonly string[];
  /** DID（例: `did:key:<keyId>`）。 */
  readonly id: string;
  /** DID Document の controller（DID 文字列または DID 文字列の配列）。 */
  readonly controller?: string | readonly string[];
  /** 過去・別名の識別子（DID Core `alsoKnownAs`）。 */
  readonly alsoKnownAs?: readonly string[];
  /** 検証メソッドの配列。 */
  readonly verificationMethod: readonly VerificationMethod[];
  /** authentication に使える VerificationMethod の参照または埋め込み。 */
  readonly authentication: readonly (string | VerificationMethod)[];
  /** assertionMethod に使える VerificationMethod の参照または埋め込み。 */
  readonly assertionMethod: readonly (string | VerificationMethod)[];
  /** keyAgreement に使える VerificationMethod の参照または埋め込み。 */
  readonly keyAgreement?: readonly (string | VerificationMethod)[];
  /** capabilityInvocation に使える VerificationMethod の参照または埋め込み。 */
  readonly capabilityInvocation?: readonly (string | VerificationMethod)[];
  /** capabilityDelegation に使える VerificationMethod の参照または埋め込み。 */
  readonly capabilityDelegation?: readonly (string | VerificationMethod)[];
  /** サービスエンドポイントの配列（did:web / did:peer 等）。 */
  readonly service?: readonly Service[];
  /** 無効化フラグ（did:webvh 等）。`true` の場合は失効扱い。 */
  readonly deactivated?: boolean;
}

/**
 * DID 生成オプション（`DIDMethod.create`）。
 */
export interface CreateOptions {
  /** 公開鍵の鍵タイプ。 */
  readonly keyType: DidKeyType;
  /** raw 公開鍵バイト列（Ed25519=32B、secp256k1 / P-256=圧縮 33B）。 */
  readonly publicKey: Uint8Array;
}

/**
 * DID Document に適用する差分操作 6 種。
 *
 * 適用規則は `internal/identity/did-document-patch.ts` の `applyDidDocumentUpdate` が 1 か所で
 * 持つ。内部の {@link UpdateOptions} はこの型を extends する。
 *
 * **公開 API の `UpdateDIDOptions`（`wallet/options.ts`）は現状この型を土台にしておらず、同じ
 * 6 メンバを逐語で再宣言している。** 増減が片方にしか入らなければ「ファサードは受け取るが
 * プラグインへ渡らない差分」が黙って生まれるので、公開型をこの型から導出するか、少なくとも
 * 両者を同時に直すこと。ここに「どちらも土台にする」と書いてあるだけでは不変条件にならない。
 */
export interface DidDocumentPatch {
  /** 追加する VerificationMethod（`verificationMethod` 配列にのみ載る）。 */
  readonly addVerificationMethod?: VerificationMethod;
  /** 削除する VerificationMethod の id（relationship 配列の参照も外れる）。 */
  readonly removeVerificationMethod?: string;
  /** 追加する Service。 */
  readonly addService?: Service;
  /** 削除する Service の id。 */
  readonly removeService?: string;
  /** 追加する controller の DID。 */
  readonly addController?: string;
  /** 削除する controller の DID。 */
  readonly removeController?: string;
}

/**
 * DID 更新オプション（`DIDMethod.update`）。
 *
 * 差分操作 6 種（{@link DidDocumentPatch}）は Wallet ファサード `updateDID` がそのまま渡す。
 * プラグインは**差分を自分で適用しない** — 適用済みの次版 Document が `document` に入っており、
 * プラグインの責務は「それをこのメソッドのやり方で公開すること」だけである
 * （`internal/identity/did-document-patch.ts` のヘッダ参照）。差分適用と GDPR Art.9 ガードを
 * メソッドごとに書くと、片方だけ検査が抜ける。
 *
 * 不変な DID メソッド（did:key / did:jwk / did:peer / did:pkh / did:jwt）は本オプションを使わず
 * `2002` を投げる。メソッド固有の公開材料（did:ipid の IPNS 鍵など）は本インターフェースを
 * 拡張して受け取る（`IpidUpdateOptions`）。
 */
export interface UpdateOptions extends DidDocumentPatch {
  /**
   * 差分適用・Art.9 検査済みの次版 DID Document（`updateDID` ファサードが組み立てて渡す）。
   *
   * プラグインを `DIDMethod.update` 経由で直接呼ぶ経路では未指定になり得るため optional だが、
   * 公開を伴うプラグインは**未指定なら公開しない**（何を公開すべきか決まらない）。
   */
  readonly document?: DIDDocument;
}

/**
 * DID メソッドプラグインのインターフェース。
 */
export interface DIDMethod {
  /** メソッド名（例: did:key の場合 `'key'`）。 */
  method(): string;
  /** 公開鍵から DID Document を生成する。 */
  create(opts: CreateOptions): Promise<DIDDocument>;
  /**
   * DID 文字列を DID Document に解決する。
   *
   * `scope` は解決スコープ全体（VP 1 件 / DID Configuration 検証 1 回）の仕事量予算。署名検証など高コストな
   * 検証を行うメソッド（did:webvh / did:plc）だけが消費し、他のメソッドは無視してよい。
   * did:ebsi は仕事量を消費せず、取得した本文量だけを計上する。
   * did:ion は long-form の初期状態の検証（ハッシュ 2 回）を仕事量として消費する。
   * did:cheqd は did:ebsi と同じく本文量だけを計上する。
   */
  resolve(did: string, scope?: ResolutionWorkBudget): Promise<DIDDocument>;
  /** DID を更新する（did:key は非対応）。 */
  update(did: string, opts: UpdateOptions): Promise<DIDDocument>;
  /** DID を無効化する（did:key は非対応）。 */
  deactivate(did: string): Promise<void>;
}
