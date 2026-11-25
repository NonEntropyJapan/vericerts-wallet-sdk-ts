/**
 * persona モジュールの型定義。
 *
 * ペルソナはサブ DID ごとの独立したアイデンティティコンテキストを表す。BIP-32 / SLIP-0010 の HD 鍵から
 * ペルソナ index 単位で派生した鍵に基づき DID（did:key / did:jwk / did:peer）を生成し、その派生メタデータを
 * 永続化する。既存 DID を取り込んだペルソナ（did:web など）も同じメタデータで表す。
 * 本モジュールは型のみを提供し、実装は持たない。
 *
 * セキュリティ上の注意:
 * - メタデータには秘密（seed / privateKey）を含めない。公開鍵由来の did / address のみを保持する。
 */

/** ペルソナの DID メソッド（SDK の Resolver が解決できる全メソッド）。 */
export const PERSONA_DID_METHODS = [
  'key',
  'jwk',
  'peer',
  'web',
  'ethr',
  'pkh',
  'plc',
  'jwt',
  'webvh',
  'ipid',
  'ebsi',
  'ion',
  'cheqd',
] as const;

/** ペルソナの DID メソッド。 */
export type PersonaDidMethod = (typeof PERSONA_DID_METHODS)[number];

/** 新規作成（`createPersona`）できる DID メソッド。他のメソッドは既存 DID の取り込みのみ。 */
export type CreatablePersonaMethod = 'key' | 'jwk' | 'peer';

/** ペルソナの鍵の種類（P-256 = ES256 / secp256k1 = ES256K / Ed25519 = EdDSA）。 */
export const PERSONA_KEY_TYPES = ['P-256', 'secp256k1', 'Ed25519'] as const;

/** ペルソナの鍵の種類。 */
export type PersonaKeyType = (typeof PERSONA_KEY_TYPES)[number];

/** 鍵の出所（`seed` = シード導出 / `external` = 取り込んだ秘密鍵）。 */
export const PERSONA_KEY_SOURCES = ['seed', 'external'] as const;

/** 新規作成できるペルソナの鍵の種類。新規に作成する DID は P-256（ES256）のみ。 */
export type CreatablePersonaKeyType = 'P-256';

/** DID Core の検証関係のうち、ペルソナが署名で使うもの。 */
export const PERSONA_RELATIONSHIPS = ['authentication', 'assertionMethod'] as const;

/** ペルソナが署名で使う検証関係。 */
export type PersonaRelationship = (typeof PERSONA_RELATIONSHIPS)[number];

/**
 * ペルソナの派生メタデータ（storage 永続化対象）。
 *
 * `Wallet.createPersona()` などの公開 API は、この型をそのまま返す。
 *
 * `method` / `keyType` / `keySource` / `kid` / `relationships` は後から追加した任意項目で、**欠落は旧レコード**を
 * 表す: `method` 欠落 = `did:key`、`keyType` 欠落 = `secp256k1`（`m/44'/60'/<index>'/0/0` の BIP-32 導出）、
 * `keySource` 欠落 = `seed`。旧レコードは移行なしでそのまま読み書きでき、挙動は変わらない。
 *
 * `name` / `AccountType`（`type`）/ `delegatedDIDs` は本型に含まれない。これらは UI 表示用に
 * 集約したビューが必要な呼び出し側の責務であり、`label` から表示名を補完し、
 * `delegatedDIDs` は `DelegatedDIDStore.list(controllerDID)` を別途問い合わせて合成する。
 *
 * セキュリティ上の注意: 秘密情報は一切含めない。
 */
export interface PersonaMetadata {
  /** ペルソナの安定 ID（生成時に採番）。 */
  readonly id: string;
  /** ペルソナ index（非負整数。BIP-44 account / SLIP-0010 のペルソナ番号）。 */
  readonly index: number;
  /** このペルソナの DID。 */
  readonly did: string;
  /**
   * EIP-55 チェックサム付き Ethereum アドレス。secp256k1 の鍵（seed 導出）のペルソナだけが持つ。
   * P-256 / Ed25519 / 外部鍵のペルソナには無い（EOA として使えない）。
   */
  readonly address?: string;
  /**
   * このペルソナの鍵を導出したパス。`keyType` が `secp256k1` なら BIP-32（`m/44'/60'/0'/0/0`）、
   * `P-256` なら SLIP-0010（`m/9256'/0'/0'/0'`）。外部鍵（`keySource: 'external'`）では空文字。
   */
  readonly derivationPath: string;
  /** 表示用ラベル（任意。例: プライベート, 仕事）。 */
  readonly label?: string;
  /** 作成日時（エポックミリ秒）。 */
  readonly createdAt: number;
  /** 最終利用日時（エポックミリ秒）。`setActivePersona` で更新する。 */
  readonly lastUsedAt: number;
  /** DID メソッド。欠落は `key`。 */
  readonly method?: PersonaDidMethod;
  /** 署名鍵の種類。欠落は `secp256k1`。 */
  readonly keyType?: PersonaKeyType;
  /**
   * 鍵の出所。`seed` = シードから導出（欠落時も同じ）、`external` = 取り込んだ秘密鍵で、秘密鍵は
   * SDK が保持せず呼び出し側（拡張の暗号化ストア）が保持する。
   */
  readonly keySource?: (typeof PERSONA_KEY_SOURCES)[number];
  /**
   * 署名に使う検証メソッドの DID URL（JWS `kid`。`did#fragment`）。欠落時は `did:key` の規則
   * （`<did>#<method-specific-id>`）で導出する。取り込んだ DID では DID Document 上で保持鍵と一致した
   * 検証メソッドの id。
   */
  readonly kid?: string;
  /**
   * 取り込み時に保持鍵の一致を確認できた検証関係（取り込んだ DID のみ。作成した DID では欠落で、
   * `authentication` と `assertionMethod` の両方を持つ）。
   */
  readonly relationships?: readonly PersonaRelationship[];
  /**
   * 署名鍵の公開鍵 JWK（取り込んだ DID のみ。公開情報）。シード差し替えの検知と DID Document の出力に使う。
   * 作成した DID は DID 自体が公開鍵を含むため欠落。
   */
  readonly publicKeyJwk?: Readonly<Record<string, unknown>>;
}

/**
 * `createPersona` のオプション。
 *
 * 新規に作成する DID は常に P-256（ES256。SLIP-0010 の `m/9256'/0'/<index>'/0'`）。`method` / `keyType` を省略した
 * 既定は `did:key` + P-256（最初の既定ペルソナ index 0 も同じ）。`secp256k1` など P-256 以外の `keyType` は
 * 作成できない（`1030`）。ニーモニックだけの復元は index 0 を P-256 の DID として作り直す（従来の secp256k1 の
 * index 0 とは別の DID になる）。
 */
export interface CreatePersonaOptions {
  /** ペルソナ index（導出パスのペルソナ番号となる非負整数）。省略時は既存最大 index + 1。 */
  readonly index?: number;
  /** 表示用ラベル。 */
  readonly label?: string;
  /** 作成する DID メソッド（`key` / `jwk` / `peer`）。 */
  readonly method?: CreatablePersonaMethod;
  /** 鍵の種類。`P-256`（ES256、SLIP-0010）のみ。 */
  readonly keyType?: CreatablePersonaKeyType;
}

/**
 * 既存のレガシーレコード（did:key + secp256k1。BIP-32 `m/44'/60'/<index>'/0/0`）を作り直す
 * （`PersonaManager.restoreLegacyPersona`）際のオプション。バックアップ復元など**既存データ専用**で、
 * 新規作成の入口ではない。
 */
export interface RestoreLegacyPersonaOptions {
  /** 復元するペルソナ index（導出パスのペルソナ番号となる非負整数）。 */
  readonly index: number;
  /** 表示用ラベル。 */
  readonly label?: string;
}

/**
 * 既存 DID の取り込み（`PersonaManager.registerImportedPersona`）の入力。
 *
 * DID Document と保持鍵の一致の検証は**呼び出し側の責務**（`importPersonaFromDid`）。本入力は検証済みの値だけを
 * 渡す想定で、`PersonaManager` は永続化と重複検査のみを行う。
 */
export interface ImportPersonaInput {
  /** 取り込む DID。ペルソナ id になる。 */
  readonly did: string;
  /** DID メソッド。 */
  readonly method: PersonaDidMethod;
  /** 署名鍵の種類。 */
  readonly keyType: PersonaKeyType;
  /** 一致を確認した検証メソッドの DID URL（JWS `kid`）。 */
  readonly kid: string;
  /** 一致を確認した検証関係（1 つ以上）。 */
  readonly relationships: readonly PersonaRelationship[];
  /** 保持鍵の公開鍵 JWK。 */
  readonly publicKeyJwk: Readonly<Record<string, unknown>>;
  /**
   * 鍵の出所。`seed` は `index` と `keyType`（`secp256k1` / `P-256`）で導出するシード鍵、`external` は
   * 取り込んだ秘密鍵（SDK は保持しない）。
   */
  readonly keySource: 'seed' | 'external';
  /** `seed` では導出に使う index（必須）、`external` では並び順用で省略時は既存最大 index + 1。 */
  readonly index?: number;
  /** 表示用ラベル。 */
  readonly label?: string;
}

/**
 * アクティブペルソナ切替時に通知されるリスナ。
 *
 * `setActivePersona` 成功後（永続化・`lastUsedAt` 更新完了後）に、切替先ペルソナの
 * 更新済みメタデータを引数として同期的に呼び出される。
 *
 * @param persona 切替後にアクティブになったペルソナのメタデータ（`lastUsedAt` 反映済み）。
 */
export type PersonaSwitchListener = (persona: PersonaMetadata) => void;

/** `listPersonas` のソートキー。 */
export type PersonaSortKey = 'createdAt' | 'lastUsedAt' | 'label';

/**
 * `listPersonas` のオプション。
 */
export interface ListPersonasOptions {
  /** ソートキー（省略時は createdAt 昇順）。 */
  readonly sortBy?: PersonaSortKey;
  /** ソート方向（省略時は昇順）。 */
  readonly order?: 'asc' | 'desc';
  /** ラベルでフィルタする場合の完全一致値。 */
  readonly label?: string;
}
