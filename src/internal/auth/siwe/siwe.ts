/**
 * SIWE — Sign-In with Ethereum（EIP-4361）メッセージの生成 / パース / 検証と、
 * EOA（ERC-191 Personal Sign）/ AA スマートアカウント（ERC-1271）両対応の署名検証。
 *
 * ライブラリ方針:
 * - EIP-4361 メッセージの構築は実績ある `viem/siwe` に委譲する（テキスト仕様の自前実装を避ける）。
 *   パースは viem の最初一致の正規表現（二次時間・Resources 隠蔽・scheme 欠落）を避け、
 *   依存ゼロの行単位厳密パーサ `siwe-strict-parse.ts` を用いる。拡張でも同じパーサを使う。
 * - ERC-55 チェックサム・ERC-191 署名からのアドレス復元は `ethers`（SDK 全体で利用）を用いる。
 * - ERC-1271 の `isValidSignature` 呼び出しは `Erc1271Rpc` seam 経由でのみ行い（aa の BundlerRpc と同方針）、
 *   テストは fake seam を注入して実チェーン非依存で検証できる。既定実装は siwe-erc1271-adapter.ts。
 *
 * セキュリティ上の注意:
 * - アドレス・署名・メッセージ本文・RPC 応答を VericertsError の message / context / cause に伝播させない。
 * - パース / 検証失敗は 8041（SIWE_MESSAGE_INVALID）、署名不一致は 3010（SIG_INVALID）、
 *   アドレス形式不正は 4070（INVALID_EVM_ADDRESS）、eth_call 失敗は 1021（CHAIN_SUBMIT_FAILED）に正規化する。
 */

import { getAddress, isAddress } from 'ethers';
import { createSiweMessage } from 'viem/siwe';
import { parseIsoDateTimeMs } from '../../cache/iso-datetime.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseSiweStrict } from './siwe-strict-parse.js';

/** `0x` プレフィックス付き hex 文字列。 */
export type Hex = `0x${string}`;

/** ERC-1271 が有効署名で返す magicValue。 */
export const ERC1271_MAGIC_VALUE = '0x1626ba7e';
/** EIP-4361 で唯一許容される version 値。 */
const SIWE_VERSION = '1';
/** SIWE nonce に使用できるのは 8 文字以上の英数字。 */
const NONCE_PATTERN = /^[a-zA-Z0-9]{8,}$/;

/**
 * EIP-4361 SIWE メッセージのフィールド。
 */
export interface SiweMessage {
  /** `scheme://` の scheme 部（任意）。RP は `validateSiweMessage` の `expectedScheme` で検査する。 */
  readonly scheme?: string;
  /** リクエスト元ドメイン（必須）。 */
  readonly domain: string;
  /** ERC-55 チェックサム付き Ethereum アドレス（必須）。 */
  readonly address: string;
  /** ユーザー向け説明文（任意）。 */
  readonly statement?: string;
  /** リクエスト元 URI（必須）。 */
  readonly uri: string;
  /** バージョン。`"1"` のみ許容（必須）。 */
  readonly version: string;
  /** EIP-155 Chain ID（必須）。 */
  readonly chainId: number;
  /** 8 文字以上の英数字 nonce（必須、リプレイ防止）。 */
  readonly nonce: string;
  /** 発行時刻 ISO 8601（必須）。 */
  readonly issuedAt: string;
  /** 有効期限 ISO 8601（任意）。 */
  readonly expirationTime?: string;
  /** 有効開始 ISO 8601（任意）。 */
  readonly notBefore?: string;
  /** リクエスト識別子（任意）。 */
  readonly requestId?: string;
  /** リソース URI 一覧（任意）。 */
  readonly resources?: readonly string[];
}

/** `generateSiweMessage` の入力。 */
export interface SiweParams {
  readonly domain: string;
  readonly address: string;
  readonly uri: string;
  readonly nonce: string;
  readonly chainId: number;
  readonly statement?: string;
  readonly issuedAt?: Date;
  readonly expirationTime?: Date;
  readonly notBefore?: Date;
  readonly requestId?: string;
  readonly resources?: readonly string[];
}

/**
 * ERC-1271 `isValidSignature` を呼ぶための JSON-RPC seam（`eth_call`）。
 * siwe.ts はこのインターフェース経由でのみチェーンに触れる。既定実装は siwe-erc1271-adapter.ts。
 */
export interface Erc1271Rpc {
  /**
   * `eth_call` 相当で `to.isValidSignature(hash, signature)` を呼び、返り値（`0x` + 32 byte hex）を返す。
   * トランスポート / RPC 失敗は VericertsError（code `1021`）に正規化して throw する。
   *
   * @param to 検証対象のスマートアカウントアドレス。
   * @param data ABI エンコード済み calldata（セレクタ + hash + signature）。
   * @returns eth_call の戻り値（`0x` プレフィックス付き hex）。
   */
  call(to: string, data: Hex): Promise<Hex>;
}

/** ERC-55 チェックサム付きアドレスへ正規化する。不正形式は 4070 に正規化する。 */
export function toChecksumAddress(address: string): string {
  if (typeof address !== 'string' || !isAddress(address)) {
    throw new VericertsError(ErrorCodes.INVALID_EVM_ADDRESS);
  }
  try {
    return getAddress(address);
  } catch {
    throw new VericertsError(ErrorCodes.INVALID_EVM_ADDRESS);
  }
}

/**
 * SIWE メッセージ文字列を生成する。
 *
 * @param params ドメイン・アドレス・URI・nonce・chainId 等。`issuedAt` 省略時は現在時刻。
 * @returns EIP-4361 準拠のメッセージ文字列。
 * @throws アドレス形式不正（4070）/ nonce・version 等の不正（8041）。
 */
export function generateSiweMessage(params: SiweParams): string {
  const address = toChecksumAddress(params.address);
  validateNonce(params.nonce);
  try {
    // 任意フィールドは own 限定で読む（`Object.prototype.statement` / `resources` 等の汚染が、利用者が署名する
    // SIWE メッセージへ混入しないようにする）。
    const statement = ownProperty<string>(params, 'statement');
    const expirationTime = ownProperty<Date>(params, 'expirationTime');
    const notBefore = ownProperty<Date>(params, 'notBefore');
    const requestId = ownProperty<string>(params, 'requestId');
    const resources = ownProperty<readonly string[]>(params, 'resources');
    // viem は引数オブジェクトから任意フィールドを素で読むため、省略したフィールドが継承値を拾わないよう
    // null プロトタイプで渡す。
    const fields = Object.assign(Object.create(null) as object, {
      domain: params.domain,
      address: address as `0x${string}`,
      uri: params.uri,
      version: SIWE_VERSION,
      chainId: params.chainId,
      nonce: params.nonce,
      issuedAt: ownProperty<Date>(params, 'issuedAt') ?? new Date(),
      ...(statement !== undefined ? { statement } : {}),
      ...(expirationTime !== undefined ? { expirationTime } : {}),
      ...(notBefore !== undefined ? { notBefore } : {}),
      ...(requestId !== undefined ? { requestId } : {}),
      ...(resources !== undefined ? { resources: resources as `0x${string}`[] | string[] } : {}),
    });
    return createSiweMessage(fields as Parameters<typeof createSiweMessage>[0]);
  } catch (err) {
    if (err instanceof VericertsError) {
      throw err;
    }
    throw new VericertsError(ErrorCodes.SIWE_MESSAGE_INVALID);
  }
}

/** nonce が 8 文字以上の英数字であることを検証する。不正は 8041。 */
function validateNonce(nonce: unknown): void {
  if (typeof nonce !== 'string' || !NONCE_PATTERN.test(nonce)) {
    throw new VericertsError(ErrorCodes.SIWE_MESSAGE_INVALID);
  }
}

/**
 * SIWE メッセージ文字列をパースして構造体へマッピングする。
 *
 * パースは正規表現のバックトラックを持たない行単位の厳密パーサ（`siwe-strict-parse.ts`）が担い、
 * メッセージ長・Resources 数に上限を持つ。行位置で値を決めるため statement / URI に
 * `Resources:` 等を埋めても署名対象の Resources は隠れず、`Resources:` が本物の行以外に現れる入力は拒否する
 * `scheme` は `SiweMessage.scheme` に保持し、`validateSiweMessage` が検査する。
 *
 * 必須フィールド（domain / address / uri / version / chainId / nonce / issuedAt）の欠落・型不正、
 * version≠"1"、nonce 形式不正、ISO 8601 でない日時は 8041 に正規化する。address は ERC-55 チェックサム表記で
 * なければ（全小文字 / 全大文字を含め）4070 で拒否する（正規化して受理しない）。
 *
 * @param message SIWE メッセージ文字列。
 * @returns 構造化された `SiweMessage`。
 * @throws パース / 必須欠落 / 形式不正 / 長さ上限超過（8041）、アドレス非チェックサム表記（4070）。
 */
export function parseSiweMessage(message: string): SiweMessage {
  const parsed = parseSiweStrict(message);
  if (parsed === null || parsed.version !== SIWE_VERSION) {
    throw new VericertsError(ErrorCodes.SIWE_MESSAGE_INVALID);
  }
  validateNonce(parsed.nonce);
  // 日時は本文の生文字列をオフセット必須の厳格 ISO 8601 で検証する（`new Date(str)` は TZ 依存）。
  const issuedAt = toIsoStringOrThrow(parsed.issuedAt);
  const expirationTime =
    parsed.expirationTime !== undefined ? toIsoStringOrThrow(parsed.expirationTime) : undefined;
  const notBefore =
    parsed.notBefore !== undefined ? toIsoStringOrThrow(parsed.notBefore) : undefined;
  // EIP-4361: メッセージ内の `address` は ERC-55 チェックサム表記でなければならない。
  // 全小文字 / 全大文字を黙って正規化して受理すると、署名対象文字列と検証済みアドレスの表記が食い違う。
  const checksummed = toChecksumAddress(parsed.address);
  if (checksummed !== parsed.address) {
    throw new VericertsError(ErrorCodes.INVALID_EVM_ADDRESS);
  }

  return {
    domain: parsed.domain,
    address: checksummed,
    uri: parsed.uri,
    version: parsed.version,
    chainId: parsed.chainId,
    nonce: parsed.nonce,
    issuedAt,
    ...(parsed.scheme !== undefined ? { scheme: parsed.scheme } : {}),
    ...(parsed.statement !== undefined ? { statement: parsed.statement } : {}),
    ...(expirationTime !== undefined ? { expirationTime } : {}),
    ...(notBefore !== undefined ? { notBefore } : {}),
    ...(parsed.requestId !== undefined ? { requestId: parsed.requestId } : {}),
    ...(parsed.resources !== undefined ? { resources: parsed.resources } : {}),
  };
}

/**
 * 日時の生文字列をオフセット必須の厳格 ISO 8601 として検証し、UTC の ISO 文字列へ正規化する。
 * 不正なら 8041。
 */
function toIsoStringOrThrow(value: string): string {
  const ms = parseIsoDateTimeMs(value);
  if (Number.isNaN(ms)) {
    throw new VericertsError(ErrorCodes.SIWE_MESSAGE_INVALID);
  }
  return new Date(ms).toISOString();
}

/** `validateSiweMessage` の任意オプション。 */
export interface ValidateSiweOptions {
  /**
   * RP が期待する scheme（例: `https`）。メッセージが scheme を持つ場合、これと完全一致しなければ 8041。
   * 未指定のとき、scheme を持つメッセージは既定で `https` のみ受理する。
   */
  readonly expectedScheme?: string;
}

/** 期待 scheme 未指定時に受理する scheme（平文 `http` 等を既定で拒否する）。 */
const DEFAULT_EXPECTED_SCHEME = 'https';

/**
 * パース済み SIWE メッセージを検証する。
 *
 * - `domain` が期待オリジンと一致すること（フィッシング防止）。
 * - メッセージが `scheme` を持つ場合、`options.expectedScheme`（未指定は `https`）と一致すること。
 * - `version` が `"1"` であること。
 * - `expirationTime` が指定されていれば現在時刻より未来であること。
 * - `notBefore` が指定されていれば現在時刻より過去であること。
 *
 * @param msg 検証対象の `SiweMessage`。
 * @param expectedDomain 期待するリクエスト元ドメイン（例: `example.com`）。
 * @param now 判定時刻（テスト用に注入可能。既定は現在時刻）。
 * @param options 期待 scheme など。
 * @throws いずれかの検証に失敗した場合（8041）。
 */
export function validateSiweMessage(
  msg: SiweMessage,
  expectedDomain: string,
  now: Date = new Date(),
  options: ValidateSiweOptions = {},
): void {
  if (msg.domain !== expectedDomain) {
    throw new VericertsError(ErrorCodes.SIWE_MESSAGE_INVALID);
  }
  if (
    msg.scheme !== undefined &&
    msg.scheme !== (ownProperty<string>(options, 'expectedScheme') ?? DEFAULT_EXPECTED_SCHEME)
  ) {
    throw new VericertsError(ErrorCodes.SIWE_MESSAGE_INVALID);
  }
  if (msg.version !== SIWE_VERSION) {
    throw new VericertsError(ErrorCodes.SIWE_MESSAGE_INVALID);
  }
  const nowMs = now.getTime();
  // Invalid Date（NaN）の時計は比較が常に false になり期限切れ・未発効の SIWE を通す（fail-open）。
  // 期間の文字列が解釈不能な場合も同様なので、いずれも fail-closed で拒否する
  // （extension 側 `validateSiwe` と同方針）。
  if (Number.isNaN(nowMs)) {
    throw new VericertsError(ErrorCodes.SIWE_MESSAGE_INVALID);
  }
  if (msg.expirationTime !== undefined) {
    const expirationMs = parseIsoDateTimeMs(msg.expirationTime);
    if (Number.isNaN(expirationMs) || expirationMs <= nowMs) {
      throw new VericertsError(ErrorCodes.SIWE_MESSAGE_INVALID);
    }
  }
  if (msg.notBefore !== undefined) {
    const notBeforeMs = parseIsoDateTimeMs(msg.notBefore);
    if (Number.isNaN(notBeforeMs) || notBeforeMs > nowMs) {
      throw new VericertsError(ErrorCodes.SIWE_MESSAGE_INVALID);
    }
  }
}
