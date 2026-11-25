/**
 * did:pkh メソッド実装（CAIP-10 ベースのマルチチェーン DID）。
 *
 * did:pkh は CAIP-10 アカウント識別子から、did:key と同型にローカルで即時生成・
 * オフライン解決する DID（ネットワーク通信不要）:
 *   `did:pkh:<CAIP-2 namespace>:<CAIP-10 account_id の参照部+アドレス>`
 * 実体は `did:pkh:eip155:<chainId>:<address>`
 * （例 `did:pkh:eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb`）。
 *
 * 対応スコープ:
 * - 本プロジェクトのサポート範囲は eip155（EVM）名前空間のみ。
 *   非 EVM チェーン（Solana / Tezos 等）は現スコープ外。
 * - eip155 名前空間であれば chainId は数値として一般に受理する
 *   （例 1=Mainnet / 42161=Arbitrum / 1868=Soneium / 314=Filecoin）。
 *
 * VerificationMethod type は `EcdsaSecp256k1RecoveryMethod2020`、`blockchainAccountId` に
 * CAIP-10 形式（`eip155:<chainId>:<address>`）を記録する。did:pkh は不変かつ CreateOptions
 * （keyType/publicKey）・更新概念に合わないため、`create` / `update` / `deactivate` は非対応
 * （`METHOD_NOT_SUPPORTED`、code `2002`）。生成は `createDidPkh` ヘルパを使う。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・アドレスなどの入力データを含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isValidCaip2ChainId, isValidEvmAddress } from '../../evm-format.js';
import type { CreateOptions, DIDDocument, DIDMethod, UpdateOptions } from '../did.js';

/** `did:pkh:` メソッドプレフィックス。 */
const DID_PKH_PREFIX = 'did:pkh:';

/** 現スコープでサポートする CAIP-2 namespace（EVM のみ）。 */
const SUPPORTED_NAMESPACE = 'eip155';

/**
 * eip155 アカウントの chainId / address 形式を検証する（parseDidPkh と createDidPkh で共用）。
 *
 * chainId は先頭ゼロを拒否する正準の 10 進数字列（`did:ethr` 系と同じ形式）、
 * address は `0x` + 40 hex（`isValidEvmAddress`。大小文字が混在する表記は EIP-55 チェックサムを検証し、
 * 合わなければ `2001`）。
 *
 * @param chainId CAIP-2 chainId 参照部。
 * @param address EVM アドレス。
 * @throws chainId 非数字・先頭ゼロ・address 形式不正の場合（VericertsError、code `2001`）。
 *         入力は message に含めない。
 */
function assertEip155Account(chainId: string, address: string): void {
  if (!isValidCaip2ChainId(chainId) || !isValidEvmAddress(address)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
}

/**
 * did:pkh のパース結果。
 */
export interface ParsedDidPkh {
  /** CAIP-2 namespace（現スコープでは常に `eip155`）。 */
  readonly namespace: string;
  /** CAIP-2 chainId 参照部（10 進数の数字列）。 */
  readonly chainId: string;
  /** EVM アドレス（`0x` + 40 hex、入力の大小文字を保持）。 */
  readonly address: string;
  /** CAIP-10 account_id（`eip155:<chainId>:<address>`、入力どおり）。 */
  readonly accountId: string;
}

/**
 * did:pkh の構成要素（CAIP-10 アカウント）。
 */
export interface DidPkhAccount {
  /** CAIP-2 chainId 参照部（10 進数の数字列）。 */
  readonly chainId: string;
  /** EVM アドレス（`0x` + 40 hex、大小文字許容）。 */
  readonly address: string;
}

/**
 * did:pkh 文字列をパースする。
 *
 * 手順:
 * 1. `did:pkh:` プレフィックスを検証・除去。
 * 2. 残りを `:` で分割し、`eip155:<chainId>:<address>` の 3 セグメントを期待。
 * 3. namespace が `eip155`、chainId が数字列、address が `0x` + 40 hex
 *    （EIP-55 チェックサム / 素の小文字いずれも許容）であることを検証。
 *
 * 非 eip155 名前空間（例 `did:pkh:solana:...`）はこの SDK のサポート範囲外
 * （EVM のみ）のため、形式不正と同じく `INVALID_DID`（code `2001`）に正規化する。
 *
 * @param did did:pkh 文字列（`did:pkh:eip155:<chainId>:<address>`）。
 * @returns パース結果（namespace / chainId / address / CAIP-10 accountId）。
 * @throws プレフィックス不正・セグメント過不足・非 eip155 名前空間・chainId 非数字・
 *         address 形式不正の場合（VericertsError、code `2001`）。
 */
export function parseDidPkh(did: string): ParsedDidPkh {
  if (!did.startsWith(DID_PKH_PREFIX)) {
    // 入力 DID はメッセージに含めない。
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const methodSpecificId = did.slice(DID_PKH_PREFIX.length);
  const segments = methodSpecificId.split(':');
  if (segments.length !== 3) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const [namespace, chainId, address] = segments as [string, string, string];
  // 非 eip155 名前空間は現スコープ外（EVM のみ）として 2001 に正規化する。
  if (namespace !== SUPPORTED_NAMESPACE) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  assertEip155Account(chainId, address);
  return {
    namespace,
    chainId,
    address,
    accountId: `${namespace}:${chainId}:${address}`,
  };
}

/**
 * パース済み did:pkh から DID Document を構築する。
 *
 * @param did 入力 DID（`id` / `controller` に使用）。
 * @param accountId CAIP-10 account_id（`blockchainAccountId` に記録）。
 * @returns パースした識別子に対応する DID Document。
 */
function buildDidPkhDocument(did: string, accountId: string): DIDDocument {
  const verificationMethodId = `${did}#blockchainAccountId`;
  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/secp256k1recovery-2020/v2',
    ],
    id: did,
    verificationMethod: [
      {
        id: verificationMethodId,
        type: 'EcdsaSecp256k1RecoveryMethod2020',
        controller: did,
        blockchainAccountId: accountId,
      },
    ],
    authentication: [verificationMethodId],
    assertionMethod: [verificationMethodId],
  };
}

/**
 * did:pkh 文字列を DID Document に解決する（同期・オフライン）。
 *
 * `parseDidPkh` で検証後、DID Document を構築して返す。
 * `blockchainAccountId` は入力どおりの CAIP-10 文字列（`eip155:<chainId>:<address>`、
 * アドレスの大小文字を保持）。
 *
 * @param did did:pkh 文字列（`did:pkh:eip155:<chainId>:<address>`）。
 * @returns DID Document。
 * @throws 形式不正・非 eip155 名前空間の場合（VericertsError、code `2001`）。
 */
export function resolveDidPkh(did: string): DIDDocument {
  const { accountId } = parseDidPkh(did);
  return buildDidPkhDocument(did, accountId);
}

/**
 * CAIP-10 アカウントから did:pkh の DID と DID Document を生成するヘルパ。
 *
 * address は妥当性検証する（`0x` + 40 hex、大小文字許容）。chainId は数字列であることを
 * 検証する。生成した DID は `did:pkh:eip155:<chainId>:<address>` で、address の大小文字は
 * 入力どおり保持する。
 *
 * @param account CAIP-10 アカウント（`{ chainId, address }`）。
 * @returns 生成した DID 文字列と DID Document。
 * @throws chainId 非数字・address 形式不正の場合（VericertsError、code `2001`）。
 */
export function createDidPkh(account: DidPkhAccount): { did: string; document: DIDDocument } {
  assertEip155Account(account.chainId, account.address);
  const did = `${DID_PKH_PREFIX}${SUPPORTED_NAMESPACE}:${account.chainId}:${account.address}`;
  const accountId = `${SUPPORTED_NAMESPACE}:${account.chainId}:${account.address}`;
  return { did, document: buildDidPkhDocument(did, accountId) };
}

/**
 * did:pkh メソッドプラグイン。
 *
 * `resolve` のみを提供する。did:pkh は CreateOptions（keyType/publicKey）・更新概念に
 * 合わないため、`create` / `update` / `deactivate` は非対応で `METHOD_NOT_SUPPORTED`
 * （code `2002`）を投げる。CAIP-10 アカウントからの生成は `createDidPkh` ヘルパを使う。
 */
export class MethodPkh implements DIDMethod {
  /** メソッド名（`'pkh'`）。 */
  method(): string {
    return 'pkh';
  }

  /**
   * did:pkh は CAIP-10 アカウントから生成するため CreateOptions 非対応（code `2002`）。
   * 生成には `createDidPkh` を使う。
   */
  async create(_opts: CreateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** did:pkh 文字列を DID Document に解決する（オフライン）。 */
  async resolve(did: string): Promise<DIDDocument> {
    return resolveDidPkh(did);
  }

  /** did:pkh は不変のため更新非対応（code `2002`）。 */
  async update(_did: string, _opts: UpdateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** did:pkh は不変のため無効化非対応（code `2002`）。 */
  async deactivate(_did: string): Promise<void> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }
}
