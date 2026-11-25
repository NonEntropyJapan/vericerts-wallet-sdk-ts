/**
 * did:ipid メソッド実装（IPFS/IPNS ベース DID）。
 *
 * 解決: IPFS Gateway 経由で DID Document を取得する。
 * - `did:ipid:<CIDv1>`     → `GET <gateway>/ipfs/<CID>`（取得本文のハッシュを CID と照合する）
 * - `did:ipid:<ipns-name>` → `GET <gateway>/ipns/<name>`（IPNS レコードの署名検証 → 解決先 CID を取得 → 本文ハッシュ照合）
 *
 * 公開:
 * - `create`: DID Document を構築 → IPFS HTTP API（`/api/v0/add`）でアップロードして
 *   CIDv1 を得て `did:ipid:<CID>` を確定する（イミュータブル DID）。
 *   更新可能にする場合は `update` で IPNS 鍵 import + `name/publish` を行う。
 *
 * エラーコードの分類:
 * - DID 形式不正 → `INVALID_DID`（2001）。
 * - 取得・公開失敗（network / 4xx / 5xx / timeout）→ `DID_NOT_FOUND`（2003、再試行可）。
 * - Content-Type / JSON / スキーマ不正 → `DID_DOC_INVALID`（2010）。
 * - 失効（deactivate）は did:ipid に失効トレイルが無く非対応 → `METHOD_NOT_SUPPORTED`（2002）。
 *
 * Gateway / API URL は注入可能。既定は `https://ipfs.io` / `http://localhost:5001`。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID・Gateway URL・本文・鍵バイトを含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { CreateOptions, DIDDocument, DIDMethod, UpdateOptions } from '../did.js';
import { encodePublicKeyMultibase } from '../peer/method-peer.js';
import type { ResolutionWorkBudget } from '../resolution-budget.js';
import { DID_IPID_PREFIX, isValidIpidIdentifier, parseDidIpid } from './did-ipid.js';
import {
  DEFAULT_IPID_GATEWAY,
  fetchFromGateway,
  type IpidGatewayConfig,
  resolveIpnsRecordCid,
} from './gateway.js';
import { ipfsAdd, ipfsKeyImport, ipfsNamePublish } from './ipfs-api.js';

/** 鍵タイプ → VerificationMethod type（did:key / did:peer と同一の対応）。 */
const VERIFICATION_METHOD_TYPES: Record<string, string> = {
  Ed25519: 'Ed25519VerificationKey2020',
  secp256k1: 'EcdsaSecp256k1VerificationKey2019',
  'P-256': 'Multikey',
};

/** did:ipid を更新可能（IPNS）にする際の追加オプション。 */
export interface IpidUpdateOptions extends UpdateOptions {
  /** IPFS ノードに import する Ed25519 IPNS 鍵バイト列（DID 署名鍵とは独立）。 */
  readonly ipnsKeyBytes: Uint8Array;
  /** IPNS キー名（IPFS ノード上の識別名）。 */
  readonly ipnsKeyName: string;
}

/**
 * `IpidUpdateOptions` か判定する型ガード。
 *
 * `opts` は呼び出し側が任意の plain object を渡す公開 API（`UpdateOptions`）のため、
 * `ipnsKeyBytes` / `ipnsKeyName` は**自身のプロパティ**としてのみ読む（`ownProperty`）。
 * 鎖読みだと `Object.prototype` が汚染された環境で、IPNS 鍵情報を渡していない
 * `update(did, {})` 呼び出しが継承値を拾って通過し、攻撃者の鍵で `ipfsKeyImport` /
 * `ipfsNamePublish` が実行されてしまう。
 */
function isIpidUpdateOptions(opts: UpdateOptions): opts is IpidUpdateOptions {
  const ipnsKeyBytes = ownProperty<unknown>(opts, 'ipnsKeyBytes');
  const ipnsKeyName = ownProperty<unknown>(opts, 'ipnsKeyName');
  return (
    ipnsKeyBytes instanceof Uint8Array && typeof ipnsKeyName === 'string' && ipnsKeyName.length > 0
  );
}

/**
 * `CreateOptions` の公開鍵から did:ipid 用の正規（canonical）DID Document を構築する。
 *
 * CID は内容から決まるため、保存する正規形には `id`（self-referential id）を含めない。
 * `verificationMethod` / `controller` / 各参照もフラグメントのみの
 * 相対参照（`#key-1`）とし、DID に依存しない確定内容にする。要求 DID の補完は `resolve`（および
 * `create` の戻り値）側で行う。
 *
 * @param opts 鍵タイプと公開鍵。
 * @returns id を含まない正規 DID Document。
 * @throws 未対応鍵タイプ・公開鍵長不一致の場合（VericertsError、code `2001`）。
 */
function buildCanonicalDocument(opts: CreateOptions): Omit<DIDDocument, 'id'> {
  const vmType = VERIFICATION_METHOD_TYPES[opts.keyType];
  if (vmType === undefined) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const publicKeyMultibase = encodePublicKeyMultibase(opts.keyType, opts.publicKey);
  const keyId = '#key-1';
  // controller は空文字（相対 DID 参照）で文書自身の DID を指す。id 同様 DID には依存しない。
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    verificationMethod: [{ id: keyId, type: vmType, controller: '', publicKeyMultibase }],
    authentication: [keyId],
    assertionMethod: [keyId],
  };
}

/**
 * did:ipid メソッドプラグイン（IPFS/IPNS ベース DID）。
 *
 * Gateway URL（解決用）と API URL（公開用）はコンストラクタで注入できる。
 */
export class MethodIpid implements DIDMethod {
  /** Gateway / API 設定。 */
  private readonly config: IpidGatewayConfig;

  /**
   * @param config Gateway / API URL の上書き設定（省略時は既定値）。
   */
  constructor(config?: Partial<IpidGatewayConfig>) {
    // 設定は自身のプロパティだけを読む（`Object.prototype` 汚染で Gateway / API の宛先が差し替わるのを防ぐ）。
    const gatewayUrl = config === undefined ? undefined : ownProperty<string>(config, 'gatewayUrl');
    const apiUrl = config === undefined ? undefined : ownProperty<string>(config, 'apiUrl');
    this.config = {
      gatewayUrl: gatewayUrl ?? DEFAULT_IPID_GATEWAY.gatewayUrl,
      apiUrl: apiUrl ?? DEFAULT_IPID_GATEWAY.apiUrl,
    };
  }

  /** メソッド名（`'ipid'`）。 */
  method(): string {
    return 'ipid';
  }

  /**
   * 公開鍵から DID Document を構築し IPFS にアップロードしてイミュータブル DID を確定する。
   *
   * 手順:
   * 1. CID 算出のため、`id` を持たない正規（canonical）ドキュメント（鍵のみ）を JSON 化。
   * 2. `POST <api>/api/v0/add` でアップロードし CIDv1 を得る。
   * 3. CID の形式（multibase 英数字のみ）を検証し `did:ipid:<CID>` を確定する。
   * 4. IPFS 上の保存内容（id 無しの正規形）と論理的に一致する、`id` を確定 DID で補完した
   *    DID Document を返す。これにより戻り値は `resolve` の結果と一致する（往復成立）。
   *
   * 更新可能（IPNS）にするには、戻り値の DID を `update` に渡す。
   *
   * @throws CID 形式不正（VericertsError、code `2001`）。
   */
  async create(opts: CreateOptions): Promise<DIDDocument> {
    // CID は内容から決まるため、id を持たない正規ドキュメントをアップロードする。
    const canonical = buildCanonicalDocument(opts);
    const cid = await ipfsAdd(this.config, JSON.stringify(canonical));
    // API 戻り値の CID をそのまま連結すると経路偽装になり得るため resolve 経路と同じ検証を通す。
    if (!isValidIpidIdentifier(cid)) {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    const did = `${DID_IPID_PREFIX}${cid}`;
    return { ...canonical, id: did };
  }

  /**
   * did:ipid 文字列を IPFS Gateway 経由で DID Document に解決する。
   *
   * @param scope 解決スコープ全体の予算。取得した本文量を計上する。
   */
  async resolve(did: string, scope?: ResolutionWorkBudget): Promise<DIDDocument> {
    const parsed = parseDidIpid(did);
    if (parsed.kind === 'cid') {
      // CID 形式は取得本文のハッシュを CID と照合する（Gateway 運営者による差し替えの拒否）。
      return fetchFromGateway(
        this.config,
        `ipfs/${parsed.identifier}`,
        did,
        parsed.identifier,
        scope,
      );
    }
    // IPNS 名は、署名検証済みレコードが指す CID を取り直して本文ハッシュまで照合する。
    // 検証できない名前・レコードはここで拒否され、Gateway の本文を無検証で採用する経路は無い。
    const cid = await resolveIpnsRecordCid(this.config, parsed.identifier, scope);
    return fetchFromGateway(this.config, `ipfs/${cid}`, did, cid, scope);
  }

  /**
   * 既存の did:ipid を IPNS 経由で更新可能ポインタとして publish する。
   *
   * `opts` に IPNS 鍵（`ipnsKeyBytes` / `ipnsKeyName`）を渡すと、鍵を import し、現 DID が
   * 指す CID を IPNS 名に publish して `did:ipid:<ipns-name>` を返す。
   *
   * @throws IPNS 鍵情報を欠く場合（VericertsError、code `2002`）、
   *         DID 形式不正（code `2001`）、API 失敗（code `2003`）。
   */
  async update(did: string, opts: UpdateOptions): Promise<DIDDocument> {
    const parsed = parseDidIpid(did);
    if (!isIpidUpdateOptions(opts)) {
      // IPNS 鍵情報なしでは更新（可変化）できない。
      throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
    }
    await ipfsKeyImport(this.config, opts.ipnsKeyName, opts.ipnsKeyBytes);
    const ipnsName = await ipfsNamePublish(this.config, parsed.identifier, opts.ipnsKeyName);
    return this.resolve(`${DID_IPID_PREFIX}${ipnsName}`);
  }

  /** did:ipid は失効トレイルを持たないため無効化非対応（code `2002`）。 */
  async deactivate(_did: string): Promise<void> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }
}
