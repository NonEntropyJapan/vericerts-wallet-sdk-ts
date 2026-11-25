/**
 * did:ethr の ERC-1056 イベントから DID Document を構築する純関数。
 *
 * 本モジュールはネットワーク非依存。RPC で取得済みのイベント
 * （DIDOwnerChanged / DIDAttributeChanged）を入力として受け取り、古い順に適用して
 * DID Document を組み立てる。RPC 接続・イベント取得は registry.ts が担う。
 * 属性名の命名規則は attribute-name.ts の parseAttributeName を参照。
 *
 * セキュリティ上の注意:
 * - 入力をそのまま反映する純関数。例外は**件数上限超過だけ**で、それ以外は投げない。
 *   message へ機密を含める箇所はない。
 * - 属性 value のデコード失敗（公開鍵 hex / Ed25519 base64・service など）でも throw せず、
 *   当該属性のみをスキップする（不正な単一属性が解決全体を壊さない）。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { DIDDocument, Service, VerificationMethod } from '../did.js';
import { MAX_DID_DOCUMENT_ARRAY_ENTRIES } from '../did-document-read.js';
import {
  decodeServiceEndpoint,
  hexToBase64,
  normalizeHex,
  parseAttributeName,
} from './attribute-name.js';

/** DIDOwnerChanged イベント（identity の所有者変更）。 */
export interface OwnerChangeEvent {
  /** 新しい owner アドレス（`0x` + 40 hex）。 */
  readonly owner: string;
  /** イベントが含まれるブロック番号。 */
  readonly blockNumber: number;
  /** ブロック内のログインデックス（同一ブロック内の安定順序付け用）。 */
  readonly logIndex: number;
}

/** DIDAttributeChanged イベント（属性の設定・失効）。 */
export interface AttributeChangeEvent {
  /** 属性名（bytes32 をデコードした文字列、例 `did/pub/Secp256k1/veriKey/hex`）。 */
  readonly name: string;
  /** 属性値（hex 文字列、`0x` 付き）。鍵 hex / service エンドポイント等。 */
  readonly value: string;
  /** 有効期限（Unix 秒）。`<= now` は失効（0 は revoke 再発行で表れる）。 */
  readonly validTo: number;
  /** イベントが含まれるブロック番号。 */
  readonly blockNumber: number;
  /** ブロック内のログインデックス。 */
  readonly logIndex: number;
}

/** ERC-1056 のイベント集合（1 つの identity 分）。 */
export interface Erc1056Events {
  /** DIDOwnerChanged イベント列。 */
  readonly ownerChanges: readonly OwnerChangeEvent[];
  /** DIDAttributeChanged イベント列。 */
  readonly attributeChanges: readonly AttributeChangeEvent[];
}

/**
 * 1 回の解決で受け付ける ERC-1056 イベントの最大件数（owner + attribute の合計）。
 *
 * 署名検証前に攻撃者が選べる identity のイベントは、L2 等で安価に水増しできる。1 解決あたりの
 * メモリ・CPU を件数に比例させないため、超過は部分採用せず fail-closed（`DID_DOC_INVALID`）にする。
 * 正当な identity の鍵ローテーション・service 更新履歴は数十件に収まる。
 */
export const MAX_ERC1056_EVENTS = 1000;

/** ゼロアドレス（owner = 0x0 で deactivated 扱い）。 */
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

/** DID Document の基本 @context。 */
const DID_V1_CONTEXT = 'https://www.w3.org/ns/did/v1';
/** secp256k1 recovery suite の @context（#controller 用）。 */
const SECP256K1_RECOVERY_CONTEXT = 'https://w3id.org/security/suites/secp256k1recovery-2020/v2';
/** Ed25519 suite の @context（Ed25519 鍵を含む場合に追加）。 */
const ED25519_CONTEXT = 'https://w3id.org/security/suites/ed25519-2018/v1';

/** イベントの安定ソート用キー（blockNumber asc, logIndex asc）。 */
interface Ordered {
  readonly blockNumber: number;
  readonly logIndex: number;
}

/** blockNumber 昇順、同一なら logIndex 昇順で比較する。 */
function compareOrder(a: Ordered, b: Ordered): number {
  if (a.blockNumber !== b.blockNumber) {
    return a.blockNumber - b.blockNumber;
  }
  return a.logIndex - b.logIndex;
}

/** 内部で集約する属性エントリ（最新の validTo / 順序を保持）。 */
interface AttributeEntry {
  readonly name: string;
  readonly value: string;
  validTo: number;
  blockNumber: number;
  logIndex: number;
}

/**
 * ERC-1056 イベントから DID Document を構築する。アルゴリズム:
 * 1. owner / attribute 両イベントを (blockNumber asc, logIndex asc) で安定ソート。
 * 2. owner 変更を古い順に適用し、最終的な controller アドレスを決定する。
 * 3. attribute は同一 (name, value) を最新エントリで集約し、`validTo > now` のみ採用。
 * 4. controller アドレスの `#controller`（EcdsaSecp256k1RecoveryMethod2020）を常に含める。
 * 5. owner = ゼロアドレスなら `deactivated: true`。この場合 VM / authentication / assertionMethod / service は
 *    すべて空（失効 DID の委任鍵で検証鍵を作れないようにする。手順 3・4 より優先）。
 *
 * @param did 入力 DID（`id` / 各 VerificationMethod の controller に使用）。
 * @param address identity アドレス（owner 変更がない場合の初期 controller）。
 * @param chainId チェーン ID（controller DID / blockchainAccountId の `eip155:<chainId>` に使用）。
 * @param events ERC-1056 イベント集合。
 * @param nowSeconds 現在時刻（Unix 秒）。validTo 評価の基準。
 * @returns 構築した DID Document。
 * @throws イベント総数が {@link MAX_ERC1056_EVENTS} を超える場合、または生成した VerificationMethod /
 *         service が読み手の上限 `MAX_DID_DOCUMENT_ARRAY_ENTRIES` を超える場合
 *         （VericertsError、code `2010`。部分採用せず fail-closed）。
 */
export function buildDidEthrDocument(
  did: string,
  address: string,
  chainId: number,
  events: Erc1056Events,
  nowSeconds: number,
): DIDDocument {
  // ソート・集約で配列を複製する前に件数を絞る。任意の `Erc1056EventSource` 実装に対する最終防衛線。
  if (events.ownerChanges.length + events.attributeChanges.length > MAX_ERC1056_EVENTS) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }
  const owner = resolveOwner(address, events.ownerChanges);
  const controllerDid = `did:ethr:${chainId}:${owner}`;
  if (owner === ZERO_ADDRESS) {
    // owner = 0x0 は ERC-1056 の失効表現。有効な属性（委任鍵・service）が残っていても、
    // 失効 DID の鍵で検証鍵が作れてしまわないよう VM / relationship / service を一切載せない。
    return {
      '@context': [DID_V1_CONTEXT, SECP256K1_RECOVERY_CONTEXT],
      id: did,
      controller: controllerDid,
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
      deactivated: true,
    };
  }

  const controllerVmId = `${did}#controller`;
  const controllerVm: VerificationMethod = {
    id: controllerVmId,
    type: 'EcdsaSecp256k1RecoveryMethod2020',
    controller: controllerDid,
    blockchainAccountId: `eip155:${chainId}:${owner}`,
  };

  const verificationMethod: VerificationMethod[] = [controllerVm];
  const authentication: (string | VerificationMethod)[] = [controllerVmId];
  const assertionMethod: (string | VerificationMethod)[] = [controllerVmId];
  const services: Service[] = [];
  let usesEd25519 = false;

  const activeAttributes = collectActiveAttributes(events.attributeChanges, nowSeconds);
  let keyIndex = 0;
  let serviceIndex = 0;

  for (const attr of activeAttributes) {
    const parsed = parseAttributeName(attr.name);
    if (parsed === null) {
      continue;
    }
    if (parsed.kind === 'service') {
      // value のデコード失敗（奇数長・非 hex 等）は throw せず当該属性をスキップする（不変条件）。
      const serviceEndpoint = decodeServiceEndpoint(attr.value);
      if (serviceEndpoint === null) {
        continue;
      }
      serviceIndex += 1;
      services.push({
        id: `${did}#service-${serviceIndex}`,
        type: parsed.serviceType,
        serviceEndpoint,
      });
      continue;
    }
    if (parsed.kind === 'ed25519') {
      // 公開鍵 hex のデコード失敗時は throw せずスキップ（不変条件）。
      const publicKeyBase64 = hexToBase64(attr.value);
      if (publicKeyBase64 === null) {
        continue;
      }
      keyIndex += 1;
      const vmId = `${did}#delegate-${keyIndex}`;
      usesEd25519 = true;
      verificationMethod.push({
        id: vmId,
        type: 'Ed25519VerificationKey2018',
        controller: did,
        publicKeyBase64,
      });
      assertionMethod.push(vmId);
      continue;
    }
    // secp256k1（veriKey / sigAuth）
    keyIndex += 1;
    const vmId = `${did}#delegate-${keyIndex}`;
    verificationMethod.push({
      id: vmId,
      type: 'EcdsaSecp256k1VerificationKey2019',
      controller: did,
      publicKeyHex: normalizeHex(attr.value),
    });
    if (parsed.kind === 'sigAuth') {
      authentication.push(vmId);
    } else {
      assertionMethod.push(vmId);
    }
  }

  // 読み手（`verificationMethodsOf` 等）は 256 件超の配列を 2010 で拒否する。生成側も同じ上限で
  // 打ち切り、水増しされた identity の巨大文書を作り切らない。
  if (
    verificationMethod.length > MAX_DID_DOCUMENT_ARRAY_ENTRIES ||
    services.length > MAX_DID_DOCUMENT_ARRAY_ENTRIES
  ) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
  }

  const context = [DID_V1_CONTEXT, SECP256K1_RECOVERY_CONTEXT];
  if (usesEd25519) {
    context.push(ED25519_CONTEXT);
  }

  const document: DIDDocument = {
    '@context': context,
    id: did,
    controller: controllerDid,
    verificationMethod,
    authentication,
    assertionMethod,
    ...(services.length > 0 ? { service: services } : {}),
  };
  return document;
}

/** owner 変更を古い順に適用し、最終 owner アドレスを返す。 */
function resolveOwner(address: string, ownerChanges: readonly OwnerChangeEvent[]): string {
  const sorted = [...ownerChanges].sort(compareOrder);
  const last = sorted.at(-1);
  return last !== undefined ? last.owner : address;
}

/** 属性イベントを (name, value) で集約し、最新 validTo の `validTo > now` 分のみ順序どおり返す。 */
function collectActiveAttributes(
  attributeChanges: readonly AttributeChangeEvent[],
  nowSeconds: number,
): AttributeEntry[] {
  const sorted = [...attributeChanges].sort(compareOrder);
  const byKey = new Map<string, AttributeEntry>();
  for (const event of sorted) {
    // 非対称: 比較キーは value を小文字化（case-insensitive 集約）するが、出力 value
    // （entry.value）は最初に観測した表記をそのまま保持する（小文字化しない）。
    const key = `${event.name} ${event.value.toLowerCase()}`;
    const existing = byKey.get(key);
    if (existing === undefined) {
      byKey.set(key, {
        name: event.name,
        value: event.value,
        validTo: event.validTo,
        blockNumber: event.blockNumber,
        logIndex: event.logIndex,
      });
      continue;
    }
    // 同一 (name, value) は最新イベント（最大順序）で validTo / 順序を更新する。
    existing.validTo = event.validTo;
    existing.blockNumber = event.blockNumber;
    existing.logIndex = event.logIndex;
  }
  return [...byKey.values()].filter((entry) => entry.validTo > nowSeconds).sort(compareOrder);
}
