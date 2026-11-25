/**
 * did:plc の操作生成（`createDidPlc` / `updateDidPlc` / `deactivateDidPlc`）と公開（`submitPlcOperation`）
 * を提供する独立関数。`MethodPlc` のインスタンスは不要。
 *
 * 公開後に直せない（DID はジェネシスのハッシュで決まる）ため、署名の**前**に入力（GDPR Art.9・`rotationKeys` の件数と
 * 鍵種別・DAG-CBOR 7500 バイト上限）を検査し、返却の**前**に自分で作った操作が自分で検証できる（`sig` が署名鍵で通り、
 * 構造が受理され、ジェネシスは DID を再計算できる）ことを確かめる。秘密鍵は受け取らず、署名は `signer` コールバックが行う。
 * 旧形式 `create` は生成しない（検証でのみ受理する）。
 *
 * セキュリティ上の注意: 例外メッセージや `context` に操作の内容・DID・鍵を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import { assertNoSpecialCategoryOnChain } from '../../special-category.js';
import { encodeDagCbor } from './dag-cbor.js';
import { assertPlcDid, assertPrevCid } from './did.js';
import { DEFAULT_PLC_DIRECTORY_URL, directoryBase, postDirectoryOperation } from './directory.js';
import { normalizeSignature, parseRotationKey, verifySignature } from './keys.js';
import {
  assertRotationKeys,
  didOfGenesisBytes,
  MAX_OPERATION_BYTES,
  type PlcOperationData,
  type PlcSignedOperation,
  parseOperation,
  readOperationData,
} from './operation.js';

/** 署名器: sig を除いた操作の DAG-CBOR を受け取り、64 バイト（r || s）を返す。SDK が low-S へ正規化・検証する。 */
export type PlcSigner = (unsigned: Uint8Array) => Promise<Uint8Array>;

/** base64url（パディングなし）で 64 バイトの署名の文字数。サイズ上限の事前計算に使う。 */
const SIGNATURE_PLACEHOLDER = 'A'.repeat(86);

function invalidOperation(): VericertsError {
  return new VericertsError(ErrorCodes.INVALID_DID, {
    context: { reason: 'plc_operation_invalid' },
  });
}

/**
 * `data` を own プロパティだけで 1 度読み、検証したスナップショットを返す（署名に載る値と検査する値を一致させる）。
 * サービスの `endpoint` は http / https の URL であること、公開される値が GDPR Art.9 属性を含まないこと。
 */
function snapshotData(data: unknown): PlcOperationData {
  if (typeof data !== 'object' || data === null) {
    throw invalidOperation();
  }
  const snapshot = readOperationData({
    rotationKeys: ownProperty<unknown>(data, 'rotationKeys'),
    verificationMethods: ownProperty<unknown>(data, 'verificationMethods'),
    alsoKnownAs: ownProperty<unknown>(data, 'alsoKnownAs'),
    services: ownProperty<unknown>(data, 'services'),
  });
  assertRotationKeys(snapshot.rotationKeys);
  for (const { endpoint } of Object.values(snapshot.services)) {
    let protocol: string;
    try {
      protocol = new URL(endpoint).protocol;
    } catch {
      throw invalidOperation();
    }
    if (protocol !== 'https:' && protocol !== 'http:') {
      throw invalidOperation();
    }
  }
  assertNoSpecialCategoryOnChain(snapshot);
  return snapshot;
}

/** 署名器の呼び出しと、署名前のサイズ検査・返却前の自己検証。 */
async function signOperation(
  unsignedOperation: Record<string, unknown>,
  signer: PlcSigner | undefined,
  signerKey: string | undefined,
): Promise<{ operation: PlcSignedOperation; signed: Uint8Array }> {
  if (typeof signerKey !== 'string' || typeof signer !== 'function') {
    throw invalidOperation();
  }
  const key = parseRotationKey(signerKey);
  // 署名前に、署名済みの操作がサイズ上限に収まることを確かめる（`sig` は常に 86 文字）。
  const placeholderSize = encodeDagCbor({
    ...unsignedOperation,
    sig: SIGNATURE_PLACEHOLDER,
  }).length;
  if (placeholderSize > MAX_OPERATION_BYTES) {
    throw invalidOperation();
  }
  const sig = normalizeSignature(key.keyType, await signer(encodeDagCbor(unsignedOperation)));
  const operation = { ...unsignedOperation, sig } as PlcSignedOperation;
  const parsed = parseOperation(operation);
  if (!verifySignature(key, parsed.unsigned, parsed.sig)) {
    throw new VericertsError(ErrorCodes.DID_DOC_INVALID, {
      context: { reason: 'plc_signature_invalid' },
    });
  }
  return { operation, signed: parsed.signed };
}

function operationBody(data: PlcOperationData, prev: string | null): Record<string, unknown> {
  return {
    type: 'plc_operation',
    rotationKeys: data.rotationKeys,
    verificationMethods: data.verificationMethods,
    alsoKnownAs: data.alsoKnownAs,
    services: data.services,
    prev,
  };
}

/**
 * ジェネシス操作を署名し、DID と署名済み操作を返す（公開はしない。公開は {@link submitPlcOperation}）。
 *
 * @param options.data 状態データ。`rotationKeys` は 1〜5 件・重複なし・secp256k1 / P-256。
 * @param options.signer 署名器。
 * @param options.signerKey 署名に使う鍵（`data.rotationKeys` に含まれる `did:key`）。
 * @throws 入力不正・サイズ超過・署名鍵が `rotationKeys` にない（code `2001`、`plc_operation_invalid`）、
 *         GDPR Art.9 属性を含む（code `10601`）、署名器の戻り値が不正・自己検証失敗（code `2010`）。
 */
export async function createDidPlc(options: {
  data: PlcOperationData;
  signer: PlcSigner;
  signerKey: string;
}): Promise<{ did: string; operation: PlcSignedOperation }> {
  const data = snapshotData(ownProperty<unknown>(options, 'data'));
  const signerKey = ownProperty<string>(options, 'signerKey');
  if (typeof signerKey !== 'string' || !data.rotationKeys.includes(signerKey)) {
    throw invalidOperation();
  }
  const { operation, signed } = await signOperation(
    operationBody(data, null),
    ownProperty<PlcSigner>(options, 'signer'),
    signerKey,
  );
  return { did: didOfGenesisBytes(signed), operation };
}

/**
 * 次の操作（更新・鍵ローテ・回復）を署名する。`prev` は直前の有効操作の CID（監査ログの `cid`）。
 *
 * @throws {@link createDidPlc} と同じ。加えて `did` / `prev` の形式不正（code `2001`）。
 *         `signerKey` が直前の操作の `rotationKeys` に含まれるかは SDK からは分からず、ディレクトリが検証する。
 */
export async function updateDidPlc(options: {
  did: string;
  prev: string;
  data: PlcOperationData;
  signer: PlcSigner;
  signerKey: string;
}): Promise<PlcSignedOperation> {
  assertPlcDid(ownProperty<unknown>(options, 'did'));
  const prev = ownProperty<unknown>(options, 'prev');
  assertPrevCid(prev);
  const data = snapshotData(ownProperty<unknown>(options, 'data'));
  const { operation } = await signOperation(
    operationBody(data, prev),
    ownProperty<PlcSigner>(options, 'signer'),
    ownProperty<string>(options, 'signerKey'),
  );
  return operation;
}

/**
 * 失効（`plc_tombstone`）を署名する。回復窓（72 時間）内なら上位の回転鍵で巻き戻せるが、以降は復活できない。
 *
 * @throws `did` / `prev` / 署名鍵の不正（code `2001`）、署名器の戻り値が不正・自己検証失敗（code `2010`）。
 */
export async function deactivateDidPlc(options: {
  did: string;
  prev: string;
  signer: PlcSigner;
  signerKey: string;
}): Promise<PlcSignedOperation> {
  assertPlcDid(ownProperty<unknown>(options, 'did'));
  const prev = ownProperty<unknown>(options, 'prev');
  assertPrevCid(prev);
  const { operation } = await signOperation(
    { type: 'plc_tombstone', prev },
    ownProperty<PlcSigner>(options, 'signer'),
    ownProperty<string>(options, 'signerKey'),
  );
  return operation;
}

/**
 * 署名済み操作を `POST <directoryUrl>/<did>` で公開する。ジェネシスは `did` を再計算して一致を確かめてから送る。
 *
 * @param did 対象の DID。
 * @param operation {@link createDidPlc} / {@link updateDidPlc} / {@link deactivateDidPlc} の戻り値。
 * @param options.directoryUrl ディレクトリ（既定 `https://plc.directory`。`https:` のみ）。
 * @param options.fetchFn fetch 実装（既定はグローバル `fetch`）。
 * @throws `did` / 操作の不正・ジェネシスの DID 不一致（code `2001`）、GDPR Art.9 属性を含む（code `10601`）、
 *         宛先が不正・送信失敗・非 2xx・リダイレクト（code `2003`）。
 */
export async function submitPlcOperation(
  did: string,
  operation: PlcSignedOperation,
  options?: { directoryUrl?: string; fetchFn?: typeof fetch },
): Promise<void> {
  assertPlcDid(did);
  // toJSON / getter を含む入力は送信する JSON へ一度だけ畳み、同じ本文を検査して送る。
  let body: string;
  let snapshot: unknown;
  try {
    body = JSON.stringify(operation);
    snapshot = parseJsonWithoutPrototype(body);
  } catch {
    throw invalidOperation();
  }
  const parsed = parseOperation(snapshot);
  if (parsed.prev === null && didOfGenesisBytes(parsed.signed) !== did) {
    throw invalidOperation();
  }
  assertNoSpecialCategoryOnChain(snapshot);
  const base = directoryBase(
    (options === undefined ? undefined : ownProperty<string>(options, 'directoryUrl')) ??
      DEFAULT_PLC_DIRECTORY_URL,
  );
  const fetchFn =
    options === undefined
      ? undefined
      : nonObjectPrototypeProperty<typeof fetch>(options, 'fetchFn');
  await postDirectoryOperation(`${base}/${did}`, body, fetchFn);
}
