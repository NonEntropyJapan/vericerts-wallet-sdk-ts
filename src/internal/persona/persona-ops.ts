/**
 * `PersonaManager.createPersona` / `registerImportedPersona` の本体（ロック内で呼ばれる手続き）。
 *
 * `persona.ts` の行数上限（CI 規約）に対応するための分離。storage への読み書きと採番は `PersonaManager` が
 * 注入する関数経由で行い、ここは「入力の検証 → 鍵の導出 → 重複検査 → メタデータ組み立て」だけを持つ。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import type { KeyManager } from '../keymanager/keymanager.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { personaFields } from './persona-fields.js';
import { buildImportedMetadata } from './persona-import.js';
import {
  type CreateDidKeyFn,
  createPersonaKey,
  LEGACY_SECP256K1_CREATION,
  type ResolvedCreation,
  resolveCreation,
} from './persona-key.js';
import type {
  CreatePersonaOptions,
  ImportPersonaInput,
  PersonaMetadata,
  RestoreLegacyPersonaOptions,
} from './types.js';

/** `PersonaManager` が注入する依存。 */
export interface PersonaOpsDeps {
  readonly keymanager: KeyManager;
  readonly createDid: CreateDidKeyFn;
  readonly now: () => number;
  /** 保存済みペルソナを 1 件取得する（未存在は `null`）。 */
  readonly getPersona: (id: string) => Promise<PersonaMetadata | null>;
  /** 保存済みペルソナの一覧。 */
  readonly listPersonas: () => Promise<PersonaMetadata[]>;
  /** 次に採番する index（既存最大 + 1）。 */
  readonly nextIndex: () => Promise<number>;
}

/**
 * label は文字列か未指定に限る。読み取り側（`decodeMetadata`）は非文字列の label を 2005 で拒否するため、書き込み前に
 * 弾く。通すと以後 `listPersonas` / `createPersona` が恒久的に 2005 になる。
 *
 * @throws 文字列でない場合（`1040`）。
 */
function requireStringLabel(label: unknown): string | undefined {
  if (label !== undefined && typeof label !== 'string') {
    throw new VericertsError(ErrorCodes.DERIVATION_PATH_INVALID);
  }
  return label;
}

/**
 * ペルソナを作成してメタデータを返す（保存は呼び出し側）。仕様は `PersonaManager.createPersona` を参照。
 *
 * @throws 1041 / 1040 / 1030 / 2008（`PersonaManager.createPersona` と同じ）。
 */
export async function createPersonaWith(
  deps: PersonaOpsDeps,
  opts?: CreatePersonaOptions,
): Promise<PersonaMetadata> {
  // 任意プロパティは自身のプロパティに限って読む。`opts?.index` はプロトタイプ鎖を辿るため、
  // index を**渡していない**正当な作成でも汚染値が採用される。全ペルソナが同一 HD 派生パスに固定されると
  // ペルソナの非連結性が壊れ、同じ鍵が使い回される。
  const own = <T>(key: keyof CreatePersonaOptions): T | undefined =>
    opts === undefined ? undefined : ownProperty<T>(opts, key);
  const label = requireStringLabel(own<unknown>('label'));
  const creation = resolveCreation(
    own<CreatePersonaOptions['method']>('method'),
    own<CreatePersonaOptions['keyType']>('keyType'),
  );
  const index = own<number>('index') ?? (await deps.nextIndex());
  return buildPersona(deps, creation, index, label);
}

/**
 * 既存のレガシーレコード（method / keyType が無い = did:key + secp256k1、BIP-32 `m/44'/60'/<index>'/0/0`）を
 * 同じ index で作り直してメタデータを返す（保存は呼び出し側）。バックアップ復元など既存データ専用で、
 * 新規作成の入口ではない（新規は {@link createPersonaWith} = P-256 のみ）。
 *
 * @throws 1041 / 1040 / 2008（`createPersonaWith` と同じ）。
 */
export async function restoreLegacyPersonaWith(
  deps: PersonaOpsDeps,
  opts: RestoreLegacyPersonaOptions,
): Promise<PersonaMetadata> {
  const label = requireStringLabel(ownProperty<unknown>(opts, 'label'));
  return buildPersona(
    deps,
    LEGACY_SECP256K1_CREATION,
    ownProperty<number>(opts, 'index') ?? Number.NaN,
    label,
  );
}

/** 解決済みの作成条件と index から、鍵の導出 → 重複検査 → メタデータ組み立てを行う。 */
async function buildPersona(
  deps: PersonaOpsDeps,
  creation: ResolvedCreation,
  index: number,
  label: string | undefined,
): Promise<PersonaMetadata> {
  const created = await createPersonaKey(deps.keymanager, deps.createDid, index, creation);
  const did = ownProperty<string>(created.document, 'id') ?? '';
  // 同じ DID、または同じ導出パス（= 同じ鍵）のペルソナは作らない。別 DID メソッドで同じ鍵を使い回すと
  // ペルソナ間が連結される。
  if (
    (await deps.getPersona(did)) !== null ||
    (await deps.listPersonas()).some(
      (persona) => personaFields(persona).derivationPath === created.derivationPath,
    )
  ) {
    throw new VericertsError(ErrorCodes.PERSONA_ALREADY_EXISTS);
  }
  const timestamp = deps.now();
  // レガシー（`restoreLegacyPersona` = 既存の旧レコードの復元）は旧レコードと同形（method / keyType / kid を載せない）で保存する。
  return {
    id: did,
    index,
    did,
    ...(created.address !== undefined ? { address: created.address } : {}),
    derivationPath: created.derivationPath,
    ...(label !== undefined ? { label } : {}),
    createdAt: timestamp,
    lastUsedAt: timestamp,
    ...(creation.legacy
      ? {}
      : { method: creation.method, keyType: creation.keyType, kid: created.kid }),
  };
}

/**
 * 検証済みの既存 DID のメタデータを組み立てる（保存は呼び出し側）。
 *
 * @throws 2008（同じ DID が既にある）、1040 / 1030 / 1041（`buildImportedMetadata`）。
 */
export async function registerImportedWith(
  deps: PersonaOpsDeps,
  input: ImportPersonaInput,
): Promise<PersonaMetadata> {
  if ((await deps.getPersona(input.did)) !== null) {
    throw new VericertsError(ErrorCodes.PERSONA_ALREADY_EXISTS);
  }
  return buildImportedMetadata(deps.keymanager, input, deps.nextIndex, deps.now());
}
