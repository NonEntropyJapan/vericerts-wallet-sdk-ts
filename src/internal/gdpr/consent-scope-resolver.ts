/**
 * `revokeConsent` の `rpIdentifier` / `purpose` スコープ解決。
 *
 * `scope.vcId` 未指定時に `CredentialStore.revokeConsent` から呼ばれる。全 VC レコードの `presentedTo`
 * （`recordPresentation` が記録した提示履歴）を走査し、指定フィールドがすべて一致するエントリを持つ VC を
 * 対象とする（複数指定時は AND 条件）。`recordPresentation` を一度も呼んでいない VC は対象にならない。
 *
 * `scope.rpIdentifier` / `scope.purpose` がいずれも未指定（= `scope.pseudonym` のみ指定）の場合は空配列を
 * 返す。Pseudonym subject から VC を逆引きする手段を Wallet は持たない（`presentedTo` は `rpIdentifier` /
 * `purpose` のみを記録する）。RP に関連する Pseudonym の破棄はファサードが担当する。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { decodeCredentialRecord } from './codec.js';
import {
  CREDENTIAL_KEY_PREFIX,
  type CredentialStorage,
  readRecord,
} from './credential-store/records.js';
import type { ConsentScope, CredentialRecord } from './types.js';

/** 本モジュールが要求する最小限の storage 依存。 */
interface ConsentScopeStorage {
  get(key: string): Promise<Uint8Array | null>;
  list(prefix: string): Promise<string[]>;
}

/**
 * 呼び出し側が渡す `scope` を own プロパティだけから読み直した `ConsentScope` にする。
 *
 * `scope.vcId` 等の直接読みはプロトタイプ鎖を辿るため、`Object.prototype` 汚染下で空スコープ
 * （`revokeConsent({})`）が汚染値で `GDPR_CONSENT_NOT_FOUND` のガードを素通りする。未指定のキーは
 * 生やさない（継承値を own に化かさない）。戻り値はプロトタイプを持たないため、以降の `scope.vcId` 等の
 * 直接読みも汚染を拾わない（記録に使う場合は `{ ...scope }` で通常オブジェクトへ展開する）。
 */
export function ownConsentScope(scope: ConsentScope): ConsentScope {
  const rpIdentifier = ownProperty<string>(scope, 'rpIdentifier');
  const purpose = ownProperty<string>(scope, 'purpose');
  const vcId = ownProperty<string>(scope, 'vcId');
  const pseudonym = ownProperty<string>(scope, 'pseudonym');
  return Object.assign(Object.create(null) as ConsentScope, {
    ...(rpIdentifier !== undefined ? { rpIdentifier } : {}),
    ...(purpose !== undefined ? { purpose } : {}),
    ...(vcId !== undefined ? { vcId } : {}),
    ...(pseudonym !== undefined ? { pseudonym } : {}),
  });
}

/**
 * `rpIdentifier` / `purpose` スコープに一致する VC を `presentedTo` 履歴から解決する。
 *
 * @param storage 走査先（VC レコードの storage）。
 * @param credentialKeyPrefix VC レコードの storage キー prefix。
 * @param scope 撤回スコープ。
 * @returns 対象 VC レコードの配列（該当なしは空配列）。
 */
export async function resolveConsentTargetsByPresentation(
  storage: ConsentScopeStorage,
  credentialKeyPrefix: string,
  consentScope: ConsentScope,
): Promise<CredentialRecord[]> {
  const scope = ownConsentScope(consentScope);
  if (scope.rpIdentifier === undefined && scope.purpose === undefined) {
    return [];
  }
  const keys = await storage.list(credentialKeyPrefix);
  const matches: CredentialRecord[] = [];
  for (const key of keys) {
    const stored = await storage.get(key);
    if (stored === null) {
      continue;
    }
    const record = decodeCredentialRecord(stored);
    const matched = (
      ownProperty<CredentialRecord['presentedTo']>(record, 'presentedTo') ?? []
    ).some(
      (entry) =>
        (scope.rpIdentifier === undefined || entry.rpIdentifier === scope.rpIdentifier) &&
        (scope.purpose === undefined || ownProperty<string>(entry, 'purpose') === scope.purpose),
    );
    if (matched) {
      matches.push(record);
    }
  }
  return matches;
}

/** スコープに撤回対象が 1 つ以上指定されているかを判定する（全フィールド未指定は撤回対象なし）。 */
export function hasConsentTarget(consentScope: ConsentScope): boolean {
  const scope = ownConsentScope(consentScope);
  return (
    scope.rpIdentifier !== undefined ||
    scope.purpose !== undefined ||
    scope.vcId !== undefined ||
    scope.pseudonym !== undefined
  );
}

/**
 * `revokeConsent` の対象 VC を解決する（`vcId` 指定時は当該 1 件、未指定時は `presentedTo` 履歴から解決）。
 *
 * @throws `scope.vcId` 指定で当該 VC が見つからない場合（VericertsError、code `3070`）。
 */
export async function resolveConsentTargets(
  storage: CredentialStorage,
  consentScope: ConsentScope,
): Promise<CredentialRecord[]> {
  const scope = ownConsentScope(consentScope);
  if (scope.vcId === undefined) {
    return resolveConsentTargetsByPresentation(storage, CREDENTIAL_KEY_PREFIX, scope);
  }
  const record = await readRecord(storage, scope.vcId);
  if (record === null) {
    throw new VericertsError(ErrorCodes.VC_NOT_FOUND);
  }
  return [record];
}
