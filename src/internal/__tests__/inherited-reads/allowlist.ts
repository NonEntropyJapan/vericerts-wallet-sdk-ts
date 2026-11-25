/**
 * 継承読みゲート（scan.ts）が型だけでは「安全」と判定しきれない読みの許可リスト。
 *
 * ここに置いてよいのは、**このライブラリ自身が own で作った値**（null プロトタイプの写し・全キーを own で持つ写し）を読む箇所だけ。
 * 外部入力を読む箇所は `ownProperty` / `nonObjectPrototypeProperty`（`internal/prototype-safety/own-property.ts`）か
 * `Object.hasOwn` で読んで直す（許可リストへの追加は最後の手段）。許可するときは、実際に `Object.prototype` 汚染下で動作が変わらない
 * ことを `inherited-inputs.pollution.test.ts` のような汚染テストで確認し、その旨を `reason` に書く。
 *
 * 照合は `file`（SDK ルートからの相対パス）と `expression`（検出式）の完全一致で、行番号には依存しない。1 件も一致しない（= 不要になった）
 * 許可は {@link applyAllowlist} が `unused` として返し、ゲートが失敗させる。
 */

import type { InheritedRead } from './scan.js';

export interface AllowedRead {
  readonly file: string;
  readonly expression: string;
  readonly reason: string;
}

const CONSENT_SCOPE = 'src/internal/gdpr/consent-scope-resolver.ts';
const CONSENT_SCOPE_REASON =
  '`ownConsentScope()` の戻り値（`Object.create(null)` に own の 4 キーだけを写した null プロトタイプ）を読む。' +
  '汚染の継承元が無いので、省略したキーは常に undefined（inherited-inputs.pollution.test.ts の hasConsentTarget / resolveConsentTargets で確認）。';
const KMS_DESCRIPTOR = 'src/internal/keymanager/kms/provider.ts';
const KMS_DESCRIPTOR_REASON =
  '`snapshotKeyDescriptor()` が返すオブジェクトリテラルで、`kid` / `messageFormat` / `signatureFormat` を値が undefined でも' +
  '必ず own キーとして持つ（写し元も null プロトタイプ）。省略時は own の undefined を読むので汚染値を拾わない' +
  '（inherited-inputs.pollution.test.ts の createKmsSigner で確認）。';

/**
 * JSON の絞り込み先の**必須**プロパティで、読む値が own で保証されている箇所を、保証の根拠ごとに集めた群。
 * 各群は `files` × `expressions` の全組を許可する。根拠は「パース境界で null プロトタイプ化済み（`parseJsonWithoutPrototype`）」
 * 「検証関数が own の型を確認済み」「このライブラリが own のオブジェクトリテラルで組み立てた値」のいずれか。外部入力の
 * プロパティは `ownProperty` で読む。
 * 各群の根拠は `narrowed.pollution.test.ts`（デコーダは必須キーを欠く入力を汚染下でも同じ例外で拒否する）で確認した。
 */
interface ReadGroup {
  readonly reads: readonly (readonly [file: string, expressions: readonly string[]])[];
  readonly reason: string;
}

const NULL_PROTO_PARSE =
  'ストレージ・ネットワークの JSON は `parseJsonWithoutPrototype`（入れ子まで null プロトタイプ化）でデコードされ、' +
  'デコーダが必須フィールドの型を検査して不正なら拒否する。欠落した必須キーは継承元が無いので常に undefined' +
  '（汚染値を拾えない。narrowed.pollution.test.ts の「デコーダは必須キーを欠く入力を汚染下でも拒否」で確認）。';

const READ_GROUPS: readonly ReadGroup[] = [
  {
    reason:
      'Entity Statement の `jwks` は `parseJwks` が own のオブジェクトリテラル `{ keys }`（Array.isArray・件数上限を確認済み）で' +
      '返し、Trust Anchor のピン鍵は `isPinnedJwkSet` が own の `keys` 配列を確認済み。`keys` は継承では埋まらない。' +
      '（汚染された Object.prototype.keys は parseJwks / isPinnedJwkSet が own 限定で読むので入口で効かない）',
    reads: [
      [
        'src/internal/trust/federation/revocation/trust-chain-revocation.ts',
        ['child.statement.jwks.keys'],
      ],
      ['src/internal/credential/issuer-key-revocation.ts', ['node.statement.jwks.keys']],
      ['src/internal/trust/federation/statement/statement.ts', ['jwks.keys']],
      [
        'src/internal/trust/federation/anchor-pin/anchor-pin.ts',
        ['anchorConfig.statement.jwks.keys', 'pinned.keys'],
      ],
      ['src/internal/trust/federation/subordinate.ts', ['jwks.keys']],
      ['src/internal/auth/jar/jar-trust-oidf.ts', ['leafNode.statement.jwks.keys']],
    ],
  },
  {
    reason: NULL_PROTO_PARSE,
    reads: [
      ['src/internal/delegated-did/delegated-did-store.ts', ['record.did', 'item.controllerDID']],
      [
        'src/internal/eudi/batch/pool-store.ts',
        ['item.vct', 'pool.totalCount', 'pool.usedCount', 'pool.id'],
      ],
      ['src/internal/gdpr/log-filter.ts', ['entry.recordedAt', 'entry.type', 'entry.payload']],
      ['src/internal/gdpr/dashboard-log/dashboard-log-shared.ts', ['entry.signature']],
      [
        'src/internal/gdpr/dashboard-log/dashboard-log-delete.ts',
        ['entry.payload', 'entry.id', 'entry.prevHash'],
      ],
      ['src/internal/gdpr/dashboard-log/dashboard-log-export.ts', ['entry.prevHash']],
      [
        'src/internal/gdpr/dashboard-log/dashboard-log-import.ts',
        ['line.prevHash', 'line.id', 'previous.id', 'rootLine.count', 'rootLine.merkleRoot'],
      ],
      ['src/internal/gdpr/dashboard-log/dashboard-log-persist.ts', ['entry.id']],
      ['src/internal/gdpr/dashboard-log/dashboard-log.ts', ['e.payload', 'entry.id']],
      ['src/internal/gdpr/active-credentials.ts', ['record.credential']],
      ['src/internal/gdpr/credential-store/records.ts', ['record.id']],
      ['src/internal/gdpr/consent-scope-resolver.ts', ['entry.rpIdentifier']],
      ['src/internal/gdpr/credential-store/store.ts', ['target.id']],
      ['src/internal/identity/ipid/ipfs-api.ts', ['result.Hash', 'result.Name']],
      ['src/internal/identity/jwt/method-jwt.ts', ['vm.id', 'vm.type']],
      [
        'src/internal/persona/sort.ts',
        ['a.createdAt', 'a.lastUsedAt', 'b.createdAt', 'b.lastUsedAt'],
      ],
      ['src/internal/persona/persona.ts', ['metadata.id', 'persona.index']],
      ['src/wallet/credential/create-presentation.ts', ['record.credential']],
      ['src/wallet/wallet-record.ts', ['active.did']],
      ['src/wallet/recovery/facade.ts', ['persona.id']],
    ],
  },
  {
    reason:
      'Dashboard ログの chain 検証は、入口（`verifyDashboardLogChain` / `resolveDeletionRecords`）で全エントリを' +
      '`snapshotDashboardLogEntry`（null プロトタイプ・6 キーを必ず own で持つ写し）へ畳んでから読む。写しは省略キーを継承で' +
      '埋めない（narrowed.pollution.test.ts の chain 検証ケースで、汚染前後の issues が一致することを確認）。',
    reads: [
      [
        'src/internal/gdpr/log-integrity/entry-signature.ts',
        ['entry.signature', 'entry.type', 'entry.recordedAt', 'entry.prevHash', 'entry.payload'],
      ],
      ['src/internal/gdpr/log-integrity/deletion-records.ts', ['entry.type', 'entry.payload']],
      ['src/internal/gdpr/log-integrity/tail-anchor.ts', ['entry.id', 'atAnchor.id', 'last.id']],
      ['src/internal/gdpr/log-integrity/chain.ts', ['entry.id', 'entry.prevHash']],
    ],
  },
  {
    reason:
      '検証済みの DID Document 要素・構造体の `id`。`verificationMethodsOf` / `servicesOf` は全要素の own の `id` が文字列であることを' +
      '確認して返し（`isIdentifiedObject`）、追加される構造体は `toVerificationMethod` / `toService` が own の非空文字列 `id` を確認する。' +
      '作成直後の DID Document（`method.create` / `createDid`）は own のオブジェクトリテラル。',
    reads: [
      [
        'src/internal/identity/did-document-patch.ts',
        ['method.id', 'service.id', 'existing.id', 'addedMethod.id'],
      ],
      ['src/wallet/did/facade.ts', ['document.id']],
    ],
  },
];

const GROUPED_READS: readonly AllowedRead[] = READ_GROUPS.flatMap((group) =>
  group.reads.flatMap(([file, expressions]) =>
    expressions.map((expression) => ({ file, expression, reason: group.reason })),
  ),
);

export const ALLOWED_READS: readonly AllowedRead[] = [
  ...GROUPED_READS,
  {
    file: 'src/internal/credential/vc/jws.ts',
    expression: '(result as { then?: unknown } | null).then',
    reason:
      '検証コールバックの戻り値が thenable のとき、未処理 rejection を避けるためだけに `then` の有無を見る（結果は使わず、' +
      '判定は `result === true`）。own 限定にすると prototype 上の `then` を持つ本物の Promise を見逃す。' +
      '汚染された `Object.prototype.then` で変わるのは握りつぶしの catch の付与だけで、検証結果は変わらない。',
  },
  ...['rpIdentifier', 'purpose', 'vcId', 'pseudonym'].map((key) => ({
    file: CONSENT_SCOPE,
    expression: `scope.${key}`,
    reason: CONSENT_SCOPE_REASON,
  })),
  ...['kid', 'messageFormat', 'signatureFormat'].map((key) => ({
    file: KMS_DESCRIPTOR,
    expression: `descriptor.${key}`,
    reason: KMS_DESCRIPTOR_REASON,
  })),
];

/** `found` から許可済みの読みを除き、残り（違反）と、どの検出にも一致しなかった許可（不要）を返す。 */
export function applyAllowlist(
  found: readonly InheritedRead[],
  allowed: readonly AllowedRead[] = ALLOWED_READS,
): { readonly violations: InheritedRead[]; readonly unused: AllowedRead[] } {
  const matched = new Set<AllowedRead>();
  const violations = found.filter((read) => {
    const entry = allowed.find((a) => a.file === read.file && a.expression === read.expression);
    if (entry === undefined) return true;
    matched.add(entry);
    return false;
  });
  return { violations, unused: allowed.filter((a) => !matched.has(a)) };
}
