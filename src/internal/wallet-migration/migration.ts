/**
 * DIDComm メッセージによる W2W デバイス移行と、旧端末との二重利用防止。
 *
 * 設計方針:
 * - トランスポート（QR / BLE / NFC / HTTPS）は本モジュールの責務外とし、メッセージの
 *   組み立て・解釈とセッション状態機械のみを担う（notification モジュールと同じ DI 方針）。
 * - OOB Invitation には nonce を含め、`acceptDeviceMigration` は招待の期限を検証する。
 * - `completeMigration` は `transfer_mode=full` のとき旧端末 VC 無効化を実行し、
 *   失敗時は 4035（W2W_DOUBLE_ACTIVE）で失効未達を通知する。
 *
 * セキュリティ上の注意:
 * - 秘密（VC 平文 / 鍵）は例外に含めない。attestation 検証失敗は 4031 に正規化する。
 */

import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../errors.js';
import { nonObjectPrototypeProperty, ownProperty } from '../prototype-safety/own-property.js';
import {
  type MigrationResult,
  type MigrationSession,
  type OOBInvitation,
  type TransferMode,
  type TransferOfferMessage,
  W2W_MESSAGE_TYPES,
} from './types.js';

/** OOB Invitation のデフォルト有効期間（秒）。生成から 1 時間。 */
const DEFAULT_INVITATION_TTL_SEC = 3600;
/** nonce 長（バイト）。 */
const NONCE_LENGTH = 32;
/** Invitation URI スキーム（QR に埋め込む）。 */
const INVITATION_SCHEME = 'openid-w2w://invite';

/** `startDeviceMigration` の依存注入。 */
export interface StartMigrationDependencies {
  /** 招待 / セッション ID 生成（テスト注入用）。省略時は `crypto.randomUUID()`。 */
  readonly generateId?: () => string;
  /** nonce 生成（テスト注入用）。省略時は `crypto.getRandomValues`。 */
  readonly generateNonce?: () => Uint8Array;
  /** 現在時刻（エポック秒。テスト注入用）。省略時は `Date.now()/1000`。 */
  readonly nowSec?: () => number;
  /** 招待の有効期間（秒）。既定 1 時間。 */
  readonly ttlSec?: number;
}

/** `acceptDeviceMigration` の依存注入。 */
export interface AcceptMigrationDependencies {
  /** セッション ID 生成（テスト注入用）。省略時は `crypto.randomUUID()`。 */
  readonly generateId?: () => string;
  /** 現在時刻（エポック秒。テスト注入用）。省略時は `Date.now()/1000`。 */
  readonly nowSec?: () => number;
  /** 受信側（新端末）の DID（`MigrationSession.theirDID` から見た相手＝招待者を格納）。 */
  readonly ourDID: string;
  /**
   * 新端末の Wallet Integrity（attestation）を検証する。
   * `false` を返すと 4031（W2W_ATTESTATION_FAILED）となる。省略時は検証省略（true 扱い）。
   */
  readonly verifyAttestation?: (invitation: OOBInvitation) => boolean | Promise<boolean>;
}

/** `completeMigration` の依存注入。 */
export interface CompleteMigrationDependencies {
  /**
   * 1 VC を暗号化・転送する。転送成功で `true`、失敗で `false` を返す。
   * 実トランスポート（BLE/NFC/HTTPS）と Authcrypt パッキングは呼び出し側が担う。
   */
  readonly transferCredential: (vcId: string) => boolean | Promise<boolean>;
  /**
   * transfer_mode=full 時に旧端末 VC を無効化（失効通知 + ローカル削除）する。
   * 失敗（失効通知未達）時に `false` を返すと 4035（W2W_DOUBLE_ACTIVE）となる。
   *
   * full モードでは旧端末の VC を失効させる必要があるため、
   * 未指定（呼び出し側の DI 忘れ）も「失効できなかった」として扱い、同じく 4035 を投げる
   * （fail-open で黙って成功扱いにはしない）。
   */
  readonly revokeOldDevice?: (vcIds: readonly string[]) => boolean | Promise<boolean>;
  /**
   * cnf 再バインドが必要かを判定する。省略時は転送成功 VC すべてを要再バインドとする。
   */
  readonly needsRebinding?: (vcId: string) => boolean;
}

/**
 * 依存注入オブジェクトから関数メンバを読む。
 *
 * `deps.nowSec` のような鎖読みだと、`Object.prototype` が汚染された環境で**省略した**依存を攻撃者の
 * 関数が埋める（期限切れ招待の受理・nonce の固定化・full 移行の旧端末失効スキップ）。`lend.ts` /
 * `backup.ts` と同じく汚染を拾わない。クラスインスタンスのプロトタイプメソッドは正当な注入なので許す
 * （`nonObjectPrototypeProperty`）。
 */
function depFn<F>(deps: object, key: string): F | undefined {
  return nonObjectPrototypeProperty<F>(deps, key);
}

/** ID 生成のヘルパ（DI 省略時は crypto.randomUUID）。 */
function makeId(deps: object): string {
  const generateId = depFn<() => string>(deps, 'generateId');
  return generateId !== undefined ? generateId.call(deps) : crypto.randomUUID();
}

/** 現在時刻（秒）のヘルパ。 */
function makeNowSec(deps: object): number {
  const nowSec = depFn<() => number>(deps, 'nowSec');
  return nowSec !== undefined ? nowSec.call(deps) : Math.floor(Date.now() / 1000);
}

/**
 * 旧端末側でデバイス移行を開始し、OOB Invitation（QR 表示用）を生成する。
 *
 * @param fromDID 招待者（旧端末）の DID（did:peer など）。
 * @param deps 依存注入（ID / nonce / 時刻 / TTL）。
 * @returns nonce と有効期限・Invitation URI を含む OOB Invitation。
 */
export function startDeviceMigration(
  fromDID: string,
  deps: StartMigrationDependencies = {},
): OOBInvitation {
  const generateNonce = depFn<() => Uint8Array>(deps, 'generateNonce');
  const nonceBytes =
    generateNonce !== undefined
      ? generateNonce.call(deps)
      : crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
  const nonce = base64urlnopad.encode(nonceBytes);
  const id = makeId(deps);
  const nowSec = makeNowSec(deps);
  const expiresTime = nowSec + (ownProperty<number>(deps, 'ttlSec') ?? DEFAULT_INVITATION_TTL_SEC);
  const params = new URLSearchParams({ id, from: fromDID, nonce, exp: String(expiresTime) });
  return {
    id,
    from: fromDID,
    nonce,
    expiresTime,
    invitationUri: `${INVITATION_SCHEME}?${params.toString()}`,
  };
}

/** `exp`（エポック秒）として受理する 10 進整数表記（符号・指数・16 進・小数・接尾辞を拒否、15 桁まで）。 */
const DECIMAL_SECONDS = /^\d{1,15}$/;

/**
 * OOB Invitation URI をパースする（新端末が QR スキャン後に呼ぶ）。
 *
 * @param invitationURI `startDeviceMigration` が生成した Invitation URI。
 * @returns パース済み OOB Invitation。
 * @throws スキーム不正 / 必須パラメータ欠落の場合（VericertsError、code `4031` は使わず形式不正として扱う）。
 */
export function parseInvitation(invitationURI: string): OOBInvitation {
  let url: URL;
  try {
    url = new URL(invitationURI);
  } catch {
    throw new VericertsError(ErrorCodes.W2W_ATTESTATION_FAILED);
  }
  const params = url.searchParams;
  const id = params.get('id');
  const from = params.get('from');
  const nonce = params.get('nonce');
  const exp = params.get('exp');
  if (id === null || from === null || nonce === null || exp === null) {
    throw new VericertsError(ErrorCodes.W2W_ATTESTATION_FAILED);
  }
  // `parseInt` は '123abc' → 123、'1e3' → 1、'-5' → -5 を通すため、10 進数字のみの文字列に限る。
  const expiresTime = DECIMAL_SECONDS.test(exp) ? Number(exp) : Number.NaN;
  if (!Number.isSafeInteger(expiresTime)) {
    throw new VericertsError(ErrorCodes.W2W_ATTESTATION_FAILED);
  }
  return {
    id,
    from,
    nonce,
    expiresTime,
    invitationUri: invitationURI,
  };
}

/**
 * 新端末側で招待を受理し、移行セッションを確立する。
 *
 * 招待の期限切れは受理しない。`verifyAttestation` が `false` を返すと 4031。
 *
 * @param invitationURI 旧端末が生成した Invitation URI。
 * @param deps 依存注入（自 DID / attestation 検証 / ID / 時刻）。
 * @returns 確立済み移行セッション（state='connected'）。
 * @throws 招待期限切れ / attestation 失敗の場合（VericertsError、code `4031`）。
 */
export async function acceptDeviceMigration(
  invitationURI: string,
  deps: AcceptMigrationDependencies,
): Promise<MigrationSession> {
  const invitation = parseInvitation(invitationURI);
  const nowSec = makeNowSec(deps);
  if (!Number.isFinite(nowSec) || invitation.expiresTime <= nowSec) {
    // 期限切れ招待はリプレイ・改ざんの疑いがあるため attestation 失敗に正規化する。
    throw new VericertsError(ErrorCodes.W2W_ATTESTATION_FAILED);
  }
  const verifyAttestation = depFn<AcceptMigrationDependencies['verifyAttestation'] & object>(
    deps,
    'verifyAttestation',
  );
  if (verifyAttestation !== undefined) {
    const ok = await verifyAttestation.call(deps, invitation);
    if (!ok) {
      throw new VericertsError(ErrorCodes.W2W_ATTESTATION_FAILED);
    }
  }
  return {
    session_id: makeId(deps),
    theirDID: invitation.from,
    state: 'connected',
    credentialCount: 0,
    nonce: invitation.nonce,
  };
}

/**
 * Transfer-Offer メッセージを組み立てる。旧端末が転送を提案する。
 *
 * @param session 移行セッション（`theirDID` を宛先に使う）。
 * @param fromDID 送信者（旧端末）の DID。
 * @param body オファー本文（件数・フォーマット・サイズ・モード等）。
 * @param opts 時刻・ID・TTL の注入。
 * @returns Transfer-Offer メッセージ。
 */
export function buildTransferOffer(
  session: MigrationSession,
  fromDID: string,
  body: TransferOfferMessage['body'],
  opts: { generateId?: () => string; nowSec?: () => number; ttlSec?: number } = {},
): TransferOfferMessage {
  const createdTime = makeNowSec(opts);
  return {
    id: makeId(opts),
    type: W2W_MESSAGE_TYPES.TRANSFER_OFFER,
    from: fromDID,
    to: [session.theirDID],
    created_time: createdTime,
    expires_time: createdTime + (ownProperty<number>(opts, 'ttlSec') ?? DEFAULT_INVITATION_TTL_SEC),
    body,
  };
}

/**
 * 移行を完了する。
 *
 * 各 VC を `transferCredential` で転送し、`transfer_mode=full` の場合は転送成功 VC を
 * `revokeOldDevice` で旧端末側から無効化する。失効通知未達は 4035 で通知する。
 *
 * @param session 確立済み移行セッション。
 * @param vcIds 転送対象の VC ID 群。
 * @param mode 転送モード（full / selective / clone）。
 * @param deps 依存注入（転送 / 旧端末無効化 / 再バインド判定）。
 * @returns 転送件数・失敗 ID・要再バインド ID を含む結果。
 * @throws transfer_mode=full で旧端末無効化に失敗した場合（VericertsError、code `4035`）。
 */
export async function completeMigration(
  session: MigrationSession,
  vcIds: readonly string[],
  mode: TransferMode,
  deps: CompleteMigrationDependencies,
): Promise<MigrationResult> {
  session.state = 'transferring';
  const transferred: string[] = [];
  const failed: string[] = [];
  const transferCredential = depFn<CompleteMigrationDependencies['transferCredential']>(
    deps,
    'transferCredential',
  );
  for (const vcId of vcIds) {
    if (transferCredential === undefined) {
      throw new TypeError('transferCredential is required');
    }
    const ok = await transferCredential.call(deps, vcId);
    if (ok) {
      transferred.push(vcId);
    } else {
      failed.push(vcId);
    }
  }

  // full モードは旧端末で VC を無効化する（同時有効を防ぐ）。
  // revokeOldDevice が未指定の場合も「無効化できなかった」として扱う（fail-safe）。
  // 成功として扱うと、旧端末の VC が有効なまま移行が完了してしまう。
  if (mode === 'full' && transferred.length > 0) {
    const revokeOldDevice = depFn<NonNullable<CompleteMigrationDependencies['revokeOldDevice']>>(
      deps,
      'revokeOldDevice',
    );
    const revoked =
      revokeOldDevice !== undefined ? await revokeOldDevice.call(deps, transferred) : false;
    if (!revoked) {
      throw new VericertsError(ErrorCodes.W2W_DOUBLE_ACTIVE, {
        context: { transferred: transferred.length },
      });
    }
  }

  const needsRebinding = depFn<NonNullable<CompleteMigrationDependencies['needsRebinding']>>(
    deps,
    'needsRebinding',
  );
  const rebindingRequired =
    needsRebinding !== undefined
      ? transferred.filter((id) => needsRebinding.call(deps, id))
      : [...transferred];

  session.state = 'completed';
  session.credentialCount = transferred.length;
  return { transferred: transferred.length, failed, rebindingRequired };
}
