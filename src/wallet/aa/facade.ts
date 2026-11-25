/**
 * Wallet ファサードの AA 緊急 Validator 失効 API の委譲実装。
 *
 * `WalletImpl`（`wallet.ts`）が肥大化しないよう、AA 操作まわりの委譲処理を本クラスへ切り出す
 * （`gdpr/facade.ts` と同じ「ファサードを薄く保つ」方針）。インターフェース定義は `../aa-api.ts`。
 *
 * Dashboard ログ署名はアクティブペルソナ鍵で行う。
 * UserOperation の署名は `opts.keyId` が指す K1 派生鍵（アクティブペルソナとは独立、install 済みの
 * ECDSAValidator に対応する鍵）で行う。生成は `factory.ts` の `createWallet` 経由のみを想定する
 * （`eudi/facade.ts` と同じ「呼び出し元が組み立てて渡す」方針。`wallet.ts` を薄く保つため）。
 *
 * セキュリティ上の注意: `opts` は呼び出し側から受け取る任意オブジェクトの
 * ため、`opts.x` の鎖読みは `Object.prototype` 汚染下で継承値を拾う。純データは `ownProperty`、
 * `callSource` / `bundlerRpc`（プロトタイプメソッドを持つ DI 依存）は `nonObjectPrototypeProperty`
 * で own 限定に読む。
 */

import type { BundlerRpc } from '../../internal/aa/bundler.js';
import {
  type EmergencyRevokeResult,
  emergencyRevoke,
  type RevokeReason,
} from '../../internal/aa/emergency-revoke.js';
import type { Hex } from '../../internal/aa/types.js';
import type { EvmCallSource } from '../../internal/asset/rpc.js';
import { ErrorCodes, VericertsError } from '../../internal/errors.js';
import type { DashboardLog } from '../../internal/gdpr/dashboard-log/dashboard-log.js';
import type { KeyManager } from '../../internal/keymanager/keymanager.js';
import { errorLogAttributes, type Logger } from '../../internal/observability/logger.js';
import { safeEmit } from '../../internal/observability/safe-emit.js';
import type { PersonaManager } from '../../internal/persona/persona.js';
import {
  nonObjectPrototypeProperty,
  ownProperty,
} from '../../internal/prototype-safety/own-property.js';
import type { EmergencyRevokeOptions } from '../aa-api.js';
import { type ActiveSignerOptions, resolveActiveSigner } from '../setup.js';

/**
 * `opts` の必須文字列項目を own 限定で読み、空文字・非文字列は送信前に弾く。
 *
 * アドレス・鍵 ID は例外へ載せない。どの項目が欠けているかは
 * 呼び出し側が自分の引数を見れば分かるため、`1022`（Validator を特定できない）へ倒すだけにする。
 */
function requireString(opts: EmergencyRevokeOptions, key: string): string {
  const value = ownProperty<unknown>(opts, key);
  if (typeof value !== 'string' || value.length === 0) {
    throw new VericertsError(ErrorCodes.VALIDATOR_NOT_AVAILABLE);
  }
  return value;
}

/** `chainId` を own 限定で読む。UserOpHash のドメイン分離に入るため既定値で埋めない。 */
function requireChainId(opts: EmergencyRevokeOptions): number {
  const value = ownProperty<unknown>(opts, 'chainId');
  if (typeof value !== 'number' || !Number.isInteger(value) || value <= 0) {
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
  }
  return value;
}

/** EIP-1559 の fee を own 限定で読む。0 や欠落のまま UserOperation を送らない。 */
function requireFee(opts: EmergencyRevokeOptions, key: string): bigint {
  const value = ownProperty<unknown>(opts, key);
  if (typeof value !== 'bigint' || value <= 0n) {
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
  }
  return value;
}

/** AA 緊急 Validator 失効 API の委譲先。 */
export class AaFacade {
  constructor(
    private readonly keymanager: KeyManager,
    private readonly personas: PersonaManager,
    private readonly dashboardLog: DashboardLog,
    /** `component: 'sdk.aa'` を束縛済みのロガー（`factory.ts` が組み立てる）。未注入時は no-op。 */
    private readonly logger: Logger,
    /** 取り込んだ DID のペルソナで署名するための Resolver・外部秘密鍵の提供元（`factory.ts` が組み立てる）。 */
    private readonly signing?: ActiveSignerOptions,
  ) {}

  /**
   * `Wallet.emergencyRevokeValidator` の実体。UserOperation を構築・署名・送信し、
   * 成功時は Dashboard ログに `reason` 付きで記録する。
   */
  async emergencyRevokeValidator(
    reason: RevokeReason,
    opts: EmergencyRevokeOptions,
  ): Promise<EmergencyRevokeResult> {
    // 任意プロパティは自身のプロパティに限って読む。継承値を拾うと、
    // 「未指定」の正当な呼び出しが汚染値を「明示指定」として実行してしまう。
    //
    // 必須項目は既定値で埋めずに送信前へ倒す。`ownProperty` は own 限定読みを保証するだけで型は
    // 検証しないため（own-property.ts の「読み取った値を検証せずに as でキャストしないこと」）、
    // 欠落・型不一致を `?? ''` / `?? 0` / `?? 0n` で吸収すると、`chainId = 0` のまま
    // `getUserOpHash` のドメイン分離へ入る（別チェーン向けに解釈され得る UserOp を署名する）、
    // `maxFeePerGas = 0n` の UserOperation を送る、といった形で「明示していない値」で
    // チェーンに触れてしまう。JS 呼び出し元や Object.prototype 汚染下では型は守ってくれない。
    const keyId = requireString(opts, 'keyId');
    const accountAddress = requireString(opts, 'accountAddress') as Hex;
    const signingValidatorAddress = requireString(opts, 'signingValidatorAddress') as Hex;
    const chainId = requireChainId(opts);
    const callSource = nonObjectPrototypeProperty<EvmCallSource>(opts, 'callSource');
    const bundlerRpc = nonObjectPrototypeProperty<BundlerRpc>(opts, 'bundlerRpc');
    const maxFeePerGas = requireFee(opts, 'maxFeePerGas');
    const maxPriorityFeePerGas = requireFee(opts, 'maxPriorityFeePerGas');
    // 予算は任意だが、指定されたのに不正な型・値なら無視せず送信前に倒す（予算無しで署名させない）。
    const maxTotalCostWei = ownProperty<bigint>(opts, 'maxTotalCostWei');
    if (
      maxTotalCostWei !== undefined &&
      (typeof maxTotalCostWei !== 'bigint' || maxTotalCostWei <= 0n)
    ) {
      throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
    }
    const maxReceiptAttempts = ownProperty<number>(opts, 'maxReceiptAttempts');
    const receiptPollIntervalMs = ownProperty<number>(opts, 'receiptPollIntervalMs');

    if (callSource === undefined || bundlerRpc === undefined) {
      // 型上は必須だが、Object.prototype 汚染下では own 限定読みが未指定として弾くため
      // 実行時にも防御する（黒く失敗させず、明示的なチェーン送信不能エラーへ倒す）。
      throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
    }

    const result = await emergencyRevoke({
      callSource,
      bundlerRpc,
      chainId,
      accountAddress,
      signingValidatorAddress,
      sign: async (digest) => this.keymanager.signRawDigest(keyId, digest),
      maxFeePerGas,
      maxPriorityFeePerGas,
      maxTotalCostWei,
      maxReceiptAttempts,
      receiptPollIntervalMs,
    });

    await this.appendRevokeLog(reason, result);
    return result;
  }

  /**
   * 失効を Dashboard ログへ記録する。
   *
   * **記録の失敗で失効の成功を巻き戻さない。** 失効は既にチェーン上で確定しており、ここで例外を
   * 投げると「成功したのに失敗が返る」ことになる。特にログ署名鍵の解決（`resolveActiveSigner`）は
   * アクティブペルソナ未設定で `2005` を投げるが、緊急失効は盗難直後・復旧直後に呼ばれるため
   * ペルソナが無い状況が現実的に起こる。記録できなかったことは呼び出し側が検知できるよう
   * PII マスキングを適用する構造化ロガーの `logger.error` に記録する。
   */
  private async appendRevokeLog(
    reason: RevokeReason,
    result: EmergencyRevokeResult,
  ): Promise<void> {
    try {
      const { signer } = await resolveActiveSigner(this.personas, this.keymanager, this.signing);
      await this.dashboardLog.append(
        'emergencyRevoked',
        { reason, txHash: result.txHash, revokedValidators: result.revokedValidators },
        signer,
      );
    } catch (e) {
      // 緊急失効は完了済み。ログ sink の失敗で失効結果を reject に変えない。
      safeEmit(() =>
        this.logger.error('failed to append emergencyRevoked dashboard log', errorLogAttributes(e)),
      );
    }
  }
}
