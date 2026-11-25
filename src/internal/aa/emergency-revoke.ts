/**
 * 緊急時に K1 由来の署名用 Validator を残し、他の Validator を失効させる。
 *
 * K1 派生の ECDSA Validator の署名で ModularAccount の `uninstallValidator` を呼び出す
 * UserOperation を構築・署名・送信する。対象は「署名に使う Validator 自身を除く、現在 install
 * 済みの全 Validator」（cooldown なしで即時削除）。
 *
 * **`ThresholdUnreachable` はこの経路では発生しない**（したがって閾値を操作する「対策」も不要）。
 * `ModularAccount.uninstallValidator` のガードは `remaining < threshold` で revert するが、
 * 1. この UserOperation が実行フェーズへ到達する前提は `accumulated >= threshold`
 *    （`ERC4337Account._aggregate`）であり、署名者は 1 人なので `W_署名者 >= threshold`。
 * 2. 署名者自身は削除対象から除外しているため、バッチ中のどの時点でも `remaining >= W_署名者`。
 * したがって常に `remaining >= W_署名者 >= threshold` が成り立つ。
 *
 * 逆に `W_署名者 < threshold` のアカウントでは、**署名検証フェーズで弾かれる**ため実行フェーズの
 * `setThreshold` では救えない（そのケースは送信前に `1022` で落とす）。加えて `setThreshold` は
 * 閾値を**恒久的に**書き換えるため、`threshold < W_署名者` の構成で差し込むと、復旧後に weight の
 * 小さい新 Passkey Validator を追加したときにその Validator 単独では署名できなくなる（利用者が
 * 要求していないマルチシグ方針の変更になる）。
 *
 * ネットワーク／署名は DI（`EvmCallSource` / `BundlerRpc` / `sign`）で注入し、本ファイルは
 * UserOperation 構築フローのみを持つ（aa/ 配下の既存モジュールと同じ「実 RPC 非依存」方針）。
 * EntryPoint は ERC-4337 v0.7 の決定論的シングルトン（`ENTRY_POINT_V07_ADDRESS`）に固定する
 * （`getUserOpHash` / `sendUserOperation` / `estimateUserOperationGas` が内部でこの定数を使うため、
 * 呼び出し側が別アドレスを渡せる設計だと nonce 読み取り先と署名対象・送信先が食い違う）。
 *
 * fee（`maxFeePerGas` / `maxPriorityFeePerGas`）は Bundler の `eth_estimateUserOperationGas` が
 * 返す対象ではない（ガス上限のみを返す）ため、呼び出し側が現在のネットワーク fee 相場から
 * 明示的に注入する。
 *
 * セキュリティ上の注意: アドレス・calldata・署名を例外に含めない。
 */

import { getBytes } from 'ethers';
import type { EvmCallSource } from '../asset/rpc.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import type { RecoverableSignature } from '../keymanager/signer.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import {
  type BundlerRpc,
  estimateUserOperationGas,
  getUserOperationReceipt,
  sendUserOperation,
} from './bundler.js';
import { assertTotalGasCostWithin } from './gas-limits.js';
import { resolveReceiptOptions } from './receipt-options.js';
import { confirmValidatorsRevoked, readInstalledValidators, sleep } from './revoke-confirm.js';
import { ENTRY_POINT_V07_ADDRESS, type Hex } from './types.js';
import { buildUserOperation, getUserOpHash, withUserOperationFields } from './user-operation.js';
import {
  createEntryPointAbiCodec,
  createModularAccountAbiCodec,
  encodeValidatorSignature,
} from './validator-abi.js';

/** 鍵の失効理由。 */
export type RevokeReason = 'lost' | 'stolen' | 'compromised' | 'upgrade';

/** 緊急失効のために送信した UserOperation の結果。 */
export interface EmergencyRevokeResult {
  /** UserOperation を内包した実チェーン Tx のハッシュ。 */
  readonly txHash: Hex;
  /** 削除した Validator のアドレス一覧（署名に使った Validator 自身は含まない）。 */
  readonly revokedValidators: readonly Hex[];
  /** 削除後、WUA の再発行が必要か（本 API は常に `true`）。 */
  readonly newWuaRequired: boolean;
}

/** `emergencyRevoke` の依存（ネットワーク・署名の DI seam）。 */
export interface EmergencyRevokeDeps {
  /** ModularAccount / EntryPoint の view 呼び出し（`getValidators` / `getNonce`）に使う。 */
  readonly callSource: EvmCallSource;
  /** UserOperation の送信・レシート取得に使う Bundler RPC。 */
  readonly bundlerRpc: BundlerRpc;
  /** 対象チェーン ID。 */
  readonly chainId: number;
  /** 失効対象の ModularAccount アドレス。 */
  readonly accountAddress: Hex;
  /** 署名に使う ECDSAValidator インスタンスのアドレス（K1 派生鍵に対応する install 済み Validator）。 */
  readonly signingValidatorAddress: Hex;
  /** UserOpHash（すでに計算済みの 32 バイトダイジェスト）への署名。 */
  readonly sign: (digest: Uint8Array) => Promise<RecoverableSignature>;
  /**
   * EIP-1559 の最大ガス価格（wei）。Bundler の gas estimate はガス上限のみを返すため、
   * 呼び出し側が現在のネットワーク fee 相場から明示的に注入する。
   */
  readonly maxFeePerGas: bigint;
  /** EIP-1559 の最大 priority fee（wei）。 */
  readonly maxPriorityFeePerGas: bigint;
  /**
   * 署名してよい最悪ケースのガス代総額（wei。全ガス上限の合計 × `maxFeePerGas`）。超える見積りは
   * 署名前に `1021` で拒否する。未指定でも各ガス値には絶対上限が掛かる（`gas-limits.ts`）。
   */
  readonly maxTotalCostWei?: bigint;
  /** レシート未確定時のポーリング回数（既定 10）。テストでは 1 に設定し即時解決させる。 */
  readonly maxReceiptAttempts?: number;
  /** ポーリング間隔（ミリ秒、既定 1000）。テストでは 0 に設定する。 */
  readonly receiptPollIntervalMs?: number;
}

const ENTRY_POINT_NONCE_KEY = 0n;

async function readNonce(
  callSource: EvmCallSource,
  chainId: number,
  accountAddress: Hex,
): Promise<bigint> {
  const codec = createEntryPointAbiCodec();
  const data = await callSource.call({
    chainId,
    to: ENTRY_POINT_V07_ADDRESS,
    data: codec.encode('getNonce', [accountAddress, ENTRY_POINT_NONCE_KEY]),
  });
  const [nonce] = codec.decode('getNonce', data) as [bigint];
  return nonce;
}

/** 署名に使う Validator 自身の現在の weight を読み取る（閾値到達性の事前判定に使う）。 */
async function readSigningValidatorWeight(
  callSource: EvmCallSource,
  chainId: number,
  accountAddress: Hex,
  signingValidatorAddress: Hex,
): Promise<bigint> {
  const codec = createModularAccountAbiCodec();
  const data = await callSource.call({
    chainId,
    to: accountAddress,
    data: codec.encode('validatorWeight', [signingValidatorAddress]),
  });
  const [weight] = codec.decode('validatorWeight', data) as [bigint];
  return weight;
}

/** アカウントの現在の署名閾値を読み取る。 */
async function readThreshold(
  callSource: EvmCallSource,
  chainId: number,
  accountAddress: Hex,
): Promise<bigint> {
  const codec = createModularAccountAbiCodec();
  const data = await callSource.call({
    chainId,
    to: accountAddress,
    data: codec.encode('threshold', []),
  });
  const [threshold] = codec.decode('threshold', data) as [bigint];
  return threshold;
}

/**
 * 失効対象 Validator ごとの `uninstallValidator` 呼び出しを `executeBatch` の calldata へ組み立てる。
 *
 * バッチは `uninstallValidator` だけで構成する（閾値は変更しない。理由はファイル先頭の JSDoc）。
 */
function buildRevokeCallData(accountAddress: Hex, validatorsToRevoke: readonly Hex[]): Hex {
  const codec = createModularAccountAbiCodec();
  const func = validatorsToRevoke.map((validator) =>
    codec.encode('uninstallValidator', [validator, '0x']),
  );
  const dest = func.map(() => accountAddress);
  const value = func.map(() => 0n);
  return codec.encode('executeBatch', [dest, value, func]) as Hex;
}

/**
 * レシートを待つ。確定しないまま試行上限に達した場合は `phase: 'receipt_timeout'` で落とす。
 *
 * 緊急失効では「まだ確定していない（再送・再確認すべき）」と「実行されて失敗した（再送しても
 * 同じ）」を呼び出し側が区別できる必要がある。同じコードで理由も `userOpHash` も返さないと、
 * 失効が成立したのか判断できない。`userOpHash` は公開情報なので context に載せてよい
 * （アドレス・calldata・署名は載せない）。
 */
async function waitForReceipt(
  bundlerRpc: BundlerRpc,
  userOpHash: Hex,
  maxAttempts: number,
  pollIntervalMs: number,
) {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const receipt = await getUserOperationReceipt(bundlerRpc, userOpHash);
    if (receipt !== null) {
      return receipt;
    }
    if (attempt < maxAttempts - 1) {
      await sleep(pollIntervalMs);
    }
  }
  throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED, {
    context: { phase: 'receipt_timeout', userOpHash, attempts: maxAttempts },
  });
}

/**
 * K1 派生 ECDSA Validator の署名で、署名者自身を除く install 済み全 Validator を削除する。
 *
 * @throws {RangeError} `maxReceiptAttempts` が 1 以上の安全な整数でない、`receiptPollIntervalMs` が 0 以上
 *         タイマー上限 以下の有限数でない場合（UserOperation 送信前に拒否する）。
 * @throws 署名に使う Validator が install されていない場合、署名者の weight が閾値未満の場合、
 *         削除対象の Validator が 1 件も無い場合（いずれも VericertsError、code `1022`）、
 *         UserOperation 送信・レシート取得・実行結果が失敗の場合、Bundler が返した `userOpHash` が
 *         署名対象として計算したものと一致しない場合、レシート成功後の Validator 状態の読み直しで失効対象が
 *         残っている / 読み直せない場合（いずれも VericertsError、code `1021`）。
 */
export async function emergencyRevoke(deps: EmergencyRevokeDeps): Promise<EmergencyRevokeResult> {
  // UserOperation 送信**前**に拒否する。
  const { maxReceiptAttempts, receiptPollIntervalMs } = resolveReceiptOptions(deps);
  const validators = await readInstalledValidators(
    deps.callSource,
    deps.chainId,
    deps.accountAddress,
  );
  const signingValidator = deps.signingValidatorAddress.toLowerCase();
  if (!validators.some((v) => v.toLowerCase() === signingValidator)) {
    throw new VericertsError(ErrorCodes.VALIDATOR_NOT_AVAILABLE);
  }
  const revokedValidators = validators.filter((v) => v.toLowerCase() !== signingValidator);
  if (revokedValidators.length === 0) {
    // 署名者しか install されていない。空の `executeBatch` を送っても何も削除されないのに、
    // ガスは払い、レシートは `success` で返るため呼び出し側には「失効した」と見える。
    // 送信前に落として、失効すべき Validator が無かったことを `1022` で返す。
    throw new VericertsError(ErrorCodes.VALIDATOR_NOT_AVAILABLE);
  }

  // 署名者の weight が閾値に届かないアカウントでは、この UserOperation は**署名検証フェーズ**で
  // 弾かれる（`_aggregate` の `accumulated >= threshold`）。実行フェーズに入れない以上こちらでは
  // どうにもできないので、Bundler の不透明な検証失敗にせず送信前に落として理由を呼び出し側へ返す。
  const [signerWeight, threshold] = await Promise.all([
    readSigningValidatorWeight(
      deps.callSource,
      deps.chainId,
      deps.accountAddress,
      deps.signingValidatorAddress,
    ),
    readThreshold(deps.callSource, deps.chainId, deps.accountAddress),
  ]);
  if (signerWeight < threshold) {
    throw new VericertsError(ErrorCodes.VALIDATOR_NOT_AVAILABLE);
  }

  const nonce = await readNonce(deps.callSource, deps.chainId, deps.accountAddress);
  const callData = buildRevokeCallData(deps.accountAddress, revokedValidators);

  // 見積りは実署名と同形・同長のダミー署名で行う。`signature: '0x'` のままだと
  // `_validateSignature` がデコード段階で失敗して Validator の staticcall / ecrecover に到達せず、
  // `verificationGasLimit` に実際の検証コストが入らない（過小見積りのまま送信することになる）。
  // r/s が 0 だと ecrecover が早期リターンするため非ゼロで埋める。
  // `getUserOpHash`（ERC-4337 v0.7）は signature を署名対象に含めないため、ダミー → 実署名の
  // 差し替えでハッシュは変わらない。
  const dummySignature = encodeValidatorSignature(
    deps.signingValidatorAddress,
    new Uint8Array(64).fill(1),
    0,
  );
  let userOp = buildUserOperation({
    sender: deps.accountAddress,
    nonce,
    callData,
    maxFeePerGas: deps.maxFeePerGas,
    maxPriorityFeePerGas: deps.maxPriorityFeePerGas,
    signature: dummySignature,
  });
  const gas = await estimateUserOperationGas(deps.bundlerRpc, userOp);
  userOp = withUserOperationFields(userOp, gas);
  // 見積り反映後の最悪ケース prefund が呼び出し側の予算を超える UserOp には署名しない。
  // 予算は own 限定で読む。省略した呼び出しが `Object.prototype.maxTotalCostWei` の汚染値を
  // 「指定された予算」として拾うと、予算検査が汚染値で評価される。
  const maxTotalCostWei = ownProperty<unknown>(deps, 'maxTotalCostWei');
  if (maxTotalCostWei !== undefined) assertTotalGasCostWithin(userOp, maxTotalCostWei);

  const userOpHash = getUserOpHash(userOp, deps.chainId);
  const sig = await deps.sign(getBytes(userOpHash));
  const signature = encodeValidatorSignature(
    deps.signingValidatorAddress,
    sig.signature,
    sig.recovery,
  );
  userOp = withUserOperationFields(userOp, { signature });

  const sentUserOpHash = await sendUserOperation(deps.bundlerRpc, userOp);
  if (sentUserOpHash.toLowerCase() !== userOpHash.toLowerCase()) {
    // Bundler が返したハッシュでそのままレシートを引くと、別の UserOperation のレシートを見て
    // `success` を返し得る。緊急失効で「失効していないのに成功」は最も避けたい失敗なので、
    // 署名対象として自分で計算したハッシュと一致しない時点で落とす。ハッシュは公開情報のため
    // context に載せてよい（アドレス・calldata・署名は載せない）。
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED, {
      context: { phase: 'userop_hash_mismatch', userOpHash, returnedUserOpHash: sentUserOpHash },
    });
  }
  const receipt = await waitForReceipt(
    deps.bundlerRpc,
    sentUserOpHash,
    maxReceiptAttempts,
    receiptPollIntervalMs,
  );
  if (!receipt.success) {
    // 実行されたうえで revert した（再送しても同じ結果になる）。タイムアウトと区別できるよう
    // phase を載せる。
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED, {
      context: {
        phase: 'execution_reverted',
        userOpHash: sentUserOpHash,
        txHash: receipt.transactionHash,
      },
    });
  }
  // Bundler のレシートは偽造できる（`userOpHash` は公開値）。成功を返す前にオンチェーン状態で確認する。
  await confirmValidatorsRevoked({
    callSource: deps.callSource,
    chainId: deps.chainId,
    accountAddress: deps.accountAddress,
    signingValidatorAddress: deps.signingValidatorAddress,
    revokedValidators,
    userOpHash: sentUserOpHash,
    txHash: receipt.transactionHash,
    pollIntervalMs: receiptPollIntervalMs,
  });

  return {
    txHash: receipt.transactionHash,
    revokedValidators,
    newWuaRequired: true,
  };
}
