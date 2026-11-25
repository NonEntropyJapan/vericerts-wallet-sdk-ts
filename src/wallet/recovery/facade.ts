/**
 * Wallet の完全復旧 API の委譲実装。
 *
 * `WalletImpl`（`wallet.ts`）が肥大化しないよう、復旧フローの委譲処理を本クラスへ切り出す
 * （`gdpr/facade.ts` / `aa/facade.ts` と同じ「ファサードを薄く保つ」方針）。
 * インターフェース定義は `../recovery-api.ts`。
 *
 * セキュリティ上の注意: `options` は呼び出し側から受け取る任意オブジェクトの
 * ため、`options.x` のような鎖読みは `Object.prototype` 汚染下で継承値を「明示指定」として拾う
 * （例: 汚染された `wuaProviderEndpoint` が付き、指定していない呼び出しで WUA 再発行が走る）。
 * 純データ（`newPin` / `newPasskey` / `wuaProviderEndpoint`）は `ownProperty`、関数値
 * （`createPasskey`）は `nonObjectPrototypeProperty` で own 限定に読む。
 */

import { ErrorCodes, VericertsError } from '../../internal/errors.js';
import type { KeyManager } from '../../internal/keymanager/keymanager.js';
import type { MnemonicLanguage } from '../../internal/keymanager/mnemonic.js';
import { assertValidMnemonic } from '../../internal/keymanager/mnemonic.js';
import type { ShamirRecoveryResult } from '../../internal/keymanager/shamir/index.js';
import type { PersonaManager } from '../../internal/persona/persona.js';
import { personaFields } from '../../internal/persona/persona-fields.js';
import { clearSeedBoundPersonaState } from '../../internal/persona/reset.js';
import { isValidPinFormat } from '../../internal/pin-policy.js';
import { KeyLock } from '../../internal/primitives/key-lock.js';
import {
  nonObjectPrototypeProperty,
  ownProperty,
} from '../../internal/prototype-safety/own-property.js';
import type { Storage } from '../../internal/storage-port.js';
import type { EudiFacade } from '../eudi/index.js';
import type { ImportMnemonicOptions } from '../options.js';
import type { ImportRecoveredWalletOptions, ImportRecoveredWalletResult } from '../recovery-api.js';
import type { WalletRecordStore } from '../wallet-record.js';

/** `seedChanges` ロックのキー（インスタンス内で単一）。 */
const SEED_CHANGE_LOCK_KEY = 'seed-change';

/** ウォレット完全復旧 API の委譲先。 */
export class RecoveryFacade {
  /** seed を差し替える公開 API（復旧・import・Shamir 復旧）を直列化する。 */
  private readonly seedChanges = new KeyLock();

  constructor(
    private readonly keymanager: KeyManager,
    private readonly walletRecordStore: WalletRecordStore,
    private readonly eudi: EudiFacade,
    private readonly personas: PersonaManager,
    private readonly storage: Pick<Storage, 'list' | 'delete'>,
  ) {}

  /**
   * `Wallet.importRecoveredWallet` の実体。1043 ガードの検査から seed 差し替え・掃除までを `seedChanges` で
   * 他の seed 差し替え経路と直列化する（分けると並行する 2 つの復旧が両方ガードを通り、2 つ目の
   * Passkey 作成・PIN 設定まで走る）。
   *
   * @throws 既存エンベロープがあるのに `overwriteExisting` が真でない場合（code `1043`）、
   *         `newPin` / `walletPassword` がポリシー不適合の場合（code `1031`）。
   */
  async importRecoveredWallet(
    mnemonic: string,
    options: ImportRecoveredWalletOptions,
  ): Promise<ImportRecoveredWalletResult> {
    return this.seedChanges.run(SEED_CHANGE_LOCK_KEY, () =>
      this.importRecoveredWalletLocked(mnemonic, options),
    );
  }

  private async importRecoveredWalletLocked(
    mnemonic: string,
    options: ImportRecoveredWalletOptions,
  ): Promise<ImportRecoveredWalletResult> {
    // 任意プロパティは自身のプロパティに限って読む。継承値を拾うと、
    // 「未指定」の正当な呼び出しが汚染値を「明示指定」として実行してしまう。
    const walletPassword = ownProperty<string>(options, 'walletPassword');
    const newPin = ownProperty<string>(options, 'newPin');
    const setPin = nonObjectPrototypeProperty<(pin: string) => Promise<void>>(options, 'setPin');
    const overwriteExisting = ownProperty<boolean>(options, 'overwriteExisting');
    const newPasskey = ownProperty<boolean>(options, 'newPasskey');
    const createPasskey = nonObjectPrototypeProperty<() => Promise<void>>(options, 'createPasskey');
    const wuaProviderEndpoint = ownProperty<string>(options, 'wuaProviderEndpoint');

    // `ownProperty<string>` は own 限定読みを保証するだけで型は検証しない（own-property.ts の
    // 「読み取った値を検証せずに as でキャストしないこと」）。非文字列を渡されたまま先へ進めると
    // `.length` が undefined になり、長さ比較が false 判定されてポリシーチェックを素通りする。
    if (!isValidPinFormat(newPin)) {
      throw new VericertsError(ErrorCodes.PIN_POLICY_VIOLATION);
    }
    // vault の暗号化鍵（K4）はウォレットパスワードから導出する。
    // PIN は検証子専用。空のパスワードでは vault を保護できない。
    if (typeof walletPassword !== 'string' || walletPassword.length === 0) {
      throw new VericertsError(ErrorCodes.PIN_POLICY_VIOLATION);
    }

    // 既存ウォレットの上書きは明示指定を要求する（`recoverFromShamirShares` と同じ規律。
    // `assertOverwriteAllowed` を共有する）。本 API は Passkey 作成と PIN 設定を vault の上書きより
    // 前に実行するため、このガードが無いと「別端末からの復旧」のつもりで同一端末で誤実行した
    // ときに、旧ウォレットのエンベロープに加えて PIN 検証子まで書き換わる。取り消せない手順
    // （Passkey 作成・PIN 設定）より前に判定する。
    await this.keymanager.assertMnemonicOverwriteAllowed(overwriteExisting);
    // ニーモニックの妥当性（1001）は副作用なしの純粋検査なので、Passkey 作成・PIN 設定より前に行う。
    // 後ろに置くと、入力ミスだけで新 Passkey が作られ既存 PIN 検証子が上書きされる。
    assertValidMnemonic(mnemonic);

    // Passkey 作成と PIN 検証子の設定は現在のウォレット状態と無関係なので、既存の masterSeed /
    // 永続鍵を書き換える前（= まだ取り消せる時点）に先に試す。ここで失敗すれば、以降の
    // importMnemonic による上書きが起きないまま復旧全体を安全に中断できる
    // （import 後に失敗すると永続化済みの状態のまま失敗扱いになり、呼び出し側が
    // 「失敗したのに部分的に書き換わっている」状態を扱うことになる）。
    await this.createPasskeyIfRequested(newPasskey, createPasskey);
    await this.setPinIfRequested(newPin, setPin);

    // 永続化・アンロックは既存 importMnemonic に委譲する（1001 は上で検査済み）。
    await this.keymanager.importMnemonic(mnemonic, undefined, undefined, {
      persistPassword: walletPassword,
    });
    await this.discardStateIfSeedReplaced();

    // 新規に作る DID は P-256 で EOA を持たない。EOA アドレスを持つのは、この端末に残っている旧レコード
    // （secp256k1 のペルソナ）だけで、新しいウォレットの復旧では空になる。
    const addresses = (await this.personas.listPersonas()).flatMap((persona) => {
      const { address } = personaFields(persona);
      return address === undefined ? [] : [address];
    });

    const wuaRenewed = await this.reissueWuaIfRequested(wuaProviderEndpoint);

    const record = await this.walletRecordStore.get();
    return { walletId: record.id, addresses, wuaRenewed };
  }

  /**
   * `Wallet.recoverFromShamirShares` の実体。復旧に成功し、かつ seed が別ウォレットへ差し替わった場合のみ、
   * 旧 seed 由来のペルソナ・ウォレット id を掃除する。同一 seed の再復旧（シェア検証など）では
   * `importMnemonic` と同じく保持する。`insufficient_shares` / `invalid_share` では何も変えない。
   */
  async recoverFromShamirShares(
    shares: readonly string[],
    options?: { readonly persistPassword?: string; readonly overwriteExisting?: boolean },
  ): Promise<ShamirRecoveryResult> {
    return this.seedChanges.run(SEED_CHANGE_LOCK_KEY, async () => {
      const result = await this.keymanager.recoverFromShamirShares(shares, options);
      if (result.status === 'success') {
        await this.discardStateIfSeedReplaced();
      }
      return result;
    });
  }

  /**
   * `Wallet.importMnemonic` の実体。keymanager への委譲後、保存済みペルソナが新 seed と食い違う
   * （= seed を別ウォレットへ差し替えた）場合に限り、旧 seed 由来の状態を掃除する。
   *
   * `masterSeed` は `importMnemonic` でしか設定されず、再起動後の再 import は同一ニーモニックで行うため、
   * 常に掃除するとその度にペルソナが消える。ゆえに各ペルソナを新 seed で `derivationPath` から導出し直し、
   * 保存済みアドレスと一致するかで判定する（パスフレーズ違いの差し替えも検出できる）。ペルソナが 1 件も
   * 無ければ食い違いを検出できないため、ウォレット id は維持される。
   *
   * @throws keymanager の `importMnemonic` の例外（`1001` / `1031` / `1042` 等）。ペルソナメタデータ
   *         破損時は旧 seed 由来とみなして掃除する（中断しない）。
   */
  async importMnemonic(
    mnemonic: string,
    passphrase?: string,
    language?: MnemonicLanguage,
    options?: ImportMnemonicOptions,
  ): Promise<void> {
    await this.seedChanges.run(SEED_CHANGE_LOCK_KEY, async () => {
      await this.keymanager.importMnemonic(mnemonic, passphrase, language, options);
      await this.discardStateIfSeedReplaced();
    });
  }

  /** 3 つの seed 差し替え経路で共通の掃除判定。同一 seed の再投入では何も消さない。 */
  private async discardStateIfSeedReplaced(): Promise<void> {
    if (await this.hasPersonaOfOtherSeed()) {
      await this.discardPreviousSeedState();
    }
  }

  /**
   * 保存済みペルソナのうち、現在の seed から導出し直したアドレスと一致しないものがあるか。
   * 導出不能・メタデータ破損（一覧取得の失敗）も不一致とみなす（fail-closed）。破損レコードが
   * あるときに 2005 で中断すると、seed だけ差し替わって旧ペルソナが残る。
   */
  private async hasPersonaOfOtherSeed(): Promise<boolean> {
    let personas: Awaited<ReturnType<PersonaManager['listPersonas']>>;
    try {
      personas = await this.personas.listPersonas();
    } catch (error) {
      if (!(error instanceof VericertsError)) {
        throw error;
      }
      return true;
    }
    for (const persona of personas) {
      try {
        if (!(await this.personas.matchesSeed(persona))) {
          return true;
        }
      } catch (error) {
        if (!(error instanceof VericertsError)) {
          throw error;
        }
        return true;
      }
    }
    return false;
  }

  /**
   * seed を差し替えた直後に、旧 seed 由来の永続状態（ペルソナ・アクティブ指定・ウォレット id）と
   * `EudiFacade` のメモリ保持 PID/EAA/WUA を消す。
   *
   * 残すと、`resolveActiveSigner` が新 seed の鍵で署名しつつ旧 seed の DID を名乗る JWT / VP / ログを
   * 作ってしまい、検証側で原因不明の署名不一致になる。`credential/` / `dashboard-log/` は
   * 旧ウォレットの VC・監査証跡として本 API では消さない（呼び出し側が必要に応じて `purge` 等で扱う）。
   */
  private async discardPreviousSeedState(): Promise<void> {
    await clearSeedBoundPersonaState(this.storage);
    await this.walletRecordStore.reset();
    this.eudi.discardHeldCredentials();
  }

  /**
   * PIN 検証子を設定する。実体は呼び出し側が注入する（SDK スコープ外）。
   *
   * 未注入なら形式検証だけで済ませる（検証子の永続化は呼び出し側の責務）。ここで設定に失敗したら
   * 復旧全体を中断する。PIN を設定できないまま復旧を完了させると、利用者はアンロック手段を
   * 持たないウォレットを掴むことになる。
   */
  private async setPinIfRequested(
    newPin: string,
    setPin: ((pin: string) => Promise<void>) | undefined,
  ): Promise<void> {
    if (setPin === undefined) {
      return;
    }
    try {
      await setPin(newPin);
    } catch {
      throw new VericertsError(ErrorCodes.PIN_POLICY_VIOLATION);
    }
  }

  /** Passkey 自動作成（既定 true）。実体は呼び出し側が注入する（SDK スコープ外）。 */
  private async createPasskeyIfRequested(
    newPasskey: boolean | undefined,
    createPasskey: (() => Promise<void>) | undefined,
  ): Promise<void> {
    if (newPasskey === false) {
      return;
    }
    if (createPasskey === undefined) {
      throw new VericertsError(ErrorCodes.PASSKEY_CREATE_FAILED);
    }
    try {
      await createPasskey();
    } catch {
      throw new VericertsError(ErrorCodes.PASSKEY_CREATE_FAILED);
    }
  }

  /**
   * WUA 再発行。`wuaProviderEndpoint` を渡した場合のみ行う。
   *
   * 発行前にアクティブペルソナを確保する。WUA 発行はアクティブペルソナの holder DID を要求する
   * （`eudi/facade.ts` の `resolveHolder`）一方、本 API はニーモニックを復元するだけでペルソナ
   * ストアには何も書かないため、新端末での復旧（= ペルソナが 1 件も無い状態）では必ず
   * `PERSONA_NOT_FOUND` で失敗する。復元した seed から既定ペルソナを導出すれば解決する。
   */
  private async reissueWuaIfRequested(wuaProviderEndpoint: string | undefined): Promise<boolean> {
    if (wuaProviderEndpoint === undefined) {
      return false;
    }
    await this.ensureActivePersona();
    try {
      await this.eudi.obtainWalletAttestation(wuaProviderEndpoint);
      return true;
    } catch (e) {
      // 原因を一律 1033 へ潰さない。ペルソナ未解決（2005）・Wallet Provider 未設定（10102）等は
      // 呼び出し側が対処できる失敗であり、潰すと「何を直せばよいか」が失われる。
      if (e instanceof VericertsError) {
        throw e;
      }
      throw new VericertsError(ErrorCodes.WUA_REISSUE_FAILED);
    }
  }

  /**
   * アクティブペルソナを確保する（無ければ復元した seed から既定ペルソナを作ってアクティブ化）。
   *
   * 既にアクティブペルソナがある場合は触らない（同一端末での復旧で、利用者が選んでいた
   * ペルソナを勝手に切り替えないため）。
   */
  private async ensureActivePersona(): Promise<void> {
    if ((await this.personas.getActivePersona()) !== null) {
      return;
    }
    const existing = await this.personas.listPersonas();
    const persona = existing[0] ?? (await this.personas.createPersona({ index: 0 }));
    await this.personas.setActivePersona(persona.id);
  }
}
