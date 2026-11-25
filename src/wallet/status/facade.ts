/**
 * `createStatusListResolver` に Wallet の監査記録先を渡す。
 * `onPolicyEvent` を省略すると、Fail-open 判定をアクティブペルソナ鍵で署名し Dashboard ログに追記する。
 */

import type { StatusListResolver } from '../../internal/credential/index.js';
import { createDashboardLogAuditRecorder } from '../../internal/failsafe/dashboard-audit.js';
import type { DashboardLog } from '../../internal/gdpr/index.js';
import { createStatusListResolver } from '../../internal/issuer/index.js';
import type { KeyManager } from '../../internal/keymanager/keymanager.js';
import type { PersonaManager } from '../../internal/persona/persona.js';
import { nonObjectPrototypeProperty } from '../../internal/prototype-safety/own-property.js';
import { type ActiveSignerOptions, resolveActiveSigner } from '../setup.js';
import type { CreateStatusListResolverOptions } from './api.js';

/** Status List Resolver 生成 API（`StatusApi`）の委譲先。依存を束ねて `WalletImpl` から薄く呼び出せるようにする。 */
export class StatusFacade {
  constructor(
    private readonly dashboardLog: Pick<DashboardLog, 'append'>,
    private readonly personas: PersonaManager,
    private readonly keymanager: KeyManager,
    /** 取り込んだ DID のペルソナで署名するための Resolver・外部秘密鍵の提供元（`factory.ts` が組み立てる）。 */
    private readonly signing?: ActiveSignerOptions,
  ) {}

  /**
   * `StatusListResolver` を生成する。`onPolicyEvent` 省略時は本 Wallet の Dashboard ログへ
   * アクティブペルソナ鍵で署名付き追記する記録先（`createDashboardLogAuditRecorder`）を既定値にする。
   */
  async createStatusListResolver(
    opts: CreateStatusListResolverOptions,
  ): Promise<StatusListResolver> {
    // 継承値（Object.prototype 汚染）の関数を監査記録先に採用しない。
    const onPolicyEvent =
      nonObjectPrototypeProperty<CreateStatusListResolverOptions['onPolicyEvent']>(
        opts,
        'onPolicyEvent',
      ) ?? (await this.defaultOnPolicyEvent());
    return createStatusListResolver({ ...opts, onPolicyEvent });
  }

  /** アクティブペルソナの署名鍵で Dashboard ログへ結線した既定の監査記録先を組み立てる。 */
  private async defaultOnPolicyEvent(): Promise<
    NonNullable<CreateStatusListResolverOptions['onPolicyEvent']>
  > {
    const { signer } = await resolveActiveSigner(this.personas, this.keymanager, this.signing);
    return createDashboardLogAuditRecorder(this.dashboardLog, signer);
  }
}
