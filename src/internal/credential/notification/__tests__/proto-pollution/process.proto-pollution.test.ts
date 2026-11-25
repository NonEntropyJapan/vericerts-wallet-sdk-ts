/**
 * `processCredentialNotification` の `Object.prototype` 汚染耐性テスト。
 *
 * `notification/process.ts` は `own-property.js` を import すらしておらず、`req`（Wallet からの
 * 外部 HTTP リクエストボディ）の `notification_id` / `event` / `event_description`、および
 * `deps`（`ProcessNotificationDependencies`）の `verifyAccessToken` / `resolveNotificationId` /
 * `recordAudit` をプロトタイプ鎖経由の裸プロパティアクセスで読んでいた。
 *
 * とくに深刻なのは `verifyAccessToken`: `Object.prototype` が汚染された環境では、この関数を
 * **持たない** `deps` オブジェクトが渡された場合でも、汚染された関数が「トークン検証結果」として
 * 採用され、アクセストークン未検証のまま監査記録まで到達し得る。`req.notification_id` /
 * `req.event` も同様に、これらのフィールドを持たないリクエストが汚染値で構造検証を通過する。
 *
 * 各テストは「その DI/フィールドを渡していない呼び出し」が汚染値を採用せず fail-closed に倒れる
 * こと、および「明示指定した呼び出し」の挙動が変わらないことの両方を固定する。データプロパティ
 * 汚染とアクセサ（getter）汚染の両方で検証する。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes } from '../../../../errors.js';
import { processCredentialNotification } from '../../process.js';
import type {
  CredentialNotificationRequest,
  ProcessNotificationDependencies,
} from '../../types.js';

const OK_REQ: CredentialNotificationRequest = {
  notification_id: 'notif-1',
  event: 'credential_accepted',
  event_description: 'stored',
};

function okDeps(): { deps: ProcessNotificationDependencies; audit: unknown[] } {
  const audit: unknown[] = [];
  return {
    audit,
    deps: {
      verifyAccessToken: () => true,
      resolveNotificationId: () => true,
      recordAudit: (entry) => {
        audit.push(entry);
      },
    },
  };
}

describe('processCredentialNotification: verifyAccessToken の Object.prototype 汚染耐性', () => {
  it('verifyAccessToken を持たない deps は汚染関数へ委譲せず 3041 で fail-closed になる（データ汚染）', async () => {
    let attackerCalled = false;
    const deps = {
      resolveNotificationId: () => true,
      recordAudit: () => {},
    } as unknown as ProcessNotificationDependencies;
    await withPollutedPrototypeAsync(
      {
        verifyAccessToken: () => {
          attackerCalled = true;
          return true;
        },
      },
      async () => {
        await expect(processCredentialNotification(OK_REQ, 'token', deps)).rejects.toMatchObject({
          code: ErrorCodes.NOTIFICATION_ACCESS_TOKEN_INVALID,
        });
      },
    );
    expect(attackerCalled).toBe(false);
  });

  it('verifyAccessToken を持たない deps は汚染関数へ委譲しない（アクセサ汚染）', async () => {
    let attackerCalled = false;
    const deps = {
      resolveNotificationId: () => true,
      recordAudit: () => {},
    } as unknown as ProcessNotificationDependencies;
    await withPollutedPrototypeAccessorAsync(
      {
        verifyAccessToken: () => () => {
          attackerCalled = true;
          return true;
        },
      },
      async () => {
        await expect(processCredentialNotification(OK_REQ, 'token', deps)).rejects.toMatchObject({
          code: ErrorCodes.NOTIFICATION_ACCESS_TOKEN_INVALID,
        });
      },
    );
    expect(attackerCalled).toBe(false);
  });

  it('明示指定した verifyAccessToken は汚染下でも指定どおり使われる（非退行）', async () => {
    const { deps, audit } = okDeps();
    await withPollutedPrototypeAsync({ verifyAccessToken: () => false }, async () => {
      await processCredentialNotification(OK_REQ, 'token', deps);
    });
    expect(audit).toHaveLength(1);
  });
});

describe('processCredentialNotification: resolveNotificationId の Object.prototype 汚染耐性', () => {
  it('resolveNotificationId を持たない deps は汚染関数へ委譲せず 3042 で fail-closed になる（データ汚染）', async () => {
    let attackerCalled = false;
    const deps = {
      verifyAccessToken: () => true,
      recordAudit: () => {},
    } as unknown as ProcessNotificationDependencies;
    await withPollutedPrototypeAsync(
      {
        resolveNotificationId: () => {
          attackerCalled = true;
          return true;
        },
      },
      async () => {
        await expect(processCredentialNotification(OK_REQ, 'token', deps)).rejects.toMatchObject({
          code: ErrorCodes.NOTIFICATION_ID_UNKNOWN,
        });
      },
    );
    expect(attackerCalled).toBe(false);
  });
});

describe('processCredentialNotification: recordAudit の Object.prototype 汚染耐性', () => {
  it('recordAudit を持たない deps は汚染関数へ委譲しない（データ汚染）', async () => {
    let attackerCalled = false;
    const deps = {
      verifyAccessToken: () => true,
      resolveNotificationId: () => true,
    } as unknown as ProcessNotificationDependencies;
    await withPollutedPrototypeAsync(
      {
        recordAudit: () => {
          attackerCalled = true;
        },
      },
      async () => {
        await processCredentialNotification(OK_REQ, 'token', deps);
      },
    );
    expect(attackerCalled).toBe(false);
  });
});

describe('processCredentialNotification: req.notification_id の Object.prototype 汚染耐性', () => {
  it('notification_id を持たないリクエストは汚染値を採用せず 3042 で fail-closed になる（データ汚染）', async () => {
    const { deps, audit } = okDeps();
    const req = { event: 'credential_accepted' } as unknown as CredentialNotificationRequest;
    await withPollutedPrototypeAsync({ notification_id: 'attacker-id' }, async () => {
      await expect(processCredentialNotification(req, 'token', deps)).rejects.toMatchObject({
        code: ErrorCodes.NOTIFICATION_ID_UNKNOWN,
      });
    });
    expect(audit).toHaveLength(0);
  });

  it('notification_id を持たないリクエストは汚染値を採用しない（アクセサ汚染）', async () => {
    const { deps, audit } = okDeps();
    const req = { event: 'credential_accepted' } as unknown as CredentialNotificationRequest;
    await withPollutedPrototypeAccessorAsync({ notification_id: () => 'attacker-id' }, async () => {
      await expect(processCredentialNotification(req, 'token', deps)).rejects.toMatchObject({
        code: ErrorCodes.NOTIFICATION_ID_UNKNOWN,
      });
    });
    expect(audit).toHaveLength(0);
  });

  it('明示指定した notification_id は汚染下でも指定どおり監査記録される（非退行）', async () => {
    const { deps, audit } = okDeps();
    await withPollutedPrototypeAsync({ notification_id: 'attacker-id' }, async () => {
      await processCredentialNotification(OK_REQ, 'token', deps);
    });
    expect(audit).toEqual([
      { notification_id: 'notif-1', event: 'credential_accepted', event_description: 'stored' },
    ]);
  });
});

describe('processCredentialNotification: req.event の Object.prototype 汚染耐性', () => {
  it('event を持たないリクエストは汚染値を採用せず 3042 で fail-closed になる（データ汚染）', async () => {
    const { deps, audit } = okDeps();
    const req = { notification_id: 'notif-1' } as unknown as CredentialNotificationRequest;
    await withPollutedPrototypeAsync({ event: 'credential_accepted' }, async () => {
      await expect(processCredentialNotification(req, 'token', deps)).rejects.toMatchObject({
        code: ErrorCodes.NOTIFICATION_ID_UNKNOWN,
      });
    });
    expect(audit).toHaveLength(0);
  });
});

describe('processCredentialNotification: req.event_description の Object.prototype 汚染耐性', () => {
  it('event_description を持たないリクエストは汚染値を監査ログへ記録しない（データ汚染）', async () => {
    const { deps, audit } = okDeps();
    const req = {
      notification_id: 'notif-1',
      event: 'credential_accepted',
    } as unknown as CredentialNotificationRequest;
    await withPollutedPrototypeAsync({ event_description: 'attacker-description' }, async () => {
      await processCredentialNotification(req, 'token', deps);
    });
    expect(audit).toEqual([{ notification_id: 'notif-1', event: 'credential_accepted' }]);
  });
});
