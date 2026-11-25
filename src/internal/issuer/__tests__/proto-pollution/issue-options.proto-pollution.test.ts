/**
 * VC 発行オプションの `Object.prototype` 汚染耐性テスト。
 *
 * `opts.credentialStatus` / `opts.statusListType` / `opts.format` をプロトタイプ鎖で読むと、
 * これらを**指定していない**正当な発行でも実効の失効管理方式が汚染値へ差し替わる。
 * `token-status-list` 以外に化けると `issueVC` の status 確保が飛ぶため、発行 VC から
 * `credentialStatus` が落ちて**失効不能な VC** が署名される。
 */

import { beforeEach, describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAsync,
} from '../../../__tests__/prototype-pollution.fixtures.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { resolveStatusListType } from '../../module/issue-options.js';
import { IssuerModule } from '../../module/issuer-module.js';
import { createStatusList, type StatusListManager } from '../../token-status-list.js';

const ISSUER = 'did:key:z6MkIssuerProtoPollution';
const HOLDER = 'did:key:z6MkHolderProtoPollution';
const REVOCATION_URI = 'https://issuer.example/status/revocation';
const SIGNER_KEY = new Uint8Array(32).fill(59);
const NOW = new Date('2026-08-28T00:00:00.000Z');

describe('発行オプションの Object.prototype 汚染耐性', () => {
  let revocation: StatusListManager;
  let issuer: IssuerModule;

  beforeEach(() => {
    revocation = createStatusList({
      uri: REVOCATION_URI,
      issuer: ISSUER,
      size: 64,
      purpose: 'revocation',
    });
    issuer = new IssuerModule({
      issuer: ISSUER,
      signer: createPrivateKeySigner(SIGNER_KEY, 'ES256'),
      statusLists: { revocation },
      now: () => NOW,
    });
  });

  it('継承した credentialStatus: false は失効管理の省略として扱わない', async () => {
    const vc = await withPollutedPrototypeAsync({ credentialStatus: false }, () =>
      issuer.issueVC(HOLDER, { degree: 'BSc' }),
    );
    // 汚染値を拾うと status が付かず、失効不能な VC になる。
    expect(vc.status).toEqual({ status_list: { idx: 0, uri: REVOCATION_URI } });
  });

  it('継承した statusListType は実効の失効管理方式にならない', () => {
    const resolved = withPollutedPrototype({ statusListType: 'bitstring-v1' }, () =>
      resolveStatusListType({}),
    );
    // 既定形式の 'jwt' では 'token-status-list' を使用する。
    expect(resolved).toBe('token-status-list');
  });

  it('継承した format は既定の失効管理方式を変えない', () => {
    const resolved = withPollutedPrototype({ format: 'data-integrity' }, () =>
      resolveStatusListType({}),
    );
    expect(resolved).toBe('token-status-list');
  });

  it('継承した statusListType 経由で失効不能な VC を発行させられない', async () => {
    const vc = await withPollutedPrototypeAsync({ statusListType: 'bitstring-v1' }, () =>
      issuer.issueVC(HOLDER, { degree: 'BSc' }),
    );
    expect(vc.status).toEqual({ status_list: { idx: 0, uri: REVOCATION_URI } });
  });

  it('継承した id / issuanceDate は署名対象の VC に載らない', async () => {
    const vc = await withPollutedPrototypeAsync(
      { id: 'urn:uuid:attacker', issuanceDate: '1999-01-01T00:00:00Z' },
      () => issuer.issueVC(HOLDER, { degree: 'BSc' }),
    );
    // `id` が汚染値に固定されると、Status List のインデックス対応が壊れて失効操作が効かなくなる。
    expect(vc.id).not.toBe('urn:uuid:attacker');
    expect(vc.issuanceDate).toBe(NOW.toISOString());
  });

  it('継承した now は署名済み VC の issuanceDate を攻撃者の時刻にしない', async () => {
    const attacker = new Date('1999-01-01T00:00:00.000Z');
    // `now` を渡さずに構築する。汚染値を拾うと発行 VC の `issuanceDate`（= JWT-VC の `nbf`）が
    // 攻撃者の時刻になる。
    const vc = await withPollutedPrototypeAsync({ now: () => attacker }, async () => {
      const polluted = new IssuerModule({
        issuer: ISSUER,
        signer: createPrivateKeySigner(SIGNER_KEY, 'ES256'),
        statusLists: { revocation },
      });
      return polluted.issueVC(HOLDER, { degree: 'BSc' });
    });
    expect(vc.issuanceDate).not.toBe(attacker.toISOString());
  });

  it('明示的に渡したオプションは従来どおり尊重される（正常系）', async () => {
    expect(resolveStatusListType({ statusListType: 'bitstring-v1' })).toBe('bitstring-v1');
    expect(resolveStatusListType({ format: 'data-integrity' })).toBe('bitstring-v1');
    const vc = await issuer.issueVC(HOLDER, { degree: 'BSc' }, { credentialStatus: false });
    expect(vc.status).toBeUndefined();
  });
});
