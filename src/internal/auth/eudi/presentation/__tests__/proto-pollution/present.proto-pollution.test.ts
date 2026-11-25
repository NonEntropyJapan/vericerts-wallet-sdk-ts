/**
 * eudi/presentation の `Object.prototype` 汚染耐性テスト。
 *
 * 検証するのは「その任意プロパティを**省略した**正当な呼び出し」が継承値を拾わないこと。
 * - `Object.prototype.fetchImpl`: 汚染下でも攻撃者の fetch へ vp_token を渡さない。
 * - `Object.prototype.credential`: 汚染しても、明示的に渡した Credential 以外は提示されない。
 * - `Object.prototype.raw`: 汚染下でも `raw` を持たない Credential が提示されない（8035 で止まる）。
 * - `Object.prototype.vct`: 汚染下でも `vct` を持たない (Q)EAA が「一致」と判定されない。
 */

import { describe, expect, test } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../../__tests__/prototype-pollution.fixtures.js';
import { parseSdJwt } from '../../../../../credential/sdjwt/sdjwt.js';
import { VericertsError } from '../../../../../errors.js';
import { PID_VCT } from '../../../../../eudi/pid/index.js';
import { presentEAACredential, presentPIDCredential } from '../../present.js';
import {
  buildRequestURI,
  buildSdJwtVc,
  createSubmitStub,
  EAA_VCT,
  eaaCredential,
  holderSigner,
  pidCredential,
  presentDeps,
  submittedVpToken,
} from '../presentation-fixtures.js';

describe('presentPIDCredential / Object.prototype 汚染', () => {
  test('汚染された fetchImpl は採用しない（vp_token が攻撃者へ渡らない）', async () => {
    let attackerCalled = false;
    const attackerFetch = () => {
      attackerCalled = true;
      return Promise.resolve(new Response('', { status: 200 }));
    };
    const stub = createSubmitStub();
    await withPollutedPrototypeAsync({ fetchImpl: attackerFetch }, async () =>
      presentPIDCredential(buildRequestURI(), ['family_name'], pidCredential(), {
        signer: holderSigner(),
        fetchImpl: stub.fetchImpl,
      }),
    );
    expect(attackerCalled).toBe(false);
    expect(stub.calls).toHaveLength(1);
  });

  test('汚染された credential は提示対象を差し替えない', async () => {
    const stub = createSubmitStub();
    const attackerCredential = {
      vct: PID_VCT,
      claims: {},
      raw: buildSdJwtVc(PID_VCT, { family_name: 'Attacker' }),
    };
    const vp = await withPollutedPrototypeAsync({ credential: attackerCredential }, async () =>
      presentPIDCredential(
        buildRequestURI(),
        ['family_name'],
        pidCredential(),
        presentDeps(stub.fetchImpl),
      ),
    );
    const vpToken = submittedVpToken(stub.calls[0]);
    const disclosed = parseSdJwt(vpToken).disclosures;
    expect(disclosed).toHaveLength(1);
    expect(disclosed[0]?.value).toBe('Bianchi');
    expect(vp.verifiableCredential).toEqual([vpToken]);
  });

  test('汚染された raw は提示に使われない（8035 で止まる）', async () => {
    const stub = createSubmitStub();
    const attackerRaw = buildSdJwtVc(PID_VCT, { family_name: 'Attacker' });
    const credential = { vct: PID_VCT, claims: pidCredential().claims };
    await withPollutedPrototypeAsync({ raw: attackerRaw }, async () => {
      try {
        await presentPIDCredential(
          buildRequestURI(),
          ['family_name'],
          credential,
          presentDeps(stub.fetchImpl),
        );
        throw new Error('should throw');
      } catch (e) {
        expect(e).toBeInstanceOf(VericertsError);
        expect((e as VericertsError).code).toBe('8035');
      }
    });
    expect(stub.calls).toHaveLength(0);
  });
});

describe('presentEAACredential / Object.prototype 汚染', () => {
  test('汚染された vct は一致判定に使われない（8035 で止まる）', async () => {
    const stub = createSubmitStub();
    const withoutVct = { claims: { degree: 'X' }, raw: eaaCredential().raw } as never;
    await withPollutedPrototypeAsync({ vct: EAA_VCT }, async () => {
      try {
        await presentEAACredential(
          buildRequestURI(),
          EAA_VCT,
          [withoutVct],
          presentDeps(stub.fetchImpl),
        );
        throw new Error('should throw');
      } catch (e) {
        expect(e).toBeInstanceOf(VericertsError);
        expect((e as VericertsError).code).toBe('8035');
      }
    });
    expect(stub.calls).toHaveLength(0);
  });
});
