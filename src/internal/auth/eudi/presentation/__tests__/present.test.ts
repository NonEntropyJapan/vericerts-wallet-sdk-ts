/**
 * `presentPIDCredential` / `presentEAACredential` のテスト。
 *
 * 送信された `vp_token` の中身（開示された Disclosure が同意範囲ちょうどであること）と、
 * 戻り値の `VerifiablePresentation` が送信した vp_token を保持することを検証する。
 * 送信はすべて `fetchImpl` 注入で行い、グローバル `fetch` は差し替えない。
 */

import { describe, expect, test } from 'bun:test';
import {
  presentEAACredential,
  presentPIDCredential,
} from '../../../../../exports/experimental/eudi.js';
import { VC_V2_CONTEXT, VP_TYPE } from '../../../../credential/presentation/vp.js';
import { parseSdJwt } from '../../../../credential/sdjwt/sdjwt.js';
import { VericertsError } from '../../../../errors.js';
import { PID_VCT } from '../../../../eudi/pid/index.js';
import {
  buildRequestURI,
  createSubmitStub,
  EAA_VCT,
  eaaCredential,
  HOLDER_DID,
  pidCredential,
  presentDeps,
  RESPONSE_URI,
  submittedVpToken,
} from './presentation-fixtures.js';

/** vp_token に含まれる Disclosure のクレーム名（開示された属性）。 */
function disclosedClaimNames(vpToken: string): string[] {
  return parseSdJwt(vpToken)
    .disclosures.flatMap((disclosure) => disclosure.claimName ?? [])
    .sort();
}

describe('presentPIDCredential', () => {
  test('正常系: 指定した属性だけを開示して送信し、vp_token を保持した VP を返す', async () => {
    const stub = createSubmitStub();
    const vp = await presentPIDCredential(
      buildRequestURI(),
      ['family_name', 'birth_date'],
      pidCredential(),
      presentDeps(stub.fetchImpl),
    );
    expect(stub.calls).toHaveLength(1);
    expect(stub.calls[0]?.url).toBe(RESPONSE_URI);
    const vpToken = submittedVpToken(stub.calls[0]);
    // 開示は同意範囲ちょうど（given_name / issuing_country 等は含まれない）。
    expect(disclosedClaimNames(vpToken)).toEqual(['birth_date', 'family_name']);
    // Key Binding JWT が付与されている（nonce / aud は要求からバインドされる）。
    expect(parseSdJwt(vpToken).keyBinding).toBeString();
    expect(vp.verifiableCredential).toEqual([vpToken]);
    expect(vp.holder).toBe(HOLDER_DID);
    expect(vp.type).toEqual([VP_TYPE]);
    expect(vp['@context'][0]).toBe(VC_V2_CONTEXT);
  });

  test('age_over_18 のみの最小開示では birth_date を出さない', async () => {
    const stub = createSubmitStub();
    const vp = await presentPIDCredential(
      buildRequestURI(),
      ['age_over_18'],
      pidCredential(),
      presentDeps(stub.fetchImpl),
    );
    const vpToken = submittedVpToken(stub.calls[0]);
    const disclosed = disclosedClaimNames(vpToken);
    // 成人性の証明に必要な 1 件だけを開示する。
    expect(disclosed).toEqual(['age_over_18']);
    // 生年月日・氏名は Verifier へ渡さない（データ最小化。開示しなかった属性は digest のみ残る）。
    expect(disclosed).not.toContain('birth_date');
    expect(disclosed).not.toContain('family_name');
    expect(disclosed).not.toContain('given_name');
    expect(vp.verifiableCredential).toEqual([vpToken]);
  });

  test('開示属性が空でも送信でき、Disclosure は 0 件になる', async () => {
    const stub = createSubmitStub();
    await presentPIDCredential(buildRequestURI(), [], pidCredential(), presentDeps(stub.fetchImpl));
    expect(disclosedClaimNames(submittedVpToken(stub.calls[0]))).toEqual([]);
  });

  test('raw を持たない PID は 8035（送信は発生しない）', async () => {
    const stub = createSubmitStub();
    const credential = { vct: PID_VCT, claims: pidCredential().claims };
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
    expect(stub.calls).toHaveLength(0);
  });

  test('kid を持たない signer は 8035（提示者 DID を導出できない）', async () => {
    const stub = createSubmitStub();
    const deps = presentDeps(stub.fetchImpl);
    const signer = {
      alg: deps.signer.alg,
      publicKeyJwk: deps.signer.publicKeyJwk,
      sign: deps.signer.sign,
    };
    try {
      await presentPIDCredential(buildRequestURI(), ['family_name'], pidCredential(), {
        signer,
        fetchImpl: stub.fetchImpl,
      });
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('8035');
    }
    expect(stub.calls).toHaveLength(0);
  });
});

describe('presentEAACredential', () => {
  test('正常系: vct が一致する (Q)EAA の全 top-level クレームを開示する', async () => {
    const stub = createSubmitStub();
    const credentials = [eaaCredential('urn:eudi:eaa:other:1'), eaaCredential()];
    const vp = await presentEAACredential(
      buildRequestURI(),
      EAA_VCT,
      credentials,
      presentDeps(stub.fetchImpl),
    );
    const vpToken = submittedVpToken(stub.calls[0]);
    expect(disclosedClaimNames(vpToken)).toEqual(['degree', 'institution']);
    expect(vp.verifiableCredential).toEqual([vpToken]);
    expect(vp.holder).toBe(HOLDER_DID);
  });

  test('vct が一致する (Q)EAA が無ければ 8035（送信は発生しない）', async () => {
    const stub = createSubmitStub();
    try {
      await presentEAACredential(
        buildRequestURI(),
        'urn:eudi:eaa:missing:1',
        [eaaCredential()],
        presentDeps(stub.fetchImpl),
      );
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('8035');
    }
    expect(stub.calls).toHaveLength(0);
  });

  test('vct が一致する複数の (Q)EAA は vp_token 配列として送信される', async () => {
    const stub = createSubmitStub();
    const vp = await presentEAACredential(
      buildRequestURI(),
      EAA_VCT,
      [eaaCredential(), eaaCredential()],
      presentDeps(stub.fetchImpl),
    );
    const raw = submittedVpToken(stub.calls[0]);
    const tokens = JSON.parse(raw) as string[];
    expect(tokens).toHaveLength(2);
    expect(vp.verifiableCredential).toEqual(tokens);
  });
});
