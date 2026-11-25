/**
 * did:ion の DID 形式と long-form のローカル検証。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { expectThrows } from '../../__tests__/network-method.fixtures.js';
import {
  createResolutionWorkBudget,
  DEFAULT_MAX_SCOPE_WORK_UNITS,
} from '../../resolution-budget.js';
import { parseDidIon, verifyIonLongForm, WORK_UNITS_PER_ION_LONG_FORM } from '../did-ion.js';
import { makeIonCreate, multihash, withInitialState } from './ion.fixtures.js';

describe('parseDidIon', () => {
  const create = makeIonCreate();

  it('short-form と long-form を受理する', () => {
    expect(parseDidIon(create.shortForm)).toEqual({ suffix: create.suffix });
    const parsed = parseDidIon(create.longForm);
    expect(parsed.suffix).toBe(create.suffix);
    expect(create.longForm.endsWith(`:${parsed.longForm}`)).toBe(true);
  });

  it('did-suffix は Ei で始まる multihash（独立実装の値と一致する）', () => {
    expect(create.suffix.startsWith('Ei')).toBe(true);
    expect(create.suffix).toHaveLength(46);
  });

  it('追加セグメント（ネットワーク名など）は 2001 ion_unsupported_form', () => {
    expectThrows(
      () => parseDidIon(`did:ion:test:${create.suffix}:abc`),
      ErrorCodes.INVALID_DID,
      'ion_unsupported_form',
    );
    expectThrows(
      () => parseDidIon(`${create.longForm}:extra`),
      ErrorCodes.INVALID_DID,
      'ion_unsupported_form',
    );
  });

  it('suffix の形式不正（接頭辞・長さ・multihash コード・文字種・パディング）は 2001 ion_invalid_suffix', () => {
    const wrongCode = Buffer.concat([Buffer.from([0x13, 0x20]), Buffer.alloc(32)]).toString(
      'base64url',
    );
    for (const bad of [
      'did:web:example.com',
      'did:ion:',
      'did:ion:abc',
      `did:ion:${create.suffix}=`,
      `did:ion:${create.suffix.slice(1)}`,
      `did:ion:${wrongCode}`,
      `did:ion:test:${create.suffix}`,
      `did:ion:${'E'.repeat(3000)}`,
    ]) {
      expectThrows(
        () => parseDidIon(bad),
        ErrorCodes.INVALID_DID,
        bad.length > 2048 ? 'ion_invalid_suffix' : undefined,
      );
    }
    expectThrows(
      () => parseDidIon(`did:ion:test:${create.suffix}`),
      ErrorCodes.INVALID_DID,
      'ion_invalid_suffix',
    );
  });

  it('long-form セグメントが空 / base64url 文字以外は 2001 ion_invalid_long_form', () => {
    expectThrows(
      () => parseDidIon(`${create.shortForm}:`),
      ErrorCodes.INVALID_DID,
      'ion_invalid_long_form',
    );
    expectThrows(
      () => parseDidIon(`${create.shortForm}:a+b/c=`),
      ErrorCodes.INVALID_DID,
      'ion_invalid_long_form',
    );
  });
});

describe('verifyIonLongForm', () => {
  const create = makeIonCreate();

  it('short-form は何もせず、予算も使わない', () => {
    const scope = createResolutionWorkBudget();
    verifyIonLongForm(parseDidIon(create.shortForm), scope);
    expect(scope.remaining).toBe(DEFAULT_MAX_SCOPE_WORK_UNITS);
  });

  it('整合した long-form を受理し、ハッシュ 2 回ぶんを scope に計上する', () => {
    const scope = createResolutionWorkBudget();
    verifyIonLongForm(parseDidIon(create.longForm), scope);
    expect(scope.remaining).toBe(DEFAULT_MAX_SCOPE_WORK_UNITS - WORK_UNITS_PER_ION_LONG_FORM);
    // scope なし（スコープ外の単独解決）でも検証する。
    verifyIonLongForm(parseDidIon(create.longForm));
  });

  it('予算が足りなければ 2001 resolution_work_limit（消費しない）', () => {
    const scope = createResolutionWorkBudget(WORK_UNITS_PER_ION_LONG_FORM - 1);
    expectThrows(
      () => verifyIonLongForm(parseDidIon(create.longForm), scope),
      ErrorCodes.INVALID_DID,
      'resolution_work_limit',
    );
    expect(scope.remaining).toBe(WORK_UNITS_PER_ION_LONG_FORM - 1);
  });

  it('suffixData が did-suffix と一致しなければ 2010 ion_long_form_mismatch', () => {
    const other = makeIonCreate(2);
    // suffix は create のまま、初期状態だけ other のものを差し込む。
    const did = withInitialState(create, { suffixData: other.suffixData, delta: other.delta });
    expectThrows(
      () => verifyIonLongForm(parseDidIon(did)),
      ErrorCodes.DID_DOC_INVALID,
      'ion_long_form_mismatch',
    );
  });

  it('delta が deltaHash と一致しなければ 2010 ion_long_form_mismatch（suffixData は正しい）', () => {
    const tampered = { ...create.delta, updateCommitment: multihash('attacker') };
    const did = withInitialState(create, { suffixData: create.suffixData, delta: tampered });
    expectThrows(
      () => verifyIonLongForm(parseDidIon(did)),
      ErrorCodes.DID_DOC_INVALID,
      'ion_long_form_mismatch',
    );
  });

  it('初期状態が JSON / 形式として読めなければ 2001 ion_invalid_long_form', () => {
    const notJson = `did:ion:${create.suffix}:${Buffer.from('not json').toString('base64url')}`;
    const invalidUtf8 = `did:ion:${create.suffix}:${Buffer.from([0xff, 0xfe]).toString('base64url')}`;
    const cases = [
      notJson,
      invalidUtf8,
      withInitialState(create, []),
      withInitialState(create, { suffixData: create.suffixData }),
      withInitialState(create, { delta: create.delta }),
      withInitialState(create, { suffixData: { recoveryCommitment: 'x' }, delta: create.delta }),
      withInitialState(create, { suffixData: [], delta: create.delta }),
    ];
    for (const did of cases) {
      expectThrows(
        () => verifyIonLongForm(parseDidIon(did)),
        ErrorCodes.INVALID_DID,
        'ion_invalid_long_form',
      );
    }
  });
});
