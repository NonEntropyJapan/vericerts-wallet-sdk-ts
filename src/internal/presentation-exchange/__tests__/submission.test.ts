/**
 * Presentation Submission の構築・検証のユニットテスト。
 *
 * 検証内容:
 * - buildPresentationSubmission: descriptor_map の組み立て / generateId 注入 / 件数不一致で 8035。
 * - validatePresentationSubmission: 正常系 / definition_id 不一致 / 記述子欠落 / 余剰 / id 重複。
 */

import { describe, expect, it } from 'bun:test';
import type { QueryableCredential } from '../../auth/dcql/dcql.js';
import { ErrorCodes, type VericertsError } from '../../errors.js';
import { parsePresentationDefinition } from '../definition.js';
import {
  buildPresentationSubmission,
  type PresentationSubmission,
  validatePresentationSubmission,
} from '../submission.js';

const pd = parsePresentationDefinition({
  id: 'pd-1',
  input_descriptors: [
    { id: 'name', constraints: { fields: [{ path: ['$.credentialSubject.name'] }] } },
    { id: 'age', constraints: { fields: [{ path: ['$.credentialSubject.age'] }] } },
  ],
});

const selected: QueryableCredential[] = [
  { id: 'vc-1', format: 'dc+sd-jwt', claims: { credentialSubject: { name: 'Alice' } } },
  { id: 'vc-2', format: 'jwt_vc_json', claims: { credentialSubject: { age: 20 } } },
];

describe('buildPresentationSubmission', () => {
  it('input_descriptors と同順に descriptor_map を組み立てる', () => {
    const submission = buildPresentationSubmission(pd, selected, { generateId: () => 'sub-1' });
    expect(submission).toEqual({
      id: 'sub-1',
      definition_id: 'pd-1',
      descriptor_map: [
        { id: 'name', format: 'dc+sd-jwt', path: '$.verifiableCredential[0]' },
        { id: 'age', format: 'jwt_vc_json', path: '$.verifiableCredential[1]' },
      ],
    });
  });

  it('generateId 未指定なら crypto.randomUUID で採番する', () => {
    const submission = buildPresentationSubmission(pd, selected);
    expect(submission.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });

  it('選択 VC が少ないと 8035', () => {
    try {
      buildPresentationSubmission(pd, [selected[0] as QueryableCredential]);
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.PRESENTATION_SUBMIT_FAILED);
    }
  });

  it('選択 VC が多いと 8035', () => {
    try {
      buildPresentationSubmission(pd, [...selected, ...selected]);
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.PRESENTATION_SUBMIT_FAILED);
    }
  });
});

describe('validatePresentationSubmission', () => {
  const valid = buildPresentationSubmission(pd, selected, { generateId: () => 'sub-1' });

  it('自身が組み立てた Submission は true', () => {
    expect(validatePresentationSubmission(valid, pd)).toBe(true);
  });

  it('definition_id が一致しないと false', () => {
    const submission: PresentationSubmission = { ...valid, definition_id: 'other' };
    expect(validatePresentationSubmission(submission, pd)).toBe(false);
  });

  it('descriptor_map が記述子を欠くと false', () => {
    const submission: PresentationSubmission = {
      ...valid,
      descriptor_map: valid.descriptor_map.slice(0, 1),
    };
    expect(validatePresentationSubmission(submission, pd)).toBe(false);
  });

  it('未知の記述子 id を含むと false', () => {
    const submission: PresentationSubmission = {
      ...valid,
      descriptor_map: [
        ...valid.descriptor_map,
        { id: 'unknown', format: 'dc+sd-jwt', path: '$.verifiableCredential[2]' },
      ],
    };
    expect(validatePresentationSubmission(submission, pd)).toBe(false);
  });

  it('descriptor_map 内で id が重複すると false', () => {
    const first = valid.descriptor_map[0];
    if (first === undefined) {
      throw new Error('fixture must have at least one descriptor');
    }
    const submission: PresentationSubmission = { ...valid, descriptor_map: [first, first] };
    expect(validatePresentationSubmission(submission, pd)).toBe(false);
  });
});
