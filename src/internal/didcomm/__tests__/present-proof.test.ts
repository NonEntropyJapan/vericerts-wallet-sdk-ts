/**
 * `didcomm/present-proof.ts`（present-proof/3.0 プロトコルメッセージ構築・抽出）のテスト
 */

import { describe, expect, it } from 'bun:test';
import { VericertsError } from '../../errors.js';
import {
  buildPresentationMessage,
  buildPresentationRequestMessage,
  extractPresentationJwt,
  PRESENT_PROOF_PRESENTATION_TYPE,
  PRESENT_PROOF_REQUEST_TYPE,
} from '../present-proof.js';

describe('present-proof メッセージのスレッド構築', () => {
  it('request-presentation → presentation が thid で一貫したスレッドになる', () => {
    const request = buildPresentationRequestMessage({
      fromDid: 'did:peer:2.verifier',
      toDid: 'did:peer:2.holder',
      presentationDefinition: { id: 'pd-1', input_descriptors: [] },
      comment: '学位証明の提示をお願いします',
    });
    expect(request.type).toBe(PRESENT_PROOF_REQUEST_TYPE);
    expect(request.thid).toBeUndefined();
    expect(request.body.presentation_definition).toEqual({ id: 'pd-1', input_descriptors: [] });

    const presentation = buildPresentationMessage({
      fromDid: 'did:peer:2.holder',
      toDid: 'did:peer:2.verifier',
      requestId: request.id,
      presentationJwt: 'header.payload.signature',
    });
    expect(presentation.type).toBe(PRESENT_PROOF_PRESENTATION_TYPE);
    expect(presentation.thid).toBe(request.id);
  });
});

describe('extractPresentationJwt', () => {
  it('presentation メッセージの添付から JWT-VP を復元する', () => {
    const presentation = buildPresentationMessage({
      fromDid: 'did:peer:2.holder',
      toDid: 'did:peer:2.verifier',
      requestId: 'req-1',
      presentationJwt: 'header.payload.signature',
    });
    expect(extractPresentationJwt(presentation)).toBe('header.payload.signature');
  });

  it('type が presentation でないメッセージは DIDCOMM_UNPACKING_FAILED', () => {
    const request = buildPresentationRequestMessage({
      fromDid: 'did:peer:2.verifier',
      toDid: 'did:peer:2.holder',
      presentationDefinition: {},
    });
    expect(() => extractPresentationJwt(request)).toThrow(VericertsError);
    try {
      extractPresentationJwt(request);
      expect.unreachable();
    } catch (error) {
      expect((error as VericertsError).code).toBe('9004');
    }
  });

  it('添付が無い presentation メッセージは DIDCOMM_UNPACKING_FAILED', () => {
    const malformed = {
      id: 'x',
      type: PRESENT_PROOF_PRESENTATION_TYPE,
      thid: 'req-1',
      body: {},
    };
    expect(() => extractPresentationJwt(malformed)).toThrow(VericertsError);
  });
});
