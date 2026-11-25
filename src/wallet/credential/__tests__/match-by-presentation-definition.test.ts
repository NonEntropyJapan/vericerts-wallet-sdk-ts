/**
 * matchCredentialsByPresentationDefinitionWith の単体テスト。
 *
 * `Wallet.matchCredentialsByPresentationDefinition` の実処理本体（純粋関数、
 * `CredentialStore.listActiveCredentials()` が集めた保持 VC を受け取る）。DIF Presentation
 * Exchange v2 の代表的パターンを VerifiableCredential[] 起点でカバーする（`evaluate.test.ts` は
 * `QueryableCredential` 起点の評価ロジック自体を検証しており、本ファイルはその上の
 * VerifiableCredential ⇄ VC 選定の配線を検証する）。
 *
 * 検証内容:
 * - constraints.fields を満たす VC だけを返す（不一致 VC は候補に含めない）。
 * - filter（type / const）を満たさない VC は候補にならない。
 * - format 要件が jwt_vc_json 以外だと候補が空になる（`toQueryableFromVc` は常に jwt_vc_json）。
 * - 複数の Input Descriptor に同一 VC がマッチしても重複排除して 1 回だけ返す。
 * - マッチする VC が無ければ空配列を返す。
 * - id を持たない VC でも constraints を満たせば候補になる（選定は index ベースであり、
 *   id 経由の逆引きに依存しない）。
 * - 同一 id を持つ複数 VC のうち一部だけが constraints を満たす場合、満たした VC だけを返す
 *   （id 経由の逆引きだと id の一致だけで両方拾ってしまい偽陽性になる）。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../../internal/credential/index.js';
import { parsePresentationDefinition } from '../../../internal/presentation-exchange/index.js';
import { matchCredentialsByPresentationDefinitionWith } from '../match-by-presentation-definition.js';

const VC_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

/** テスト用の VC を作る（`credentialSubject` にクレームを持たせる）。 */
function makeVc(id: string | undefined, subject: Record<string, unknown>): VerifiableCredential {
  return {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', ...subject },
    issuanceDate: '2026-01-01T00:00:00Z',
    ...(id !== undefined ? { id } : {}),
  };
}

/** 単一 Input Descriptor の PresentationDefinition を組み立てる。 */
function definitionWith(descriptor: Record<string, unknown>) {
  return parsePresentationDefinition({ id: 'pd-1', input_descriptors: [descriptor] });
}

describe('matchCredentialsByPresentationDefinitionWith', () => {
  it('constraints.fields を満たす VC だけを返す', () => {
    const alice = makeVc('vc-alice', { name: 'Alice', age: 20 });
    const bob = makeVc('vc-bob', { name: 'Bob' });
    const pd = definitionWith({
      id: 'd1',
      constraints: { fields: [{ path: ['$.credentialSubject.age'] }] },
    });

    expect(matchCredentialsByPresentationDefinitionWith(pd, [alice, bob])).toEqual([alice]);
  });

  it('filter（type / const）を満たさない VC は候補にならない', () => {
    const adult = makeVc('vc-adult', { age: 20 });
    const minor = makeVc('vc-minor', { age: 17 });
    const pd = definitionWith({
      id: 'd1',
      constraints: {
        fields: [{ path: ['$.credentialSubject.age'], filter: { type: 'number', const: 20 } }],
      },
    });

    expect(matchCredentialsByPresentationDefinitionWith(pd, [adult, minor])).toEqual([adult]);
  });

  it('format 要件が jwt_vc_json 以外だと候補が空になる', () => {
    const alice = makeVc('vc-alice', { name: 'Alice' });
    const pd = definitionWith({
      id: 'd1',
      format: { 'dc+sd-jwt': { alg: ['ES256'] } },
      constraints: { fields: [{ path: ['$.credentialSubject.name'] }] },
    });

    expect(matchCredentialsByPresentationDefinitionWith(pd, [alice])).toEqual([]);
  });

  it('複数 Input Descriptor に同一 VC がマッチしても重複排除して 1 回だけ返す', () => {
    const alice = makeVc('vc-alice', { name: 'Alice', age: 20 });
    const pd = parsePresentationDefinition({
      id: 'pd-1',
      input_descriptors: [
        { id: 'd1', constraints: { fields: [{ path: ['$.credentialSubject.name'] }] } },
        { id: 'd2', constraints: { fields: [{ path: ['$.credentialSubject.age'] }] } },
      ],
    });

    expect(matchCredentialsByPresentationDefinitionWith(pd, [alice])).toEqual([alice]);
  });

  it('マッチする VC が無ければ空配列を返す', () => {
    const pd = definitionWith({
      id: 'd1',
      constraints: { fields: [{ path: ['$.credentialSubject.name'] }] },
    });

    expect(matchCredentialsByPresentationDefinitionWith(pd, [])).toEqual([]);
  });

  it('id を持たない VC でも constraints を満たせば候補になる', () => {
    const noId = makeVc(undefined, { name: 'Alice' });
    const pd = definitionWith({
      id: 'd1',
      constraints: { fields: [{ path: ['$.credentialSubject.name'] }] },
    });

    expect(matchCredentialsByPresentationDefinitionWith(pd, [noId])).toEqual([noId]);
  });

  it('同一 id を持つ複数 VC のうち constraints を満たす VC だけを返す（id 逆引きによる偽陽性を避ける）', () => {
    const matching = makeVc('vc-dup', { age: 20 });
    const nonMatching = makeVc('vc-dup', { age: 17 });
    const pd = definitionWith({
      id: 'd1',
      constraints: {
        fields: [{ path: ['$.credentialSubject.age'], filter: { type: 'number', const: 20 } }],
      },
    });

    expect(matchCredentialsByPresentationDefinitionWith(pd, [matching, nonMatching])).toEqual([
      matching,
    ]);
  });
});
