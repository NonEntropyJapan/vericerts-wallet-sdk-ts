/**
 * `buildDerivedCredential` の `parent.id` own 限定読み取りの回帰テスト。
 *
 * `const parentId = parent.id;` はプロトタイプ鎖を辿っていた。親 VC は**呼び出し側が渡す入力**で
 * パース境界を通らない場合があるため、`id` を持たない親 VC が
 * `Object.prototype.id` の汚染値を拾い、`3002` のガードを素通りして**汚染値がそのまま
 * `derivedFrom`（監査可能なチェーンエッジ）に格納される**（fail-open）。
 *
 * さらに従来の `parentId === undefined || parentId.length === 0` は、汚染値が**非文字列**のとき
 * `parentId.length` が `undefined` になり `undefined === 0` が false になるため、
 * **ガードが二重に素通り**して非文字列が `derivedFrom` に載った。型検査を明示して塞ぐ。
 *
 * **トートロジー回避**: 汚染値と own 値を食い違わせ、own の `id` が使われることまで検証する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { VerifiableCredential } from '../../../vc/vc.js';
import { buildDerivedCredential } from '../../build.js';
import type { DerivedCredentialInput } from '../../types.js';

const SCHEMA_INVALID = new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);

const V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
const ISSUER_DID = 'did:example:issuer';
const SUBJECT_DID = 'did:example:subject';
const ATTACKER_ID = 'urn:uuid:attacker-parent';

/** `id` を持つ / 持たない親 VC。 */
function parentVc(id?: string): VerifiableCredential {
  const vc: Record<string, unknown> = {
    '@context': [V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer: ISSUER_DID,
    credentialSubject: { id: SUBJECT_DID },
    issuanceDate: '2026-01-01T00:00:00Z',
  };
  if (id !== undefined) {
    vc.id = id;
  }
  return vc as unknown as VerifiableCredential;
}

/** 最小の子 VC。 */
function childVc(): DerivedCredentialInput {
  return {
    '@context': [V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer: ISSUER_DID,
    credentialSubject: { id: SUBJECT_DID },
    issuanceDate: '2026-01-01T00:00:00Z',
    id: 'urn:uuid:child-1',
  } as unknown as DerivedCredentialInput;
}

describe('buildDerivedCredential の parent.id は own 限定', () => {
  it('id を own に持たない親 VC は汚染下でも 3002 で拒否される', () => {
    expect(() =>
      withPollutedPrototype({ id: ATTACKER_ID }, () =>
        buildDerivedCredential(parentVc(), childVc()),
      ),
    ).toThrow(SCHEMA_INVALID);
  });

  it('汚染値が非文字列でもガードは素通りしない（二重の素通りを塞ぐ）', () => {
    // 従来は `parentId.length` が undefined になり `undefined === 0` が false でガードを抜け、
    // 非文字列がそのまま `derivedFrom` に載った。
    expect(() =>
      withPollutedPrototype({ id: 12_345 }, () => buildDerivedCredential(parentVc(), childVc())),
    ).toThrow(SCHEMA_INVALID);
    expect(() =>
      withPollutedPrototype({ id: { nested: 'object' } }, () =>
        buildDerivedCredential(parentVc(), childVc()),
      ),
    ).toThrow(SCHEMA_INVALID);
  });

  it('own の id が汚染値ですり替わらない（derivedFrom に own 値が載る）', () => {
    const derived = withPollutedPrototype({ id: ATTACKER_ID }, () =>
      buildDerivedCredential(parentVc('urn:uuid:real-parent'), childVc()),
    );

    expect(derived.derivedFrom).toBe('urn:uuid:real-parent');
    expect(JSON.stringify(derived)).not.toContain(ATTACKER_ID);
  });

  it('対照: 汚染なしで id を欠く親 VC は従来どおり 3002', () => {
    expect(() => buildDerivedCredential(parentVc(), childVc())).toThrow(SCHEMA_INVALID);
  });

  it('対照: 空文字の id も従来どおり 3002', () => {
    expect(() => buildDerivedCredential(parentVc(''), childVc())).toThrow(SCHEMA_INVALID);
  });
});
