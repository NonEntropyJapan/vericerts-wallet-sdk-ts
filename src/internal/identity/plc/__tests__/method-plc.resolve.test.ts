/**
 * `MethodPlc.resolve` の正常系と形式・取得エラー。
 *
 * 取得は `fetchFn` 注入のモックで、実ネットワークには接続しない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { encodeDagCbor } from '../dag-cbor.js';
import { MethodPlc } from '../method-plc.js';
import { didOfGenesisBytes, parseOperation } from '../operation.js';
import {
  DIRECTORY,
  dataOf,
  directoryFor,
  documentOf,
  entry,
  expectVericertsError,
  genesis,
  makeKey,
  nextOperation,
} from './plc.fixtures.js';

const T0 = '2026-10-01T00:00:00.000Z';
const T1 = '2026-10-01T01:00:00.000Z';

describe('MethodPlc.resolve — 正常系', () => {
  it('ジェネシスだけの DID を解決し、PLC の形（検証関係は空）で文書を組み立てる', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const dir = directoryFor(g.did, g.entries, documentOf(g.did, g.data));
    const doc = await new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did);
    expect(doc.id).toBe(g.did);
    expect(doc.authentication).toEqual([]);
    expect(doc.assertionMethod).toEqual([]);
    expect(doc.verificationMethod).toEqual([
      {
        id: `${g.did}#atproto`,
        type: 'Multikey',
        controller: g.did,
        publicKeyMultibase: g.data.verificationMethods.atproto?.replace('did:key:', ''),
      },
    ]);
    expect(doc.service).toEqual([
      {
        id: '#atproto_pds',
        type: 'AtprotoPersonalDataServer',
        serviceEndpoint: 'https://pds.example.com',
      },
    ]);
    expect(doc.alsoKnownAs).toEqual(['at://alice.example.com']);
    expect(doc['@context']).toContain('https://w3id.org/security/multikey/v1');
    expect(dir.requests.map((r) => r.url).sort()).toEqual(
      [`${DIRECTORY}/${g.did}`, `${DIRECTORY}/${g.did}/log/audit`].sort(),
    );
  });

  it('鍵種別に応じた security suite の @context を追加する（P-256 / secp256k1）', async () => {
    const key = makeKey();
    const g = await genesis(key, dataOf([key], makeKey('secp256k1')));
    const dir = directoryFor(g.did, g.entries, documentOf(g.did, g.data));
    const doc = await new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did);
    expect(doc['@context']).toContain('https://w3id.org/security/suites/secp256k1-2019/v1');
    const p = await genesis(key);
    const doc2 = await new MethodPlc({
      fetchFn: directoryFor(p.did, p.entries, documentOf(p.did, p.data)).fetchFn,
    }).resolve(p.did);
    expect(doc2['@context']).toContain('https://w3id.org/security/suites/ecdsa-2019/v1');
  });

  it('更新操作の連鎖をたどり、最新の操作の状態から文書を組み立てる', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const updated = { ...g.data, alsoKnownAs: ['at://bob.example.com'] };
    const op = await nextOperation(g.did, g.entries[0] as never, updated, key);
    const entries = [...g.entries, entry(g.did, op, T1)];
    const dir = directoryFor(g.did, entries, documentOf(g.did, updated));
    const doc = await new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did);
    expect(doc.alsoKnownAs).toEqual(['at://bob.example.com']);
  });

  it('relationshipsForKeys で明示した鍵名にだけ検証関係を付ける', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const dir = directoryFor(g.did, g.entries, documentOf(g.did, g.data));
    const doc = await new MethodPlc({
      fetchFn: dir.fetchFn,
      relationshipsForKeys: { atproto: ['assertionMethod'], missing: ['authentication'] },
    }).resolve(g.did);
    expect(doc.assertionMethod).toEqual([`${g.did}#atproto`]);
    expect(doc.authentication).toEqual([]);
  });

  it.each([
    'alice.example.com',
    'at://alice.example.com',
    'http://alice.example.com',
    'https://alice.example.com',
  ])('旧形式 create の handle %s を参照実装と同じ状態へ正規化する', async (handle) => {
    const signing = makeKey();
    const recovery = makeKey('P-256');
    const unsigned = {
      type: 'create',
      signingKey: signing.didKey,
      recoveryKey: recovery.didKey,
      handle,
      service: 'pds.example.com',
      prev: null,
    };
    const sig = Buffer.from(await recovery.sign(encodeDagCbor(unsigned))).toString('base64url');
    const operation = { ...unsigned, sig };
    const did = didOfGenesisBytes(parseOperation(operation).signed);
    const normalized = {
      rotationKeys: [recovery.didKey, signing.didKey],
      verificationMethods: { atproto: signing.didKey },
      alsoKnownAs: ['at://alice.example.com'],
      services: {
        atproto_pds: { type: 'AtprotoPersonalDataServer', endpoint: 'https://pds.example.com' },
      },
    };
    const dir = directoryFor(did, [entry(did, operation, T0)], documentOf(did, normalized));
    const doc = await new MethodPlc({ fetchFn: dir.fetchFn }).resolve(did);
    expect(doc.alsoKnownAs).toEqual(['at://alice.example.com']);
    expect(doc.service?.[0]?.serviceEndpoint).toBe('https://pds.example.com');
  });
});

describe('MethodPlc.resolve — 形式・取得', () => {
  it.each([
    'did:plc:EWVI7NXZYOUN6ZHXRHS64OIZ',
    'did:plc:ewvi7nxzyoun6zhxrhs64oi',
    'did:plc:ewvi7nxzyoun6zhxrhs64oiz1',
    'did:plc:ewvi7nxzyoun6zhxrhs64oi0',
    'did:plc:',
    'did:web:example.com',
  ])('形式不正 %s は取得せず 2001', async (did) => {
    const dir = directoryFor(did, [], {});
    await expectVericertsError(
      () => new MethodPlc({ fetchFn: dir.fetchFn }).resolve(did),
      ErrorCodes.INVALID_DID,
    );
    expect(dir.requests).toHaveLength(0);
  });

  it('ディレクトリが 404 なら 2003', async () => {
    const did = 'did:plc:ewvi7nxzyoun6zhxrhs64oiz';
    const dir = directoryFor(did, [], {}, { audit: new Response('', { status: 404 }) });
    await expectVericertsError(
      () => new MethodPlc({ fetchFn: dir.fetchFn }).resolve(did),
      ErrorCodes.DID_NOT_FOUND,
    );
  });

  it('ネットワークエラーは 2003', async () => {
    const did = 'did:plc:ewvi7nxzyoun6zhxrhs64oiz';
    const dir = directoryFor(did, [], {}, { audit: new Error('down') });
    await expectVericertsError(
      () => new MethodPlc({ fetchFn: dir.fetchFn }).resolve(did),
      ErrorCodes.DID_NOT_FOUND,
    );
  });

  it('文書の取得に失敗（410 / 5xx）しても 2003', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const dir = directoryFor(g.did, g.entries, {}, { doc: new Response('', { status: 500 }) });
    await expectVericertsError(
      () => new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did),
      ErrorCodes.DID_NOT_FOUND,
    );
  });

  it('Content-Type が JSON でない応答は 2010、JSON でない本文も 2010', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const doc = documentOf(g.did, g.data);
    const wrongType = new Response(JSON.stringify(g.entries), {
      status: 200,
      headers: { 'content-type': 'text/html' },
    });
    await expectVericertsError(
      () =>
        new MethodPlc({
          fetchFn: directoryFor(g.did, g.entries, doc, { audit: wrongType }).fetchFn,
        }).resolve(g.did),
      ErrorCodes.DID_DOC_INVALID,
    );
    const notJson = new Response('{', {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
    await expectVericertsError(
      () =>
        new MethodPlc({
          fetchFn: directoryFor(g.did, g.entries, doc, { audit: notJson }).fetchFn,
        }).resolve(g.did),
      ErrorCodes.DID_DOC_INVALID,
    );
  });

  it('directoryUrl が https でなければ取得せず 2003', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const dir = directoryFor(g.did, g.entries, documentOf(g.did, g.data));
    await expectVericertsError(
      () =>
        new MethodPlc({ fetchFn: dir.fetchFn, directoryUrl: 'http://plc.directory' }).resolve(
          g.did,
        ),
      ErrorCodes.DID_NOT_FOUND,
      'insecure_directory_url',
    );
    expect(dir.requests).toHaveLength(0);
  });

  it('解決先ホストは DID から導出しない（directoryUrl の固定ホストだけに取りに行く）', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const urls: string[] = [];
    const fetchFn = (async (input: string | URL | Request) => {
      urls.push(String(input));
      return new Response('', { status: 404 });
    }) as unknown as typeof fetch;
    await new MethodPlc({ fetchFn }).resolve(g.did).catch(() => undefined);
    expect(urls.length).toBeGreaterThan(0);
    expect(urls.every((u) => new URL(u).host === 'plc.directory')).toBe(true);
  });
});
