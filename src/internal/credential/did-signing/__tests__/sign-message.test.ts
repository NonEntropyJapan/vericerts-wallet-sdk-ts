/**
 * `did_signMessage` の detached コンパクト JWS（RFC 7515 + RFC 7797、Q5）の署名・検証。
 *
 * 形式: header は `{alg, kid, b64: false, crit: ["b64"]}`、payload セグメントは空（detached）、署名対象は
 * `ASCII(header) || '.' || message(UTF-8)`。検証は `kid` の DID を解決し、検証メソッドが `authentication` に載って
 * いることを確かめ、呼び出し側が渡したメッセージに対して署名を検証する。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes } from '../../../errors.js';
import { buildDidWebDocument } from '../did-document-export.js';
import { importPersonaFromDid } from '../import-persona.js';
import { resolvePersonaSigner } from '../persona-signer.js';
import { signMessageJws, verifyMessageJws } from '../sign-message.js';
import { externalKey, newWorld } from './fixtures.js';

const encoder = new TextEncoder();
const b64u = (text: string): string => base64urlnopad.encode(encoder.encode(text));

async function setup() {
  const world = await newWorld();
  const persona = await world.personas.createPersona({ method: 'key', keyType: 'P-256' });
  const { signer } = await resolvePersonaSigner(world.km, persona);
  return { world, persona, signer };
}

async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
  } catch (error) {
    return (error as { code?: string }).code;
  }
  return undefined;
}

/** 任意のヘッダ・payload セグメントを、persona の署名鍵で署名した JWS（検証器の拒否条件を作る）。 */
async function craft(
  signer: Awaited<ReturnType<typeof setup>>['signer'],
  header: Record<string, unknown>,
  payloadSegment: string,
  signedPayload: string,
): Promise<string> {
  const headerSegment = b64u(JSON.stringify(header));
  const signature = signer.sign(encoder.encode(`${headerSegment}.${signedPayload}`));
  return `${headerSegment}.${payloadSegment}.${base64urlnopad.encode(signature)}`;
}

describe('signMessageJws / verifyMessageJws', () => {
  it('header は alg / kid / b64:false / crit:["b64"]、payload セグメントは空（detached）、署名はメッセージそのものへの署名', async () => {
    const { world, persona, signer } = await setup();
    const jws = await signMessageJws('hello', signer);
    const [headerSegment, payloadSegment, signatureSegment, ...rest] = jws.split('.') as string[];
    expect(rest).toEqual([]);
    expect(payloadSegment).toBe('');
    expect(
      JSON.parse(new TextDecoder().decode(base64urlnopad.decode(headerSegment as string))),
    ).toEqual({
      alg: 'ES256',
      kid: signer.kid,
      b64: false,
      crit: ['b64'],
    });
    // RFC 7797 §3: signing-input は ASCII(header) || '.' || payload（payload は無加工の UTF-8）。
    expect(base64urlnopad.decode(signatureSegment as string)).toEqual(
      signer.sign(encoder.encode(`${headerSegment}.hello`)),
    );
    expect(
      await verifyMessageJws(jws, {
        message: 'hello',
        resolver: world.resolver,
        expectedDid: persona.did,
      }),
    ).toEqual({ did: persona.did, kid: signer.kid as string, alg: 'ES256' });
  });

  it('空・数字だけ・ピリオド / 改行 / 非 ASCII を含むメッセージも往復する（メッセージは payload に入らない）', async () => {
    const { world, persona, signer } = await setup();
    for (const message of [
      '',
      '5',
      '0hello',
      'a.b.c',
      'x\ny',
      '日本語',
      `${b64u('{"a":1}')}.${b64u('{}')}`,
    ]) {
      const jws = await signMessageJws(message, signer);
      const verified = await verifyMessageJws(jws, {
        message,
        resolver: world.resolver,
        expectedDid: persona.did,
      });
      expect(verified.did).toBe(persona.did);
    }
  });

  it('メッセージが違えば 3010（署名はメッセージに束縛される）', async () => {
    const { world, signer } = await setup();
    const jws = await signMessageJws('a', signer);
    expect(await codeOf(verifyMessageJws(jws, { message: 'b', resolver: world.resolver }))).toBe(
      ErrorCodes.SIG_INVALID,
    );
  });

  it('メッセージを渡さない検証は 3010', async () => {
    const { world, signer } = await setup();
    const jws = await signMessageJws('a', signer);
    const opts = { resolver: world.resolver } as unknown as Parameters<typeof verifyMessageJws>[1];
    expect(await codeOf(verifyMessageJws(jws, opts))).toBe(ErrorCodes.SIG_INVALID);
  });

  it('別 DID（解決できるが kid を列挙していない）を期待すれば 3010 did_mismatch', async () => {
    const { world, signer } = await setup();
    const other = await world.personas.createPersona({ method: 'key', keyType: 'P-256' });
    const jws = await signMessageJws('a', signer);
    expect(
      await codeOf(
        verifyMessageJws(jws, { message: 'a', resolver: world.resolver, expectedDid: other.did }),
      ),
    ).toBe(ErrorCodes.SIG_INVALID);
  });

  it('expectedDid を解決できなければ 3010 に畳まず解決の失敗（2001 / 2003）をそのまま伝播する', async () => {
    const { world, signer } = await setup();
    const jws = await signMessageJws('a', signer);
    expect(
      await codeOf(
        verifyMessageJws(jws, {
          message: 'a',
          resolver: world.resolver,
          expectedDid: 'did:key:zOther',
        }),
      ),
    ).toBe(ErrorCodes.INVALID_DID);
    expect(
      await codeOf(
        verifyMessageJws(jws, {
          message: 'a',
          resolver: world.resolver,
          expectedDid: 'did:web:absent.example',
        }),
      ),
    ).toBe(ErrorCodes.DID_NOT_FOUND);
  });

  it('kid の無い署名鍵では署名できない（2007）', async () => {
    const { signer } = await setup();
    const { kid: _kid, ...withoutKid } = signer;
    expect(await codeOf(signMessageJws('a', withoutKid))).toBe(
      ErrorCodes.DID_SIGNING_KEY_UNAVAILABLE,
    );
  });

  it('改ざんした署名は 3010', async () => {
    const { world, signer } = await setup();
    const [header, , signature] = (await signMessageJws('a', signer)).split('.') as [
      string,
      string,
      string,
    ];
    const bytes = base64urlnopad.decode(signature);
    bytes[0] = (bytes[0] as number) ^ 0xff;
    const forged = `${header}..${base64urlnopad.encode(bytes)}`;
    expect(await codeOf(verifyMessageJws(forged, { message: 'a', resolver: world.resolver }))).toBe(
      ErrorCodes.SIG_INVALID,
    );
  });

  it('b64:true・crit 欠落 / 余剰 / b64 以外・b64 欠落・payload 添付は署名が正しくても拒否する（RFC 7797 の形のみ受理）', async () => {
    const { world, signer } = await setup();
    const base = { alg: 'ES256', kid: signer.kid };
    const message = 'a';
    const cases: Record<string, string> = {
      // 通常の（b64 なし・crit なし）attached JWS: JWT として読める形はここで拒否する。
      attached: await craft(signer, { ...base }, b64u(message), b64u(message)),
      'attached with b64:false header': await craft(
        signer,
        { ...base, b64: false, crit: ['b64'] },
        message,
        message,
      ),
      'b64:true': await craft(signer, { ...base, b64: true, crit: ['b64'] }, '', message),
      'crit missing': await craft(signer, { ...base, b64: false }, '', message),
      'crit empty': await craft(signer, { ...base, b64: false, crit: [] }, '', message),
      'crit extra': await craft(signer, { ...base, b64: false, crit: ['b64', 'exp'] }, '', message),
      'crit other': await craft(signer, { ...base, b64: false, crit: ['exp'] }, '', message),
      'crit not array': await craft(signer, { ...base, b64: false, crit: 'b64' }, '', message),
      'b64 missing': await craft(signer, { ...base, crit: ['b64'] }, '', message),
      'b64 string': await craft(signer, { ...base, b64: 'false', crit: ['b64'] }, '', message),
    };
    // 前提: 同じ鍵・同じメッセージで、受理される形はちゃんと通る（拒否の理由がヘッダ形式であること）。
    const ok = await craft(signer, { ...base, b64: false, crit: ['b64'] }, '', message);
    expect((await verifyMessageJws(ok, { message, resolver: world.resolver })).kid).toBe(
      signer.kid as string,
    );
    for (const [name, jws] of Object.entries(cases)) {
      expect({
        name,
        code: await codeOf(verifyMessageJws(jws, { message, resolver: world.resolver })),
      }).toEqual({
        name,
        code: ErrorCodes.SIG_INVALID,
      });
    }
  });

  it('alg=none は 3011、kid 欠落・構造不正は 3010', async () => {
    const { world, signer } = await setup();
    const none = `${b64u('{"alg":"none","kid":"did:key:z#z","b64":false,"crit":["b64"]}')}..AAAA`;
    expect(await codeOf(verifyMessageJws(none, { message: 'a', resolver: world.resolver }))).toBe(
      ErrorCodes.ALG_NONE,
    );
    const noKid = `${b64u(JSON.stringify({ alg: signer.alg, b64: false, crit: ['b64'] }))}..AAAA`;
    expect(await codeOf(verifyMessageJws(noKid, { message: 'a', resolver: world.resolver }))).toBe(
      ErrorCodes.SIG_INVALID,
    );
    for (const malformed of ['a.b', 'a..', '..b', '!!!..AAAA']) {
      expect(
        await codeOf(verifyMessageJws(malformed, { message: 'a', resolver: world.resolver })),
      ).toBe(ErrorCodes.SIG_INVALID);
    }
  });

  it('kid の検証メソッドが authentication に無ければ 2017（assertionMethod のみの鍵では検証しない）', async () => {
    const key = externalKey('P-256', 41);
    const did = 'did:web:example.com';
    const document = { ...buildDidWebDocument({ did, publicKeyJwk: key.publicKeyJwk }).document };
    const world = await newWorld({
      files: { 'https://example.com/.well-known/did.json': document },
    });
    const persona = await importPersonaFromDid(
      { personas: world.personas, keymanager: world.km, resolver: world.resolver },
      { did, key: { external: key.privateKeyJwk } },
    );
    const { signer } = await resolvePersonaSigner(world.km, persona, {
      resolver: world.resolver,
      externalKey: key.privateKeyJwk,
    });
    const jws = await signMessageJws('a', signer);
    // 署名後に DID Document から authentication が外された。
    const files = {
      'https://example.com/.well-known/did.json': { ...document, authentication: [] },
    };
    const rotated = await newWorld({ files });
    expect(await codeOf(verifyMessageJws(jws, { message: 'a', resolver: rotated.resolver }))).toBe(
      ErrorCodes.DID_KEY_MISMATCH,
    );
    // 失効した DID も拒否する。
    const deactivated = await newWorld({
      files: { 'https://example.com/.well-known/did.json': { ...document, deactivated: true } },
    });
    expect(
      await codeOf(verifyMessageJws(jws, { message: 'a', resolver: deactivated.resolver })),
    ).toBe(ErrorCodes.DID_KEY_MISMATCH);
  });

  it('別の鍵で署名した JWS（kid は他人の検証メソッド）は 3010', async () => {
    const { world, persona } = await setup();
    // 別のニーモニック（= 別の鍵）の署名者が、被害者の kid を名乗る。
    const attacker = await newWorld({
      mnemonic: 'legal winner thank year wave sausage worth useful legal winner thank yellow',
    });
    const attackerPersona = await attacker.personas.createPersona({
      method: 'key',
      keyType: 'P-256',
    });
    const { signer } = await resolvePersonaSigner(attacker.km, attackerPersona);
    const victimKid = `${persona.did}#${persona.did.slice('did:key:'.length)}`;
    const jws = await signMessageJws('a', { ...signer, kid: victimKid });
    expect(await codeOf(verifyMessageJws(jws, { message: 'a', resolver: world.resolver }))).toBe(
      ErrorCodes.SIG_INVALID,
    );
  });
});
