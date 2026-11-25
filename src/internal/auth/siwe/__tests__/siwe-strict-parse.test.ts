/**
 * SIWE 厳密パーサの回帰テスト（二次時間 DoS / Resources 隠蔽 / scheme 欠落）と、
 * EIP-4361 参照メッセージを壊さないことの固定。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { parseSiweMessage, validateSiweMessage } from '../siwe.js';
import {
  MAX_SIWE_MESSAGE_LENGTH,
  MAX_SIWE_RESOURCES,
  parseSiweStrict,
} from '../siwe-strict-parse.js';

const ADDRESS = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';
const NOW = new Date('2021-10-01T00:00:00Z');

interface Parts {
  origin?: string;
  statement?: string;
  uri?: string;
  requestId?: string;
  resources?: string[];
}

function build({
  origin = 'service.org',
  statement,
  uri = 'https://service.org/login',
  requestId,
  resources,
}: Parts = {}): string {
  return [
    `${origin} wants you to sign in with your Ethereum account:`,
    ADDRESS,
    '',
    ...(statement !== undefined ? [statement] : []),
    '',
    `URI: ${uri}`,
    'Version: 1',
    'Chain ID: 1',
    'Nonce: 32891756',
    'Issued At: 2021-09-30T16:25:24Z',
    ...(requestId !== undefined ? [`Request ID: ${requestId}`] : []),
    ...(resources !== undefined ? ['Resources:', ...resources.map((r) => `- ${r}`)] : []),
  ].join('\n');
}

function expectInvalid(message: string): void {
  try {
    parseSiweMessage(message);
  } catch (err) {
    expect(err).toBeInstanceOf(VericertsError);
    expect((err as VericertsError).code).toBe(ErrorCodes.SIWE_MESSAGE_INVALID);
    expect(parseSiweStrict(message)).toBeNull();
    return;
  }
  throw new Error('should have thrown');
}

describe('EIP-4361 参照メッセージ（正規メッセージを壊さない）', () => {
  it('EIP-4361 の例（statement + Resources）をそのまま受理する', () => {
    const message = [
      'service.org wants you to sign in with your Ethereum account:',
      ADDRESS,
      '',
      'I accept the ServiceOrg Terms of Service: https://service.org/tos',
      '',
      'URI: https://service.org/login',
      'Version: 1',
      'Chain ID: 1',
      'Nonce: 32891756',
      'Issued At: 2021-09-30T16:25:24Z',
      'Resources:',
      '- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/',
      '- https://example.com/my-web2-claim.json',
    ].join('\n');
    const parsed = parseSiweMessage(message);
    expect(parsed).toMatchObject({
      domain: 'service.org',
      address: ADDRESS,
      statement: 'I accept the ServiceOrg Terms of Service: https://service.org/tos',
      uri: 'https://service.org/login',
      version: '1',
      chainId: 1,
      nonce: '32891756',
      issuedAt: '2021-09-30T16:25:24.000Z',
      resources: [
        'ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/',
        'https://example.com/my-web2-claim.json',
      ],
    });
    expect(parsed.scheme).toBeUndefined();
  });

  it('statement なし・全任意フィールド・ポート付き domain も受理する', () => {
    const message = `${build({ origin: 'localhost:3000', requestId: 'req-1', resources: ['https://a'] })}`;
    expect(parseSiweMessage(message)).toMatchObject({
      domain: 'localhost:3000',
      requestId: 'req-1',
      resources: ['https://a'],
    });
    expect(parseSiweMessage(build()).statement).toBeUndefined();
  });

  it('statement に URI: / Version: 等が含まれても（予約語を含むだけの正当な文面）値は行位置で決まる', () => {
    const parsed = parseSiweMessage(build({ statement: 'see URI: and Version: docs' }));
    expect(parsed.statement).toBe('see URI: and Version: docs');
    expect(parsed.uri).toBe('https://service.org/login');
  });
});

describe('長さ・件数の上限（決定的な上限で二次時間入力を弾く）', () => {
  it('400KB の `URI: ` 反復 statement は走査せず 8041', () => {
    const message = build({ statement: 'URI: '.repeat(80000) });
    expect(message.length).toBeGreaterThan(400_000);
    expectInvalid(message);
  });

  it('長さ上限ちょうどは受理、1 文字超過は 8041', () => {
    const base = build({ statement: 'x' }).length - 1;
    const atLimit = build({ statement: 'a'.repeat(MAX_SIWE_MESSAGE_LENGTH - base) });
    expect(atLimit.length).toBe(MAX_SIWE_MESSAGE_LENGTH);
    expect(parseSiweMessage(atLimit).statement?.length).toBe(MAX_SIWE_MESSAGE_LENGTH - base);
    expectInvalid(build({ statement: 'a'.repeat(MAX_SIWE_MESSAGE_LENGTH - base + 1) }));
  });

  it('上限内の `URI: ` 反復 statement は statement として保持され、値は行位置から取る', () => {
    const parsed = parseSiweMessage(build({ statement: 'URI: '.repeat(2000) }));
    expect(parsed.statement).toBe('URI: '.repeat(2000));
    expect(parsed.uri).toBe('https://service.org/login');
  });

  it('Resources 件数は上限ちょうどまで受理、超過は 8041', () => {
    const items = (n: number): string[] => Array.from({ length: n }, (_, i) => `https://a/${i}`);
    expect(
      parseSiweMessage(build({ resources: items(MAX_SIWE_RESOURCES) })).resources,
    ).toHaveLength(MAX_SIWE_RESOURCES);
    expectInvalid(build({ resources: items(MAX_SIWE_RESOURCES + 1) }));
  });
});

describe('Resources 隠蔽の拒否', () => {
  const evil = ['https://evil.example/grant'];

  it.each([
    ['statement', { statement: 'Resources: hi' }],
    ['URI', { uri: 'https://service.org/Resources:' }],
    ['Request ID', { requestId: 'Resources:' }],
  ] as [
    string,
    Parts,
  ][])('%s に Resources: を含み、本物の Resources ブロックが続く入力は 8041', (_name, parts) => {
    expectInvalid(build({ ...parts, resources: evil }));
  });

  it('Resources 項目内の `Resources:`（最初一致パーサが以降を切り落とす）も 8041', () => {
    expectInvalid(build({ resources: ['https://a/Resources:x', ...evil] }));
  });

  it('Resources ブロックが無くても Resources: を含む文面は 8041（下流パーサの解釈差を残さない）', () => {
    expectInvalid(build({ statement: 'Resources: hi' }));
  });

  it('Resources: を含まない場合、本物の Resources は欠落せず全件返る', () => {
    expect(parseSiweMessage(build({ statement: 'hello', resources: evil })).resources).toEqual(
      evil,
    );
  });
});

describe('scheme の保持と照合', () => {
  const withScheme = (scheme: string): string => build({ origin: `${scheme}://service.org` });

  it('scheme を SiweMessage に保持し、domain には含めない', () => {
    const parsed = parseSiweMessage(withScheme('https'));
    expect(parsed.scheme).toBe('https');
    expect(parsed.domain).toBe('service.org');
  });

  it('http:// 向けの署名は既定（https 期待）の RP で 8041', () => {
    const parsed = parseSiweMessage(withScheme('http'));
    expect(() => validateSiweMessage(parsed, 'service.org', NOW)).toThrow(VericertsError);
    expect(() =>
      validateSiweMessage(parsed, 'service.org', NOW, { expectedScheme: 'https' }),
    ).toThrow(VericertsError);
  });

  it('任意 scheme（javascript 等）は expectedScheme と不一致なら 8041', () => {
    const parsed = parseSiweMessage(withScheme('javascript'));
    expect(() => validateSiweMessage(parsed, 'service.org', NOW)).toThrow(VericertsError);
  });

  it('https:// は既定で受理、expectedScheme 明示で http も受理（開発用）', () => {
    expect(() =>
      validateSiweMessage(parseSiweMessage(withScheme('https')), 'service.org', NOW),
    ).not.toThrow();
    expect(() =>
      validateSiweMessage(parseSiweMessage(withScheme('http')), 'service.org', NOW, {
        expectedScheme: 'http',
      }),
    ).not.toThrow();
  });

  it('scheme を持たないメッセージ（EIP-4361 の既定形）は従来どおり受理される', () => {
    expect(() => validateSiweMessage(parseSiweMessage(build()), 'service.org', NOW)).not.toThrow();
  });

  it.each([
    ['不正な scheme 文字', '1http://service.org'],
    ['空の scheme', '://service.org'],
    ['パス付き domain', 'service.org/evil'],
    ['userinfo 区切りの空白', 'service.org evil'],
    ['二重 scheme 区切り', 'https://https://service.org'],
    ['空の domain', 'https://'],
  ])('ヘッダ先頭部が不正（%s）なら 8041', (_name, origin) => {
    expectInvalid(build({ origin }));
  });
});

describe('制御文字', () => {
  it.each([
    ['\r'],
    ['\u0000'],
    ['\t'],
    ['\u2028'],
  ])('改行以外の制御文字 %j を含むメッセージは 8041', (ch) => {
    expectInvalid(build({ statement: `a${ch}b` }));
  });
});
