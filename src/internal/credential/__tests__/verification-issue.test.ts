/**
 * `VerificationIssue` への変換の単体テスト。
 *
 * 高レベル Verifier API の `errors` / `warnings` はここで作られる。秘密や PII が紛れ込むと
 * 検証結果を素直にログへ出した利用側から漏れるため、**載る情報が限定されていること**を固定する。
 */

import { describe, expect, it } from 'bun:test';
import { ERROR_REGISTRY } from '../../error-registry.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import {
  verificationIssueFromCode,
  verificationIssueFromVericertsError,
} from '../verification-issue.js';

describe('verificationIssueFromCode', () => {
  it('コードとレジストリの静的な message を返す', () => {
    const issue = verificationIssueFromCode(ErrorCodes.SIG_INVALID);

    expect(issue.code).toBe('3010');
    expect(issue.message).toBe(ERROR_REGISTRY['3010'].message);
    expect(issue.context).toBeUndefined();
  });

  it('全エラーコードで message が引け、キーは code / message だけになる', () => {
    for (const code of Object.values(ErrorCodes)) {
      const issue = verificationIssueFromCode(code);
      expect(issue.message).toBe(ERROR_REGISTRY[code].message);
      expect(Object.keys(issue).sort()).toEqual(['code', 'message']);
    }
  });
});

describe('verificationIssueFromVericertsError', () => {
  it('code / message を引き継ぎ、context が無ければキー自体を持たない', () => {
    const issue = verificationIssueFromVericertsError(new VericertsError(ErrorCodes.VC_EXPIRED));

    expect(issue.code).toBe('3024');
    expect(issue.message).toBe(ERROR_REGISTRY['3024'].message);
    expect('context' in issue).toBe(false);
  });

  it('context は同一参照でそのまま引き継ぐ（新たな情報を足さない）', () => {
    const context = { vcIndex: 2 };
    const issue = verificationIssueFromVericertsError(
      new VericertsError(ErrorCodes.SIG_INVALID, { context }),
    );

    expect(issue.context).toBe(context);
  });

  it('cause は引き継がない（秘密を含み得るメッセージを結果へ載せない）', () => {
    // @scure 由来の例外など、message にエントロピー等の秘密が載り得るものを cause に持つ。
    const secret = 'seed=abandon abandon abandon';
    const error = new VericertsError(ErrorCodes.SIG_INVALID, { cause: new Error(secret) });

    const issue = verificationIssueFromVericertsError(error);

    expect(Object.keys(issue).sort()).toEqual(['code', 'message']);
    expect(JSON.stringify(issue)).not.toContain(secret);
    // message は VericertsError が ERROR_REGISTRY から取った静的文言そのもの。
    expect(issue.message).toBe(ERROR_REGISTRY['3010'].message);
  });

  it('JWT / VC 本文を message に載せない（静的文言のみ）', () => {
    const jwt = 'eyJhbGciOiJFUzI1NksifQ.eyJzZWNyZXQiOiJ2YWx1ZSJ9.AA';
    const issue = verificationIssueFromVericertsError(
      new VericertsError(ErrorCodes.SIG_INVALID, { cause: new Error(jwt) }),
    );

    expect(issue.message).not.toContain(jwt);
  });
});
