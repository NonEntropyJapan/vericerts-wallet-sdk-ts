import { describe, expect, it } from 'bun:test';
import { isObjectPrototypeProperty, nonObjectPrototypeProperty } from '../own-property.js';

const proto = Object.prototype as unknown as Record<string, unknown>;

/** `Object.prototype` に一時的にプロパティを生やして `run` を実行し、必ず元に戻す。 */
function withPollution(key: string, descriptor: PropertyDescriptor, run: () => void): void {
  Object.defineProperty(Object.prototype, key, { configurable: true, ...descriptor });
  try {
    run();
  } finally {
    delete proto[key];
  }
}

describe('isObjectPrototypeProperty', () => {
  it('汚染が無ければ false', () => {
    expect(isObjectPrototypeProperty({}, 'probe3983')).toBe(false);
    expect(isObjectPrototypeProperty(Object.create(null) as object, 'probe3983')).toBe(false);
  });

  it('データ汚染・アクセサ汚染のどちらも true（getter は起動しない）', () => {
    withPollution('probe3983', { value: () => {}, writable: true }, () => {
      expect(isObjectPrototypeProperty({}, 'probe3983')).toBe(true);
    });
    let getterCalls = 0;
    withPollution(
      'probe3983',
      {
        get: () => {
          getterCalls += 1;
          return () => {};
        },
      },
      () => {
        expect(isObjectPrototypeProperty({}, 'probe3983')).toBe(true);
      },
    );
    expect(getterCalls).toBe(0);
  });

  it('own・クラスのプロトタイプ・Object.create 元が先に持つなら、汚染があっても false', () => {
    class Holder {
      probe3983(): void {}
    }
    withPollution('probe3983', { value: 1, writable: true }, () => {
      expect(isObjectPrototypeProperty({ probe3983: 1 }, 'probe3983')).toBe(false);
      expect(isObjectPrototypeProperty(new Holder(), 'probe3983')).toBe(false);
      expect(
        isObjectPrototypeProperty(Object.create({ probe3983: 1 }) as object, 'probe3983'),
      ).toBe(false);
    });
  });

  it('nonObjectPrototypeProperty が「未指定」にする入力と同じ入力を true にする', () => {
    withPollution('probe3983', { value: 'polluted', writable: true }, () => {
      expect(nonObjectPrototypeProperty({}, 'probe3983')).toBeUndefined();
      expect(isObjectPrototypeProperty({}, 'probe3983')).toBe(true);
    });
  });
});
