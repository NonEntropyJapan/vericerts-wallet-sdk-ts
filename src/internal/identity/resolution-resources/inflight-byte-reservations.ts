/** SDK-owned FIFO reservations for concurrent DID web response bodies. */
export class InflightByteReservations {
  private reserved = 0;
  private readonly waiting: Array<{
    readonly bytes: number;
    readonly grant: (release: () => void) => void;
  }> = [];

  constructor(private readonly capacity: number) {}

  async run<T>(bytes: number, work: () => Promise<T>): Promise<T> {
    this.assertSize(bytes);
    const release =
      this.tryReserve(bytes) ??
      (await new Promise<() => void>((grant) => {
        this.waiting.push({ bytes, grant });
      }));
    try {
      return await work();
    } finally {
      release();
    }
  }

  /** An upgrade never waits while retaining its first reservation or overtakes a waiter. */
  tryReserve(bytes: number): (() => void) | undefined {
    this.assertSize(bytes);
    if (this.waiting.length > 0 || bytes > this.capacity - this.reserved) {
      return undefined;
    }
    this.reserved += bytes;
    return this.releaseOnce(bytes);
  }

  private assertSize(bytes: number): void {
    if (!Number.isSafeInteger(bytes) || bytes <= 0 || bytes > this.capacity) {
      throw new RangeError('Invalid DID body reservation size');
    }
  }

  private releaseOnce(bytes: number): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.reserved -= bytes;
      while (this.waiting.length > 0) {
        const next = this.waiting[0];
        if (next === undefined || next.bytes > this.capacity - this.reserved) break;
        this.waiting.shift();
        this.reserved += next.bytes;
        next.grant(this.releaseOnce(next.bytes));
      }
    };
  }
}
