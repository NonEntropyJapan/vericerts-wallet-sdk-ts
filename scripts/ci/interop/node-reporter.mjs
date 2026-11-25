export default async function* reportNodeEvents(events) {
  for await (const event of events) {
    const seen = new WeakSet();
    const line = JSON.stringify(event, (_key, value) => {
      if (typeof value === 'bigint') return String(value);
      if (!value || typeof value !== 'object') return value;
      if (seen.has(value)) return '[Circular]';
      seen.add(value);
      if (value instanceof Error) {
        return Object.fromEntries(
          Object.getOwnPropertyNames(value).map((name) => [name, value[name]]),
        );
      }
      return value;
    });
    yield `${line}\n`;
  }
}
