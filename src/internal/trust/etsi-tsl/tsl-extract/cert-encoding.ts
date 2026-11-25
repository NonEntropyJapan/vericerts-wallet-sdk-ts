import { base64 } from '@scure/base';

/** テキストから base64 デコード（空白除去）。 */
export function decodeCert(text: string): Uint8Array {
  return base64.decode(text.replace(/\s+/g, ''));
}

/** 証明書 DER を PEM（64 文字折返し）にエンコードする。 */
export function encodeCertToPem(der: Uint8Array): string {
  const b64 = base64.encode(der);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}
