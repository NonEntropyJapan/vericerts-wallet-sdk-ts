/** 処理制限がかかっていない保持 VC を列挙する。 */

import type { VerifiableCredential } from '../credential/index.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { decodeCredentialRecord } from './codec.js';

/** 処理制限（`processingRestricted: true`、Art.18）がかかっていない保持 VC を列挙する。 */
export async function resolveActiveCredentials(
  storage: {
    get(key: string): Promise<Uint8Array | null>;
    list(prefix: string): Promise<string[]>;
  },
  credentialKeyPrefix: string,
): Promise<VerifiableCredential[]> {
  const keys = await storage.list(credentialKeyPrefix);
  const credentials: VerifiableCredential[] = [];
  for (const key of keys) {
    const stored = await storage.get(key);
    if (stored === null) {
      continue;
    }
    const record = decodeCredentialRecord(stored);
    if (ownProperty<boolean>(record, 'processingRestricted') === true) {
      continue;
    }
    credentials.push(record.credential);
  }
  return credentials;
}
