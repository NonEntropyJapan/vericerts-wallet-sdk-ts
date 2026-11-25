import { isBuiltin } from 'node:module';
import { fileURLToPath } from 'node:url';
import { containedFile } from './containment.mjs';

let root;
let port;
export function initialize(data) {
  root = data.root;
  port = data.port;
  port.on('message', (message) => {
    if (message === 'flush') port.postMessage('flushed');
  });
}

export async function resolve(specifier, context, nextResolve) {
  const result = await nextResolve(specifier, context);
  if (isBuiltin(result.url)) return result;
  try {
    if (!result.url.startsWith('file:')) throw new Error('Non-file consumer module');
    containedFile(root, fileURLToPath(result.url));
  } catch (error) {
    port.postMessage('violation');
    throw error;
  }
  return result;
}
