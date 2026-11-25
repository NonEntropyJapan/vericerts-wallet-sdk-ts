import { isMainModule } from '../lib/is-main-module.mjs';
import { produceArtifact } from '../packed-consumer/producer.mjs';
import { saveReceipt } from '../packed-consumer/receipt.mjs';
import { requireValidationOrigin } from '../packed-consumer/source-origin.mjs';

if (isMainModule(import.meta.url)) {
  if (process.argv.length !== 6)
    throw new Error('usage: local-artifact.mjs <artifact-dir> <receipt> <revision> <origin>');
  const [directory, receipt, revision, origin] = process.argv.slice(2);
  const result = produceArtifact({
    'artifact-dir': directory,
    receipt,
    'source-sha': revision,
    validationOrigin: requireValidationOrigin(origin),
  });
  saveReceipt(result.receiptPath, result.receipt);
}
