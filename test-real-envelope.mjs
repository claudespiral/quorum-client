import { createSecureStore } from './src/secure-store.mjs';
import { initCrypto, doubleRatchetEncrypt } from './src/crypto.mjs';
import { join } from 'path';
import { homedir } from 'os';

const DATA_DIR = join(homedir(), '.quorum-client');
await initCrypto();
const store = await createSecureStore(DATA_DIR);

// Get Jack's session with real ratchet state
const session = store.getSession('QmRgPaapcYgaKrQWVENTfn14hBfkbqAD4htwJpVH5VzKYz');
console.log('Has session:', !!session);
console.log('Has ratchet:', !!session?.ratchet_state);

// Try encrypting with the real ratchet
const testMessage = JSON.stringify({ test: 'hello' });
const result = doubleRatchetEncrypt(session.ratchet_state, testMessage);

console.log('\nEncrypt result keys:', Object.keys(result));
console.log('Envelope type:', typeof result.envelope);
console.log('Envelope length:', result.envelope?.length);
console.log('Envelope preview:', result.envelope?.substring(0, 500));

// Try parsing as JSON
try {
  const parsed = JSON.parse(result.envelope);
  console.log('\nParsed envelope keys:', Object.keys(parsed));
  console.log('Full structure:', JSON.stringify(parsed, null, 2).substring(0, 1000));
} catch (e) {
  console.log('Not JSON:', e.message);
}
