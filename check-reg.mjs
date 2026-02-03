import { initCrypto } from './src/crypto.mjs';
import { createSecureStore } from './src/secure-store.mjs';
import { homedir } from 'os';
import { join } from 'path';

const dataDir = process.env.QUORUM_DATA_DIR || join(homedir(), '.quorum-client');
console.log('Data dir:', dataDir);

await initCrypto();
const store = await createSecureStore(dataDir);

const reg = store.getRegistration();
if (reg) {
  console.log('Already registered as:', reg.user_address);
  console.log('Display name:', reg.display_name);
} else {
  console.log('No registration found. Need to register.');
}
