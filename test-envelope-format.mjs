import { initCrypto, doubleRatchetEncrypt, newDoubleRatchet, generateX448, senderX3DH } from './src/crypto.mjs';

await initCrypto();

// Create a fake ratchet state for testing
const myKey = generateX448();
const theirKey = generateX448();

const sessionKey = senderX3DH(
  myKey.private_key,
  generateX448().private_key,
  theirKey.public_key,
  theirKey.public_key,
  96
);

const rootKey = [...Buffer.from(sessionKey, 'base64')];
const ratchet = newDoubleRatchet({
  session_key: rootKey.slice(0, 32),
  sending_header_key: rootKey.slice(32, 64),
  next_receiving_header_key: rootKey.slice(64, 96),
  is_sender: true,
  sending_ephemeral_private_key: myKey.private_key,
  receiving_ephemeral_public_key: theirKey.public_key,
});

console.log('Ratchet state:', typeof ratchet, ratchet?.substring?.(0, 100) || 'not a string');

try {
  const result = doubleRatchetEncrypt(ratchet, 'test message');
  console.log('Result keys:', Object.keys(result));
  console.log('Envelope type:', typeof result.envelope);
  console.log('Envelope:', result.envelope);
} catch (e) {
  console.log('Encrypt error:', e.message);
}
