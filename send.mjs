#!/usr/bin/env node
/**
 * Send an encrypted Quorum message
 * Usage: node send.mjs <message> [recipient_address]
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const WebSocket = require('ws');
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

import { 
  initCrypto, senderX3DH, newDoubleRatchet, 
  doubleRatchetEncrypt, generateX448, encryptInboxMessageBytes 
} from './src/crypto.mjs';
import { QuorumAPI } from './src/api.mjs';
import { createSecureStore } from './src/secure-store.mjs';

const DATA_DIR = join(homedir(), '.quorum-client');

const message = process.argv[2];
const recipientAddr = process.argv[3];

if (!message || !recipientAddr) {
  console.error('Usage: node send.mjs <message> <recipient_address>');
  process.exit(1);
}

await initCrypto();

// Load keys from secure store (keychain-backed)
const store = await createSecureStore(DATA_DIR);
const deviceKeyset = await store.getDeviceKeyset();
const registration = store.getRegistration();

if (!deviceKeyset || !registration) {
  console.error('No identity found. Run: node cli.mjs register <name>');
  process.exit(1);
}

const api = new QuorumAPI();
let recipient;
try {
  recipient = await api.getUser(recipientAddr);
} catch (e) {
  console.error('Failed to lookup recipient:', e.message);
  process.exit(1);
}

if (!recipient?.device_registrations?.length) {
  console.error('Recipient not found or has no registered devices');
  process.exit(1);
}

const device = recipient.device_registrations[0];

const ephemeralKey = generateX448();
const receiverIdentityKey = [...Buffer.from(device.identity_public_key, 'hex')];
const receiverPreKey = [...Buffer.from(device.pre_public_key, 'hex')];

const sessionKeyB64 = senderX3DH(
  deviceKeyset.identity_key.private_key,
  ephemeralKey.private_key,
  receiverIdentityKey,
  receiverPreKey,
  96
);

const rootKey = [...Buffer.from(sessionKeyB64, 'base64')];

let ratchetState = newDoubleRatchet({
  session_key: rootKey.slice(0, 32),
  sending_header_key: rootKey.slice(32, 64),
  next_receiving_header_key: rootKey.slice(64, 96),
  is_sender: true,
  sending_ephemeral_private_key: ephemeralKey.private_key,
  receiving_ephemeral_key: receiverPreKey,
});

const { envelope: msgEnvelope } = doubleRatchetEncrypt(
  ratchetState,
  JSON.stringify({
    messageId: require('crypto').randomUUID(),
    content: { type: 'post', senderId: registration.user_address, text: message },
    createdDate: Date.now(),
    modifiedDate: Date.now(),
  })
);

const initEnvelope = {
  user_address: registration.user_address,
  display_name: readFileSync(join(DATA_DIR, 'profile.json'), 'utf-8') 
    ? JSON.parse(readFileSync(join(DATA_DIR, 'profile.json'), 'utf-8')).displayName 
    : 'Quorum User',
  return_inbox_address: deviceKeyset.inbox_address,
  return_inbox_encryption_key: Buffer.from(new Uint8Array(deviceKeyset.inbox_encryption_key.public_key)).toString('hex'),
  return_inbox_public_key: Buffer.from(new Uint8Array(deviceKeyset.inbox_signing_key.public_key)).toString('hex'),
  return_inbox_private_key: Buffer.from(new Uint8Array(deviceKeyset.inbox_signing_key.private_key)).toString('hex'),
  identity_public_key: Buffer.from(new Uint8Array(deviceKeyset.identity_key.public_key)).toString('hex'),
  tag: deviceKeyset.inbox_address,
  message: msgEnvelope,
  type: 'direct',
};

const inboxEncKey = [...Buffer.from(device.inbox_registration.inbox_encryption_public_key, 'hex')];
const sealedEnvelope = encryptInboxMessageBytes(inboxEncKey, ephemeralKey.private_key, [...Buffer.from(JSON.stringify(initEnvelope), 'utf-8')]);

const sealedMessage = {
  inbox_address: device.inbox_registration.inbox_address,
  ephemeral_public_key: Buffer.from(new Uint8Array(ephemeralKey.public_key)).toString('hex'),
  envelope: sealedEnvelope,
  hub_address: '',
  hub_public_key: '',
  hub_signature: '',
  timestamp: Date.now(),
};

const ws = new WebSocket('wss://api.quorummessenger.com/ws');
ws.on('open', () => {
  ws.send(JSON.stringify(sealedMessage));
  fetch('https://api.quorummessenger.com/inbox', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(sealedMessage),
  }).then(r => r.text()).then(t => {
    console.log('✅ Sent to', recipientAddr.substring(0, 20) + '...');
    ws.close();
  });
});
ws.on('close', () => process.exit(0));
