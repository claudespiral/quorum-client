#!/usr/bin/env node
/**
 * Listen for incoming Quorum messages, decrypt, and delete from server
 * Usage: node listen.mjs [timeout_seconds]
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const WebSocket = require('ws');
import { readFileSync, existsSync, writeFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

import { 
  initCrypto, decryptInboxMessage, receiverX3DH, 
  newDoubleRatchet, doubleRatchetDecrypt, signEd448
} from './src/crypto.mjs';
import { QuorumAPI } from './src/api.mjs';

const DATA_DIR = join(homedir(), '.quorum-client');
const TIMEOUT = (parseInt(process.argv[2]) || 120) * 1000;

// Load identity
const deviceKeysetPath = join(DATA_DIR, 'device-keyset.json');
if (!existsSync(deviceKeysetPath)) {
  console.error('No identity found. Run: node cli.mjs register <name>');
  process.exit(1);
}

await initCrypto();

const deviceKeyset = JSON.parse(readFileSync(deviceKeysetPath, 'utf-8'));
const INBOX = deviceKeyset.inbox_address;
const api = new QuorumAPI();

// Track timestamps of messages to delete
const processedTimestamps = [];

console.log('Listening on inbox:', INBOX);

/**
 * Decrypt and process an incoming message
 */
async function processMessage(raw) {
  try {
    const parsed = JSON.parse(raw);
    const timestamp = parsed.timestamp;
    const sealed = JSON.parse(parsed.encryptedContent);
    
    // Decrypt outer envelope
    const ephPubKey = [...Buffer.from(sealed.ephemeral_public_key, 'hex')];
    const plaintext = decryptInboxMessage(
      deviceKeyset.inbox_encryption_key.private_key,
      ephPubKey,
      sealed.envelope
    );
    const envelope = JSON.parse(Buffer.from(new Uint8Array(plaintext)).toString('utf-8'));
    
    // Receiver X3DH to get session key
    const senderIdentityKey = [...Buffer.from(envelope.identity_public_key, 'hex')];
    const senderEphemeralKey = [...Buffer.from(sealed.ephemeral_public_key, 'hex')];
    
    const sessionKeyB64 = receiverX3DH(
      deviceKeyset.identity_key.private_key,
      deviceKeyset.pre_key.private_key,
      senderIdentityKey,
      senderEphemeralKey,
      96
    );
    
    const rootKey = [...Buffer.from(sessionKeyB64, 'base64')];
    
    let ratchetState = newDoubleRatchet({
      session_key: rootKey.slice(0, 32),
      sending_header_key: rootKey.slice(32, 64),
      next_receiving_header_key: rootKey.slice(64, 96),
      is_sender: false,
      sending_ephemeral_private_key: deviceKeyset.pre_key.private_key,
      receiving_ephemeral_key: senderEphemeralKey,
    });
    
    // Decrypt inner message
    const result = doubleRatchetDecrypt(ratchetState, envelope.message);
    const msg = JSON.parse(result.message);
    
    console.log(`\n📨 [${new Date(timestamp).toLocaleTimeString()}] ${envelope.display_name || envelope.user_address.substring(0, 12)}:`);
    console.log(`   ${msg.content?.text || '(no text)'}`);
    
    // Mark for deletion
    processedTimestamps.push(timestamp);
    
    return { success: true, envelope, msg };
  } catch (e) {
    console.error('Failed to decrypt:', e.message);
    return { success: false };
  }
}

/**
 * Delete processed messages from inbox
 */
async function deleteProcessedMessages() {
  if (processedTimestamps.length === 0) return;
  
  try {
    // Build signature: inbox_address + timestamps as strings
    const messageToSign = INBOX + processedTimestamps.map(t => `${t}`).join('');
    const messageB64 = Buffer.from(messageToSign, 'utf-8').toString('base64');
    const privKeyB64 = Buffer.from(new Uint8Array(deviceKeyset.inbox_signing_key.private_key)).toString('base64');
    
    const sig = signEd448(privKeyB64, messageB64);
    const sigHex = Buffer.from(sig, 'base64').toString('hex');
    const pubKeyHex = Buffer.from(new Uint8Array(deviceKeyset.inbox_signing_key.public_key)).toString('hex');
    
    await api.deleteInboxMessages(INBOX, processedTimestamps, pubKeyHex, sigHex);
    console.log(`\n🗑️  Deleted ${processedTimestamps.length} message(s) from inbox`);
    processedTimestamps.length = 0;
  } catch (e) {
    console.error('Failed to delete messages:', e.message);
  }
}

const ws = new WebSocket('wss://api.quorummessenger.com/ws');

ws.on('open', () => {
  console.log('Connected — waiting for messages...\n');
  ws.send(JSON.stringify({ type: 'listen', inbox_addresses: [INBOX] }));
});

ws.on('message', async (data) => {
  await processMessage(data.toString());
});

ws.on('error', (err) => console.error('WS Error:', err.message));

ws.on('close', async () => {
  await deleteProcessedMessages();
  console.log('Disconnected');
  process.exit(0);
});

// Cleanup on exit
process.on('SIGINT', async () => {
  console.log('\nShutting down...');
  await deleteProcessedMessages();
  ws.close();
});

setTimeout(async () => {
  console.log('\nTimeout — closing');
  await deleteProcessedMessages();
  ws.close();
}, TIMEOUT);
