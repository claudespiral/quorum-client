#!/usr/bin/env node
/**
 * Quorum Space CLI
 * 
 * Commands:
 *   space join <invite-url>       - Join a space from invite link
 *   space send <space-id> <text>  - Send a message to a space
 *   space listen <space-id>       - Listen for messages in a space
 *   space list                    - List joined spaces
 * 
 * Usage:
 *   node space.mjs join "https://app.quorummessenger.com/#spaceId=..."
 *   node space.mjs send QmaQqr... "Hello world!"
 *   node space.mjs listen QmaQqr...
 */

import WebSocket from 'ws';
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from 'fs';
import { createHash, randomBytes } from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

import { 
  initCrypto, 
  generateEd448, 
  generateX448, 
  signEd448,
  getEd448PubKey,
  getX448PubKey,
  deriveAddress,
  encryptInboxMessageBytes,
  decryptInboxMessage
} from './src/crypto.mjs';

const API_BASE = 'https://api.quorummessenger.com';
const WS_URL = 'wss://api.quorummessenger.com/ws';
const SPACE_KEYS_DIR = path.join(process.env.HOME, '.quorum-client', 'spaces');

// ============ Helpers ============

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function bytesToBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function base64ToBytes(b64) {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

function loadSpaceKeys(spaceId) {
  const keyPath = path.join(SPACE_KEYS_DIR, `${spaceId}.json`);
  if (!existsSync(keyPath)) {
    throw new Error(`Space not found: ${spaceId}. Join it first with: space join <invite-url>`);
  }
  return JSON.parse(readFileSync(keyPath, 'utf8'));
}

function saveSpaceKeys(spaceId, keys) {
  if (!existsSync(SPACE_KEYS_DIR)) {
    mkdirSync(SPACE_KEYS_DIR, { recursive: true });
  }
  const keyPath = path.join(SPACE_KEYS_DIR, `${spaceId}.json`);
  writeFileSync(keyPath, JSON.stringify(keys, null, 2));
  return keyPath;
}

// ============ Commands ============

async function cmdJoin(inviteUrl) {
  console.log('Parsing invite link...');
  
  const url = new URL(inviteUrl);
  const hash = url.hash.slice(1);
  const params = new URLSearchParams(hash);
  
  const invite = {
    spaceId: params.get('spaceId'),
    configKey: params.get('configKey'),
    template: params.get('template'),
    secret: params.get('secret'),
    hubKey: params.get('hubKey'),
  };
  
  if (!invite.spaceId || !invite.configKey) {
    throw new Error('Invalid invite: missing spaceId or configKey');
  }
  
  console.log('Space ID:', invite.spaceId);
  
  // Decode template
  let templateJson = null;
  let channelId = null;
  if (invite.template) {
    templateJson = Buffer.from(invite.template, 'hex').toString('utf8');
  }
  
  // Generate inbox keys
  console.log('Generating keys...');
  const inboxSigningKey = generateEd448();
  const inboxEncryptionKey = generateX448();
  const inboxAddress = deriveAddress(inboxSigningKey.public_key);
  
  console.log('Inbox address:', inboxAddress);
  
  // Derive hub info from hub private key
  const hubPrivKeyBytes = hexToBytes(invite.hubKey);
  const hubPubKey = getEd448PubKey(bytesToBase64(hubPrivKeyBytes));
  const hubPubKeyBytes = base64ToBytes(hubPubKey);
  const hubPubKeyHex = bytesToHex(hubPubKeyBytes);
  const hubAddress = deriveAddress([...hubPubKeyBytes]);
  
  console.log('Hub address:', hubAddress);
  
  // Fetch space info to get channel ID
  console.log('Fetching space info...');
  try {
    const regResponse = await fetch(`${API_BASE}/spaces/${invite.spaceId}`);
    if (regResponse.ok) {
      const reg = await regResponse.json();
      console.log('Space registered:', !!reg.space_address);
    }
  } catch (e) {
    console.log('Could not fetch space info:', e.message);
  }
  
  // Register with hub
  console.log('Registering with hub...');
  const inboxPubKeyHex = bytesToHex(new Uint8Array(inboxSigningKey.public_key));
  
  // Hub signature: sign("add" + inbox_public_key_hex)
  const addInboxMsg = 'add' + inboxPubKeyHex;
  const hubSig = signEd448(
    bytesToBase64(hubPrivKeyBytes),
    bytesToBase64(new TextEncoder().encode(addInboxMsg))
  );
  
  // Inbox signature: sign("add" + hub_public_key_hex)
  const addHubMsg = 'add' + hubPubKeyHex;
  const inboxSig = signEd448(
    bytesToBase64(new Uint8Array(inboxSigningKey.private_key)),
    bytesToBase64(new TextEncoder().encode(addHubMsg))
  );
  
  const hubResult = await fetch(`${API_BASE}/hub/add`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      hub_address: hubAddress,
      hub_public_key: hubPubKeyHex,
      hub_signature: bytesToHex(base64ToBytes(hubSig)),
      inbox_public_key: inboxPubKeyHex,
      inbox_signature: bytesToHex(base64ToBytes(inboxSig)),
    }),
  }).then(r => r.json());
  
  console.log('Hub registration:', hubResult.status || hubResult.error || 'unknown');
  
  // Save keys
  const spaceKeys = {
    spaceId: invite.spaceId,
    hubAddress,
    hubPublicKey: hubPubKeyHex,
    hubPrivateKey: invite.hubKey,
    configPrivateKey: invite.configKey,
    secret: invite.secret,
    template: templateJson,
    inboxAddress,
    inboxSigningKey: {
      public_key: bytesToHex(new Uint8Array(inboxSigningKey.public_key)),
      private_key: bytesToHex(new Uint8Array(inboxSigningKey.private_key)),
    },
    inboxEncryptionKey: {
      public_key: bytesToHex(new Uint8Array(inboxEncryptionKey.public_key)),
      private_key: bytesToHex(new Uint8Array(inboxEncryptionKey.private_key)),
    },
    joinedAt: Date.now(),
  };
  
  const savedPath = saveSpaceKeys(invite.spaceId, spaceKeys);
  console.log('\n✅ Joined space:', invite.spaceId);
  console.log('Keys saved to:', savedPath);
}

async function cmdSend(spaceId, text) {
  const spaceKeys = loadSpaceKeys(spaceId);
  
  // Default channel - get from template or use known one
  // TODO: Parse from manifest
  let channelId = 'QmZWt1AYqsAMLuLg8iwmhmVqRjQnbAAWF7AHGPkWPNXEoc';
  
  // Try to get channel from stored info
  if (spaceKeys.defaultChannelId) {
    channelId = spaceKeys.defaultChannelId;
  }
  
  const timestamp = Date.now();
  const nonce = bytesToHex(randomBytes(16));
  const idContent = `${spaceId}:${channelId}:${spaceKeys.inboxAddress}:${nonce}:${timestamp}`;
  const messageId = bytesToHex(createHash('sha256').update(idContent).digest());
  
  // Build message
  const message = {
    channelId,
    spaceId,
    messageId,
    digestAlgorithm: 'sha256',
    nonce,
    createdDate: timestamp,
    modifiedDate: timestamp,
    lastModifiedHash: '',
    content: {
      type: 'post',
      senderId: spaceKeys.inboxAddress,
      text,
    },
    reactions: [],
    mentions: { memberIds: [], roleIds: [], channelIds: [] },
    publicKey: spaceKeys.inboxSigningKey.public_key,
  };
  
  // Sign message
  const msgBytes = new TextEncoder().encode(JSON.stringify(message));
  const sig = signEd448(
    bytesToBase64(hexToBytes(spaceKeys.inboxSigningKey.private_key)),
    bytesToBase64(msgBytes)
  );
  message.signature = bytesToHex(base64ToBytes(sig));
  
  // Wrap in hub payload
  const hubPayload = JSON.stringify({ type: 'message', message });
  
  // Encrypt with config key
  const ephemeral = generateX448();
  const configPrivKey = hexToBytes(spaceKeys.configPrivateKey);
  const configPubKeyB64 = getX448PubKey(bytesToBase64(configPrivKey));
  const configPubKey = base64ToBytes(configPubKeyB64);
  
  const encrypted = encryptInboxMessageBytes(
    [...configPubKey],
    ephemeral.private_key,
    [...new TextEncoder().encode(hubPayload)]
  );
  
  // Sign with hub key
  const hubSig = signEd448(
    bytesToBase64(hexToBytes(spaceKeys.hubPrivateKey)),
    bytesToBase64(new TextEncoder().encode(encrypted))
  );
  
  // Build sealed message
  const wsEnvelope = JSON.stringify({
    type: 'group',
    hub_address: spaceKeys.hubAddress,
    hub_public_key: spaceKeys.hubPublicKey,
    ephemeral_public_key: bytesToHex(new Uint8Array(ephemeral.public_key)),
    envelope: encrypted,
    hub_signature: bytesToHex(base64ToBytes(hubSig)),
  });
  
  // Send via WebSocket
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(WS_URL);
    
    ws.on('open', () => {
      ws.send(wsEnvelope);
      console.log('✅ Sent:', text);
      setTimeout(() => {
        ws.close();
        resolve();
      }, 1000);
    });
    
    ws.on('error', reject);
  });
}

async function cmdListen(spaceId, duration = 0) {
  const spaceKeys = loadSpaceKeys(spaceId);
  
  console.log('Space:', spaceId);
  console.log('Inbox:', spaceKeys.inboxAddress);
  console.log('Listening for messages...\n');
  
  const ws = new WebSocket(WS_URL);
  
  ws.on('open', () => {
    ws.send(JSON.stringify({
      type: 'listen',
      inbox_addresses: [spaceKeys.inboxAddress]
    }));
  });
  
  ws.on('message', async (data) => {
    try {
      const msg = JSON.parse(data.toString());
      if (!msg.encryptedContent) return;
      
      const envelope = JSON.parse(msg.encryptedContent);
      const innerEnvelope = JSON.parse(envelope.envelope);
      
      // Decrypt
      const configPrivKey = hexToBytes(spaceKeys.configPrivateKey);
      const ephPubKey = hexToBytes(envelope.ephemeral_public_key);
      
      const decrypted = decryptInboxMessage(
        [...configPrivKey],
        [...ephPubKey],
        innerEnvelope
      );
      
      const plaintext = new TextDecoder().decode(new Uint8Array(decrypted));
      const parsed = JSON.parse(plaintext);
      
      if (parsed.type === 'message' && parsed.message?.content?.text) {
        const sender = parsed.message.content.senderId;
        const isMe = sender === spaceKeys.inboxAddress;
        const displaySender = isMe ? 'Me' : sender.substring(0, 12) + '...';
        console.log(`[${new Date().toLocaleTimeString()}] ${displaySender}: ${parsed.message.content.text}`);
      }
    } catch (err) {
      // Silently ignore decrypt errors (control messages, etc)
    }
  });
  
  ws.on('error', (err) => console.error('Error:', err.message));
  ws.on('close', () => console.log('Disconnected'));
  
  if (duration > 0) {
    setTimeout(() => {
      ws.close();
      process.exit(0);
    }, duration * 1000);
  }
}

function cmdList() {
  if (!existsSync(SPACE_KEYS_DIR)) {
    console.log('No spaces joined yet.');
    return;
  }
  
  const files = readdirSync(SPACE_KEYS_DIR).filter(f => f.endsWith('.json'));
  if (files.length === 0) {
    console.log('No spaces joined yet.');
    return;
  }
  
  console.log('Joined spaces:\n');
  for (const file of files) {
    const keys = JSON.parse(readFileSync(path.join(SPACE_KEYS_DIR, file), 'utf8'));
    console.log(`  ${keys.spaceId}`);
    console.log(`    Inbox: ${keys.inboxAddress}`);
    console.log(`    Joined: ${new Date(keys.joinedAt).toLocaleString()}`);
    console.log();
  }
}

// ============ Main ============

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  
  if (!cmd || cmd === 'help' || cmd === '-h' || cmd === '--help') {
    console.log(`
Quorum Space CLI

Commands:
  join <invite-url>       Join a space from invite link
  send <space-id> <text>  Send a message to a space
  listen <space-id>       Listen for messages (Ctrl+C to stop)
  list                    List joined spaces

Examples:
  node space.mjs join "https://app.quorummessenger.com/#spaceId=..."
  node space.mjs send QmaQqr... "Hello!"
  node space.mjs listen QmaQqr...
`);
    return;
  }
  
  await initCrypto();
  
  switch (cmd) {
    case 'join':
      if (!args[0]) throw new Error('Usage: space join <invite-url>');
      await cmdJoin(args[0]);
      break;
    case 'send':
      if (!args[0] || !args[1]) throw new Error('Usage: space send <space-id> <text>');
      await cmdSend(args[0], args.slice(1).join(' '));
      break;
    case 'listen':
      if (!args[0]) throw new Error('Usage: space listen <space-id>');
      await cmdListen(args[0], parseInt(args[1]) || 0);
      break;
    case 'list':
      cmdList();
      break;
    default:
      console.error('Unknown command:', cmd);
      process.exit(1);
  }
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
