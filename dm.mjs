#!/usr/bin/env node
/**
 * Quorum DM CLI
 * 
 * Commands:
 *   dm send <address> <text> [-r reply-to-id]  Send a DM
 *   dm react <address> <msg-id> <emoji>        React to a message
 *   dm unreact <address> <msg-id> <emoji>      Remove a reaction
 *   dm delete <address> <msg-id>               Delete a message
 *   dm listen [timeout]                        Listen for DMs
 *   dm conversations                           List conversations
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const WebSocket = require('ws');
import { randomUUID } from 'crypto';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

import { 
  initCrypto, 
  senderX3DH, 
  receiverX3DH,
  newDoubleRatchet, 
  doubleRatchetEncrypt,
  doubleRatchetDecrypt,
  generateX448, 
  encryptInboxMessageBytes,
  decryptInboxMessage,
} from './src/crypto.mjs';
import { QuorumAPI } from './src/api.mjs';
import { createSecureStore } from './src/secure-store.mjs';

const DATA_DIR = join(homedir(), '.quorum-client');
const WS_URL = 'wss://api.quorummessenger.com/ws';
const API_BASE = 'https://api.quorummessenger.com';

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

// ============ Send Message ============

async function sendDM(recipientAddress, content, store, deviceKeyset, registration) {
  const api = new QuorumAPI();
  
  // Check for existing session
  let session = store.getSession(recipientAddress);
  
  // Fetch fresh device info to check if inbox changed
  const recipient = await api.getUser(recipientAddress);
  if (!recipient?.device_registrations?.length) {
    throw new Error('Recipient not found or has no devices');
  }
  const device = recipient.device_registrations[0];
  const currentInboxAddress = device.inbox_registration.inbox_address;
  
  // If inbox address changed, we need to start fresh (device re-registered)
  if (session && session.sending_inbox?.inbox_address !== currentInboxAddress) {
    console.log('📱 Device re-registered, starting new session...');
    session = null;
  }
  
  if (!session) {
    // First message - establish new session with X3DH
    return await sendFirstMessage(recipientAddress, content, device, recipient, store, deviceKeyset, registration);
  } else {
    // Follow-up message - use existing ratchet state
    return await sendFollowUpMessage(recipientAddress, content, session, device, store, deviceKeyset, registration);
  }
}

async function sendFirstMessage(recipientAddress, content, device, recipient, store, deviceKeyset, registration) {
  const ephemeralKey = generateX448();
  const receiverIdentityKey = [...Buffer.from(device.identity_public_key, 'hex')];
  const receiverPreKey = [...Buffer.from(device.pre_public_key, 'hex')];
  
  // X3DH key exchange
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
  
  // Build message
  const messageId = randomUUID();
  const messagePayload = JSON.stringify({
    messageId,
    content: { ...content, senderId: registration.user_address },
    createdDate: Date.now(),
    modifiedDate: Date.now(),
  });
  
  const { ratchet_state: newState, envelope: msgEnvelope } = doubleRatchetEncrypt(ratchetState, messagePayload);
  
  // Build init envelope with full handshake info
  const initEnvelope = {
    user_address: registration.user_address,
    display_name: getDisplayName(),
    return_inbox_address: deviceKeyset.inbox_address,
    return_inbox_encryption_key: bytesToHex(new Uint8Array(deviceKeyset.inbox_encryption_key.public_key)),
    return_inbox_public_key: bytesToHex(new Uint8Array(deviceKeyset.inbox_signing_key.public_key)),
    return_inbox_private_key: bytesToHex(new Uint8Array(deviceKeyset.inbox_signing_key.private_key)),
    identity_public_key: bytesToHex(new Uint8Array(deviceKeyset.identity_key.public_key)),
    tag: deviceKeyset.inbox_address,
    message: msgEnvelope,
    type: 'direct',
  };
  
  const inboxEncKey = [...Buffer.from(device.inbox_registration.inbox_encryption_public_key, 'hex')];
  const sealedEnvelope = encryptInboxMessageBytes(
    inboxEncKey, 
    ephemeralKey.private_key, 
    [...Buffer.from(JSON.stringify(initEnvelope), 'utf-8')]
  );
  
  const sealedMessage = {
    inbox_address: device.inbox_registration.inbox_address,
    ephemeral_public_key: bytesToHex(new Uint8Array(ephemeralKey.public_key)),
    envelope: sealedEnvelope,
    hub_address: '',
    hub_public_key: '',
    hub_signature: '',
    timestamp: Date.now(),
  };
  
  // Send via API
  await fetch(`${API_BASE}/inbox`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(sealedMessage),
  });
  
  // Save session for follow-up messages
  store.saveSession(recipientAddress, {
    ratchet_state: newState,
    sending_inbox: {
      inbox_address: device.inbox_registration.inbox_address,
      inbox_encryption_key: device.inbox_registration.inbox_encryption_public_key,
    },
    recipient_address: recipientAddress,
    sender_name: recipient.display_name || recipientAddress.substring(0, 12),
  });
  
  return { sent: true, messageId, firstMessage: true };
}

async function sendFollowUpMessage(recipientAddress, content, session, device, store, deviceKeyset, registration) {
  // Build message
  const messageId = randomUUID();
  const messagePayload = JSON.stringify({
    messageId,
    content: { ...content, senderId: registration.user_address },
    createdDate: Date.now(),
    modifiedDate: Date.now(),
  });
  
  // Ratchet state is stored as a JSON string - pass it directly to WASM
  // (The WASM expects a string, not a parsed object)
  const ratchetState = session.ratchet_state;
  
  // Encrypt with existing ratchet (continues the conversation)
  const { ratchet_state: newState, envelope } = doubleRatchetEncrypt(ratchetState, messagePayload);
  
  const ephemeralKey = generateX448();
  
  // Build payload with return info (in case they need to reply)
  const payload = JSON.stringify({
    return_inbox_address: deviceKeyset.inbox_address,
    return_inbox_encryption_key: bytesToHex(new Uint8Array(deviceKeyset.inbox_encryption_key.public_key)),
    return_inbox_public_key: bytesToHex(new Uint8Array(deviceKeyset.inbox_signing_key.public_key)),
    return_inbox_private_key: bytesToHex(new Uint8Array(deviceKeyset.inbox_signing_key.private_key)),
    user_address: registration.user_address,
    identity_public_key: bytesToHex(new Uint8Array(deviceKeyset.identity_key.public_key)),
    tag: deviceKeyset.inbox_address,
    display_name: getDisplayName(),
    message: envelope,
    type: 'direct',
  });
  
  const ciphertext = encryptInboxMessageBytes(
    [...Buffer.from(session.sending_inbox.inbox_encryption_key, 'hex')],
    ephemeralKey.private_key,
    [...Buffer.from(payload, 'utf-8')]
  );
  
  const sealedMessage = {
    inbox_address: session.sending_inbox.inbox_address,
    ephemeral_public_key: bytesToHex(new Uint8Array(ephemeralKey.public_key)),
    envelope: ciphertext,
    hub_address: '',
    hub_public_key: '',
    hub_signature: '',
    timestamp: Date.now(),
  };
  
  // Send via API
  await fetch(`${API_BASE}/inbox`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(sealedMessage),
  });
  
  // Update session with new ratchet state
  session.ratchet_state = newState;
  store.saveSession(recipientAddress, session);
  
  return { sent: true, messageId, firstMessage: false };
}

function getDisplayName() {
  try {
    const profile = JSON.parse(readFileSync(join(DATA_DIR, 'profile.json'), 'utf-8'));
    return profile.displayName || 'Quorum User';
  } catch {
    return 'Quorum User';
  }
}

// ============ Commands ============

async function cmdSend(recipientAddress, text, replyToId, store, deviceKeyset, registration) {
  const content = { type: 'post', text };
  if (replyToId) {
    content.repliesToMessageId = replyToId;
  }
  
  const result = await sendDM(recipientAddress, content, store, deviceKeyset, registration);
  console.log(`✅ Sent to ${recipientAddress.substring(0, 20)}...`);
  console.log(`   id: ${result.messageId}`);
}

async function cmdReact(recipientAddress, messageId, emoji, store, deviceKeyset, registration) {
  const content = {
    type: 'reaction',
    reaction: emoji,
    messageId: messageId,
  };
  
  await sendDM(recipientAddress, content, store, deviceKeyset, registration);
  console.log(`✅ Reacted with ${emoji}`);
}

async function cmdUnreact(recipientAddress, messageId, emoji, store, deviceKeyset, registration) {
  const content = {
    type: 'remove-reaction',
    reaction: emoji,
    messageId: messageId,
  };
  
  await sendDM(recipientAddress, content, store, deviceKeyset, registration);
  console.log(`✅ Removed reaction ${emoji}`);
}

async function cmdDelete(recipientAddress, messageId, store, deviceKeyset, registration) {
  const content = {
    type: 'remove-message',
    removeMessageId: messageId,
  };
  
  await sendDM(recipientAddress, content, store, deviceKeyset, registration);
  console.log(`✅ Deleted message ${messageId.substring(0, 16)}...`);
}

async function cmdListen(duration, store, deviceKeyset, registration) {
  const inboxAddress = deviceKeyset.inbox_address;
  console.log(`Listening on inbox: ${inboxAddress}`);
  
  const ws = new WebSocket(WS_URL);
  
  ws.on('open', () => {
    ws.send(JSON.stringify({ type: 'listen', inbox_addresses: [inboxAddress] }));
    console.log('Connected — waiting for messages...\n');
  });
  
  ws.on('message', async (data) => {
    try {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'ack') return;
      if (!msg.encryptedContent) return;
      
      const envelope = JSON.parse(msg.encryptedContent);
      const ephPubKey = hexToBytes(envelope.ephemeral_public_key);
      
      // Try to decrypt with inbox key
      const decrypted = decryptInboxMessage(
        [...new Uint8Array(deviceKeyset.inbox_encryption_key.private_key)],
        [...ephPubKey],
        JSON.parse(envelope.envelope)
      );
      
      const outer = JSON.parse(new TextDecoder().decode(new Uint8Array(decrypted)));
      
      // Get or create session for this sender
      const senderAddress = outer.user_address || outer.return_inbox_address;
      let session = store.getSession(senderAddress);
      
      if (!session && outer.return_inbox_address) {
        // Initialize session from received message
        const senderIdentityKey = hexToBytes(outer.identity_public_key);
        const senderPreKey = ephPubKey;
        
        const sessionKeyB64 = receiverX3DH(
          deviceKeyset.identity_key.private_key,
          deviceKeyset.pre_key.private_key,
          [...senderIdentityKey],
          [...senderPreKey],
          96
        );
        
        const rootKey = [...Buffer.from(sessionKeyB64, 'base64')];
        
        session = {
          ratchet_state: newDoubleRatchet({
            session_key: rootKey.slice(0, 32),
            sending_header_key: rootKey.slice(64, 96),
            next_receiving_header_key: rootKey.slice(32, 64),
            is_sender: false,
            receiving_ephemeral_key: [...senderPreKey],
          }),
          sending_inbox: {
            inbox_address: outer.return_inbox_address,
            inbox_encryption_key: outer.return_inbox_encryption_key,
          },
          recipient_address: senderAddress,
          sender_name: outer.display_name || senderAddress.substring(0, 12),
        };
      }
      
      if (!session) {
        console.log(`[${new Date().toLocaleTimeString()}] Unknown sender, cannot decrypt`);
        return;
      }
      
      // Decrypt the actual message
      const { ratchet_state: newState, plaintext } = doubleRatchetDecrypt(
        session.ratchet_state,
        outer.message
      );
      
      // Update session
      session.ratchet_state = newState;
      if (outer.return_inbox_address) {
        session.sending_inbox = {
          inbox_address: outer.return_inbox_address,
          inbox_encryption_key: outer.return_inbox_encryption_key,
        };
      }
      store.saveSession(session.recipient_address || senderAddress, session);
      
      // Parse and display message
      const msgData = JSON.parse(plaintext);
      const content = msgData.content;
      const displayName = session.sender_name || senderAddress?.substring(0, 12) || 'Unknown';
      
      if (content.type === 'post' && content.text) {
        const replyInfo = content.repliesToMessageId ? ` ↩️ ${content.repliesToMessageId.substring(0, 8)}` : '';
        console.log(`\n📨 [${new Date().toLocaleTimeString()}] ${displayName}:`);
        console.log(`   ${content.text}${replyInfo}`);
        console.log(`   id: ${msgData.messageId}`);
      } else if (content.type === 'reaction') {
        console.log(`[${new Date().toLocaleTimeString()}] ${displayName} reacted ${content.reaction} to ${content.messageId?.substring(0, 12)}...`);
      } else if (content.type === 'remove-reaction') {
        console.log(`[${new Date().toLocaleTimeString()}] ${displayName} removed ${content.reaction} from ${content.messageId?.substring(0, 12)}...`);
      } else if (content.type === 'remove-message') {
        console.log(`[${new Date().toLocaleTimeString()}] ${displayName} deleted message ${content.removeMessageId?.substring(0, 12)}...`);
      } else {
        console.log(`[${new Date().toLocaleTimeString()}] ${displayName}: [${content.type}]`);
      }
      
    } catch (err) {
      // Silently ignore decrypt errors
      if (process.env.DEBUG) console.error('Decrypt error:', err.message);
    }
  });
  
  ws.on('error', (err) => console.error('WebSocket error:', err.message));
  ws.on('close', () => console.log('Disconnected'));
  
  if (duration > 0) {
    setTimeout(() => {
      console.log('\nTimeout — closing');
      ws.close();
      process.exit(0);
    }, duration * 1000);
  }
}

async function cmdConversations(store) {
  const sessions = store.listSessions();
  
  if (sessions.length === 0) {
    console.log('No conversations yet.');
    return;
  }
  
  console.log('Conversations:\n');
  for (const tag of sessions) {
    const session = store.getSession(tag);
    const name = session?.sender_name || tag.substring(0, 20);
    const addr = session?.recipient_address || tag;
    console.log(`  ${name}`);
    console.log(`    Address: ${addr}`);
    console.log();
  }
}

// ============ Main ============

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  
  if (!cmd || cmd === 'help' || cmd === '-h' || cmd === '--help') {
    console.log(`
Quorum DM CLI

Commands:
  send <address> <text> [-r reply-to-id]   Send a direct message
  react <address> <msg-id> <emoji>         React to a message
  unreact <address> <msg-id> <emoji>       Remove a reaction
  delete <address> <msg-id>                Delete a message
  listen [timeout_seconds]                 Listen for incoming DMs
  conversations                            List conversations

Examples:
  node dm.mjs send QmRecipient... "Hello!"
  node dm.mjs send QmRecipient... "Reply!" -r abc123-def456...
  node dm.mjs react QmRecipient... abc123-def456... 👍
  node dm.mjs unreact QmRecipient... abc123-def456... 👍
  node dm.mjs delete QmRecipient... abc123-def456...
  node dm.mjs listen
  node dm.mjs listen 60
`);
    return;
  }
  
  await initCrypto();
  
  // Load identity
  const store = await createSecureStore(DATA_DIR);
  const deviceKeyset = await store.getDeviceKeyset();
  const registration = store.getRegistration();
  
  if (!deviceKeyset || !registration) {
    console.error('No identity found. Run: node cli.mjs register <name>');
    process.exit(1);
  }
  
  console.log('🔐 Using OS keychain for key storage');
  
  switch (cmd) {
    case 'send': {
      if (!args[0] || !args[1]) {
        throw new Error('Usage: dm send <address> <text> [-r reply-to-id]');
      }
      const address = args[0];
      const rIndex = args.indexOf('-r');
      let replyToId = null;
      let textParts = args.slice(1);
      
      if (rIndex > 0) {
        replyToId = args[rIndex + 1];
        textParts = textParts.filter((_, i) => i !== rIndex - 1 && i !== rIndex);
      }
      
      const text = textParts.join(' ');
      if (!text) throw new Error('Usage: dm send <address> <text> [-r reply-to-id]');
      await cmdSend(address, text, replyToId, store, deviceKeyset, registration);
      break;
    }
    case 'react': {
      if (!args[0] || !args[1] || !args[2]) {
        throw new Error('Usage: dm react <address> <msg-id> <emoji>');
      }
      await cmdReact(args[0], args[1], args[2], store, deviceKeyset, registration);
      break;
    }
    case 'unreact': {
      if (!args[0] || !args[1] || !args[2]) {
        throw new Error('Usage: dm unreact <address> <msg-id> <emoji>');
      }
      await cmdUnreact(args[0], args[1], args[2], store, deviceKeyset, registration);
      break;
    }
    case 'delete': {
      if (!args[0] || !args[1]) {
        throw new Error('Usage: dm delete <address> <msg-id>');
      }
      await cmdDelete(args[0], args[1], store, deviceKeyset, registration);
      break;
    }
    case 'listen':
      await cmdListen(parseInt(args[0]) || 0, store, deviceKeyset, registration);
      break;
    case 'conversations':
      await cmdConversations(store);
      break;
    default:
      console.error('Unknown command:', cmd);
      process.exit(1);
  }
}

main().catch(err => {
  console.error('Error:', err.message);
  if (process.env.DEBUG) console.error(err.stack);
  process.exit(1);
});
