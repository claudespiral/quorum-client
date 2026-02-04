#!/usr/bin/env node
/**
 * Quorum DM CLI
 * 
 * Global flags:
 *   -i, --identity <name>    Use specific identity (default: "default")
 * 
 * Identity commands:
 *   dm identity list                           List all identities
 *   dm identity create <name>                  Create new identity
 *   dm identity show                           Show current identity info
 *   dm identity rename <old> <new>             Rename an identity
 *   dm identity delete <name>                  Delete an identity
 * 
 * Message commands:
 *   dm send <address> <text> [-r reply-to-id]  Send a DM
 *   dm embed <address> <image-path> [-r id]    Send an image
 *   dm edit <address> <msg-id> <new-text>      Edit a message
 *   dm react <address> <msg-id> <emoji>        React to a message
 *   dm unreact <address> <msg-id> <emoji>      Remove a reaction
 *   dm delete <address> <msg-id>               Delete a message
 *   dm listen [timeout]                        Listen for DMs
 *   dm conversations                           List conversations
 *   dm status <address>                        Show ratchet health for a conversation
 *   dm reset <address>                         Reset session (fixes out-of-sync ratchet)
 *   dm sync                                    Sync local keyset with API registration
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const WebSocket = require('ws');
import { randomUUID } from 'crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, renameSync, rmSync } from 'fs';
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
  generateEd448,
  deriveAddress,
  encryptInboxMessageBytes,
  decryptInboxMessage,
} from './src/crypto.mjs';
import { QuorumAPI } from './src/api.mjs';
import { createSecureStore } from './src/secure-store.mjs';

const BASE_DIR = process.env.QUORUM_BASE_DIR || join(homedir(), '.quorum-client');
const WS_URL = 'wss://api.quorummessenger.com/ws';
const API_BASE = 'https://api.quorummessenger.com';

// Current identity directory (set in main)
let IDENTITY_DIR = null;

// ============ Identity Management ============

function getIdentitiesDir() {
  const dir = join(BASE_DIR, 'identities');
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

function listIdentities() {
  const dir = getIdentitiesDir();
  const identities = readdirSync(dir, { withFileTypes: true })
    .filter(d => d.isDirectory())
    .map(d => d.name);
  
  // Also check for legacy default location (keys stored in keychain, but registration.json exists)
  const legacyReg = join(BASE_DIR, 'keys', 'registration.json');
  if (existsSync(legacyReg) && !identities.includes('default')) {
    // Migrate legacy to identities/default
    const legacyDir = join(BASE_DIR, 'keys');
    const newDir = join(getIdentitiesDir(), 'default');
    const newKeysDir = join(newDir, 'keys');
    if (!existsSync(newDir)) {
      mkdirSync(newKeysDir, { recursive: true });
      mkdirSync(join(newDir, 'sessions'), { recursive: true });
      // Move registration file to keys/ subdirectory (QuorumStore expects it there)
      if (existsSync(join(legacyDir, 'registration.json'))) {
        renameSync(join(legacyDir, 'registration.json'), join(newKeysDir, 'registration.json'));
      }
      // Copy profile if exists (stays in root of identity dir)
      if (existsSync(join(BASE_DIR, 'profile.json'))) {
        renameSync(join(BASE_DIR, 'profile.json'), join(newDir, 'profile.json'));
      }
      // Move sessions
      if (existsSync(join(BASE_DIR, 'sessions'))) {
        renameSync(join(BASE_DIR, 'sessions'), join(newDir, 'sessions'));
      }
      console.log('📦 Migrated legacy identity to "default"');
    }
    identities.unshift('default');
  }
  
  return identities;
}

function getIdentityDir(name) {
  return join(getIdentitiesDir(), name);
}

function identityExists(name) {
  return existsSync(getIdentityDir(name));
}

async function createIdentity(name) {
  if (identityExists(name)) {
    throw new Error(`Identity "${name}" already exists`);
  }
  
  const dir = getIdentityDir(name);
  mkdirSync(dir, { recursive: true });
  
  // Use QuorumClient for full registration flow
  const { QuorumClient } = await import('./src/client.mjs');
  const client = new QuorumClient({ dataDir: dir });
  await client.init();
  await client.register(name);
  
  return { name, address: client.registration.user_address };
}

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
  
  if (session && session.sending_inbox?.inbox_address) {
    // Check if recipient's inbox has changed (device re-registration)
    try {
      const recipient = await api.getUser(recipientAddress);
      if (recipient?.device_registrations?.length) {
        const currentInbox = recipient.device_registrations[0].inbox_registration?.inbox_address;
        const cachedInbox = session.sending_inbox.inbox_address;
        
        if (currentInbox && cachedInbox !== currentInbox) {
          console.log(`⚠️  Recipient's inbox changed - resetting session for fresh X3DH`);
          console.log(`   Cached: ${cachedInbox.substring(0, 20)}...`);
          console.log(`   Current: ${currentInbox.substring(0, 20)}...`);
          store.deleteSession(recipientAddress);
          session = null;
          // Fall through to first message path below
        }
      }
    } catch (e) {
      // API error - proceed with cached session
      console.log(`⚠️  Could not verify recipient inbox: ${e.message}`);
    }
    
    if (session) {
      // Check ratchet health - warn if potentially out of sync
      try {
        const ratchet = JSON.parse(session.ratchet_state);
        const totalSent = (ratchet.current_sending_chain_length || 0) + (ratchet.previous_sending_chain_length || 0);
        const totalRecv = (ratchet.current_receiving_chain_length || 0) + (ratchet.previous_receiving_chain_length || 0);
        
        if (totalSent > 10 && totalRecv === 0) {
          console.log(`⚠️  Warning: Sent ${totalSent} messages without receiving any.`);
          console.log(`   Ratchet may be out of sync. Use 'dm status <address>' to check,`);
          console.log(`   or 'dm reset <address>' to start fresh.`);
        }
      } catch {}
      
      // Use existing session
      return await sendFollowUpMessage(recipientAddress, content, session, null, store, deviceKeyset, registration);
    }
  }
  
  // No session - fetch device info from API to establish new session
  const recipient = await api.getUser(recipientAddress);
  if (!recipient?.device_registrations?.length) {
    throw new Error('Recipient not found or has no devices');
  }
  const device = recipient.device_registrations[0];
  
  // First message - establish new session with X3DH
  return await sendFirstMessage(recipientAddress, content, device, recipient, store, deviceKeyset, registration);
}

async function sendFirstMessage(recipientAddress, content, device, recipient, store, deviceKeyset, registration) {
  const ephemeralKey = generateX448();
  const receiverIdentityKey = [...Buffer.from(device.identity_public_key, 'hex')];
  const receiverPreKey = [...Buffer.from(device.pre_public_key, 'hex')];
  
  // Generate conversation-specific inbox keypairs (like mobile does)
  // X448 for encryption, Ed448 for signing, derive address from Ed448 public key
  const conversationId = `${recipientAddress}/${recipientAddress}`;
  const convEncryptionKey = generateX448();
  const convSigningKey = generateEd448();
  const convInboxAddress = deriveAddress(convSigningKey.public_key);
  
  // Save conversation inbox keypair for receiving replies
  store.saveConversationInboxKeypair({
    conversationId,
    inboxAddress: convInboxAddress,
    encryptionPublicKey: convEncryptionKey.public_key,
    encryptionPrivateKey: convEncryptionKey.private_key,
    signingPublicKey: convSigningKey.public_key,
    signingPrivateKey: convSigningKey.private_key,
  });
  
  console.log(`📥 Created conversation inbox: ${convInboxAddress.substring(0, 20)}...`);
  
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
  
  // Build message with full structure (matching mobile app format)
  const messageId = randomUUID();
  const now = Date.now();
  const messagePayload = JSON.stringify({
    messageId: `${messageId}-${now}`,
    channelId: recipientAddress,
    spaceId: recipientAddress,
    digestAlgorithm: "SHA-256",
    nonce: messageId,
    createdDate: now,
    modifiedDate: now,
    lastModifiedHash: "",
    content: content.senderId ? content : { ...content, senderId: registration.user_address },
    reactions: [],
    mentions: { memberIds: [], roleIds: [], channelIds: [] },
  });
  
  const { ratchet_state: newState, envelope: msgEnvelope } = doubleRatchetEncrypt(ratchetState, messagePayload);
  
  // Build init envelope with conversation-specific inbox as return address (like mobile)
  const initEnvelope = {
    user_address: registration.user_address,
    display_name: getDisplayName(),
    return_inbox_address: convInboxAddress,
    return_inbox_encryption_key: bytesToHex(new Uint8Array(convEncryptionKey.public_key)),
    return_inbox_public_key: bytesToHex(new Uint8Array(convSigningKey.public_key)),
    return_inbox_private_key: bytesToHex(new Uint8Array(convSigningKey.private_key)),
    identity_public_key: bytesToHex(new Uint8Array(deviceKeyset.identity_key.public_key)),
    tag: convInboxAddress,
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
    receiving_inbox: {
      inbox_address: convInboxAddress,
    },
    // Store X3DH ephemeral key for reuse in subsequent init envelopes (until session confirmed)
    x3dh_ephemeral_public_key: bytesToHex(new Uint8Array(ephemeralKey.public_key)),
    x3dh_ephemeral_private_key: bytesToHex(new Uint8Array(ephemeralKey.private_key)),
    recipient_address: recipientAddress,
    sender_name: recipient.display_name || recipientAddress.substring(0, 12),
  });
  
  return { sent: true, messageId, firstMessage: true, conversationInbox: convInboxAddress };
}

async function sendFollowUpMessage(recipientAddress, content, session, device, store, deviceKeyset, registration) {
  // For follow-up messages to device inbox (before we know conversation inbox),
  // we MUST wrap in InitializationEnvelope format so the device inbox processing
  // path can handle it correctly. The mobile app's init processing path can
  // handle messages where the inner content is a DR envelope (trial decryption).
  const messageId = randomUUID();
  const now = Date.now();
  const messagePayload = JSON.stringify({
    messageId: `${messageId}-${now}`,
    channelId: recipientAddress,
    spaceId: recipientAddress,
    digestAlgorithm: "SHA-256",
    nonce: messageId,
    createdDate: now,
    modifiedDate: now,
    lastModifiedHash: "",
    content: content.senderId ? content : { ...content, senderId: registration.user_address },
    reactions: [],
    mentions: { memberIds: [], roleIds: [], channelIds: [] },
  });
  
  const ratchetState = session.ratchet_state;
  
  // Encrypt with existing ratchet - produces Type 2 envelope (protocol_identifier: 512)
  const { ratchet_state: newState, envelope } = doubleRatchetEncrypt(ratchetState, messagePayload);
  
  const ephemeralKey = generateX448();
  
  // Wrap in InitializationEnvelope format so device inbox path can process it
  // The mobile app will unseal this, see it has user_address, and try to process
  // The inner 'message' field contains the DR envelope which it will decrypt
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
  console.log('📤 Sending to inbox:', session.sending_inbox.inbox_address);
  console.log('📤 Message content type:', content.type);
  const response = await fetch(`${API_BASE}/inbox`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(sealedMessage),
  });
  console.log('📤 API response:', response.status, response.statusText);
  
  // Update session with new ratchet state
  session.ratchet_state = newState;
  store.saveSession(recipientAddress, session);
  
  return { sent: true, messageId, firstMessage: false };
}

// Send Type 2 message (continuation/reaction) - envelope is sent directly without Type 1 wrapper
async function sendType2Message(recipientAddress, content, session, store, deviceKeyset, registration) {
  const messageId = randomUUID();
  const now = Date.now();
  const messagePayload = JSON.stringify({
    messageId: `${messageId}-${now}`,
    channelId: recipientAddress,
    spaceId: recipientAddress,
    digestAlgorithm: "SHA-256",
    nonce: messageId,
    createdDate: now,
    modifiedDate: now,
    lastModifiedHash: "",
    content: content.senderId ? content : { ...content, senderId: registration.user_address },
    reactions: [],
    mentions: { memberIds: [], roleIds: [], channelIds: [] },
  });
  
  const ratchetState = session.ratchet_state;
  
  // Encrypt - this produces Type 2 envelope (protocol_identifier: 512, message_header, message_body)
  const { ratchet_state: newState, envelope } = doubleRatchetEncrypt(ratchetState, messagePayload);
  
  const ephemeralKey = generateX448();
  
  // For Type 2, send the envelope DIRECTLY without wrapping in Type 1 structure
  // The envelope already has protocol_identifier: 512
  const ciphertext = encryptInboxMessageBytes(
    [...Buffer.from(session.sending_inbox.inbox_encryption_key, 'hex')],
    ephemeralKey.private_key,
    [...Buffer.from(envelope, 'utf-8')]  // envelope is already the Type 2 JSON
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
  
  console.log('📤 Sending Type 2 to inbox:', session.sending_inbox.inbox_address);
  console.log('📤 Message content type:', content.type);
  const response = await fetch(`${API_BASE}/inbox`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(sealedMessage),
  });
  console.log('📤 API response:', response.status, response.statusText);
  
  // Update session with new ratchet state
  session.ratchet_state = newState;
  store.saveSession(recipientAddress, session);
  
  return { sent: true, messageId, firstMessage: false };
}

function getDisplayName() {
  try {
    const profile = JSON.parse(readFileSync(join(IDENTITY_DIR, 'profile.json'), 'utf-8'));
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

async function cmdReact(recipientAddress, targetMessageId, emoji, store, deviceKeyset, registration) {
  // Match exact field order from mobile app: type, senderId, messageId, reaction
  const content = {
    type: 'reaction',
    senderId: registration.user_address,
    messageId: targetMessageId,
    reaction: emoji,
  };
  
  // Check for existing session - reactions MUST use Type 2 envelope
  const session = store.getSession(recipientAddress);
  if (!session || !session.sending_inbox?.inbox_address) {
    throw new Error('No existing session - cannot send reaction without prior conversation');
  }
  
  // Use Type 2 format (continuation message)
  await sendType2Message(recipientAddress, content, session, store, deviceKeyset, registration);
  console.log(`✅ Reacted with ${emoji}`);
}

async function cmdUnreact(recipientAddress, messageId, emoji, store, deviceKeyset, registration) {
  const content = {
    type: 'remove-reaction',
    reaction: emoji,
    messageId: messageId,
  };
  
  // Unreact must use existing session with Type 2
  const session = store.getSession(recipientAddress);
  if (!session || !session.sending_inbox?.inbox_address) {
    throw new Error('No existing session - cannot unreact without prior conversation');
  }
  
  await sendType2Message(recipientAddress, content, session, store, deviceKeyset, registration);
  console.log(`✅ Removed reaction ${emoji}`);
}

async function cmdDelete(recipientAddress, messageId, store, deviceKeyset, registration) {
  const content = {
    type: 'remove-message',
    removeMessageId: messageId,
  };
  
  // Delete must use existing session with Type 2
  const session = store.getSession(recipientAddress);
  if (!session || !session.sending_inbox?.inbox_address) {
    throw new Error('No existing session - cannot delete without prior conversation');
  }
  
  await sendType2Message(recipientAddress, content, session, store, deviceKeyset, registration);
  console.log(`✅ Deleted message ${messageId.substring(0, 16)}...`);
}

async function cmdEmbed(recipientAddress, imagePath, replyToId, store, deviceKeyset, registration) {
  // Read the image file
  const imageData = readFileSync(imagePath);
  
  // Detect mime type from extension
  const ext = imagePath.toLowerCase().split('.').pop();
  const mimeTypes = {
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'gif': 'image/gif',
    'webp': 'image/webp',
  };
  const mimeType = mimeTypes[ext] || 'application/octet-stream';
  
  // Convert to base64 data URL
  const base64 = imageData.toString('base64');
  const dataUrl = `data:${mimeType};base64,${base64}`;
  
  console.log(`📎 Sending ${ext.toUpperCase()} image (${(imageData.length / 1024).toFixed(1)} KB)...`);
  
  const content = {
    type: 'embed',
    imageUrl: dataUrl,
  };
  
  if (replyToId) {
    content.repliesToMessageId = replyToId;
  }
  
  const result = await sendDM(recipientAddress, content, store, deviceKeyset, registration);
  console.log(`✅ Image sent to ${recipientAddress.substring(0, 20)}...`);
  console.log(`   id: ${result.messageId}`);
}

async function cmdEdit(recipientAddress, messageId, newText, store, deviceKeyset, registration) {
  const content = {
    type: 'edit-message',
    originalMessageId: messageId,
    editedText: newText,
    editedAt: Date.now(),
    editNonce: randomUUID(),
  };
  
  // Edit should use Type 2 for existing sessions
  const session = store.getSession(recipientAddress);
  if (!session || !session.sending_inbox?.inbox_address) {
    throw new Error('No existing session - cannot edit without prior conversation');
  }
  
  await sendType2Message(recipientAddress, content, session, store, deviceKeyset, registration);
  console.log(`✅ Edited message ${messageId.substring(0, 16)}...`);
}

async function cmdListen(duration, store, deviceKeyset, registration) {
  const deviceInbox = deviceKeyset.inbox_address;
  const conversationInboxes = store.listConversationInboxes();
  const allInboxes = [deviceInbox, ...conversationInboxes];
  
  console.log(`Listening on inbox: ${deviceInbox}`);
  if (conversationInboxes.length > 0) {
    console.log(`Plus ${conversationInboxes.length} conversation inbox(es)`);
  }
  
  const ws = new WebSocket(WS_URL);
  
  ws.on('open', () => {
    ws.send(JSON.stringify({ type: 'listen', inbox_addresses: allInboxes }));
    console.log('Connected — waiting for messages...\n');
  });
  
  ws.on('message', async (data) => {
    try {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'ack') return;
      if (!msg.encryptedContent) return;
      
      const envelope = JSON.parse(msg.encryptedContent);
      const ephPubKey = hexToBytes(envelope.ephemeral_public_key);
      const receivedOnInbox = msg.inboxAddress;
      
      // Determine which keypair to use for decryption
      let decryptionPrivKey;
      if (receivedOnInbox === deviceInbox) {
        // Received on device inbox - use device keys
        decryptionPrivKey = [...new Uint8Array(deviceKeyset.inbox_encryption_key.private_key)];
      } else {
        // Check if it's a conversation inbox
        const convKeypair = store.getConversationInboxKeypairByAddress(receivedOnInbox);
        if (convKeypair) {
          decryptionPrivKey = convKeypair.encryptionPrivateKey;
        } else {
          // Unknown inbox, try device key as fallback
          decryptionPrivKey = [...new Uint8Array(deviceKeyset.inbox_encryption_key.private_key)];
        }
      }
      
      // Decrypt the sealed envelope
      const decrypted = decryptInboxMessage(
        decryptionPrivKey,
        [...ephPubKey],
        JSON.parse(envelope.envelope)
      );
      
      const outer = JSON.parse(new TextDecoder().decode(new Uint8Array(decrypted)));
      
      // Check if this is a raw DR envelope (no InitializationEnvelope wrapper)
      // Raw DR envelopes have protocol_identifier, message_header, message_body
      const isRawDREnvelope = outer.protocol_identifier !== undefined && outer.message_header;
      
      // Get or create session for this sender
      let senderAddress = outer.user_address || outer.return_inbox_address;
      let session = senderAddress ? store.getSession(senderAddress) : null;
      const isInitEnvelope = outer.identity_public_key && outer.return_inbox_address;
      
      // Helper to create fresh session from init envelope
      const createFreshSession = () => {
        const senderIdentityKey = hexToBytes(outer.identity_public_key);
        const senderEphemeralKey = ephPubKey;
        
        const sessionKeyB64 = receiverX3DH(
          deviceKeyset.identity_key.private_key,
          deviceKeyset.pre_key.private_key,
          [...senderIdentityKey],
          [...senderEphemeralKey],
          96
        );
        
        const rootKey = [...Buffer.from(sessionKeyB64, 'base64')];
        
        // NOTE: Header key slices are NOT swapped - WASM handles perspective via is_sender
        return {
          ratchet_state: newDoubleRatchet({
            session_key: rootKey.slice(0, 32),
            sending_header_key: rootKey.slice(32, 64),       // Same as sender
            next_receiving_header_key: rootKey.slice(64, 96), // Same as sender
            is_sender: false,
            sending_ephemeral_private_key: deviceKeyset.pre_key.private_key, // Our pre-key
            receiving_ephemeral_key: [...senderEphemeralKey],
          }),
          sending_inbox: {
            inbox_address: outer.return_inbox_address,
            inbox_encryption_key: outer.return_inbox_encryption_key,
          },
          recipient_address: senderAddress,
          sender_name: outer.display_name || senderAddress.substring(0, 12),
        };
      };
      
      // Helper to safely try decryption
      const tryDecrypt = (ratchetState, envelope) => {
        try {
          const result = doubleRatchetDecrypt(ratchetState, envelope);
          // WASM returns error messages in result instead of throwing
          if (result.message.includes('Decryption failed') || 
              result.message.includes('aead') ||
              result.message.includes('invalid')) {
            return null;
          }
          return result;
        } catch (e) {
          return null;
        }
      };
      
      let decryptResult = null;
      
      // Handle raw DR envelopes (no InitializationEnvelope wrapper)
      // These don't have user_address, so we try all known sessions
      if (isRawDREnvelope) {
        const allSessions = store.listSessions();
        for (const tag of allSessions) {
          const candidateSession = store.getSession(tag);
          if (!candidateSession) continue;
          
          decryptResult = tryDecrypt(candidateSession.ratchet_state, outer);
          if (decryptResult) {
            session = candidateSession;
            senderAddress = candidateSession.recipient_address || tag;
            break;
          }
        }
        
        if (!decryptResult) {
          if (process.env.DEBUG) console.log(`[${new Date().toLocaleTimeString()}] Raw DR envelope - no matching session`);
          return;
        }
      } else {
        // Standard InitializationEnvelope handling
        // Strategy: try existing session first, fall back to fresh if it fails
        if (session) {
          decryptResult = tryDecrypt(session.ratchet_state, outer.message);
        }
        
        // If existing session failed and this is an init envelope, try fresh session
        // (handles case where sender reset their session)
        if (!decryptResult && isInitEnvelope) {
          session = createFreshSession();
          decryptResult = tryDecrypt(session.ratchet_state, outer.message);
        }
      }
      
      if (!decryptResult || !session) {
        if (process.env.DEBUG) console.log(`[${new Date().toLocaleTimeString()}] Could not decrypt message`);
        return;
      }
      
      const { ratchet_state: newState, message: plaintext } = decryptResult;
      
      // Update session
      session.ratchet_state = newState;
      if (!isRawDREnvelope && outer.return_inbox_address) {
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
      } else if (content.type === 'edit-message') {
        console.log(`[${new Date().toLocaleTimeString()}] ${displayName} edited message ${content.originalMessageId?.substring(0, 12)}...`);
        console.log(`   New text: ${content.editedText}`);
      } else if (content.type === 'embed') {
        const replyInfo = content.repliesToMessageId ? ` ↩️ ${content.repliesToMessageId.substring(0, 8)}` : '';
        console.log(`\n🖼️ [${new Date().toLocaleTimeString()}] ${displayName} sent an image${replyInfo}`);
        if (content.imageUrl?.startsWith('data:')) {
          const sizeMatch = content.imageUrl.match(/base64,(.+)$/);
          if (sizeMatch) {
            const sizeKB = (sizeMatch[1].length * 0.75 / 1024).toFixed(1);
            console.log(`   Size: ~${sizeKB} KB`);
          }
        } else if (content.imageUrl) {
          console.log(`   URL: ${content.imageUrl.substring(0, 50)}...`);
        }
        console.log(`   id: ${msgData.messageId}`);
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

async function cmdStatus(recipientAddress, store) {
  const session = store.getSession(recipientAddress);
  
  if (!session) {
    console.log(`No session found for ${recipientAddress}`);
    console.log('Start a conversation first with: dm send <address> <text>');
    return;
  }
  
  const name = session.sender_name || recipientAddress.substring(0, 16);
  console.log(`\n📊 Session status: ${name}`);
  console.log(`   Address: ${recipientAddress}`);
  console.log(`   Inbox: ${session.sending_inbox?.inbox_address || 'unknown'}`);
  
  // Parse ratchet state
  let ratchet;
  try {
    ratchet = JSON.parse(session.ratchet_state);
  } catch {
    console.log('\n⚠️  Ratchet state: CORRUPTED or MISSING');
    console.log('   Recommend: dm reset <address>');
    return;
  }
  
  const sent = ratchet.current_sending_chain_length || 0;
  const prevSent = ratchet.previous_sending_chain_length || 0;
  const recv = ratchet.current_receiving_chain_length || 0;
  const prevRecv = ratchet.previous_receiving_chain_length || 0;
  const skippedCount = Object.keys(ratchet.skipped_keys_map || {}).length;
  
  console.log(`\n🔄 Ratchet state:`);
  console.log(`   Messages sent (this chain): ${sent}`);
  console.log(`   Messages received (this chain): ${recv}`);
  console.log(`   Previous chains: sent=${prevSent}, recv=${prevRecv}`);
  console.log(`   Skipped keys cached: ${skippedCount}`);
  
  // Health check
  const totalSent = sent + prevSent;
  const totalRecv = recv + prevRecv;
  
  console.log(`\n💚 Health:`);
  
  if (totalSent > 10 && totalRecv === 0) {
    console.log(`   ⚠️  WARNING: Sent ${totalSent} messages, received 0`);
    console.log(`      Ratchet may be out of sync with recipient!`);
    console.log(`      If they can't read your messages, try: dm reset ${recipientAddress}`);
  } else if (totalSent > totalRecv * 5 && totalSent > 5) {
    console.log(`   ⚠️  CAUTION: Sent ${totalSent}, received ${totalRecv}`);
    console.log(`      Large imbalance - consider verifying recipient can decrypt`);
  } else {
    console.log(`   ✅ Looks healthy (sent=${totalSent}, recv=${totalRecv})`);
  }
  
  if (skippedCount > 50) {
    console.log(`   ⚠️  Many skipped keys (${skippedCount}) - some messages may have been lost`);
  }
  
  console.log();
}

async function cmdReset(recipientAddress, store) {
  const session = store.getSession(recipientAddress);
  
  if (!session) {
    console.log(`No session found for ${recipientAddress}`);
    return;
  }
  
  const name = session.sender_name || recipientAddress.substring(0, 16);
  
  // Delete the session
  store.deleteSession(recipientAddress);
  
  console.log(`🗑️  Deleted session with ${name}`);
  console.log(`   Next message will start a fresh X3DH handshake`);
  console.log(`   Recipient should be able to decrypt the new conversation`);
}

// ============ Main ============

function parseArgs(argv) {
  const result = { identity: 'default', args: [] };
  let i = 0;
  while (i < argv.length) {
    if (argv[i] === '-i' || argv[i] === '--identity') {
      result.identity = argv[i + 1];
      i += 2;
    } else {
      result.args.push(argv[i]);
      i++;
    }
  }
  return result;
}

async function main() {
  const { identity, args: rawArgs } = parseArgs(process.argv.slice(2));
  const [cmd, ...args] = rawArgs;
  
  if (!cmd || cmd === 'help' || cmd === '-h' || cmd === '--help') {
    console.log(`
Quorum DM CLI

Global flags:
  -i, --identity <name>    Use specific identity (default: "default")

Identity commands:
  identity list                            List all identities
  identity create <name>                   Create new identity  
  identity show                            Show current identity info
  identity rename <old> <new>              Rename an identity
  identity delete <name>                   Delete an identity (cannot delete active)

Message commands:
  send <address> <text> [-r reply-to-id]   Send a direct message
  embed <address> <image-path> [-r id]     Send an image
  edit <address> <msg-id> <new-text>       Edit a message
  react <address> <msg-id> <emoji>         React to a message
  unreact <address> <msg-id> <emoji>       Remove a reaction
  delete <address> <msg-id>                Delete a message
  listen [timeout_seconds]                 Listen for incoming DMs
  conversations                            List conversations
  status <address>                         Show ratchet health for a conversation
  reset <address>                          Reset session (fixes out-of-sync ratchet)
  sync                                     Sync local keyset with API registration

Examples:
  node dm.mjs identity create alice
  node dm.mjs -i alice send QmBob... "Hello from Alice!"
  node dm.mjs send QmRecipient... "Hello!"  (uses default identity)
  node dm.mjs listen
`);
    return;
  }
  
  // Handle identity commands (don't need full crypto init)
  if (cmd === 'identity') {
    const subCmd = args[0];
    
    if (subCmd === 'list') {
      const identities = listIdentities();
      if (identities.length === 0) {
        console.log('No identities found. Create one with: dm identity create <name>');
      } else {
        console.log('Identities:\n');
        for (const name of identities) {
          const dir = getIdentityDir(name);
          try {
            // Registration is stored in keys/ subdirectory
            const regFile = join(dir, 'keys', 'registration.json');
            if (existsSync(regFile)) {
              const reg = JSON.parse(readFileSync(regFile, 'utf-8'));
              const marker = name === identity ? ' (active)' : '';
              console.log(`  ${name}${marker}`);
              console.log(`    Address: ${reg.user_address}`);
            } else {
              console.log(`  ${name} (not registered)`);
            }
          } catch {
            console.log(`  ${name} (error reading)`);
          }
        }
      }
      return;
    }
    
    if (subCmd === 'create') {
      const name = args[1];
      if (!name) throw new Error('Usage: dm identity create <name>');
      if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
        throw new Error('Identity name must be alphanumeric (with - or _)');
      }
      console.log(`Creating identity "${name}"...`);
      const { address } = await createIdentity(name);
      console.log(`✅ Created identity "${name}"`);
      console.log(`   Address: ${address}`);
      return;
    }
    
    if (subCmd === 'show') {
      await initCrypto();
      const dir = getIdentityDir(identity);
      if (!identityExists(identity)) {
        throw new Error(`Identity "${identity}" not found`);
      }
      const store = await createSecureStore(dir);
      const reg = store.getRegistration();
      const profile = existsSync(join(dir, 'profile.json')) 
        ? JSON.parse(readFileSync(join(dir, 'profile.json'), 'utf-8'))
        : {};
      console.log(`Identity: ${identity}`);
      console.log(`  Address: ${reg?.user_address || 'not registered'}`);
      console.log(`  Display name: ${profile.displayName || reg?.display_name || identity}`);
      console.log(`  Data dir: ${dir}`);
      return;
    }
    
    if (subCmd === 'rename') {
      const [oldName, newName] = [args[1], args[2]];
      if (!oldName || !newName) throw new Error('Usage: dm identity rename <old> <new>');
      if (!identityExists(oldName)) throw new Error(`Identity "${oldName}" not found`);
      if (identityExists(newName)) throw new Error(`Identity "${newName}" already exists`);
      renameSync(getIdentityDir(oldName), getIdentityDir(newName));
      console.log(`✅ Renamed "${oldName}" to "${newName}"`);
      return;
    }
    
    if (subCmd === 'delete') {
      const name = args[1];
      if (!name) throw new Error('Usage: dm identity delete <name>');
      if (!identityExists(name)) throw new Error(`Identity "${name}" not found`);
      rmSync(getIdentityDir(name), { recursive: true });
      console.log(`✅ Deleted identity "${name}"`);
      return;
    }
    
    throw new Error(`Unknown identity command: ${subCmd}`);
  }
  
  await initCrypto();
  
  // Resolve identity directory
  IDENTITY_DIR = getIdentityDir(identity);
  if (!identityExists(identity)) {
    if (identity === 'default') {
      // Auto-create default identity
      console.log('Creating default identity...');
      await createIdentity('default');
    } else {
      throw new Error(`Identity "${identity}" not found. Create with: dm identity create ${identity}`);
    }
  }
  
  // Load identity
  const store = await createSecureStore(IDENTITY_DIR);
  const deviceKeyset = await store.getDeviceKeyset();
  const registration = store.getRegistration();
  
  if (!deviceKeyset || !registration) {
    console.error(`Identity "${identity}" not properly initialized.`);
    console.error('Try: dm identity delete ' + identity + ' && dm identity create ' + identity);
    process.exit(1);
  }
  
  console.log(`🔐 Using identity: ${identity}`);
  
  // Verify registration is in sync with API (skip for listen command to avoid delay)
  if (cmd !== 'listen' && cmd !== 'conversations' && cmd !== 'status') {
    const localInbox = deviceKeyset.inbox_address;
    try {
      const api = new QuorumAPI();
      const apiUser = await api.getUser(registration.user_address);
      const apiInbox = apiUser?.device_registrations?.[0]?.inbox_registration?.inbox_address;
      
      if (apiInbox && localInbox !== apiInbox) {
        console.log(`\n⚠️  Registration mismatch detected!`);
        console.log(`   Local inbox:  ${localInbox.substring(0, 20)}...`);
        console.log(`   API inbox:    ${apiInbox.substring(0, 20)}...`);
        console.log(`\n   This can cause DMs to fail silently.`);
        console.log(`   Run 'dm sync' to fix this.\n`);
      }
    } catch (e) {
      // Don't block on API errors, just warn
      if (process.env.DEBUG) console.warn('Could not verify registration:', e.message);
    }
  }
  
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
    case 'edit': {
      if (!args[0] || !args[1] || !args[2]) {
        throw new Error('Usage: dm edit <address> <msg-id> <new-text>');
      }
      const address = args[0];
      const msgId = args[1];
      const newText = args.slice(2).join(' ');
      await cmdEdit(address, msgId, newText, store, deviceKeyset, registration);
      break;
    }
    case 'embed':
    case 'image': {
      if (!args[0] || !args[1]) {
        throw new Error('Usage: dm embed <address> <image-path> [-r reply-to-id]');
      }
      const address = args[0];
      const imagePath = args[1];
      const rIndex = args.indexOf('-r');
      const replyToId = rIndex > 0 ? args[rIndex + 1] : null;
      
      if (!existsSync(imagePath)) {
        throw new Error(`File not found: ${imagePath}`);
      }
      await cmdEmbed(address, imagePath, replyToId, store, deviceKeyset, registration);
      break;
    }
    case 'listen':
      await cmdListen(parseInt(args[0]) || 0, store, deviceKeyset, registration);
      break;
    case 'conversations':
      await cmdConversations(store);
      break;
    case 'status': {
      if (!args[0]) throw new Error('Usage: dm status <address>');
      await cmdStatus(args[0], store);
      break;
    }
    case 'reset': {
      if (!args[0]) throw new Error('Usage: dm reset <address>');
      await cmdReset(args[0], store);
      break;
    }
    case 'sync': {
      // Re-register device keyset with API to fix mismatch
      const api = new QuorumAPI();
      
      console.log('Checking registration sync...');
      const apiUser = await api.getUser(registration.user_address);
      const apiInbox = apiUser?.device_registrations?.[0]?.inbox_registration?.inbox_address;
      const localInbox = deviceKeyset.inbox_address;
      
      if (apiInbox === localInbox) {
        console.log('✅ Registration already in sync!');
        console.log(`   Inbox: ${localInbox}`);
        break;
      }
      
      console.log(`Local inbox:  ${localInbox}`);
      console.log(`API inbox:    ${apiInbox || 'none'}`);
      console.log('\nRe-registering with API...');
      
      // Get user keyset for signing
      const userKeyset = await store.getUserKeyset();
      if (!userKeyset) {
        throw new Error('No user keyset found - cannot sign registration');
      }
      
      // Build new registration
      const { constructRegistration } = await import('./src/crypto.mjs');
      const userPrivHex = bytesToHex(new Uint8Array(userKeyset.private_key));
      const newReg = constructRegistration(
        registration.user_address,
        registration.user_public_key,
        userPrivHex,
        deviceKeyset
      );
      
      // Post to API
      await api.registerUser(newReg);
      
      // Update local registration
      store.saveRegistration(newReg);
      
      console.log('✅ Registration synced!');
      console.log(`   Inbox: ${localInbox}`);
      break;
    }
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
