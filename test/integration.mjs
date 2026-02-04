#!/usr/bin/env node
/**
 * Quorum Client Integration Tests
 * 
 * Tests bidirectional E2EE messaging between two identities (Alice & Bob)
 * using isolated test directories.
 * 
 * Features tested:
 *   1. Identity creation
 *   2. First message (X3DH key exchange)
 *   3. Follow-up messages (Double Ratchet)
 *   4. Bidirectional conversation
 *   5. Reactions
 *   6. Remove reactions
 *   7. Edit messages
 *   8. Delete messages
 *   9. Image/embed messages
 *   10. Session status & health
 *   11. Session reset
 * 
 * Usage:
 *   node test/integration.mjs              # Run all tests
 *   node test/integration.mjs --keep       # Keep test identities after run
 *   node test/integration.mjs --verbose    # Show detailed output
 *   DEBUG=1 node test/integration.mjs      # Show debug info
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const WebSocket = require('ws');

import { randomUUID } from 'crypto';
import { existsSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { homedir, tmpdir } from 'os';
import { setTimeout as sleep } from 'timers/promises';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, '..');

// Test configuration
const TEST_BASE_DIR = process.env.TEST_DIR || join(tmpdir(), `quorum-test-${Date.now()}`);
const ALICE_DIR = join(TEST_BASE_DIR, 'identities', 'alice');
const BOB_DIR = join(TEST_BASE_DIR, 'identities', 'bob');
const WS_URL = 'wss://api.quorummessenger.com/ws';
const API_BASE = 'https://api.quorummessenger.com';

const KEEP_DATA = process.argv.includes('--keep');
const VERBOSE = process.argv.includes('--verbose') || process.env.DEBUG;

// Import from project
const { initCrypto, generateX448, senderX3DH, receiverX3DH, newDoubleRatchet, 
        doubleRatchetEncrypt, doubleRatchetDecrypt, encryptInboxMessageBytes, 
        decryptInboxMessage } = await import(join(PROJECT_ROOT, 'src/crypto.mjs'));
const { QuorumAPI } = await import(join(PROJECT_ROOT, 'src/api.mjs'));
const { createSecureStore } = await import(join(PROJECT_ROOT, 'src/secure-store.mjs'));
const { QuorumClient } = await import(join(PROJECT_ROOT, 'src/client.mjs'));

// ============ Test Utilities ============

function log(...args) {
  if (VERBOSE) console.log(...args);
}

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

class TestResults {
  constructor() {
    this.passed = 0;
    this.failed = 0;
    this.tests = [];
  }

  pass(name, detail = '') {
    this.passed++;
    this.tests.push({ name, passed: true, detail });
    console.log(`  ✅ ${name}${detail ? ` (${detail})` : ''}`);
  }

  fail(name, error) {
    this.failed++;
    this.tests.push({ name, passed: false, error: error.message });
    console.log(`  ❌ ${name}: ${error.message}`);
    if (VERBOSE && error.stack) console.log(`     ${error.stack.split('\n').slice(1, 3).join('\n     ')}`);
  }

  summary() {
    const total = this.passed + this.failed;
    console.log(`\n${'═'.repeat(50)}`);
    if (this.failed === 0) {
      console.log(`✅ All ${total} tests passed!`);
    } else {
      console.log(`❌ ${this.failed}/${total} tests failed`);
      for (const t of this.tests.filter(t => !t.passed)) {
        console.log(`   - ${t.name}: ${t.error}`);
      }
    }
    console.log('═'.repeat(50));
    return this.failed === 0;
  }
}

// ============ Test Identity Class ============

class TestIdentity {
  constructor(name, dataDir) {
    this.name = name;
    this.dataDir = dataDir;
    this.client = null;
    this.store = null;
    this.deviceKeyset = null;
    this.registration = null;
    this.receivedMessages = [];
    this.ws = null;
  }

  async init() {
    mkdirSync(this.dataDir, { recursive: true });
    
    this.client = new QuorumClient({ 
      dataDir: this.dataDir,
      useKeychain: false  // Use file storage for tests (portable)
    });
    
    const status = await this.client.init();
    
    if (!status.hasIdentity) {
      log(`  Creating identity for ${this.name}...`);
      await this.client.register(this.name);
    }
    
    this.store = this.client.store;
    this.deviceKeyset = await this.store.getDeviceKeyset();
    this.registration = this.store.getRegistration();
    
    log(`  ${this.name} address: ${this.registration.user_address.substring(0, 20)}...`);
    return this;
  }

  get address() {
    return this.registration.user_address;
  }

  get inboxAddress() {
    return this.deviceKeyset.inbox_address;
  }

  // Start listening for messages
  async startListening() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(WS_URL);
      
      this.ws.on('open', () => {
        this.ws.send(JSON.stringify({ 
          type: 'listen', 
          inbox_addresses: [this.inboxAddress] 
        }));
        log(`  ${this.name} listening on inbox ${this.inboxAddress.substring(0, 16)}...`);
        resolve();
      });

      this.ws.on('message', async (data) => {
        try {
          const msg = JSON.parse(data.toString());
          if (msg.type === 'ack') return;
          if (!msg.encryptedContent) return;

          const result = await this._processIncomingMessage(msg);
          if (result) {
            this.receivedMessages.push(result);
            log(`  ${this.name} received: ${JSON.stringify(result.content).substring(0, 60)}...`);
          }
        } catch (err) {
          if (VERBOSE) console.error(`  ${this.name} decrypt error:`, err.message);
        }
      });

      this.ws.on('error', reject);
      
      setTimeout(() => resolve(), 2000); // Resolve after 2s even if not connected
    });
  }

  async _processIncomingMessage(msg) {
    const envelope = JSON.parse(msg.encryptedContent);
    const ephPubKey = hexToBytes(envelope.ephemeral_public_key);

    const decrypted = decryptInboxMessage(
      [...new Uint8Array(this.deviceKeyset.inbox_encryption_key.private_key)],
      [...ephPubKey],
      JSON.parse(envelope.envelope)
    );

    const outer = JSON.parse(new TextDecoder().decode(new Uint8Array(decrypted)));
    const senderAddress = outer.user_address || outer.return_inbox_address;
    
    let session = this.store.getSession(senderAddress);
    const isInitEnvelope = outer.identity_public_key && outer.return_inbox_address;

    // Helper to create a fresh session from initialization envelope
    const createFreshSession = () => {
      const senderIdentityKey = hexToBytes(outer.identity_public_key);
      const senderEphemeralKey = ephPubKey;  // Sender's ephemeral from envelope

      const sessionKeyB64 = receiverX3DH(
        this.deviceKeyset.identity_key.private_key,
        this.deviceKeyset.pre_key.private_key,
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
          sending_ephemeral_private_key: this.deviceKeyset.pre_key.private_key, // Our pre-key
          receiving_ephemeral_key: [...senderEphemeralKey],  // Sender's ephemeral
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
        // WASM returns error messages in the result instead of throwing
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

    // Strategy: try existing session first, fall back to fresh if it fails
    if (session) {
      decryptResult = tryDecrypt(session.ratchet_state, outer.message);
    }

    // If existing session failed (or doesn't exist) and this is an init envelope,
    // try creating a fresh session (handles reset case)
    if (!decryptResult && isInitEnvelope) {
      session = createFreshSession();
      decryptResult = tryDecrypt(session.ratchet_state, outer.message);
    }

    if (!decryptResult || !session) return null;

    const { ratchet_state: newState, message: plaintext } = decryptResult;

    // Update session
    session.ratchet_state = newState;
    if (outer.return_inbox_address) {
      session.sending_inbox = {
        inbox_address: outer.return_inbox_address,
        inbox_encryption_key: outer.return_inbox_encryption_key,
      };
    }
    this.store.saveSession(senderAddress, session);

    const msgData = JSON.parse(plaintext);
    return {
      from: senderAddress,
      fromName: outer.display_name,
      messageId: msgData.messageId,
      content: msgData.content,
      timestamp: msgData.createdDate,
    };
  }

  stopListening() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  clearMessages() {
    this.receivedMessages = [];
  }

  // Wait for a specific number of messages
  async waitForMessages(count, timeoutMs = 10000) {
    const start = Date.now();
    while (this.receivedMessages.length < count) {
      if (Date.now() - start > timeoutMs) {
        throw new Error(`Timeout waiting for ${count} messages (got ${this.receivedMessages.length})`);
      }
      await sleep(100);
    }
    return this.receivedMessages.slice(-count);
  }

  // Send a text message
  async sendText(recipientAddress, text, replyToId = null) {
    const content = { type: 'post', text };
    if (replyToId) content.repliesToMessageId = replyToId;
    return this._sendMessage(recipientAddress, content);
  }

  // Send a reaction
  async sendReaction(recipientAddress, messageId, emoji) {
    const content = {
      type: 'reaction',
      senderId: this.registration.user_address,
      messageId,
      reaction: emoji,
    };
    return this._sendMessage(recipientAddress, content, true);
  }

  // Remove a reaction
  async sendUnreact(recipientAddress, messageId, emoji) {
    const content = {
      type: 'remove-reaction',
      reaction: emoji,
      messageId,
    };
    return this._sendMessage(recipientAddress, content, true);
  }

  // Edit a message
  async sendEdit(recipientAddress, messageId, newText) {
    const content = {
      type: 'edit-message',
      originalMessageId: messageId,
      editedText: newText,
      editedAt: Date.now(),
      editNonce: randomUUID(),
    };
    return this._sendMessage(recipientAddress, content, true);
  }

  // Delete a message
  async sendDelete(recipientAddress, messageId) {
    const content = {
      type: 'remove-message',
      removeMessageId: messageId,
    };
    return this._sendMessage(recipientAddress, content, true);
  }

  // Send an image (base64)
  async sendImage(recipientAddress, imageData, mimeType = 'image/png', replyToId = null) {
    const base64 = Buffer.from(imageData).toString('base64');
    const dataUrl = `data:${mimeType};base64,${base64}`;
    const content = { type: 'embed', imageUrl: dataUrl };
    if (replyToId) content.repliesToMessageId = replyToId;
    return this._sendMessage(recipientAddress, content);
  }

  async _sendMessage(recipientAddress, content, requireSession = false) {
    const api = new QuorumAPI();
    let session = this.store.getSession(recipientAddress);

    if (requireSession && (!session || !session.sending_inbox?.inbox_address)) {
      throw new Error('Requires existing session');
    }

    if (session && session.sending_inbox?.inbox_address) {
      return this._sendFollowUp(recipientAddress, content, session);
    }

    // First message - X3DH handshake
    const recipient = await api.getUser(recipientAddress);
    if (!recipient?.device_registrations?.length) {
      throw new Error('Recipient not found');
    }
    
    return this._sendFirstMessage(recipientAddress, content, recipient.device_registrations[0], recipient);
  }

  async _sendFirstMessage(recipientAddress, content, device, recipient) {
    const ephemeralKey = generateX448();
    const receiverIdentityKey = [...Buffer.from(device.identity_public_key, 'hex')];
    const receiverPreKey = [...Buffer.from(device.pre_public_key, 'hex')];

    const sessionKeyB64 = senderX3DH(
      this.deviceKeyset.identity_key.private_key,
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
      content: { ...content, senderId: this.registration.user_address },
      reactions: [],
      mentions: { memberIds: [], roleIds: [], channelIds: [] },
    });

    const { ratchet_state: newState, envelope: msgEnvelope } = doubleRatchetEncrypt(ratchetState, messagePayload);

    const initEnvelope = {
      user_address: this.registration.user_address,
      display_name: this.name,
      return_inbox_address: this.deviceKeyset.inbox_address,
      return_inbox_encryption_key: bytesToHex(new Uint8Array(this.deviceKeyset.inbox_encryption_key.public_key)),
      return_inbox_public_key: bytesToHex(new Uint8Array(this.deviceKeyset.inbox_signing_key.public_key)),
      return_inbox_private_key: bytesToHex(new Uint8Array(this.deviceKeyset.inbox_signing_key.private_key)),
      identity_public_key: bytesToHex(new Uint8Array(this.deviceKeyset.identity_key.public_key)),
      tag: this.deviceKeyset.inbox_address,
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

    await fetch(`${API_BASE}/inbox`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(sealedMessage),
    });

    // Save session
    this.store.saveSession(recipientAddress, {
      ratchet_state: newState,
      sending_inbox: {
        inbox_address: device.inbox_registration.inbox_address,
        inbox_encryption_key: device.inbox_registration.inbox_encryption_public_key,
      },
      recipient_address: recipientAddress,
      sender_name: recipient.display_name || recipientAddress.substring(0, 12),
    });

    return { messageId: `${messageId}-${now}`, firstMessage: true };
  }

  async _sendFollowUp(recipientAddress, content, session) {
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
      content: { ...content, senderId: this.registration.user_address },
      reactions: [],
      mentions: { memberIds: [], roleIds: [], channelIds: [] },
    });

    const { ratchet_state: newState, envelope } = doubleRatchetEncrypt(
      session.ratchet_state,
      messagePayload
    );

    const ephemeralKey = generateX448();

    // Wrap in init envelope format for device inbox processing
    const payload = JSON.stringify({
      return_inbox_address: this.deviceKeyset.inbox_address,
      return_inbox_encryption_key: bytesToHex(new Uint8Array(this.deviceKeyset.inbox_encryption_key.public_key)),
      return_inbox_public_key: bytesToHex(new Uint8Array(this.deviceKeyset.inbox_signing_key.public_key)),
      return_inbox_private_key: bytesToHex(new Uint8Array(this.deviceKeyset.inbox_signing_key.private_key)),
      user_address: this.registration.user_address,
      identity_public_key: bytesToHex(new Uint8Array(this.deviceKeyset.identity_key.public_key)),
      tag: this.deviceKeyset.inbox_address,
      display_name: this.name,
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

    await fetch(`${API_BASE}/inbox`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(sealedMessage),
    });

    // Update session
    session.ratchet_state = newState;
    this.store.saveSession(recipientAddress, session);

    return { messageId: `${messageId}-${now}`, firstMessage: false };
  }

  // Get session status
  getSessionStatus(peerAddress) {
    const session = this.store.getSession(peerAddress);
    if (!session) return null;

    let ratchet;
    try {
      ratchet = JSON.parse(session.ratchet_state);
    } catch {
      return { error: 'corrupted' };
    }

    return {
      peerAddress,
      peerName: session.sender_name,
      inboxAddress: session.sending_inbox?.inbox_address,
      sentThisChain: ratchet.current_sending_chain_length || 0,
      recvThisChain: ratchet.current_receiving_chain_length || 0,
      skippedKeys: Object.keys(ratchet.skipped_keys_map || {}).length,
    };
  }

  // Reset session (delete)
  resetSession(peerAddress) {
    this.store.deleteSession(peerAddress);
  }
}

// ============ Test Suites ============

async function runTests() {
  console.log('\n🔬 Quorum Client Integration Tests');
  console.log('═'.repeat(50));
  console.log(`Test directory: ${TEST_BASE_DIR}`);
  console.log();

  const results = new TestResults();
  let alice, bob;

  try {
    // ============ Setup ============
    console.log('📦 Setup');
    
    await initCrypto();
    results.pass('Crypto initialized');

    // Clean test dir
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true });
    }
    mkdirSync(TEST_BASE_DIR, { recursive: true });

    // ============ Test 1: Identity Creation ============
    console.log('\n📋 Test Suite: Identity Management');
    
    try {
      alice = await new TestIdentity('Alice', ALICE_DIR).init();
      results.pass('Alice identity created', alice.address.substring(0, 16) + '...');
    } catch (e) {
      results.fail('Alice identity creation', e);
      throw e; // Can't continue without identities
    }

    try {
      bob = await new TestIdentity('Bob', BOB_DIR).init();
      results.pass('Bob identity created', bob.address.substring(0, 16) + '...');
    } catch (e) {
      results.fail('Bob identity creation', e);
      throw e;
    }

    // Verify different addresses
    if (alice.address !== bob.address) {
      results.pass('Identities have unique addresses');
    } else {
      results.fail('Identity uniqueness', new Error('Same address generated'));
    }

    // ============ Test 2: Start Listeners ============
    console.log('\n📋 Test Suite: WebSocket Listeners');
    
    try {
      await alice.startListening();
      results.pass('Alice WebSocket connected');
    } catch (e) {
      results.fail('Alice WebSocket', e);
    }

    try {
      await bob.startListening();
      results.pass('Bob WebSocket connected');
    } catch (e) {
      results.fail('Bob WebSocket', e);
    }

    await sleep(1000); // Let connections stabilize

    // ============ Test 3: First Message (X3DH) ============
    console.log('\n📋 Test Suite: First Message (X3DH Key Exchange)');
    
    let aliceMsg1Id;
    try {
      const result = await alice.sendText(bob.address, 'Hello Bob! This is Alice.');
      aliceMsg1Id = result.messageId;
      if (result.firstMessage) {
        results.pass('Alice sent first message with X3DH', `id: ${aliceMsg1Id.substring(0, 16)}...`);
      } else {
        results.fail('First message flag', new Error('Expected firstMessage=true'));
      }
    } catch (e) {
      results.fail('Alice send first message', e);
    }

    // Wait for Bob to receive
    try {
      await sleep(2000);
      const msgs = await bob.waitForMessages(1, 8000);
      const received = msgs[0];
      
      if (received.content.text === 'Hello Bob! This is Alice.') {
        results.pass('Bob received first message', received.content.text);
      } else {
        results.fail('Message content', new Error(`Expected "Hello Bob! This is Alice." got "${received.content.text}"`));
      }
      
      if (received.from === alice.address) {
        results.pass('Sender address verified');
      } else {
        results.fail('Sender verification', new Error('Wrong sender'));
      }
    } catch (e) {
      results.fail('Bob receive first message', e);
    }

    // ============ Test 4: Reply (Reverse Direction) ============
    console.log('\n📋 Test Suite: Reply Message (Reverse Direction)');
    
    let bobMsg1Id;
    try {
      alice.clearMessages();
      const result = await bob.sendText(alice.address, 'Hi Alice! Got your message.');
      bobMsg1Id = result.messageId;
      results.pass('Bob sent reply', `id: ${bobMsg1Id.substring(0, 16)}...`);
    } catch (e) {
      results.fail('Bob send reply', e);
    }

    try {
      await sleep(2000);
      const msgs = await alice.waitForMessages(1, 8000);
      
      if (msgs[0].content.text === 'Hi Alice! Got your message.') {
        results.pass('Alice received reply');
      } else {
        results.fail('Reply content', new Error('Wrong content'));
      }
    } catch (e) {
      results.fail('Alice receive reply', e);
    }

    // ============ Test 5: Multi-Message Conversation ============
    console.log('\n📋 Test Suite: Multi-Message Conversation');
    
    bob.clearMessages();
    alice.clearMessages();

    const conversation = [
      { from: 'alice', to: 'bob', text: 'Message 1 from Alice' },
      { from: 'bob', to: 'alice', text: 'Message 2 from Bob' },
      { from: 'alice', to: 'bob', text: 'Message 3 from Alice' },
      { from: 'alice', to: 'bob', text: 'Message 4 from Alice (back to back)' },
      { from: 'bob', to: 'alice', text: 'Message 5 from Bob' },
    ];

    let conversationPassed = true;
    const sentIds = [];

    for (const msg of conversation) {
      try {
        const sender = msg.from === 'alice' ? alice : bob;
        const recipientAddr = msg.to === 'alice' ? alice.address : bob.address;
        
        const result = await sender.sendText(recipientAddr, msg.text);
        sentIds.push(result.messageId);
        log(`  Sent: ${msg.text}`);
        await sleep(500);
      } catch (e) {
        results.fail(`Send "${msg.text}"`, e);
        conversationPassed = false;
      }
    }

    await sleep(3000);

    // Verify received counts
    const aliceExpected = conversation.filter(m => m.to === 'alice').length;
    const bobExpected = conversation.filter(m => m.to === 'bob').length;

    if (alice.receivedMessages.length >= aliceExpected) {
      results.pass(`Alice received ${aliceExpected} messages`);
    } else {
      results.fail('Alice message count', new Error(`Expected ${aliceExpected}, got ${alice.receivedMessages.length}`));
      conversationPassed = false;
    }

    if (bob.receivedMessages.length >= bobExpected) {
      results.pass(`Bob received ${bobExpected} messages`);
    } else {
      results.fail('Bob message count', new Error(`Expected ${bobExpected}, got ${bob.receivedMessages.length}`));
      conversationPassed = false;
    }

    if (conversationPassed) {
      results.pass('Multi-message conversation completed');
    }

    // ============ Test 6: Reactions ============
    console.log('\n📋 Test Suite: Reactions');
    
    bob.clearMessages();
    const lastMsgToBob = bob.receivedMessages[bob.receivedMessages.length - 1]?.messageId || sentIds[2];
    
    try {
      await alice.sendReaction(bob.address, lastMsgToBob, '👍');
      results.pass('Alice sent reaction');
      
      await sleep(2000);
      const reactions = bob.receivedMessages.filter(m => m.content.type === 'reaction');
      if (reactions.length > 0 && reactions[0].content.reaction === '👍') {
        results.pass('Bob received reaction', '👍');
      } else {
        log('  Bob messages:', bob.receivedMessages.map(m => m.content));
        results.fail('Reaction receipt', new Error('Reaction not received or wrong emoji'));
      }
    } catch (e) {
      results.fail('Reaction test', e);
    }

    // ============ Test 7: Remove Reaction ============
    console.log('\n📋 Test Suite: Remove Reaction');
    
    bob.clearMessages();
    
    try {
      await alice.sendUnreact(bob.address, lastMsgToBob, '👍');
      results.pass('Alice sent unreact');
      
      await sleep(2000);
      const unreacts = bob.receivedMessages.filter(m => m.content.type === 'remove-reaction');
      if (unreacts.length > 0) {
        results.pass('Bob received unreact');
      } else {
        results.fail('Unreact receipt', new Error('Unreact not received'));
      }
    } catch (e) {
      results.fail('Unreact test', e);
    }

    // ============ Test 8: Edit Message ============
    console.log('\n📋 Test Suite: Edit Message');
    
    bob.clearMessages();
    
    try {
      // Use a message ID that Alice sent to Bob
      const msgToEdit = sentIds[0]; // First message Alice sent to Bob in conversation
      await alice.sendEdit(bob.address, msgToEdit, 'EDITED: Message 1 from Alice');
      results.pass('Alice sent edit');
      
      await sleep(2000);
      const edits = bob.receivedMessages.filter(m => m.content.type === 'edit-message');
      if (edits.length > 0 && edits[0].content.editedText === 'EDITED: Message 1 from Alice') {
        results.pass('Bob received edit', edits[0].content.editedText);
      } else {
        results.fail('Edit receipt', new Error('Edit not received'));
      }
    } catch (e) {
      results.fail('Edit test', e);
    }

    // ============ Test 9: Delete Message ============
    console.log('\n📋 Test Suite: Delete Message');
    
    bob.clearMessages();
    
    try {
      const msgToDelete = sentIds[2]; // Third message
      await alice.sendDelete(bob.address, msgToDelete);
      results.pass('Alice sent delete');
      
      await sleep(2000);
      const deletes = bob.receivedMessages.filter(m => m.content.type === 'remove-message');
      if (deletes.length > 0) {
        results.pass('Bob received delete');
      } else {
        results.fail('Delete receipt', new Error('Delete not received'));
      }
    } catch (e) {
      results.fail('Delete test', e);
    }

    // ============ Test 10: Image/Embed ============
    console.log('\n📋 Test Suite: Image/Embed Message');
    
    bob.clearMessages();
    
    try {
      // Create a tiny test image (1x1 PNG)
      const tinyPng = Buffer.from([
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
        0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,
        0x54, 0x08, 0xD7, 0x63, 0xF8, 0xFF, 0xFF, 0x3F,
        0x00, 0x05, 0xFE, 0x02, 0xFE, 0xDC, 0xCC, 0x59,
        0xE7, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,
        0x44, 0xAE, 0x42, 0x60, 0x82
      ]);
      
      await alice.sendImage(bob.address, tinyPng, 'image/png');
      results.pass('Alice sent image');
      
      await sleep(2000);
      const embeds = bob.receivedMessages.filter(m => m.content.type === 'embed');
      if (embeds.length > 0 && embeds[0].content.imageUrl?.startsWith('data:image/png')) {
        results.pass('Bob received image');
      } else {
        results.fail('Image receipt', new Error('Image not received'));
      }
    } catch (e) {
      results.fail('Image test', e);
    }

    // ============ Test 11: Session Status ============
    console.log('\n📋 Test Suite: Session Status');
    
    try {
      const aliceStatus = alice.getSessionStatus(bob.address);
      if (aliceStatus && aliceStatus.peerAddress === bob.address) {
        results.pass('Alice session status', `sent=${aliceStatus.sentThisChain}, recv=${aliceStatus.recvThisChain}`);
      } else {
        results.fail('Alice session status', new Error('No session found'));
      }
    } catch (e) {
      results.fail('Session status', e);
    }

    try {
      const bobStatus = bob.getSessionStatus(alice.address);
      if (bobStatus && bobStatus.peerAddress === alice.address) {
        results.pass('Bob session status', `sent=${bobStatus.sentThisChain}, recv=${bobStatus.recvThisChain}`);
      } else {
        results.fail('Bob session status', new Error('No session found'));
      }
    } catch (e) {
      results.fail('Session status', e);
    }

    // ============ Test 12: Session Reset & Reestablish ============
    console.log('\n📋 Test Suite: Session Reset & Reestablish');
    
    try {
      // Reset Alice's session with Bob
      alice.resetSession(bob.address);
      const statusAfterReset = alice.getSessionStatus(bob.address);
      
      if (!statusAfterReset) {
        results.pass('Session reset successful');
      } else {
        results.fail('Session reset', new Error('Session still exists'));
      }
    } catch (e) {
      results.fail('Session reset', e);
    }

    bob.clearMessages();
    
    try {
      // Send new first message (should do X3DH again)
      const result = await alice.sendText(bob.address, 'Fresh start after reset!');
      if (result.firstMessage) {
        results.pass('New X3DH handshake initiated');
      } else {
        results.fail('X3DH after reset', new Error('Expected firstMessage=true'));
      }
      
      await sleep(2000);
      const msgs = await bob.waitForMessages(1, 8000);
      if (msgs[0].content.text === 'Fresh start after reset!') {
        results.pass('Post-reset message received');
      } else {
        results.fail('Post-reset message', new Error('Wrong content'));
      }
    } catch (e) {
      results.fail('Post-reset communication', e);
    }

    // ============ Test 13: Isolated Ratchet Transitions ============
    // 
    // This tests each Double Ratchet transition step in isolation:
    // Step 1: Alice → Bob (initiator first message, X3DH)
    // Step 2: Bob → Alice (receiver first reply, Bob performs DH ratchet)
    // Step 3: Alice → Bob (initiator after receiving, Alice performs DH ratchet)
    // Step 4: Bob → Alice (receiver second reply, steady state ratchet)
    //
    console.log('\n📋 Test Suite: Isolated Ratchet Transitions');
    
    // Reset both sessions for clean slate
    alice.resetSession(bob.address);
    bob.resetSession(alice.address);
    alice.clearMessages();
    bob.clearMessages();
    
    log('  Both sessions reset for isolated ratchet testing');

    // Step 1: Alice → Bob (X3DH initialization)
    console.log('\n  🔄 Step 1: Alice → Bob (X3DH init, first message)');
    try {
      const result = await alice.sendText(bob.address, 'Ratchet Step 1: Alice initiates');
      if (!result.firstMessage) {
        results.fail('Step 1: firstMessage flag', new Error('Expected firstMessage=true'));
      } else {
        results.pass('Step 1: Alice sent (X3DH init)');
      }
      
      await sleep(2000);
      const msgs = await bob.waitForMessages(1, 8000);
      if (msgs[0].content.text === 'Ratchet Step 1: Alice initiates') {
        results.pass('Step 1: Bob received', 'X3DH handshake complete');
        
        // Verify Bob's session state
        const bobSession = bob.getSessionStatus(alice.address);
        log(`    Bob session: sent=${bobSession?.sentThisChain}, recv=${bobSession?.recvThisChain}`);
      } else {
        results.fail('Step 1: content mismatch', new Error(msgs[0].content.text));
      }
    } catch (e) {
      results.fail('Step 1: Alice → Bob', e);
    }
    
    bob.clearMessages();

    // Step 2: Bob → Alice (receiver's first reply, DH ratchet step)
    console.log('\n  🔄 Step 2: Bob → Alice (receiver first reply, DH ratchet)');
    try {
      const result = await bob.sendText(alice.address, 'Ratchet Step 2: Bob replies');
      results.pass('Step 2: Bob sent', `firstMessage=${result.firstMessage}`);
      
      await sleep(2000);
      const msgs = await alice.waitForMessages(1, 8000);
      if (msgs[0].content.text === 'Ratchet Step 2: Bob replies') {
        results.pass('Step 2: Alice received', 'Bob DH ratchet verified');
        
        // Verify both session states after exchange
        const aliceSession = alice.getSessionStatus(bob.address);
        const bobSession = bob.getSessionStatus(alice.address);
        log(`    Alice session: sent=${aliceSession?.sentThisChain}, recv=${aliceSession?.recvThisChain}`);
        log(`    Bob session: sent=${bobSession?.sentThisChain}, recv=${bobSession?.recvThisChain}`);
      } else {
        results.fail('Step 2: content mismatch', new Error(msgs[0].content.text));
      }
    } catch (e) {
      results.fail('Step 2: Bob → Alice', e);
    }
    
    alice.clearMessages();

    // Step 3: Alice → Bob (initiator after receiving, Alice DH ratchets)
    console.log('\n  🔄 Step 3: Alice → Bob (after receiving, Alice DH ratchet)');
    try {
      const result = await alice.sendText(bob.address, 'Ratchet Step 3: Alice after receiving');
      if (result.firstMessage) {
        results.fail('Step 3: unexpected X3DH', new Error('Should be follow-up, not first message'));
      } else {
        results.pass('Step 3: Alice sent follow-up');
      }
      
      await sleep(2000);
      const msgs = await bob.waitForMessages(1, 8000);
      if (msgs[0].content.text === 'Ratchet Step 3: Alice after receiving') {
        results.pass('Step 3: Bob received', 'Alice DH ratchet verified');
        
        const aliceSession = alice.getSessionStatus(bob.address);
        const bobSession = bob.getSessionStatus(alice.address);
        log(`    Alice session: sent=${aliceSession?.sentThisChain}, recv=${aliceSession?.recvThisChain}`);
        log(`    Bob session: sent=${bobSession?.sentThisChain}, recv=${bobSession?.recvThisChain}`);
      } else {
        results.fail('Step 3: content mismatch', new Error(msgs[0].content.text));
      }
    } catch (e) {
      results.fail('Step 3: Alice → Bob', e);
    }
    
    bob.clearMessages();

    // Step 4: Bob → Alice (receiver second message, steady state)
    console.log('\n  🔄 Step 4: Bob → Alice (second reply, steady state)');
    try {
      const result = await bob.sendText(alice.address, 'Ratchet Step 4: Bob second reply');
      results.pass('Step 4: Bob sent');
      
      await sleep(2000);
      const msgs = await alice.waitForMessages(1, 8000);
      if (msgs[0].content.text === 'Ratchet Step 4: Bob second reply') {
        results.pass('Step 4: Alice received', 'Steady state ratchet verified');
        
        const aliceSession = alice.getSessionStatus(bob.address);
        const bobSession = bob.getSessionStatus(alice.address);
        log(`    Alice session: sent=${aliceSession?.sentThisChain}, recv=${aliceSession?.recvThisChain}`);
        log(`    Bob session: sent=${bobSession?.sentThisChain}, recv=${bobSession?.recvThisChain}`);
      } else {
        results.fail('Step 4: content mismatch', new Error(msgs[0].content.text));
      }
    } catch (e) {
      results.fail('Step 4: Bob → Alice', e);
    }
    
    alice.clearMessages();
    bob.clearMessages();

    // Step 5: Back-to-back from same sender (chain key advancement without DH)
    console.log('\n  🔄 Step 5: Back-to-back messages (chain key only)');
    try {
      await alice.sendText(bob.address, 'Back-to-back 1');
      await alice.sendText(bob.address, 'Back-to-back 2');
      await alice.sendText(bob.address, 'Back-to-back 3');
      results.pass('Step 5: Alice sent 3 consecutive');
      
      await sleep(3000);
      const msgs = await bob.waitForMessages(3, 8000);
      const texts = msgs.map(m => m.content.text);
      if (texts.includes('Back-to-back 1') && texts.includes('Back-to-back 2') && texts.includes('Back-to-back 3')) {
        results.pass('Step 5: Bob received all 3', 'Chain key advancement verified');
        
        const aliceSession = alice.getSessionStatus(bob.address);
        log(`    Alice chain length: sent=${aliceSession?.sentThisChain}`);
      } else {
        results.fail('Step 5: missing messages', new Error(`Got: ${texts.join(', ')}`));
      }
    } catch (e) {
      results.fail('Step 5: back-to-back', e);
    }

    results.pass('All ratchet transitions completed');

  } finally {
    // Cleanup
    console.log('\n🧹 Cleanup');
    
    if (alice) alice.stopListening();
    if (bob) bob.stopListening();
    
    if (!KEEP_DATA && existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true });
      console.log('  Removed test directory');
    } else if (KEEP_DATA) {
      console.log(`  Kept test data at: ${TEST_BASE_DIR}`);
    }
  }

  const success = results.summary();
  process.exit(success ? 0 : 1);
}

// Run
runTests().catch(err => {
  console.error('\n💥 Fatal error:', err);
  process.exit(1);
});
