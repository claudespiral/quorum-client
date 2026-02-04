#!/usr/bin/env node
/**
 * Quorum Spaces Integration Tests
 * 
 * Tests group chat functionality via Spaces:
 *   1. Space creation (generate keys, derive IDs)
 *   2. Invite URL generation & parsing
 *   3. Multiple participants joining same space
 *   4. Group message broadcast
 *   5. Message decryption by all participants
 *   6. Reactions in spaces
 *   7. Message deletion
 * 
 * Usage:
 *   node test/spaces.mjs              # Run all tests
 *   node test/spaces.mjs --keep       # Keep test data after run
 *   node test/spaces.mjs --verbose    # Show detailed output
 *   DEBUG=1 node test/spaces.mjs      # Show debug info
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const WebSocket = require('ws');

import { randomUUID, createHash, randomBytes } from 'crypto';
import { existsSync, mkdirSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { tmpdir } from 'os';
import { setTimeout as sleep } from 'timers/promises';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, '..');

// Test configuration
const TEST_BASE_DIR = process.env.TEST_DIR || join(tmpdir(), `quorum-space-test-${Date.now()}`);
const WS_URL = 'wss://api.quorummessenger.com/ws';
const API_BASE = 'https://api.quorummessenger.com';

const KEEP_DATA = process.argv.includes('--keep');
const VERBOSE = process.argv.includes('--verbose') || process.env.DEBUG;

// Import from project
const { 
  initCrypto, 
  generateX448, 
  generateEd448,
  getX448PubKey,
  getEd448PubKey,
  signEd448,
  deriveAddress,
  encryptInboxMessageBytes, 
  decryptInboxMessage,
  base58Encode,
  sha256,
} = await import(join(PROJECT_ROOT, 'src/crypto.mjs'));

const { createSecureStore } = await import(join(PROJECT_ROOT, 'src/secure-store.mjs'));

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

function bytesToBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function base64ToBytes(b64) {
  return new Uint8Array(Buffer.from(b64, 'base64'));
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

// ============ Space Creation ============

/**
 * Create a new space with all necessary keys.
 * Returns space keys and invite URL.
 */
function createSpace(spaceName = 'Test Space') {
  // Hub key (Ed448) - for signing hub messages
  const hubKey = generateEd448();
  const hubPubKeyHex = bytesToHex(new Uint8Array(hubKey.public_key));
  const hubPrivKeyHex = bytesToHex(new Uint8Array(hubKey.private_key));
  const hubAddress = deriveAddress(hubKey.public_key);
  
  // Config key (X448) - for encrypting/decrypting space messages
  const configKey = generateX448();
  const configPubKeyHex = bytesToHex(new Uint8Array(configKey.public_key));
  const configPrivKeyHex = bytesToHex(new Uint8Array(configKey.private_key));
  
  // Space ID derived from hub address (simplified - real impl may differ)
  const spaceId = hubAddress;
  
  // Default channel ID
  const defaultChannelId = deriveAddress(sha256(Buffer.from(`${spaceId}:general`)));
  
  // Build invite URL
  const inviteParams = new URLSearchParams({
    spaceId,
    configKey: configPrivKeyHex,
    hubKey: hubPrivKeyHex,
    template: Buffer.from(JSON.stringify({
      spaceName,
      defaultChannelId,
    })).toString('hex'),
  });
  
  const inviteUrl = `https://app.quorummessenger.com/#${inviteParams.toString()}`;
  
  return {
    spaceId,
    spaceName,
    hubAddress,
    hubPublicKey: hubPubKeyHex,
    hubPrivateKey: hubPrivKeyHex,
    configPublicKey: configPubKeyHex,
    configPrivateKey: configPrivKeyHex,
    defaultChannelId,
    inviteUrl,
    hubKey,
    configKey,
  };
}

/**
 * Parse an invite URL into space parameters
 */
function parseInviteUrl(inviteUrl) {
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
  
  // Parse template
  if (invite.template) {
    try {
      invite.templateJson = JSON.parse(Buffer.from(invite.template, 'hex').toString('utf8'));
    } catch (e) {
      invite.templateJson = null;
    }
  }
  
  return invite;
}

// ============ Space Participant ============

class SpaceParticipant {
  constructor(name, dataDir) {
    this.name = name;
    this.dataDir = dataDir;
    this.spaces = new Map(); // spaceId -> spaceKeys
    this.receivedMessages = [];
    this.ws = null;
    this.listeningInboxes = [];
  }

  async init() {
    mkdirSync(this.dataDir, { recursive: true });
    this.store = await createSecureStore(this.dataDir, false);
    log(`  ${this.name} initialized at ${this.dataDir}`);
    return this;
  }

  /**
   * Join a space from invite URL
   */
  async joinSpace(inviteUrl) {
    const invite = parseInviteUrl(inviteUrl);
    
    if (!invite.spaceId || !invite.configKey) {
      throw new Error('Invalid invite: missing spaceId or configKey');
    }
    
    // Derive hub info
    const hubPrivKeyBytes = hexToBytes(invite.hubKey);
    const hubPubKey = getEd448PubKey(bytesToBase64(hubPrivKeyBytes));
    const hubPubKeyBytes = base64ToBytes(hubPubKey);
    const hubPubKeyHex = bytesToHex(hubPubKeyBytes);
    const hubAddress = deriveAddress([...hubPubKeyBytes]);
    
    // Generate participant's inbox keys
    const inboxSigningKey = generateEd448();
    const inboxEncryptionKey = generateX448();
    const inboxAddress = deriveAddress(inboxSigningKey.public_key);
    
    log(`  ${this.name} joining space ${invite.spaceId.substring(0, 12)}...`);
    log(`    Inbox address: ${inboxAddress.substring(0, 16)}...`);
    
    // Register with hub
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
    
    log(`    Hub registration: ${hubResult.status || hubResult.error || 'unknown'}`);
    
    // Save space keys
    const spaceKeys = {
      spaceId: invite.spaceId,
      spaceName: invite.templateJson?.spaceName || invite.spaceId,
      hubAddress,
      hubPublicKey: hubPubKeyHex,
      hubPrivateKey: invite.hubKey,
      configPrivateKey: invite.configKey,
      defaultChannelId: invite.templateJson?.defaultChannelId,
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
    
    this.spaces.set(invite.spaceId, spaceKeys);
    await this.store.saveSpaceKeys(invite.spaceId, spaceKeys);
    
    return spaceKeys;
  }

  /**
   * Start listening for messages on all joined spaces
   */
  async startListening() {
    const inboxes = [...this.spaces.values()].map(s => s.inboxAddress);
    if (inboxes.length === 0) {
      log(`  ${this.name} has no spaces to listen on`);
      return;
    }
    
    this.listeningInboxes = inboxes;
    
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(WS_URL);
      
      this.ws.on('open', () => {
        this.ws.send(JSON.stringify({
          type: 'listen',
          inbox_addresses: inboxes,
        }));
        log(`  ${this.name} listening on ${inboxes.length} inbox(es)`);
        resolve();
      });
      
      this.ws.on('message', async (data) => {
        try {
          const msg = JSON.parse(data.toString());
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
      setTimeout(() => resolve(), 2000);
    });
  }

  async _processIncomingMessage(msg) {
    const envelope = JSON.parse(msg.encryptedContent);
    
    // Try to decrypt with each space's config key
    for (const [spaceId, spaceKeys] of this.spaces) {
      try {
        const innerEnvelope = JSON.parse(envelope.envelope);
        const configPrivKey = hexToBytes(spaceKeys.configPrivateKey);
        const ephPubKey = hexToBytes(envelope.ephemeral_public_key);
        
        const decrypted = decryptInboxMessage(
          [...configPrivKey],
          [...ephPubKey],
          innerEnvelope
        );
        
        const plaintext = new TextDecoder().decode(new Uint8Array(decrypted));
        const parsed = JSON.parse(plaintext);
        
        if (parsed.type === 'message' && parsed.message) {
          const message = parsed.message;
          return {
            spaceId,
            messageId: message.messageId,
            channelId: message.channelId,
            content: message.content,
            from: message.content.senderId,
            isMe: message.content.senderId === spaceKeys.inboxAddress,
            timestamp: message.createdDate,
          };
        }
      } catch (e) {
        // Try next space
        continue;
      }
    }
    return null;
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

  /**
   * Send a message to a space
   */
  async sendMessage(spaceId, text, channelId = null) {
    const spaceKeys = this.spaces.get(spaceId);
    if (!spaceKeys) throw new Error(`Not joined to space: ${spaceId}`);
    
    const targetChannelId = channelId || spaceKeys.defaultChannelId;
    const timestamp = Date.now();
    const nonce = bytesToHex(randomBytes(16));
    const idContent = `${spaceId}:${targetChannelId}:${spaceKeys.inboxAddress}:${nonce}:${timestamp}`;
    const messageId = bytesToHex(createHash('sha256').update(idContent).digest());
    
    const content = {
      type: 'post',
      senderId: spaceKeys.inboxAddress,
      text,
    };
    
    const message = {
      channelId: targetChannelId,
      spaceId,
      messageId,
      digestAlgorithm: 'sha256',
      nonce,
      createdDate: timestamp,
      modifiedDate: timestamp,
      lastModifiedHash: '',
      content,
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
    
    // Build sealed envelope
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
      const sendWs = new WebSocket(WS_URL);
      
      sendWs.on('open', () => {
        sendWs.send(wsEnvelope);
        setTimeout(() => {
          sendWs.close();
          resolve({ messageId, text });
        }, 1000);
      });
      
      sendWs.on('error', reject);
    });
  }

  /**
   * Send a reaction to a message
   */
  async sendReaction(spaceId, targetMessageId, emoji, channelId = null) {
    const spaceKeys = this.spaces.get(spaceId);
    if (!spaceKeys) throw new Error(`Not joined to space: ${spaceId}`);
    
    return this._sendSpaceAction(spaceKeys, channelId, {
      type: 'reaction',
      reaction: emoji,
      messageId: targetMessageId,
    });
  }

  /**
   * Delete a message
   */
  async sendDelete(spaceId, targetMessageId, channelId = null) {
    const spaceKeys = this.spaces.get(spaceId);
    if (!spaceKeys) throw new Error(`Not joined to space: ${spaceId}`);
    
    return this._sendSpaceAction(spaceKeys, channelId, {
      type: 'remove-message',
      removeMessageId: targetMessageId,
    });
  }

  async _sendSpaceAction(spaceKeys, channelId, content) {
    const targetChannelId = channelId || spaceKeys.defaultChannelId;
    const timestamp = Date.now();
    const nonce = bytesToHex(randomBytes(16));
    const idContent = `${spaceKeys.spaceId}:${targetChannelId}:${spaceKeys.inboxAddress}:${nonce}:${timestamp}`;
    const messageId = bytesToHex(createHash('sha256').update(idContent).digest());
    
    const message = {
      channelId: targetChannelId,
      spaceId: spaceKeys.spaceId,
      messageId,
      digestAlgorithm: 'sha256',
      nonce,
      createdDate: timestamp,
      modifiedDate: timestamp,
      lastModifiedHash: '',
      content: { ...content, senderId: spaceKeys.inboxAddress },
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
    
    // Build sealed envelope
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
      const sendWs = new WebSocket(WS_URL);
      
      sendWs.on('open', () => {
        sendWs.send(wsEnvelope);
        setTimeout(() => {
          sendWs.close();
          resolve({ messageId });
        }, 1000);
      });
      
      sendWs.on('error', reject);
    });
  }
}

// ============ Test Suites ============

async function runTests() {
  console.log('\n🔬 Quorum Spaces Integration Tests');
  console.log('═'.repeat(50));
  console.log(`Test directory: ${TEST_BASE_DIR}`);
  console.log();

  const results = new TestResults();
  let alice, bob, charlie;
  let testSpace;

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

    // ============ Test 1: Space Creation ============
    console.log('\n📋 Test Suite: Space Creation');
    
    try {
      testSpace = createSpace('Test Space Alpha');
      
      if (testSpace.spaceId && testSpace.hubAddress) {
        results.pass('Space keys generated', `spaceId: ${testSpace.spaceId.substring(0, 16)}...`);
      } else {
        results.fail('Space key generation', new Error('Missing spaceId or hubAddress'));
      }
      
      if (testSpace.configPrivateKey && testSpace.hubPrivateKey) {
        results.pass('Config and hub keys created');
      } else {
        results.fail('Key creation', new Error('Missing config or hub keys'));
      }
      
      if (testSpace.inviteUrl.includes('spaceId=') && testSpace.inviteUrl.includes('configKey=')) {
        results.pass('Invite URL generated');
        log(`    Invite URL: ${testSpace.inviteUrl.substring(0, 80)}...`);
      } else {
        results.fail('Invite URL generation', new Error('Invalid invite URL'));
      }
    } catch (e) {
      results.fail('Space creation', e);
      throw e;
    }

    // ============ Test 2: Invite URL Parsing ============
    console.log('\n📋 Test Suite: Invite URL Parsing');
    
    try {
      const parsed = parseInviteUrl(testSpace.inviteUrl);
      
      if (parsed.spaceId === testSpace.spaceId) {
        results.pass('SpaceId parsed correctly');
      } else {
        results.fail('SpaceId parsing', new Error('Mismatch'));
      }
      
      if (parsed.configKey === testSpace.configPrivateKey) {
        results.pass('ConfigKey parsed correctly');
      } else {
        results.fail('ConfigKey parsing', new Error('Mismatch'));
      }
      
      if (parsed.hubKey === testSpace.hubPrivateKey) {
        results.pass('HubKey parsed correctly');
      } else {
        results.fail('HubKey parsing', new Error('Mismatch'));
      }
      
      if (parsed.templateJson?.spaceName === 'Test Space Alpha') {
        results.pass('Template parsed correctly', `spaceName: ${parsed.templateJson.spaceName}`);
      } else {
        results.fail('Template parsing', new Error('Missing or wrong spaceName'));
      }
    } catch (e) {
      results.fail('Invite URL parsing', e);
    }

    // ============ Test 3: Participants Join Space ============
    console.log('\n📋 Test Suite: Participants Joining');
    
    try {
      alice = await new SpaceParticipant('Alice', join(TEST_BASE_DIR, 'alice')).init();
      bob = await new SpaceParticipant('Bob', join(TEST_BASE_DIR, 'bob')).init();
      charlie = await new SpaceParticipant('Charlie', join(TEST_BASE_DIR, 'charlie')).init();
      results.pass('Participants initialized');
    } catch (e) {
      results.fail('Participant initialization', e);
      throw e;
    }
    
    try {
      const aliceSpace = await alice.joinSpace(testSpace.inviteUrl);
      if (aliceSpace.inboxAddress) {
        results.pass('Alice joined space', `inbox: ${aliceSpace.inboxAddress.substring(0, 16)}...`);
      } else {
        results.fail('Alice join', new Error('No inbox address'));
      }
    } catch (e) {
      results.fail('Alice join space', e);
    }
    
    try {
      const bobSpace = await bob.joinSpace(testSpace.inviteUrl);
      if (bobSpace.inboxAddress) {
        results.pass('Bob joined space', `inbox: ${bobSpace.inboxAddress.substring(0, 16)}...`);
      } else {
        results.fail('Bob join', new Error('No inbox address'));
      }
    } catch (e) {
      results.fail('Bob join space', e);
    }
    
    try {
      const charlieSpace = await charlie.joinSpace(testSpace.inviteUrl);
      if (charlieSpace.inboxAddress) {
        results.pass('Charlie joined space', `inbox: ${charlieSpace.inboxAddress.substring(0, 16)}...`);
      } else {
        results.fail('Charlie join', new Error('No inbox address'));
      }
    } catch (e) {
      results.fail('Charlie join space', e);
    }

    // Verify unique inbox addresses
    const aliceInbox = alice.spaces.get(testSpace.spaceId)?.inboxAddress;
    const bobInbox = bob.spaces.get(testSpace.spaceId)?.inboxAddress;
    const charlieInbox = charlie.spaces.get(testSpace.spaceId)?.inboxAddress;
    
    if (aliceInbox !== bobInbox && bobInbox !== charlieInbox && aliceInbox !== charlieInbox) {
      results.pass('Unique inbox addresses for all participants');
    } else {
      results.fail('Inbox uniqueness', new Error('Duplicate inbox addresses'));
    }

    // ============ Test 4: Start Listening ============
    console.log('\n📋 Test Suite: WebSocket Listeners');
    
    try {
      await alice.startListening();
      results.pass('Alice listening');
    } catch (e) {
      results.fail('Alice listener', e);
    }
    
    try {
      await bob.startListening();
      results.pass('Bob listening');
    } catch (e) {
      results.fail('Bob listener', e);
    }
    
    try {
      await charlie.startListening();
      results.pass('Charlie listening');
    } catch (e) {
      results.fail('Charlie listener', e);
    }
    
    await sleep(2000); // Let connections stabilize

    // ============ Test 5: Group Message Broadcast ============
    console.log('\n📋 Test Suite: Group Message Broadcast');
    
    let aliceMsg1Id;
    try {
      const result = await alice.sendMessage(testSpace.spaceId, 'Hello everyone! This is Alice.');
      aliceMsg1Id = result.messageId;
      results.pass('Alice sent message', `id: ${aliceMsg1Id.substring(0, 16)}...`);
    } catch (e) {
      results.fail('Alice send message', e);
    }
    
    await sleep(3000);
    
    // Check Bob received
    try {
      const bobMsgs = bob.receivedMessages.filter(m => m.content?.text === 'Hello everyone! This is Alice.');
      if (bobMsgs.length > 0) {
        results.pass('Bob received Alice\'s message');
      } else {
        results.fail('Bob receive', new Error('Message not received'));
      }
    } catch (e) {
      results.fail('Bob receive check', e);
    }
    
    // Check Charlie received
    try {
      const charlieMsgs = charlie.receivedMessages.filter(m => m.content?.text === 'Hello everyone! This is Alice.');
      if (charlieMsgs.length > 0) {
        results.pass('Charlie received Alice\'s message');
      } else {
        results.fail('Charlie receive', new Error('Message not received'));
      }
    } catch (e) {
      results.fail('Charlie receive check', e);
    }

    // ============ Test 6: Multi-Sender Conversation ============
    console.log('\n📋 Test Suite: Multi-Sender Conversation');
    
    alice.clearMessages();
    bob.clearMessages();
    charlie.clearMessages();
    
    try {
      await bob.sendMessage(testSpace.spaceId, 'Hi Alice! Bob here.');
      results.pass('Bob sent message');
      
      await sleep(1000);
      
      await charlie.sendMessage(testSpace.spaceId, 'Hey all! Charlie joining.');
      results.pass('Charlie sent message');
      
      await sleep(3000);
      
      // Verify Alice got both messages
      const aliceTexts = alice.receivedMessages.map(m => m.content?.text);
      if (aliceTexts.includes('Hi Alice! Bob here.') && aliceTexts.includes('Hey all! Charlie joining.')) {
        results.pass('Alice received messages from both Bob and Charlie');
      } else {
        results.fail('Alice multi-receive', new Error(`Got: ${aliceTexts.join(', ')}`));
      }
    } catch (e) {
      results.fail('Multi-sender conversation', e);
    }

    // ============ Test 7: Reactions ============
    console.log('\n📋 Test Suite: Reactions in Space');
    
    bob.clearMessages();
    charlie.clearMessages();
    
    try {
      if (aliceMsg1Id) {
        await bob.sendReaction(testSpace.spaceId, aliceMsg1Id, '👍');
        results.pass('Bob sent reaction');
        
        await sleep(2000);
        
        // Check if Alice and Charlie received the reaction
        const aliceReactions = alice.receivedMessages.filter(m => m.content?.type === 'reaction');
        if (aliceReactions.length > 0 && aliceReactions[0].content?.reaction === '👍') {
          results.pass('Alice received reaction');
        } else {
          log('Alice messages:', alice.receivedMessages);
          results.fail('Alice reaction receive', new Error('Reaction not received'));
        }
      } else {
        results.fail('Reaction test', new Error('No message ID from earlier test'));
      }
    } catch (e) {
      results.fail('Reactions', e);
    }

    // ============ Test 8: Message Deletion ============
    console.log('\n📋 Test Suite: Message Deletion');
    
    alice.clearMessages();
    bob.clearMessages();
    charlie.clearMessages();
    
    try {
      // Charlie sends a message then deletes it
      const charlieMsg = await charlie.sendMessage(testSpace.spaceId, 'Oops, wrong message!');
      results.pass('Charlie sent message to delete');
      
      await sleep(2000);
      
      await charlie.sendDelete(testSpace.spaceId, charlieMsg.messageId);
      results.pass('Charlie deleted message');
      
      await sleep(2000);
      
      // Check if others received the delete
      const aliceDeletes = alice.receivedMessages.filter(m => m.content?.type === 'remove-message');
      if (aliceDeletes.length > 0) {
        results.pass('Alice received delete notification');
      } else {
        results.fail('Delete notification', new Error('Delete not received'));
      }
    } catch (e) {
      results.fail('Message deletion', e);
    }

    // ============ Test 9: Rapid Messages ============
    console.log('\n📋 Test Suite: Rapid Message Sequence');
    
    alice.clearMessages();
    bob.clearMessages();
    charlie.clearMessages();
    
    try {
      await alice.sendMessage(testSpace.spaceId, 'Rapid 1');
      await alice.sendMessage(testSpace.spaceId, 'Rapid 2');
      await alice.sendMessage(testSpace.spaceId, 'Rapid 3');
      results.pass('Alice sent 3 rapid messages');
      
      await sleep(4000);
      
      const bobRapids = bob.receivedMessages.filter(m => m.content?.text?.startsWith('Rapid'));
      if (bobRapids.length >= 3) {
        results.pass('Bob received all 3 rapid messages');
      } else {
        results.fail('Rapid message receive', new Error(`Expected 3, got ${bobRapids.length}`));
      }
    } catch (e) {
      results.fail('Rapid messages', e);
    }

  } finally {
    // Cleanup
    console.log('\n🧹 Cleanup');
    
    if (alice) alice.stopListening();
    if (bob) bob.stopListening();
    if (charlie) charlie.stopListening();
    
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
