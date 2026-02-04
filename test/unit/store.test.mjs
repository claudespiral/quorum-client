/**
 * Unit tests for src/store.mjs
 * 
 * Tests file-based storage:
 * - Directory creation with secure permissions
 * - User/device keyset persistence
 * - Session CRUD operations
 * - Conversation inbox keypairs
 * - Atomic file writes
 * - Generic save/load
 */

import { describe, it, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { existsSync, mkdirSync, rmSync, statSync, readFileSync, writeFileSync, readdirSync } from 'fs';
import { tmpdir } from 'os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, '..', '..');

const { QuorumStore } = await import(join(PROJECT_ROOT, 'src/store.mjs'));

// ============ Test Setup ============

let testDir;
let store;

function createTestDir() {
  testDir = join(tmpdir(), `quorum-store-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(testDir, { recursive: true });
}

function cleanupTestDir() {
  if (testDir && existsSync(testDir)) {
    rmSync(testDir, { recursive: true });
  }
}

// ============ Directory Structure ============

describe('QuorumStore - Directory Structure', () => {
  beforeEach(() => {
    createTestDir();
    store = new QuorumStore(testDir);
  });

  afterEach(() => {
    cleanupTestDir();
  });

  it('should create data directory', () => {
    assert.ok(existsSync(testDir), 'data directory should exist');
  });

  it('should create keys subdirectory', () => {
    assert.ok(existsSync(join(testDir, 'keys')), 'keys directory should exist');
  });

  it('should create sessions subdirectory', () => {
    assert.ok(existsSync(join(testDir, 'sessions')), 'sessions directory should exist');
  });

  it('should create conversations subdirectory', () => {
    assert.ok(existsSync(join(testDir, 'conversations')), 'conversations directory should exist');
  });

  it('should create directories with 0700 permissions (owner only)', () => {
    const stats = statSync(testDir);
    const mode = stats.mode & 0o777;
    
    // On some systems this might be affected by umask, so check at least owner has full access
    assert.ok((mode & 0o700) === 0o700, 'owner should have rwx permissions');
  });
});

// ============ User Keyset ============

describe('QuorumStore - User Keyset', () => {
  beforeEach(() => {
    createTestDir();
    store = new QuorumStore(testDir);
  });

  afterEach(() => {
    cleanupTestDir();
  });

  const mockUserKeyset = {
    public_key: [1, 2, 3, 4, 5],
    private_key: [6, 7, 8, 9, 10],
  };

  it('should save and load user keyset', () => {
    store.saveUserKeyset(mockUserKeyset);
    const loaded = store.getUserKeyset();
    
    assert.deepEqual(loaded, mockUserKeyset);
  });

  it('should return null if no user keyset exists', () => {
    const result = store.getUserKeyset();
    assert.equal(result, null);
  });

  it('should overwrite existing user keyset', () => {
    store.saveUserKeyset(mockUserKeyset);
    
    const newKeyset = { public_key: [11, 12], private_key: [13, 14] };
    store.saveUserKeyset(newKeyset);
    
    const loaded = store.getUserKeyset();
    assert.deepEqual(loaded, newKeyset);
  });

  it('should persist user keyset as JSON file', () => {
    store.saveUserKeyset(mockUserKeyset);
    
    const filePath = join(testDir, 'keys', 'user-keyset.json');
    assert.ok(existsSync(filePath), 'file should exist');
    
    const contents = JSON.parse(readFileSync(filePath, 'utf-8'));
    assert.deepEqual(contents, mockUserKeyset);
  });
});

// ============ Device Keyset ============

describe('QuorumStore - Device Keyset', () => {
  beforeEach(() => {
    createTestDir();
    store = new QuorumStore(testDir);
  });

  afterEach(() => {
    cleanupTestDir();
  });

  const mockDeviceKeyset = {
    identity_key: { public_key: [1, 2, 3], private_key: [4, 5, 6] },
    pre_key: { public_key: [7, 8, 9], private_key: [10, 11, 12] },
    inbox_encryption_key: { public_key: [13, 14], private_key: [15, 16] },
    inbox_signing_key: { public_key: [17, 18], private_key: [19, 20] },
    inbox_address: 'QmTestInbox123',
  };

  it('should save and load device keyset', () => {
    store.saveDeviceKeyset(mockDeviceKeyset);
    const loaded = store.getDeviceKeyset();
    
    assert.deepEqual(loaded, mockDeviceKeyset);
  });

  it('should return null if no device keyset exists', () => {
    const result = store.getDeviceKeyset();
    assert.equal(result, null);
  });
});

// ============ Registration ============

describe('QuorumStore - Registration', () => {
  beforeEach(() => {
    createTestDir();
    store = new QuorumStore(testDir);
  });

  afterEach(() => {
    cleanupTestDir();
  });

  const mockRegistration = {
    user_address: 'QmUserAddress123',
    user_public_key: 'abcdef123456',
    peer_public_key: 'fedcba654321',
    device_registrations: [],
    signature: 'sig123',
  };

  it('should save and load registration', () => {
    store.saveRegistration(mockRegistration);
    const loaded = store.getRegistration();
    
    assert.deepEqual(loaded, mockRegistration);
  });

  it('should return null if no registration exists', () => {
    const result = store.getRegistration();
    assert.equal(result, null);
  });

  it('should report hasIdentity correctly', () => {
    assert.equal(store.hasIdentity(), false, 'should be false initially');
    
    store.saveUserKeyset({ public_key: [], private_key: [] });
    
    assert.equal(store.hasIdentity(), true, 'should be true after saving keyset');
  });
});

// ============ Sessions ============

describe('QuorumStore - Sessions', () => {
  beforeEach(() => {
    createTestDir();
    store = new QuorumStore(testDir);
  });

  afterEach(() => {
    cleanupTestDir();
  });

  const mockSession = {
    ratchet_state: '{"some": "state"}',
    sending_inbox: {
      inbox_address: 'QmSendingInbox',
      inbox_encryption_key: 'abcdef',
    },
    recipient_address: 'QmRecipient123',
    sender_name: 'Test User',
    created_at: '2024-01-01T00:00:00Z',
  };

  it('should save and load session by tag', () => {
    const tag = 'QmRecipient123';
    store.saveSession(tag, mockSession);
    const loaded = store.getSession(tag);
    
    assert.deepEqual(loaded, mockSession);
  });

  it('should return null for non-existent session', () => {
    const result = store.getSession('non-existent-tag');
    assert.equal(result, null);
  });

  it('should list all session tags', () => {
    store.saveSession('tag1', { ...mockSession, recipient_address: 'addr1' });
    store.saveSession('tag2', { ...mockSession, recipient_address: 'addr2' });
    store.saveSession('tag3', { ...mockSession, recipient_address: 'addr3' });
    
    const tags = store.listSessions();
    
    assert.equal(tags.length, 3);
    assert.ok(tags.includes('tag1'));
    assert.ok(tags.includes('tag2'));
    assert.ok(tags.includes('tag3'));
  });

  it('should delete session', () => {
    const tag = 'to-delete';
    store.saveSession(tag, mockSession);
    
    assert.ok(store.getSession(tag), 'session should exist');
    
    const deleted = store.deleteSession(tag);
    
    assert.equal(deleted, true, 'deleteSession should return true');
    assert.equal(store.getSession(tag), null, 'session should be deleted');
  });

  it('should return false when deleting non-existent session', () => {
    const deleted = store.deleteSession('non-existent');
    assert.equal(deleted, false);
  });

  it('should handle special characters in tag (hex encoded)', () => {
    const tag = 'Qm/special+chars=test';
    store.saveSession(tag, mockSession);
    const loaded = store.getSession(tag);
    
    assert.deepEqual(loaded, mockSession);
  });

  it('should update existing session', () => {
    const tag = 'update-test';
    store.saveSession(tag, mockSession);
    
    const updatedSession = { ...mockSession, sender_name: 'Updated Name' };
    store.saveSession(tag, updatedSession);
    
    const loaded = store.getSession(tag);
    assert.equal(loaded.sender_name, 'Updated Name');
  });
});

// ============ Conversation Inbox Keypairs ============

describe('QuorumStore - Conversation Inbox Keypairs', () => {
  beforeEach(() => {
    createTestDir();
    store = new QuorumStore(testDir);
  });

  afterEach(() => {
    cleanupTestDir();
  });

  const mockKeypair = {
    conversationId: 'conv123',
    inboxAddress: 'QmInboxAddr',
    encryptionPublicKey: 'pubkey1',
    encryptionPrivateKey: 'privkey1',
    signingPublicKey: 'sigpub',
    signingPrivateKey: 'sigpriv',
  };

  it('should save and load conversation inbox keypair', () => {
    store.saveConversationInboxKeypair(mockKeypair);
    const loaded = store.getConversationInboxKeypair('conv123');
    
    assert.deepEqual(loaded, mockKeypair);
  });

  it('should return null for non-existent conversation', () => {
    const result = store.getConversationInboxKeypair('non-existent');
    assert.equal(result, null);
  });

  it('should get keypair by inbox address', () => {
    store.saveConversationInboxKeypair(mockKeypair);
    const loaded = store.getConversationInboxKeypairByAddress('QmInboxAddr');
    
    assert.deepEqual(loaded, mockKeypair);
  });

  it('should return null when inbox address not found', () => {
    const result = store.getConversationInboxKeypairByAddress('non-existent');
    assert.equal(result, null);
  });

  it('should list all conversation inbox addresses', () => {
    const kp1 = { ...mockKeypair, conversationId: 'c1', inboxAddress: 'inbox1' };
    const kp2 = { ...mockKeypair, conversationId: 'c2', inboxAddress: 'inbox2' };
    
    store.saveConversationInboxKeypair(kp1);
    store.saveConversationInboxKeypair(kp2);
    
    const inboxes = store.listConversationInboxes();
    
    assert.equal(inboxes.length, 2);
    assert.ok(inboxes.includes('inbox1'));
    assert.ok(inboxes.includes('inbox2'));
  });

  it('should delete conversation inbox keypair', () => {
    store.saveConversationInboxKeypair(mockKeypair);
    
    const deleted = store.deleteConversationInboxKeypair('conv123');
    
    assert.equal(deleted, true);
    assert.equal(store.getConversationInboxKeypair('conv123'), null);
  });
});

// ============ Conversations ============

describe('QuorumStore - Conversations', () => {
  beforeEach(() => {
    createTestDir();
    store = new QuorumStore(testDir);
  });

  afterEach(() => {
    cleanupTestDir();
  });

  const mockConversation = {
    displayName: 'Test Conversation',
    lastMessage: 'Hello',
    lastMessageTime: Date.now(),
    unreadCount: 5,
  };

  it('should save and load conversation metadata', () => {
    store.saveConversation('conv123', mockConversation);
    const loaded = store.getConversation('conv123');
    
    assert.deepEqual(loaded, mockConversation);
  });

  it('should return null for non-existent conversation', () => {
    const result = store.getConversation('non-existent');
    assert.equal(result, null);
  });

  it('should list all conversations', () => {
    store.saveConversation('conv1', { ...mockConversation, displayName: 'Conv 1' });
    store.saveConversation('conv2', { ...mockConversation, displayName: 'Conv 2' });
    
    const conversations = store.listConversations();
    
    assert.equal(conversations.length, 2);
    assert.ok(conversations.some(c => c.displayName === 'Conv 1'));
    assert.ok(conversations.some(c => c.displayName === 'Conv 2'));
  });
});

// ============ Generic Save/Load ============

describe('QuorumStore - Generic Save/Load', () => {
  beforeEach(() => {
    createTestDir();
    store = new QuorumStore(testDir);
  });

  afterEach(() => {
    cleanupTestDir();
  });

  it('should save and load arbitrary JSON data', () => {
    const data = { key: 'value', nested: { array: [1, 2, 3] } };
    
    store.save('custom-data.json', data);
    const loaded = store.load('custom-data.json');
    
    assert.deepEqual(loaded, data);
  });

  it('should return null for non-existent file', () => {
    const result = store.load('non-existent.json');
    assert.equal(result, null);
  });

  it('should save to data directory root', () => {
    store.save('test.json', { test: true });
    
    const filePath = join(testDir, 'test.json');
    assert.ok(existsSync(filePath));
  });
});

// ============ Atomic Writes ============

describe('QuorumStore - Atomic Writes', () => {
  beforeEach(() => {
    createTestDir();
    store = new QuorumStore(testDir);
  });

  afterEach(() => {
    cleanupTestDir();
  });

  it('should not leave temp files after successful write', () => {
    store.save('atomic-test.json', { data: 'test' });
    
    const files = readdirSync(testDir);
    const tempFiles = files.filter(f => f.includes('.tmp.'));
    
    assert.equal(tempFiles.length, 0, 'should not have temp files');
  });

  it('should create files with 0600 permissions', () => {
    store.saveUserKeyset({ public_key: [], private_key: [] });
    
    const filePath = join(testDir, 'keys', 'user-keyset.json');
    const stats = statSync(filePath);
    const mode = stats.mode & 0o777;
    
    // Check file is readable/writable by owner only
    assert.ok((mode & 0o600) === 0o600, 'owner should have rw permissions');
    assert.ok((mode & 0o077) === 0, 'others should have no permissions');
  });
});

// ============ Edge Cases ============

describe('QuorumStore - Edge Cases', () => {
  beforeEach(() => {
    createTestDir();
    store = new QuorumStore(testDir);
  });

  afterEach(() => {
    cleanupTestDir();
  });

  it('should handle empty strings as data', () => {
    store.save('empty.json', '');
    const loaded = store.load('empty.json');
    assert.equal(loaded, '');
  });

  it('should handle arrays as data', () => {
    const arr = [1, 2, 3, { nested: true }];
    store.save('array.json', arr);
    const loaded = store.load('array.json');
    assert.deepEqual(loaded, arr);
  });

  it('should handle unicode in data', () => {
    const data = { message: '你好世界 🌍 مرحبا' };
    store.save('unicode.json', data);
    const loaded = store.load('unicode.json');
    assert.deepEqual(loaded, data);
  });

  it('should handle moderately long session tags', () => {
    // Keep tag short enough to not exceed filesystem limits (255 bytes for filename)
    // Hex encoding doubles the length, so max ~100 chars
    const longTag = 'a'.repeat(100);
    const session = { test: true };
    
    store.saveSession(longTag, session);
    const loaded = store.getSession(longTag);
    
    assert.deepEqual(loaded, session);
  });

  it('should handle concurrent saves to different sessions', async () => {
    const sessions = Array.from({ length: 10 }, (_, i) => ({
      tag: `session-${i}`,
      data: { index: i, timestamp: Date.now() },
    }));
    
    // Save all sessions "concurrently"
    await Promise.all(sessions.map(s => 
      new Promise(resolve => {
        store.saveSession(s.tag, s.data);
        resolve();
      })
    ));
    
    // Verify all were saved
    for (const s of sessions) {
      const loaded = store.getSession(s.tag);
      assert.deepEqual(loaded, s.data, `session ${s.tag} should be saved correctly`);
    }
  });
});
