/**
 * Quorum State Store
 * 
 * Persists keys, ratchet states, and conversation metadata to disk.
 * All sensitive data is stored as JSON files in a configurable directory.
 */

import { mkdirSync, readFileSync, writeFileSync, existsSync, readdirSync, renameSync, openSync, closeSync, fsyncSync, chmodSync, unlinkSync } from 'fs';
import { join } from 'path';

/**
 * Atomic file write: write to temp file, fsync, then rename.
 * Rename is atomic on POSIX, so we either get the old file or the new one, never partial.
 * Uses mode 0600 (owner read/write only) for security.
 */
function atomicWriteFileSync(targetPath, data, mode = 0o600) {
  const tempPath = `${targetPath}.tmp.${process.pid}`;
  // Open with restrictive permissions from the start
  const fd = openSync(tempPath, 'w', mode);
  try {
    writeFileSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tempPath, targetPath);
  // Ensure final file has correct permissions (rename preserves temp file permissions)
  chmodSync(targetPath, mode);
}

export class QuorumStore {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.keysDir = join(dataDir, 'keys');
    this.sessionsDir = join(dataDir, 'sessions');
    this.conversationsDir = join(dataDir, 'conversations');
    
    // Ensure directories exist with secure permissions (owner only)
    for (const dir of [this.dataDir, this.keysDir, this.sessionsDir, this.conversationsDir]) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
  }

  // ============ Identity ============

  /** Save the user keyset (Ed448 user key + X448 peer key) */
  saveUserKeyset(keyset) {
    atomicWriteFileSync(join(this.keysDir, 'user-keyset.json'), JSON.stringify(keyset, null, 2));
  }

  /** Load the user keyset */
  getUserKeyset() {
    const path = join(this.keysDir, 'user-keyset.json');
    if (!existsSync(path)) return null;
    return JSON.parse(readFileSync(path, 'utf-8'));
  }

  /** Save the device keyset (identity + pre-key + inbox) */
  saveDeviceKeyset(keyset) {
    atomicWriteFileSync(join(this.keysDir, 'device-keyset.json'), JSON.stringify(keyset, null, 2));
  }

  /** Load the device keyset */
  getDeviceKeyset() {
    const path = join(this.keysDir, 'device-keyset.json');
    if (!existsSync(path)) return null;
    return JSON.parse(readFileSync(path, 'utf-8'));
  }

  /** Save the user registration (public info posted to API) */
  saveRegistration(reg) {
    atomicWriteFileSync(join(this.keysDir, 'registration.json'), JSON.stringify(reg, null, 2));
  }

  /** Load the user registration */
  getRegistration() {
    const path = join(this.keysDir, 'registration.json');
    if (!existsSync(path)) return null;
    return JSON.parse(readFileSync(path, 'utf-8'));
  }

  /** Check if identity has been created */
  hasIdentity() {
    return existsSync(join(this.keysDir, 'user-keyset.json'));
  }

  // ============ Ratchet Sessions ============

  /** 
   * Save a Double Ratchet session state.
   * tag = unique identifier for the conversation partner's inbox.
   * Uses atomic write to prevent corruption on crash.
   */
  saveSession(tag, state) {
    const safeName = Buffer.from(tag).toString('hex');
    atomicWriteFileSync(join(this.sessionsDir, `${safeName}.json`), JSON.stringify(state, null, 2));
  }

  /** Load a session state by tag */
  getSession(tag) {
    const safeName = Buffer.from(tag).toString('hex');
    const path = join(this.sessionsDir, `${safeName}.json`);
    if (!existsSync(path)) return null;
    return JSON.parse(readFileSync(path, 'utf-8'));
  }

  /** List all session tags */
  listSessions() {
    return readdirSync(this.sessionsDir)
      .filter(f => f.endsWith('.json'))
      .map(f => Buffer.from(f.replace('.json', ''), 'hex').toString());
  }

  /** Delete a session by tag */
  deleteSession(tag) {
    const safeName = Buffer.from(tag).toString('hex');
    const path = join(this.sessionsDir, `${safeName}.json`);
    if (existsSync(path)) {
      unlinkSync(path);
      return true;
    }
    return false;
  }

  // ============ Conversation Inbox Keypairs ============

  /**
   * Save a conversation-specific inbox keypair.
   * These are per-conversation inboxes used as return_inbox_address in init envelopes.
   * 
   * @param {Object} keypair - { conversationId, inboxAddress, encryptionPublicKey, encryptionPrivateKey, signingPublicKey, signingPrivateKey }
   */
  saveConversationInboxKeypair(keypair) {
    const safeName = Buffer.from(keypair.conversationId).toString('hex');
    atomicWriteFileSync(
      join(this.conversationsDir, `inbox_${safeName}.json`),
      JSON.stringify(keypair, null, 2)
    );
  }

  /** Get conversation inbox keypair by conversationId */
  getConversationInboxKeypair(conversationId) {
    const safeName = Buffer.from(conversationId).toString('hex');
    const path = join(this.conversationsDir, `inbox_${safeName}.json`);
    if (!existsSync(path)) return null;
    return JSON.parse(readFileSync(path, 'utf-8'));
  }

  /** Get conversation inbox keypair by inbox address */
  getConversationInboxKeypairByAddress(inboxAddress) {
    const files = readdirSync(this.conversationsDir).filter(f => f.startsWith('inbox_') && f.endsWith('.json'));
    for (const file of files) {
      const keypair = JSON.parse(readFileSync(join(this.conversationsDir, file), 'utf-8'));
      if (keypair.inboxAddress === inboxAddress) {
        return keypair;
      }
    }
    return null;
  }

  /** List all conversation inbox addresses */
  listConversationInboxes() {
    const files = readdirSync(this.conversationsDir).filter(f => f.startsWith('inbox_') && f.endsWith('.json'));
    return files.map(file => {
      const keypair = JSON.parse(readFileSync(join(this.conversationsDir, file), 'utf-8'));
      return keypair.inboxAddress;
    });
  }

  /** Delete conversation inbox keypair */
  deleteConversationInboxKeypair(conversationId) {
    const safeName = Buffer.from(conversationId).toString('hex');
    const path = join(this.conversationsDir, `inbox_${safeName}.json`);
    if (existsSync(path)) {
      unlinkSync(path);
      return true;
    }
    return false;
  }

  // ============ Conversations ============

  /** Save conversation metadata */
  saveConversation(conversationId, metadata) {
    atomicWriteFileSync(
      join(this.conversationsDir, `${conversationId}.json`),
      JSON.stringify(metadata, null, 2)
    );
  }

  /** Load conversation metadata */
  getConversation(conversationId) {
    const path = join(this.conversationsDir, `${conversationId}.json`);
    if (!existsSync(path)) return null;
    return JSON.parse(readFileSync(path, 'utf-8'));
  }

  /** List all conversations */
  listConversations() {
    return readdirSync(this.conversationsDir)
      .filter(f => f.endsWith('.json'))
      .map(f => {
        const id = f.replace('.json', '');
        return { id, ...JSON.parse(readFileSync(join(this.conversationsDir, f), 'utf-8')) };
      });
  }

  /** Save a generic key-value pair */
  save(filename, data) {
    atomicWriteFileSync(join(this.dataDir, filename), JSON.stringify(data, null, 2));
  }

  /** Load a generic key-value pair */
  load(filename) {
    const path = join(this.dataDir, filename);
    if (!existsSync(path)) return null;
    return JSON.parse(readFileSync(path, 'utf-8'));
  }
}
