/**
 * Quorum State Store
 * 
 * Persists keys, ratchet states, and conversation metadata to disk.
 * All sensitive data is stored as JSON files in a configurable directory.
 */

import { mkdirSync, readFileSync, writeFileSync, existsSync, readdirSync, renameSync, openSync, closeSync, fsyncSync } from 'fs';
import { join } from 'path';

/**
 * Atomic file write: write to temp file, fsync, then rename.
 * Rename is atomic on POSIX, so we either get the old file or the new one, never partial.
 */
function atomicWriteFileSync(targetPath, data) {
  const tempPath = `${targetPath}.tmp.${process.pid}`;
  const fd = openSync(tempPath, 'w');
  try {
    writeFileSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tempPath, targetPath);
}

export class QuorumStore {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.keysDir = join(dataDir, 'keys');
    this.sessionsDir = join(dataDir, 'sessions');
    this.conversationsDir = join(dataDir, 'conversations');
    
    // Ensure directories exist
    for (const dir of [this.dataDir, this.keysDir, this.sessionsDir, this.conversationsDir]) {
      mkdirSync(dir, { recursive: true });
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
