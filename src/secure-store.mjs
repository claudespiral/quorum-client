/**
 * SecureStore - Wraps QuorumStore with keychain support
 * 
 * Uses OS keychain for sensitive keys (user keyset, device keyset),
 * falls back to plaintext files if keychain unavailable.
 * 
 * Usage:
 *   const store = await createSecureStore(dataDir);
 *   const keyset = await store.getDeviceKeyset();
 */

import { QuorumStore } from './store.mjs';
import * as keychain from './keychain.mjs';

export class SecureStore {
  constructor(dataDir, useKeychain = true) {
    this.fileStore = new QuorumStore(dataDir);
    this.useKeychain = useKeychain;
    this.keychainAvailable = false;
  }

  async init() {
    if (this.useKeychain) {
      this.keychainAvailable = await keychain.isKeychainAvailable();
      if (this.keychainAvailable) {
        console.log('🔐 Using OS keychain for key storage');
        // Offer migration if we have plaintext keys
        await keychain.migrateToKeychain(this.fileStore);
      } else {
        console.warn('⚠️  OS keychain not available, using plaintext storage');
        console.warn('   Keys stored in ~/.quorum-client/keys/ (unencrypted)');
      }
    }
    return this;
  }

  // ============ Keyset Access (keychain-backed) ============

  async getUserKeyset() {
    if (this.keychainAvailable) {
      const keyset = await keychain.getUserKeyset();
      if (keyset) return keyset;
      // Fall through to file if not in keychain yet
    }
    return this.fileStore.getUserKeyset();
  }

  async saveUserKeyset(keyset) {
    if (this.keychainAvailable) {
      await keychain.saveUserKeyset(keyset);
    }
    // Also save to file as backup (can be disabled after verification)
    this.fileStore.saveUserKeyset(keyset);
  }

  async getDeviceKeyset() {
    if (this.keychainAvailable) {
      const keyset = await keychain.getDeviceKeyset();
      if (keyset) return keyset;
    }
    return this.fileStore.getDeviceKeyset();
  }

  async saveDeviceKeyset(keyset) {
    if (this.keychainAvailable) {
      await keychain.saveDeviceKeyset(keyset);
    }
    this.fileStore.saveDeviceKeyset(keyset);
  }

  // ============ Pass-through methods (non-sensitive) ============

  saveRegistration(reg) {
    return this.fileStore.saveRegistration(reg);
  }

  getRegistration() {
    return this.fileStore.getRegistration();
  }

  hasIdentity() {
    return this.fileStore.hasIdentity();
  }

  saveSession(tag, state) {
    return this.fileStore.saveSession(tag, state);
  }

  getSession(tag) {
    return this.fileStore.getSession(tag);
  }

  listSessions() {
    return this.fileStore.listSessions();
  }

  saveConversation(conversationId, metadata) {
    return this.fileStore.saveConversation(conversationId, metadata);
  }

  getConversation(conversationId) {
    return this.fileStore.getConversation(conversationId);
  }

  listConversations() {
    return this.fileStore.listConversations();
  }

  save(filename, data) {
    return this.fileStore.save(filename, data);
  }

  load(filename) {
    return this.fileStore.load(filename);
  }

  // ============ Keychain management ============

  get isUsingKeychain() {
    return this.keychainAvailable;
  }

  /**
   * Remove plaintext key files after verifying keychain works
   * Call this manually after confirming access
   */
  async removePlaintextKeys() {
    if (!this.keychainAvailable) {
      throw new Error('Cannot remove plaintext keys - keychain not available');
    }
    
    // Verify we can read from keychain first
    const userKeyset = await keychain.getUserKeyset();
    const deviceKeyset = await keychain.getDeviceKeyset();
    
    if (!userKeyset || !deviceKeyset) {
      throw new Error('Cannot remove plaintext keys - not all keys in keychain');
    }
    
    // TODO: Actually delete the files
    // For now, just instruct user
    console.log('✅ Keychain access verified');
    console.log('Run these commands to remove plaintext keys:');
    console.log('  rm ~/.quorum-client/keys/user-keyset.json');
    console.log('  rm ~/.quorum-client/keys/device-keyset.json');
  }
}

/**
 * Create and initialize a secure store
 */
export async function createSecureStore(dataDir, useKeychain = true) {
  const store = new SecureStore(dataDir, useKeychain);
  await store.init();
  return store;
}
