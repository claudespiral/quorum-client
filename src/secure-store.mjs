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
import path from 'path';

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
        // Also migrate space keys
        const spacesDir = path.join(this.fileStore.dataDir, '..', 'spaces');
        await keychain.migrateSpacesToKeychain(spacesDir);
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

  deleteSession(tag) {
    return this.fileStore.deleteSession(tag);
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

  // ============ Space Keys (keychain-backed) ============

  async getSpaceKeys(spaceId) {
    if (this.keychainAvailable) {
      const keys = await keychain.getSpaceKeys(spaceId);
      if (keys) return keys;
    }
    // Fall back to file
    return this._loadSpaceKeysFromFile(spaceId);
  }

  async saveSpaceKeys(spaceId, keys) {
    if (this.keychainAvailable) {
      await keychain.saveSpaceKeys(spaceId, keys);
    } else {
      // Save to file if keychain not available
      this._saveSpaceKeysToFile(spaceId, keys);
    }
  }

  async deleteSpaceKeys(spaceId) {
    if (this.keychainAvailable) {
      await keychain.deleteSpaceKeys(spaceId);
    }
    // Also try to delete file if it exists
    this._deleteSpaceKeysFile(spaceId);
  }

  async listSpaces() {
    if (this.keychainAvailable) {
      return await keychain.listSpaces();
    }
    // Fall back to file listing
    return this._listSpacesFromFiles();
  }

  // File-based fallbacks for spaces
  _getSpacesDir() {
    const spacesDir = path.join(this.fileStore.dataDir, '..', 'spaces');
    return spacesDir;
  }

  _loadSpaceKeysFromFile(spaceId) {
    const fs = require('fs');
    const keyPath = path.join(this._getSpacesDir(), `${spaceId}.json`);
    if (!fs.existsSync(keyPath)) return null;
    try {
      return JSON.parse(fs.readFileSync(keyPath, 'utf8'));
    } catch {
      return null;
    }
  }

  _saveSpaceKeysToFile(spaceId, keys) {
    const fs = require('fs');
    const spacesDir = this._getSpacesDir();
    if (!fs.existsSync(spacesDir)) {
      fs.mkdirSync(spacesDir, { recursive: true, mode: 0o700 });
    }
    const keyPath = path.join(spacesDir, `${spaceId}.json`);
    fs.writeFileSync(keyPath, JSON.stringify(keys, null, 2), { mode: 0o600 });
  }

  _deleteSpaceKeysFile(spaceId) {
    const fs = require('fs');
    const keyPath = path.join(this._getSpacesDir(), `${spaceId}.json`);
    if (fs.existsSync(keyPath)) {
      fs.unlinkSync(keyPath);
    }
  }

  _listSpacesFromFiles() {
    const fs = require('fs');
    const spacesDir = this._getSpacesDir();
    if (!fs.existsSync(spacesDir)) return [];
    
    const files = fs.readdirSync(spacesDir).filter(f => f.endsWith('.json'));
    return files.map(f => {
      const keys = this._loadSpaceKeysFromFile(f.replace('.json', ''));
      if (!keys) return null;
      return {
        spaceId: keys.spaceId,
        spaceName: keys.spaceName,
        inboxAddress: keys.inboxAddress,
        joinedAt: keys.joinedAt,
      };
    }).filter(Boolean);
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
