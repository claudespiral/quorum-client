/**
 * Keychain Storage - Secure key storage via OS keychain
 * 
 * Uses keytar for cross-platform keychain access:
 * - macOS: Keychain.app
 * - Linux: libsecret (GNOME Keyring / KWallet)
 * - Windows: Credential Vault
 * 
 * First access on macOS will prompt for approval.
 * On Linux, requires unlocked session keyring.
 */

import keytar from 'keytar';

const SERVICE_NAME = 'quorum-client';

// Keys we store in keychain (sensitive material)
const KEYCHAIN_KEYS = {
  USER_KEYSET: 'user-keyset',
  DEVICE_KEYSET: 'device-keyset',
};

/**
 * Check if keychain is available and accessible
 */
export async function isKeychainAvailable() {
  try {
    // Try a harmless operation to test access
    await keytar.findCredentials(SERVICE_NAME);
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Store a secret in the OS keychain
 */
export async function setSecret(key, value) {
  const json = typeof value === 'string' ? value : JSON.stringify(value);
  await keytar.setPassword(SERVICE_NAME, key, json);
}

/**
 * Retrieve a secret from the OS keychain
 */
export async function getSecret(key) {
  const value = await keytar.getPassword(SERVICE_NAME, key);
  if (!value) return null;
  try {
    return JSON.parse(value);
  } catch {
    return value; // Return as string if not JSON
  }
}

/**
 * Delete a secret from the OS keychain
 */
export async function deleteSecret(key) {
  return await keytar.deletePassword(SERVICE_NAME, key);
}

/**
 * List all secrets stored by this app
 */
export async function listSecrets() {
  const credentials = await keytar.findCredentials(SERVICE_NAME);
  return credentials.map(c => c.account);
}

// ============ Typed accessors for our specific keys ============

export async function getUserKeyset() {
  return await getSecret(KEYCHAIN_KEYS.USER_KEYSET);
}

export async function saveUserKeyset(keyset) {
  await setSecret(KEYCHAIN_KEYS.USER_KEYSET, keyset);
}

export async function getDeviceKeyset() {
  return await getSecret(KEYCHAIN_KEYS.DEVICE_KEYSET);
}

export async function saveDeviceKeyset(keyset) {
  await setSecret(KEYCHAIN_KEYS.DEVICE_KEYSET, keyset);
}

/**
 * Migrate keys from plaintext files to keychain
 * Returns true if migration occurred, false if already migrated or no keys to migrate
 */
export async function migrateToKeychain(store) {
  let migrated = false;
  
  // Check if we have plaintext keys but not keychain keys
  const plaintextUser = store.getUserKeyset();
  const plaintextDevice = store.getDeviceKeyset();
  
  if (plaintextUser && !(await getUserKeyset())) {
    console.log('🔐 Migrating user keyset to keychain...');
    await saveUserKeyset(plaintextUser);
    migrated = true;
  }
  
  if (plaintextDevice && !(await getDeviceKeyset())) {
    console.log('🔐 Migrating device keyset to keychain...');
    await saveDeviceKeyset(plaintextDevice);
    migrated = true;
  }
  
  if (migrated) {
    console.log('✅ Keys migrated to OS keychain');
    console.log('⚠️  You can now delete the plaintext files in ~/.quorum-client/keys/');
    console.log('   (Keeping them as backup until you verify keychain access works)');
  }
  
  return migrated;
}

export { KEYCHAIN_KEYS };
