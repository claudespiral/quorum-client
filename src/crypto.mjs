/**
 * Quorum E2EE Crypto Layer
 * 
 * Wraps the Quilibrium WASM module for Node.js usage.
 * Handles: X448/Ed448 key generation, X3DH key exchange, 
 * Double Ratchet encryption, inbox sealing/unsealing.
 * 
 * Based on quilibrium-js-sdk-channels by Quilibrium Inc (MIT).
 */

import { readFileSync } from 'fs';
import { createHash } from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

let wasm = null;

/** Initialize the WASM crypto module. Must be called before any crypto ops. */
export async function initCrypto() {
  if (wasm) return;
  const mod = await import('./wasm/channelwasm.js');
  const wasmPath = join(__dirname, 'wasm', 'channelwasm_bg.wasm');
  const wasmBytes = readFileSync(wasmPath);
  await mod.default(wasmBytes);
  wasm = mod;
}

// ============ Key Generation ============

export function generateX448() {
  return JSON.parse(wasm.js_generate_x448());
}

export function generateEd448() {
  return JSON.parse(wasm.js_generate_ed448());
}

export function getX448PubKey(privKeyB64) {
  return JSON.parse(wasm.js_get_pubkey_x448(privKeyB64));
}

// ============ Signing ============

export function signEd448(privKeyB64, messageB64) {
  return JSON.parse(wasm.js_sign_ed448(privKeyB64, messageB64));
}

export function verifyEd448(pubKeyB64, messageB64, signatureB64) {
  return JSON.parse(wasm.js_verify_ed448(pubKeyB64, messageB64, signatureB64));
}

// ============ Hashing & Addressing ============

export function sha256(bytes) {
  return createHash('sha256').update(Buffer.from(bytes)).digest();
}

/**
 * Derive address from public key: SHA-256 → multihash → base58
 * Produces "Qm..." style addresses (matching mobile app)
 */
export function deriveAddress(publicKey) {
  const digest = sha256(new Uint8Array(publicKey));
  // Multihash: 0x12 (sha2-256) + 0x20 (32 bytes) + digest
  const multihash = Buffer.concat([Buffer.from([0x12, 0x20]), digest]);
  return base58Encode(multihash);
}

// ============ Base58 ============

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Encode(buffer) {
  const bytes = [...buffer];
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    digits.push(0);
  }
  return digits.reverse().map(d => BASE58_ALPHABET[d]).join('');
}

export function base58Decode(str) {
  // Strip optional 'z' multibase prefix
  if (str.startsWith('z')) str = str.slice(1);
  const bytes = [0];
  for (const char of str) {
    const value = BASE58_ALPHABET.indexOf(char);
    if (value < 0) throw new Error(`Invalid base58 character: ${char}`);
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const char of str) {
    if (char !== '1') break;
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return new Uint8Array(bytes);
}

// ============ Keyset Generation ============

/**
 * Generate a complete device keyset matching the mobile app structure:
 * - X448 identity key (for X3DH)
 * - X448 pre-key (for X3DH)
 * - X448 inbox encryption key (for sealing/unsealing)
 * - Ed448 inbox signing key (for delete requests)
 * - Inbox address derived from Ed448 signing key
 */
export async function newDeviceKeyset() {
  const identityKey = generateX448();
  const preKey = generateX448();
  const inboxEncryptionKey = generateX448();
  const inboxSigningKey = generateEd448();
  const inboxAddress = deriveAddress(inboxSigningKey.public_key);

  return {
    identity_key: identityKey,
    pre_key: preKey,
    inbox_encryption_key: inboxEncryptionKey,
    inbox_signing_key: inboxSigningKey,
    inbox_address: inboxAddress,
  };
}

// ============ Registration ============

/**
 * Construct a user registration payload for the Quorum API.
 * Matches the mobile app's uploadUserRegistration format exactly.
 * 
 * @param {string} userAddress - "Qm..." address derived from Ed448 user public key
 * @param {string} userPublicKeyHex - Ed448 public key as hex
 * @param {string} userPrivateKeyHex - Ed448 private key as hex (for signing)
 * @param {Object} deviceKeyset - From newDeviceKeyset()
 */
export function constructRegistration(userAddress, userPublicKeyHex, userPrivateKeyHex, deviceKeyset) {
  const deviceReg = {
    identity_public_key: bytesToHex(deviceKeyset.identity_key.public_key),
    pre_public_key: bytesToHex(deviceKeyset.pre_key.public_key),
    inbox_registration: {
      inbox_address: deviceKeyset.inbox_address,
      inbox_encryption_public_key: bytesToHex(deviceKeyset.inbox_encryption_key.public_key),
      inbox_public_key: bytesToHex(deviceKeyset.inbox_signing_key.public_key),
    },
  };

  // Build sign payload: peer_public_key_bytes + device data
  // (peer_public_key = user_public_key in mobile app)
  const peerPubBytes = hexToBytes(userPublicKeyHex);
  const identityBytes = hexToBytes(deviceReg.identity_public_key);
  const preBytes = hexToBytes(deviceReg.pre_public_key);
  const inboxAddrBytes = base58Decode(deviceKeyset.inbox_address);
  const inboxEncBytes = hexToBytes(deviceReg.inbox_registration.inbox_encryption_public_key);

  const dataToSign = Buffer.concat([
    peerPubBytes,
    identityBytes,
    preBytes,
    inboxAddrBytes,
    inboxEncBytes,
  ]);

  const privKeyB64 = Buffer.from(hexToBytes(userPrivateKeyHex)).toString('base64');
  const msgB64 = dataToSign.toString('base64');
  const sig = signEd448(privKeyB64, msgB64);
  const signatureHex = Buffer.from(sig, 'base64').toString('hex');

  return {
    user_address: userAddress,
    user_public_key: userPublicKeyHex,
    peer_public_key: userPublicKeyHex, // Same as user_public_key (mobile app convention)
    device_registrations: [deviceReg],
    signature: signatureHex,
  };
}

// ============ X3DH Key Exchange ============

export function senderX3DH(identityPrivKey, ephemeralPrivKey, receiverIdentityKey, receiverPreKey, sessionKeyLength = 96) {
  return JSON.parse(wasm.js_sender_x3dh(JSON.stringify({
    sending_identity_private_key: identityPrivKey,
    sending_ephemeral_private_key: ephemeralPrivKey,
    receiving_identity_key: receiverIdentityKey,
    receiving_signed_pre_key: receiverPreKey,
    session_key_length: sessionKeyLength,
  })));
}

export function receiverX3DH(identityPrivKey, prePrivKey, senderIdentityKey, senderEphemeralKey, sessionKeyLength = 96) {
  return JSON.parse(wasm.js_receiver_x3dh(JSON.stringify({
    sending_identity_private_key: identityPrivKey,
    sending_signed_private_key: prePrivKey,
    receiving_identity_key: senderIdentityKey,
    receiving_ephemeral_key: senderEphemeralKey,
    session_key_length: sessionKeyLength,
  })));
}

// ============ Double Ratchet ============

export function newDoubleRatchet(params) {
  return wasm.js_new_double_ratchet(JSON.stringify(params));
}

export function doubleRatchetEncrypt(ratchetState, message) {
  return JSON.parse(wasm.js_double_ratchet_encrypt(JSON.stringify({
    ratchet_state: ratchetState,
    message: [...Buffer.from(message, 'utf-8')],
  })));
}

export function doubleRatchetDecrypt(ratchetState, envelope) {
  const result = JSON.parse(wasm.js_double_ratchet_decrypt(JSON.stringify({
    ratchet_state: ratchetState,
    envelope: envelope,
  })));
  return {
    ratchet_state: result.ratchet_state,
    message: Buffer.from(new Uint8Array(result.message)).toString('utf-8'),
  };
}

// ============ Inbox Encryption ============

export function encryptInboxMessageBytes(inboxPubKey, ephemeralPrivKey, plaintextBytes) {
  return wasm.js_encrypt_inbox_message(JSON.stringify({
    inbox_public_key: inboxPubKey,
    ephemeral_private_key: ephemeralPrivKey,
    plaintext: plaintextBytes,
  }));
}

export function decryptInboxMessage(inboxPrivKey, ephemeralPubKey, ciphertext) {
  return JSON.parse(wasm.js_decrypt_inbox_message(JSON.stringify({
    inbox_private_key: inboxPrivKey,
    ephemeral_public_key: ephemeralPubKey,
    ciphertext: typeof ciphertext === 'string' ? JSON.parse(ciphertext) : ciphertext,
  })));
}
