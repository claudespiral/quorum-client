#!/usr/bin/env node
/**
 * Join a Quorum Space from a private invite link
 * 
 * Usage: node join-space.mjs "<invite-url>"
 */

import { createHash } from 'crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Import our crypto module
import { 
  initCrypto, 
  generateEd448, 
  generateX448, 
  signEd448,
  getEd448PubKey,
  deriveAddress,
  base58Encode
} from './src/crypto.mjs';

const API_BASE = 'https://api.quorummessenger.com';
const SPACE_KEYS_DIR = path.join(process.env.HOME, '.quorum-client', 'spaces');

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

function bytesToBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function base64ToBytes(b64) {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

// ============ Invite Parsing ============

function parseInviteLink(inviteUrl) {
  const url = new URL(inviteUrl);
  const hash = url.hash.slice(1); // Remove #
  const params = new URLSearchParams(hash);
  
  const invite = {
    spaceId: params.get('spaceId'),
    configKey: params.get('configKey'),
    template: params.get('template'),
    secret: params.get('secret'),
    hubKey: params.get('hubKey'),
  };
  
  if (!invite.spaceId || !invite.configKey) {
    throw new Error('Invalid invite: missing spaceId or configKey');
  }
  
  // Decode template from hex
  if (invite.template) {
    invite.templateJson = Buffer.from(invite.template, 'hex').toString('utf8');
    invite.templateObj = JSON.parse(invite.templateJson);
  }
  
  return invite;
}

// ============ Key Generation ============

async function generateSpaceKeys() {
  // Generate inbox keys (Ed448 for signing, X448 for encryption)
  const inboxSigningKey = await generateEd448();
  const inboxEncryptionKey = await generateX448();
  
  // Derive inbox address from signing public key
  const inboxAddress = deriveAddress(inboxSigningKey.public_key);
  
  return {
    inboxAddress,
    inboxSigningKey,
    inboxEncryptionKey,
  };
}

// ============ API Calls ============

async function registerWithHub(hubAddress, hubKeyHex, hubPubKeyHex, inboxPubKeyHex, inboxPrivKeyBytes) {
  console.log('Registering inbox with hub...');
  console.log('  Hub address:', hubAddress);
  console.log('  Hub public key:', hubPubKeyHex.substring(0, 40) + '...');
  console.log('  Inbox public key:', inboxPubKeyHex.substring(0, 40) + '...');
  
  // Hub signature: sign("add" + inbox_public_key_hex) with hub key
  const hubPrivateKey = hexToBytes(hubKeyHex);
  const addInboxMessage = 'add' + inboxPubKeyHex;
  const addInboxMessageBytes = new TextEncoder().encode(addInboxMessage);
  
  const hubSignature = signEd448(
    bytesToBase64(hubPrivateKey),
    bytesToBase64(addInboxMessageBytes)
  );
  const hubSignatureHex = bytesToHex(base64ToBytes(hubSignature));
  
  // Inbox signature: sign("add" + hub_public_key_hex) with inbox key
  const addHubMessage = 'add' + hubPubKeyHex;
  const addHubMessageBytes = new TextEncoder().encode(addHubMessage);
  
  const inboxSignature = signEd448(
    bytesToBase64(inboxPrivKeyBytes),
    bytesToBase64(addHubMessageBytes)
  );
  const inboxSignatureHex = bytesToHex(base64ToBytes(inboxSignature));
  
  // POST to /hub/add
  const response = await fetch(`${API_BASE}/hub/add`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      hub_address: hubAddress,
      hub_public_key: hubPubKeyHex,
      hub_signature: hubSignatureHex,
      inbox_public_key: inboxPubKeyHex,
      inbox_signature: inboxSignatureHex,
    }),
  });
  
  const result = await response.json();
  return result;
}

async function fetchSpaceManifest(spaceId, configKeyHex) {
  console.log('\nFetching space manifest...');
  
  // First get the space registration
  const regResponse = await fetch(`${API_BASE}/spaces/${spaceId}`);
  if (!regResponse.ok) {
    console.log('Space registration not found (status', regResponse.status + ')');
    return null;
  }
  
  const registration = await regResponse.json();
  console.log('Space registration:', {
    space_address: registration.space_address,
    config_public_key: registration.config_public_key?.substring(0, 40) + '...',
    owner_public_keys: registration.owner_public_keys?.length || 0,
  });
  
  // Now get the manifest
  const manifestResponse = await fetch(`${API_BASE}/spaces/${spaceId}/manifest`);
  if (!manifestResponse.ok) {
    console.log('Space manifest not found (status', manifestResponse.status + ')');
    return { registration };
  }
  
  const manifest = await manifestResponse.json();
  console.log('Manifest fetched, encrypted length:', manifest.space_manifest?.length || 0);
  
  // TODO: Decrypt manifest using configKey
  // The manifest is encrypted with the config key's public key
  // We have the config private key, so we can decrypt it
  
  return { registration, manifest };
}

// ============ Main ============

async function main() {
  const inviteUrl = process.argv[2];
  if (!inviteUrl) {
    console.error('Usage: node join-space.mjs "<invite-url>"');
    process.exit(1);
  }
  
  console.log('Initializing WASM crypto...');
  await initCrypto();
  
  console.log('\n=== Parsing Invite Link ===');
  const invite = parseInviteLink(inviteUrl);
  console.log('Space ID:', invite.spaceId);
  console.log('Config key:', invite.configKey?.substring(0, 40) + '...');
  console.log('Hub key:', invite.hubKey?.substring(0, 40) + '...');
  console.log('Secret:', invite.secret?.substring(0, 40) + '...');
  
  if (invite.templateObj) {
    console.log('\nTemplate:');
    console.log('  threshold:', invite.templateObj.threshold);
    console.log('  peers:', Object.keys(invite.templateObj.peer_id_map || {}).length);
    console.log('  has root_key:', !!invite.templateObj.root_key);
    console.log('  has dkg_ratchet:', !!invite.templateObj.dkg_ratchet);
  }
  
  console.log('\n=== Generating Space Keys ===');
  const keys = await generateSpaceKeys();
  console.log('Generated inbox address:', keys.inboxAddress);
  
  // Derive hub address and public key from hub private key
  const hubPrivKeyBytes = hexToBytes(invite.hubKey);
  const hubPubKey = getEd448PubKey(bytesToBase64(hubPrivKeyBytes));
  const hubPubKeyBytes = base64ToBytes(hubPubKey);
  const hubPubKeyHex = bytesToHex(hubPubKeyBytes);
  const hubAddress = deriveAddress([...hubPubKeyBytes]);
  
  console.log('\nHub info (derived from invite):');
  console.log('  Hub address:', hubAddress);
  console.log('  Hub public key:', hubPubKeyHex.substring(0, 40) + '...');
  
  console.log('\n=== Fetching Space Info ===');
  const spaceInfo = await fetchSpaceManifest(invite.spaceId, invite.configKey);
  
  console.log('\n=== Registering with Hub ===');
  const inboxPubKeyHex = bytesToHex(new Uint8Array(keys.inboxSigningKey.public_key));
  const inboxPrivKeyBytes = new Uint8Array(keys.inboxSigningKey.private_key);
  
  const hubResult = await registerWithHub(
    hubAddress,
    invite.hubKey,
    hubPubKeyHex,
    inboxPubKeyHex,
    inboxPrivKeyBytes
  );
  console.log('Hub registration result:', hubResult);
  
  // Save all keys
  console.log('\n=== Saving Keys ===');
  if (!existsSync(SPACE_KEYS_DIR)) {
    mkdirSync(SPACE_KEYS_DIR, { recursive: true });
  }
  
  const spaceKeysPath = path.join(SPACE_KEYS_DIR, `${invite.spaceId}.json`);
  const spaceKeys = {
    spaceId: invite.spaceId,
    hubAddress,
    hubPublicKey: hubPubKeyHex,
    hubPrivateKey: invite.hubKey,
    configPrivateKey: invite.configKey,
    secret: invite.secret,
    template: invite.templateJson,
    inboxAddress: keys.inboxAddress,
    inboxSigningKey: {
      public_key: bytesToHex(new Uint8Array(keys.inboxSigningKey.public_key)),
      private_key: bytesToHex(new Uint8Array(keys.inboxSigningKey.private_key)),
    },
    inboxEncryptionKey: {
      public_key: bytesToHex(new Uint8Array(keys.inboxEncryptionKey.public_key)),
      private_key: bytesToHex(new Uint8Array(keys.inboxEncryptionKey.private_key)),
    },
    joinedAt: Date.now(),
  };
  
  writeFileSync(spaceKeysPath, JSON.stringify(spaceKeys, null, 2));
  console.log('Saved to:', spaceKeysPath);
  
  console.log('\n=== Join Complete ===');
  console.log('Space ID:', invite.spaceId);
  console.log('Inbox address:', keys.inboxAddress);
  console.log('Hub address:', hubAddress);
  
  console.log('\nNext: Run space-listen.mjs to receive messages');
}

main().catch(err => {
  console.error('Join failed:', err);
  process.exit(1);
});
