/**
 * Quorum Headless Client
 * 
 * E2EE messenger client for Quorum (Quilibrium) with no GUI dependency.
 * Handles identity creation, key exchange, Double Ratchet sessions,
 * and encrypted messaging via the Quorum API.
 */

import { QuorumAPI } from './api.mjs';
import { createSecureStore } from './secure-store.mjs';
import {
  initCrypto,
  newDeviceKeyset,
  constructRegistration,
  deriveAddress,
  generateEd448,
  generateX448,
  senderX3DH,
  receiverX3DH,
  newDoubleRatchet,
  doubleRatchetEncrypt,
  doubleRatchetDecrypt,
  encryptInboxMessageBytes,
  decryptInboxMessage,
  signEd448,
} from './crypto.mjs';

export class QuorumClient {
  constructor(options = {}) {
    this.dataDir = options.dataDir || '.quorum-data';
    this.displayName = options.displayName || 'Quorum User';
    this.api = new QuorumAPI(options.apiUrl);
    this.store = null; // Initialized in init()
    this.useKeychain = options.useKeychain !== false; // Default true
    this.initialized = false;
  }

  async init() {
    await initCrypto();
    
    // Initialize secure store (with keychain support)
    this.store = await createSecureStore(this.dataDir, this.useKeychain);
    
    this.userKeys = this.store.load('user-keys.json');
    this.deviceKeyset = await this.store.getDeviceKeyset();
    this.registration = this.store.getRegistration();
    this.initialized = true;
    return {
      hasIdentity: !!this.registration,
      address: this.registration?.user_address || null,
      usingKeychain: this.store.isUsingKeychain,
    };
  }

  get hasIdentity() { return !!this.registration; }
  get address() { return this.registration?.user_address || null; }

  // ============ Identity & Registration ============

  /**
   * Generate a new identity and register with the Quorum API.
   * Uses Ed448 for user identity (matching mobile app).
   */
  async register(displayName) {
    if (!this.initialized) throw new Error('Call init() first');
    if (this.hasIdentity) throw new Error('Already registered');

    this.displayName = displayName || this.displayName;

    // Generate Ed448 user key (matching mobile app's ed448 identity)
    const userKey = generateEd448();
    const userPubHex = Buffer.from(new Uint8Array(userKey.public_key)).toString('hex');
    const userPrivHex = Buffer.from(new Uint8Array(userKey.private_key)).toString('hex');
    const userAddress = deriveAddress(userKey.public_key);

    // Generate device keyset (X448 identity + pre + inbox encryption, Ed448 inbox signing)
    this.deviceKeyset = await newDeviceKeyset();

    // Build registration
    this.registration = constructRegistration(
      userAddress,
      userPubHex,
      userPrivHex,
      this.deviceKeyset
    );

    // Post to API
    await this.api.registerUser(this.registration);

    // Persist
    this.userKeys = {
      public_key: userKey.public_key,
      private_key: userKey.private_key,
      public_key_hex: userPubHex,
      private_key_hex: userPrivHex,
      address: userAddress,
    };
    this.store.save('user-keys.json', this.userKeys);
    await this.store.saveDeviceKeyset(this.deviceKeyset); // Keychain-backed
    this.store.saveRegistration(this.registration);
    this.store.save('profile.json', {
      displayName: this.displayName,
      userAddress,
      createdAt: new Date().toISOString(),
    });

    return { address: userAddress, inboxAddress: this.deviceKeyset.inbox_address };
  }

  // ============ Messaging ============

  async sendMessage(recipientAddress, text) {
    if (!this.hasIdentity) throw new Error('Not registered');

    let session = this.store.getSession(recipientAddress);
    if (!session) {
      return this._sendFirstMessage(recipientAddress, text);
    }
    return this._sendFollowUpMessage(recipientAddress, text, session);
  }

  async _sendFirstMessage(recipientAddress, text) {
    // Fetch recipient's registration
    const recipient = await this.api.getUser(recipientAddress);
    if (!recipient?.device_registrations?.length) {
      throw new Error(`Recipient not found or has no devices`);
    }

    const device = recipient.device_registrations[0];
    const receiverIdentityKey = [...Buffer.from(device.identity_public_key, 'hex')];
    const receiverPreKey = [...Buffer.from(device.pre_public_key, 'hex')];

    // X3DH key exchange
    const ephemeralKey = generateX448();
    const sessionKeyB64 = senderX3DH(
      this.deviceKeyset.identity_key.private_key,
      ephemeralKey.private_key,
      receiverIdentityKey,
      receiverPreKey,
      96
    );

    const rootKey = [...Buffer.from(sessionKeyB64, 'base64')];

    // Create Double Ratchet
    let ratchetState = newDoubleRatchet({
      session_key: rootKey.slice(0, 32),
      sending_header_key: rootKey.slice(32, 64),
      next_receiving_header_key: rootKey.slice(64, 96),
      is_sender: true,
      sending_ephemeral_private_key: ephemeralKey.private_key,
      receiving_ephemeral_key: receiverPreKey,
    });

    // Encrypt message
    const { ratchet_state: newState, envelope } = doubleRatchetEncrypt(ratchetState, text);

    // Build initialization envelope
    const initPayload = JSON.stringify({
      return_inbox_address: this.deviceKeyset.inbox_address,
      return_inbox_encryption_key: Buffer.from(
        new Uint8Array(this.deviceKeyset.inbox_encryption_key.public_key)
      ).toString('hex'),
      return_inbox_public_key: Buffer.from(
        new Uint8Array(this.deviceKeyset.inbox_signing_key.public_key)
      ).toString('hex'),
      return_inbox_private_key: Buffer.from(
        new Uint8Array(this.deviceKeyset.inbox_signing_key.private_key)
      ).toString('hex'),
      user_address: this.registration.user_address,
      identity_public_key: Buffer.from(
        new Uint8Array(this.deviceKeyset.identity_key.public_key)
      ).toString('hex'),
      tag: this.deviceKeyset.inbox_address,
      display_name: this.displayName,
      message: envelope,
      type: 'direct',
    });

    // Seal for recipient's inbox
    const inboxPubKey = [...Buffer.from(device.inbox_registration.inbox_encryption_public_key, 'hex')];
    const ciphertext = encryptInboxMessageBytes(
      inboxPubKey,
      ephemeralKey.private_key,
      [...Buffer.from(initPayload, 'utf-8')]
    );

    const sealedMessage = {
      inbox_address: device.inbox_registration.inbox_address,
      ephemeral_public_key: Buffer.from(new Uint8Array(ephemeralKey.public_key)).toString('hex'),
      envelope: ciphertext,
    };

    await this.api.sendSealedMessage(sealedMessage);

    // Save session
    this.store.saveSession(recipientAddress, {
      ratchet_state: newState,
      sending_inbox: {
        inbox_address: device.inbox_registration.inbox_address,
        inbox_encryption_key: device.inbox_registration.inbox_encryption_public_key,
        inbox_public_key: '',
        inbox_private_key: '',
      },
      tag: device.inbox_registration.inbox_address,
      recipient_address: recipientAddress,
      sent_accept: true,
      created_at: new Date().toISOString(),
    });

    return { sent: true, firstMessage: true };
  }

  async _sendFollowUpMessage(recipientAddress, text, session) {
    const { ratchet_state: newState, envelope } = doubleRatchetEncrypt(session.ratchet_state, text);
    const ephemeralKey = generateX448();

    let ciphertext;
    if (session.sent_accept && session.sending_inbox.inbox_public_key) {
      ciphertext = encryptInboxMessageBytes(
        [...Buffer.from(session.sending_inbox.inbox_encryption_key, 'hex')],
        ephemeralKey.private_key,
        [...Buffer.from(envelope, 'utf-8')]
      );
    } else {
      const payload = JSON.stringify({
        return_inbox_address: this.deviceKeyset.inbox_address,
        return_inbox_encryption_key: Buffer.from(
          new Uint8Array(this.deviceKeyset.inbox_encryption_key.public_key)
        ).toString('hex'),
        return_inbox_public_key: Buffer.from(
          new Uint8Array(this.deviceKeyset.inbox_signing_key.public_key)
        ).toString('hex'),
        return_inbox_private_key: Buffer.from(
          new Uint8Array(this.deviceKeyset.inbox_signing_key.private_key)
        ).toString('hex'),
        user_address: this.registration.user_address,
        identity_public_key: Buffer.from(
          new Uint8Array(this.deviceKeyset.identity_key.public_key)
        ).toString('hex'),
        tag: this.deviceKeyset.inbox_address,
        display_name: this.displayName,
        message: envelope,
        type: 'direct',
      });

      ciphertext = encryptInboxMessageBytes(
        [...Buffer.from(session.sending_inbox.inbox_encryption_key, 'hex')],
        ephemeralKey.private_key,
        [...Buffer.from(payload, 'utf-8')]
      );
    }

    const sealedMessage = {
      inbox_address: session.sending_inbox.inbox_address,
      ephemeral_public_key: Buffer.from(new Uint8Array(ephemeralKey.public_key)).toString('hex'),
      envelope: ciphertext,
    };

    if (session.sending_inbox.inbox_public_key && session.sending_inbox.inbox_private_key) {
      const privB64 = Buffer.from(session.sending_inbox.inbox_private_key, 'hex').toString('base64');
      const msgB64 = Buffer.from(ciphertext, 'utf-8').toString('base64');
      const sig = signEd448(privB64, msgB64);
      sealedMessage.inbox_public_key = session.sending_inbox.inbox_public_key;
      sealedMessage.inbox_signature = Buffer.from(sig, 'base64').toString('hex');
    }

    await this.api.sendSealedMessage(sealedMessage);

    session.ratchet_state = newState;
    this.store.saveSession(recipientAddress, session);

    return { sent: true, firstMessage: false };
  }

  // ============ Receiving ============

  decryptInboxMessage(sealedMessage) {
    const privKey = this.deviceKeyset.inbox_encryption_key.private_key;
    const ephPubKey = [...Buffer.from(sealedMessage.ephemeral_public_key, 'hex')];
    const plaintext = decryptInboxMessage(privKey, ephPubKey, sealedMessage.envelope);
    const decoded = Buffer.from(new Uint8Array(plaintext)).toString('utf-8');
    try { return JSON.parse(decoded); } catch { return decoded; }
  }

  async processInitMessage(unsealedEnvelope) {
    if (unsealedEnvelope.type !== 'direct') {
      throw new Error(`Unsupported type: ${unsealedEnvelope.type}`);
    }

    const senderIdentityKey = [...Buffer.from(unsealedEnvelope.identity_public_key, 'hex')];
    const senderEphemeralKey = [...Buffer.from(unsealedEnvelope.ephemeral_public_key, 'hex')];

    const sessionKeyB64 = receiverX3DH(
      this.deviceKeyset.identity_key.private_key,
      this.deviceKeyset.pre_key.private_key,
      senderIdentityKey,
      senderEphemeralKey,
      96
    );

    const rootKey = [...Buffer.from(sessionKeyB64, 'base64')];

    let ratchetState = newDoubleRatchet({
      session_key: rootKey.slice(0, 32),
      sending_header_key: rootKey.slice(32, 64),
      next_receiving_header_key: rootKey.slice(64, 96),
      is_sender: false,
      sending_ephemeral_private_key: this.deviceKeyset.pre_key.private_key,
      receiving_ephemeral_key: senderEphemeralKey,
    });

    const { ratchet_state: newState, message } = doubleRatchetDecrypt(
      ratchetState,
      unsealedEnvelope.message
    );

    const senderAddress = unsealedEnvelope.user_address;
    this.store.saveSession(senderAddress, {
      ratchet_state: newState,
      sending_inbox: {
        inbox_address: unsealedEnvelope.return_inbox_address,
        inbox_encryption_key: unsealedEnvelope.return_inbox_encryption_key,
        inbox_public_key: unsealedEnvelope.return_inbox_public_key,
        inbox_private_key: unsealedEnvelope.return_inbox_private_key,
      },
      tag: unsealedEnvelope.tag,
      recipient_address: senderAddress,
      sender_name: unsealedEnvelope.display_name,
      sent_accept: false,
      created_at: new Date().toISOString(),
    });

    return { from: senderAddress, displayName: unsealedEnvelope.display_name, message };
  }

  // ============ Info ============

  getIdentity() {
    if (!this.hasIdentity) return null;
    return {
      address: this.registration.user_address,
      publicKey: this.registration.user_public_key,
      inboxAddress: this.deviceKeyset?.inbox_address,
      displayName: this.store.load('profile.json')?.displayName,
    };
  }

  listContacts() {
    return this.store.listSessions().map(tag => {
      const session = this.store.getSession(tag);
      return {
        address: session?.recipient_address || tag,
        displayName: session?.sender_name,
        established: !!session?.ratchet_state,
      };
    });
  }
}
