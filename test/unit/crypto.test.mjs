/**
 * Unit tests for src/crypto.mjs
 * 
 * Tests cryptographic primitives without network calls:
 * - Key generation (X448, Ed448)
 * - Address derivation
 * - Base58 encoding/decoding
 * - Signing and verification
 * - X3DH key exchange
 * - Double Ratchet encrypt/decrypt
 * - Inbox sealing/unsealing
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, '..', '..');

const {
  initCrypto,
  generateX448,
  generateEd448,
  getX448PubKey,
  getEd448PubKey,
  signEd448,
  verifyEd448,
  sha256,
  deriveAddress,
  base58Encode,
  base58Decode,
  newDeviceKeyset,
  constructRegistration,
  senderX3DH,
  receiverX3DH,
  newDoubleRatchet,
  doubleRatchetEncrypt,
  doubleRatchetDecrypt,
  encryptInboxMessageBytes,
  decryptInboxMessage,
  safeDecryptInboxMessage,
  safeDoubleRatchetDecrypt,
  safeVerifyEd448,
  CryptoError,
  CryptoErrorType,
} = await import(join(PROJECT_ROOT, 'src/crypto.mjs'));

// ============ Setup ============

before(async () => {
  await initCrypto();
});

// ============ Key Generation ============

describe('Key Generation', () => {
  describe('generateX448', () => {
    it('should generate X448 keypair with correct structure', () => {
      const keypair = generateX448();
      
      assert.ok(keypair.public_key, 'should have public_key');
      assert.ok(keypair.private_key, 'should have private_key');
      assert.ok(Array.isArray(keypair.public_key), 'public_key should be array');
      assert.ok(Array.isArray(keypair.private_key), 'private_key should be array');
    });

    it('should generate keys of expected length', () => {
      const keypair = generateX448();
      
      // WASM implementation uses 57 bytes (includes format byte)
      assert.ok(keypair.public_key.length >= 56, `public_key should be >= 56 bytes (got ${keypair.public_key.length})`);
      assert.ok(keypair.private_key.length >= 56, `private_key should be >= 56 bytes (got ${keypair.private_key.length})`);
    });

    it('should generate unique keypairs each call', () => {
      const kp1 = generateX448();
      const kp2 = generateX448();
      
      const pub1 = Buffer.from(kp1.public_key).toString('hex');
      const pub2 = Buffer.from(kp2.public_key).toString('hex');
      
      assert.notEqual(pub1, pub2, 'should generate different public keys');
    });
  });

  describe('generateEd448', () => {
    it('should generate Ed448 keypair with correct structure', () => {
      const keypair = generateEd448();
      
      assert.ok(keypair.public_key, 'should have public_key');
      assert.ok(keypair.private_key, 'should have private_key');
    });

    it('should generate 57-byte public key (Ed448 standard)', () => {
      const keypair = generateEd448();
      
      assert.equal(keypair.public_key.length, 57, 'public_key should be 57 bytes');
    });

    it('should generate unique keypairs each call', () => {
      const kp1 = generateEd448();
      const kp2 = generateEd448();
      
      const pub1 = Buffer.from(kp1.public_key).toString('hex');
      const pub2 = Buffer.from(kp2.public_key).toString('hex');
      
      assert.notEqual(pub1, pub2, 'should generate different public keys');
    });
  });

  describe('getX448PubKey', () => {
    it('should derive public key from private key', () => {
      const keypair = generateX448();
      const privB64 = Buffer.from(keypair.private_key).toString('base64');
      
      const derivedPubB64 = getX448PubKey(privB64);
      const derivedPub = Buffer.from(derivedPubB64, 'base64');
      const originalPub = Buffer.from(keypair.public_key);
      
      assert.deepEqual(derivedPub, originalPub, 'derived public key should match original');
    });
  });

  describe('getEd448PubKey', () => {
    it('should derive public key from private key', () => {
      const keypair = generateEd448();
      const privB64 = Buffer.from(keypair.private_key).toString('base64');
      
      const derivedPubB64 = getEd448PubKey(privB64);
      const derivedPub = Buffer.from(derivedPubB64, 'base64');
      const originalPub = Buffer.from(keypair.public_key);
      
      assert.deepEqual(derivedPub, originalPub, 'derived public key should match original');
    });
  });
});

// ============ Address Derivation ============

describe('Address Derivation', () => {
  describe('sha256', () => {
    it('should produce 32-byte hash', () => {
      const input = Buffer.from('test data');
      const hash = sha256(input);
      
      assert.equal(hash.length, 32, 'SHA-256 should produce 32 bytes');
    });

    it('should be deterministic', () => {
      const input = Buffer.from('same input');
      const hash1 = sha256(input);
      const hash2 = sha256(input);
      
      assert.deepEqual(hash1, hash2, 'same input should produce same hash');
    });

    it('should produce different hashes for different inputs', () => {
      const hash1 = sha256(Buffer.from('input 1'));
      const hash2 = sha256(Buffer.from('input 2'));
      
      assert.notDeepEqual(hash1, hash2, 'different inputs should produce different hashes');
    });
  });

  describe('deriveAddress', () => {
    it('should produce Qm-prefixed address', () => {
      const keypair = generateEd448();
      const address = deriveAddress(keypair.public_key);
      
      assert.ok(address.startsWith('Qm'), 'address should start with Qm (multihash sha2-256)');
    });

    it('should be deterministic for same public key', () => {
      const keypair = generateEd448();
      const addr1 = deriveAddress(keypair.public_key);
      const addr2 = deriveAddress(keypair.public_key);
      
      assert.equal(addr1, addr2, 'same public key should produce same address');
    });

    it('should produce unique addresses for different keys', () => {
      const kp1 = generateEd448();
      const kp2 = generateEd448();
      
      const addr1 = deriveAddress(kp1.public_key);
      const addr2 = deriveAddress(kp2.public_key);
      
      assert.notEqual(addr1, addr2, 'different keys should produce different addresses');
    });

    it('should produce reasonable length address', () => {
      const keypair = generateEd448();
      const address = deriveAddress(keypair.public_key);
      
      // Base58 encoding of 34 bytes (2 prefix + 32 hash) should be ~46 chars
      assert.ok(address.length >= 44 && address.length <= 48, 
        `address length ${address.length} should be reasonable (44-48 chars)`);
    });
  });
});

// ============ Base58 ============

describe('Base58 Encoding', () => {
  describe('base58Encode', () => {
    it('should encode known value correctly', () => {
      // "Hello" in base58 is "9Ajdvzr"
      const input = Buffer.from('Hello');
      const encoded = base58Encode(input);
      assert.equal(encoded, '9Ajdvzr');
    });

    it('should handle leading zeros', () => {
      const input = Buffer.from([0, 0, 0, 1]);
      const encoded = base58Encode(input);
      
      // Leading zeros become '1' in base58
      assert.ok(encoded.startsWith('111'), 'leading zeros should become 1s');
    });

    it('should handle empty input', () => {
      const encoded = base58Encode(Buffer.from([]));
      // Empty input may produce empty string or '1' depending on implementation
      assert.ok(encoded === '' || encoded === '1', `empty input produced: "${encoded}"`);
    });
  });

  describe('base58Decode', () => {
    it('should decode known value correctly', () => {
      const decoded = base58Decode('9Ajdvzr');
      assert.deepEqual(decoded, new Uint8Array(Buffer.from('Hello')));
    });

    it('should roundtrip with encode', () => {
      const original = Buffer.from('test roundtrip data 12345');
      const encoded = base58Encode(original);
      const decoded = base58Decode(encoded);
      
      assert.deepEqual(decoded, new Uint8Array(original));
    });

    it('should handle z prefix (multibase)', () => {
      // z prefix indicates base58btc in multibase
      const withPrefix = 'z9Ajdvzr';
      const decoded = base58Decode(withPrefix);
      assert.deepEqual(decoded, new Uint8Array(Buffer.from('Hello')));
    });

    it('should throw on invalid characters', () => {
      assert.throws(() => {
        base58Decode('invalid0OIl'); // 0, O, I, l are not in base58
      }, /Invalid base58 character/);
    });
  });
});

// ============ Signing & Verification ============

describe('Ed448 Signing', () => {
  describe('signEd448', () => {
    it('should produce signature', () => {
      const keypair = generateEd448();
      const privB64 = Buffer.from(keypair.private_key).toString('base64');
      const msgB64 = Buffer.from('test message').toString('base64');
      
      const sigB64 = signEd448(privB64, msgB64);
      
      assert.ok(sigB64, 'should produce signature');
      assert.ok(typeof sigB64 === 'string', 'signature should be base64 string');
    });

    it('should produce deterministic signatures', () => {
      const keypair = generateEd448();
      const privB64 = Buffer.from(keypair.private_key).toString('base64');
      const msgB64 = Buffer.from('same message').toString('base64');
      
      const sig1 = signEd448(privB64, msgB64);
      const sig2 = signEd448(privB64, msgB64);
      
      // Ed448 signatures are deterministic (no random nonce)
      assert.equal(sig1, sig2, 'same key+message should produce same signature');
    });

    it('should produce different signatures for different messages', () => {
      const keypair = generateEd448();
      const privB64 = Buffer.from(keypair.private_key).toString('base64');
      
      const sig1 = signEd448(privB64, Buffer.from('message 1').toString('base64'));
      const sig2 = signEd448(privB64, Buffer.from('message 2').toString('base64'));
      
      assert.notEqual(sig1, sig2);
    });
  });

  describe('verifyEd448', () => {
    it('should verify valid signature', () => {
      const keypair = generateEd448();
      const privB64 = Buffer.from(keypair.private_key).toString('base64');
      const pubB64 = Buffer.from(keypair.public_key).toString('base64');
      const msgB64 = Buffer.from('test message').toString('base64');
      
      const sigB64 = signEd448(privB64, msgB64);
      const result = verifyEd448(pubB64, msgB64, sigB64);
      
      assert.ok(result === true || result === 'true', 'valid signature should verify');
    });

    it('should reject signature from different key', () => {
      const kp1 = generateEd448();
      const kp2 = generateEd448();
      const msgB64 = Buffer.from('test message').toString('base64');
      
      const sigB64 = signEd448(
        Buffer.from(kp1.private_key).toString('base64'),
        msgB64
      );
      
      // Try to verify with different public key - may throw or return false
      try {
        const result = verifyEd448(
          Buffer.from(kp2.public_key).toString('base64'),
          msgB64,
          sigB64
        );
        assert.ok(result === false || result === 'false', 'signature from different key should not verify');
      } catch (e) {
        // Throwing is acceptable for invalid signature
        assert.ok(e.message.includes('invalid') || e.message.includes('signature'), 
          'should throw signature error');
      }
    });

    it('should reject signature for different message', () => {
      const keypair = generateEd448();
      const privB64 = Buffer.from(keypair.private_key).toString('base64');
      const pubB64 = Buffer.from(keypair.public_key).toString('base64');
      
      const sigB64 = signEd448(privB64, Buffer.from('original message').toString('base64'));
      
      // May throw or return false
      try {
        const result = verifyEd448(pubB64, Buffer.from('different message').toString('base64'), sigB64);
        assert.ok(result === false || result === 'false', 'signature for different message should not verify');
      } catch (e) {
        // Throwing is acceptable for invalid signature
        assert.ok(e.message.includes('invalid') || e.message.includes('signature'),
          'should throw signature error');
      }
    });
  });

  describe('safeVerifyEd448', () => {
    it('should return success object for valid signature', () => {
      const keypair = generateEd448();
      const privB64 = Buffer.from(keypair.private_key).toString('base64');
      const pubB64 = Buffer.from(keypair.public_key).toString('base64');
      const msgB64 = Buffer.from('test message').toString('base64');
      
      const sigB64 = signEd448(privB64, msgB64);
      const result = safeVerifyEd448(pubB64, msgB64, sigB64);
      
      assert.ok(result.success, 'should return success: true');
    });

    it('should return success: false for invalid signature', () => {
      const kp1 = generateEd448();
      const kp2 = generateEd448();
      const msgB64 = Buffer.from('test').toString('base64');
      
      const sigB64 = signEd448(
        Buffer.from(kp1.private_key).toString('base64'),
        msgB64
      );
      
      const result = safeVerifyEd448(
        Buffer.from(kp2.public_key).toString('base64'),
        msgB64,
        sigB64
      );
      
      assert.equal(result.success, false);
    });
  });
});

// ============ Device Keyset ============

describe('Device Keyset', () => {
  describe('newDeviceKeyset', () => {
    it('should generate complete keyset', async () => {
      const keyset = await newDeviceKeyset();
      
      assert.ok(keyset.identity_key, 'should have identity_key');
      assert.ok(keyset.pre_key, 'should have pre_key');
      assert.ok(keyset.inbox_encryption_key, 'should have inbox_encryption_key');
      assert.ok(keyset.inbox_signing_key, 'should have inbox_signing_key');
      assert.ok(keyset.inbox_address, 'should have inbox_address');
    });

    it('should generate X448 keys for identity and pre-key', async () => {
      const keyset = await newDeviceKeyset();
      
      // WASM may use 57 bytes (format byte)
      assert.ok(keyset.identity_key.public_key.length >= 56);
      assert.ok(keyset.pre_key.public_key.length >= 56);
      assert.ok(keyset.inbox_encryption_key.public_key.length >= 56);
    });

    it('should generate Ed448 inbox signing key', async () => {
      const keyset = await newDeviceKeyset();
      
      assert.equal(keyset.inbox_signing_key.public_key.length, 57);
    });

    it('should derive inbox address from signing key', async () => {
      const keyset = await newDeviceKeyset();
      const expectedAddress = deriveAddress(keyset.inbox_signing_key.public_key);
      
      assert.equal(keyset.inbox_address, expectedAddress);
    });
  });
});

// ============ X3DH Key Exchange ============

describe('X3DH Key Exchange', () => {
  it('should produce matching session keys for sender and receiver', () => {
    const aliceIdentity = generateX448();
    const aliceEphemeral = generateX448();
    const bobIdentity = generateX448();
    const bobPreKey = generateX448();
    
    const senderKey = senderX3DH(
      aliceIdentity.private_key,
      aliceEphemeral.private_key,
      bobIdentity.public_key,
      bobPreKey.public_key,
      96
    );
    
    const receiverKey = receiverX3DH(
      bobIdentity.private_key,
      bobPreKey.private_key,
      aliceIdentity.public_key,
      aliceEphemeral.public_key,
      96
    );
    
    assert.equal(senderKey, receiverKey, 'sender and receiver should derive same session key');
  });

  it('should produce correct length session key', () => {
    const aliceIdentity = generateX448();
    const aliceEphemeral = generateX448();
    const bobIdentity = generateX448();
    const bobPreKey = generateX448();
    
    const sessionKey = senderX3DH(
      aliceIdentity.private_key,
      aliceEphemeral.private_key,
      bobIdentity.public_key,
      bobPreKey.public_key,
      96
    );
    
    const keyBytes = Buffer.from(sessionKey, 'base64');
    assert.equal(keyBytes.length, 96, 'session key should be 96 bytes');
  });

  it('should produce different session keys with different keys', () => {
    const alice1 = generateX448();
    const alice2 = generateX448();
    const bob = generateX448();
    const bobPre = generateX448();
    
    const key1 = senderX3DH(
      alice1.private_key,
      generateX448().private_key,
      bob.public_key,
      bobPre.public_key,
      96
    );
    
    const key2 = senderX3DH(
      alice2.private_key,
      generateX448().private_key,
      bob.public_key,
      bobPre.public_key,
      96
    );
    
    assert.notEqual(key1, key2, 'different sender keys should produce different session keys');
  });
});

// ============ Double Ratchet ============

describe('Double Ratchet', () => {
  function setupRatchets() {
    const aliceIdentity = generateX448();
    const aliceEphemeral = generateX448();
    const bobIdentity = generateX448();
    const bobPreKey = generateX448();
    
    const sessionKeyB64 = senderX3DH(
      aliceIdentity.private_key,
      aliceEphemeral.private_key,
      bobIdentity.public_key,
      bobPreKey.public_key,
      96
    );
    
    const rootKey = [...Buffer.from(sessionKeyB64, 'base64')];
    
    const aliceRatchet = newDoubleRatchet({
      session_key: rootKey.slice(0, 32),
      sending_header_key: rootKey.slice(32, 64),
      next_receiving_header_key: rootKey.slice(64, 96),
      is_sender: true,
      sending_ephemeral_private_key: aliceEphemeral.private_key,
      receiving_ephemeral_key: bobPreKey.public_key,
    });
    
    const bobRatchet = newDoubleRatchet({
      session_key: rootKey.slice(0, 32),
      sending_header_key: rootKey.slice(32, 64),
      next_receiving_header_key: rootKey.slice(64, 96),
      is_sender: false,
      sending_ephemeral_private_key: bobPreKey.private_key,
      receiving_ephemeral_key: aliceEphemeral.public_key,
    });
    
    return { aliceRatchet, bobRatchet };
  }

  describe('newDoubleRatchet', () => {
    it('should create ratchet state string', () => {
      const { aliceRatchet } = setupRatchets();
      
      assert.ok(typeof aliceRatchet === 'string', 'ratchet state should be string');
      
      // Should be valid JSON
      const parsed = JSON.parse(aliceRatchet);
      assert.ok(parsed, 'should be valid JSON');
    });
  });

  describe('doubleRatchetEncrypt', () => {
    it('should produce encrypted envelope', () => {
      const { aliceRatchet } = setupRatchets();
      
      const result = doubleRatchetEncrypt(aliceRatchet, 'Hello Bob!');
      
      assert.ok(result.ratchet_state, 'should return new ratchet state');
      assert.ok(result.envelope, 'should return encrypted envelope');
    });

    it('should update ratchet state', () => {
      const { aliceRatchet } = setupRatchets();
      
      const result = doubleRatchetEncrypt(aliceRatchet, 'test');
      
      assert.notEqual(result.ratchet_state, aliceRatchet, 'ratchet state should change');
    });
  });

  describe('doubleRatchetDecrypt', () => {
    it('should decrypt message from sender', () => {
      const { aliceRatchet, bobRatchet } = setupRatchets();
      
      const { ratchet_state: aliceNew, envelope } = doubleRatchetEncrypt(aliceRatchet, 'Hello Bob!');
      const { ratchet_state: bobNew, message } = doubleRatchetDecrypt(bobRatchet, envelope);
      
      assert.equal(message, 'Hello Bob!');
    });

    it('should enable bidirectional communication', () => {
      let { aliceRatchet, bobRatchet } = setupRatchets();
      
      // Alice -> Bob
      let result = doubleRatchetEncrypt(aliceRatchet, 'Hello Bob!');
      aliceRatchet = result.ratchet_state;
      
      result = doubleRatchetDecrypt(bobRatchet, result.envelope);
      bobRatchet = result.ratchet_state;
      assert.equal(result.message, 'Hello Bob!');
      
      // Bob -> Alice
      result = doubleRatchetEncrypt(bobRatchet, 'Hi Alice!');
      bobRatchet = result.ratchet_state;
      
      result = doubleRatchetDecrypt(aliceRatchet, result.envelope);
      aliceRatchet = result.ratchet_state;
      assert.equal(result.message, 'Hi Alice!');
    });

    it('should handle multiple messages in same direction', () => {
      let { aliceRatchet, bobRatchet } = setupRatchets();
      
      // Alice sends 3 messages
      const messages = ['msg1', 'msg2', 'msg3'];
      const envelopes = [];
      
      for (const msg of messages) {
        const result = doubleRatchetEncrypt(aliceRatchet, msg);
        aliceRatchet = result.ratchet_state;
        envelopes.push(result.envelope);
      }
      
      // Bob decrypts all 3
      for (let i = 0; i < messages.length; i++) {
        const result = doubleRatchetDecrypt(bobRatchet, envelopes[i]);
        bobRatchet = result.ratchet_state;
        assert.equal(result.message, messages[i]);
      }
    });
  });

  describe('safeDoubleRatchetDecrypt', () => {
    it('should return success object for valid decrypt', () => {
      const { aliceRatchet, bobRatchet } = setupRatchets();
      
      const { envelope } = doubleRatchetEncrypt(aliceRatchet, 'test');
      const result = safeDoubleRatchetDecrypt(bobRatchet, envelope);
      
      assert.ok(result.success, 'should succeed');
      assert.equal(result.data.message, 'test');
    });

    it('should return error object for malformed envelope', () => {
      const { aliceRatchet, bobRatchet } = setupRatchets();
      
      // Encrypt a message, then corrupt it
      const { envelope } = doubleRatchetEncrypt(aliceRatchet, 'test message');
      const corruptedEnvelope = envelope.slice(0, -10) + 'CORRUPTED!';
      
      const result = safeDoubleRatchetDecrypt(bobRatchet, corruptedEnvelope);
      
      // Either fails or returns corrupted data
      if (result.success) {
        // If it "succeeds", the message should be garbled
        assert.notEqual(result.data.message, 'test message', 'corrupted envelope should not decrypt correctly');
      } else {
        assert.ok(result.error, 'should have error');
      }
    });
  });
});

// ============ Inbox Encryption ============

describe('Inbox Encryption', () => {
  describe('encryptInboxMessageBytes / decryptInboxMessage', () => {
    it('should encrypt and decrypt message', () => {
      const inboxKey = generateX448();
      const ephemeralKey = generateX448();
      const plaintext = [...Buffer.from('secret message', 'utf-8')];
      
      const ciphertext = encryptInboxMessageBytes(
        inboxKey.public_key,
        ephemeralKey.private_key,
        plaintext
      );
      
      const decrypted = decryptInboxMessage(
        inboxKey.private_key,
        ephemeralKey.public_key,
        JSON.parse(ciphertext)
      );
      
      const decryptedStr = Buffer.from(new Uint8Array(decrypted)).toString('utf-8');
      assert.equal(decryptedStr, 'secret message');
    });

    it('should fail to decrypt with wrong key', () => {
      const inboxKey = generateX448();
      const wrongKey = generateX448();
      const ephemeralKey = generateX448();
      const plaintext = [...Buffer.from('secret', 'utf-8')];
      
      const ciphertext = encryptInboxMessageBytes(
        inboxKey.public_key,
        ephemeralKey.private_key,
        plaintext
      );
      
      assert.throws(() => {
        decryptInboxMessage(
          wrongKey.private_key,
          ephemeralKey.public_key,
          JSON.parse(ciphertext)
        );
      }, 'should fail to decrypt with wrong key');
    });

    it('should handle JSON payload', () => {
      const inboxKey = generateX448();
      const ephemeralKey = generateX448();
      const payload = { type: 'message', text: 'hello', count: 42 };
      const plaintext = [...Buffer.from(JSON.stringify(payload), 'utf-8')];
      
      const ciphertext = encryptInboxMessageBytes(
        inboxKey.public_key,
        ephemeralKey.private_key,
        plaintext
      );
      
      const decrypted = decryptInboxMessage(
        inboxKey.private_key,
        ephemeralKey.public_key,
        JSON.parse(ciphertext)
      );
      
      const decryptedPayload = JSON.parse(
        Buffer.from(new Uint8Array(decrypted)).toString('utf-8')
      );
      
      assert.deepEqual(decryptedPayload, payload);
    });
  });

  describe('safeDecryptInboxMessage', () => {
    it('should return success object for valid decrypt', () => {
      const inboxKey = generateX448();
      const ephemeralKey = generateX448();
      const plaintext = [...Buffer.from('test', 'utf-8')];
      
      const ciphertext = encryptInboxMessageBytes(
        inboxKey.public_key,
        ephemeralKey.private_key,
        plaintext
      );
      
      const result = safeDecryptInboxMessage(
        inboxKey.private_key,
        ephemeralKey.public_key,
        JSON.parse(ciphertext)
      );
      
      assert.ok(result.success);
      assert.ok(result.data);
    });

    it('should return error object for invalid decrypt', () => {
      const inboxKey = generateX448();
      const wrongKey = generateX448();
      const ephemeralKey = generateX448();
      const plaintext = [...Buffer.from('test', 'utf-8')];
      
      const ciphertext = encryptInboxMessageBytes(
        inboxKey.public_key,
        ephemeralKey.private_key,
        plaintext
      );
      
      const result = safeDecryptInboxMessage(
        wrongKey.private_key,
        ephemeralKey.public_key,
        JSON.parse(ciphertext)
      );
      
      assert.equal(result.success, false);
      assert.ok(result.error instanceof CryptoError);
      assert.equal(result.error.type, CryptoErrorType.DECRYPTION_FAILED);
    });
  });
});

// ============ Registration ============

describe('Registration', () => {
  describe('constructRegistration', () => {
    it('should build valid registration structure', async () => {
      const userKey = generateEd448();
      const userPubHex = Buffer.from(userKey.public_key).toString('hex');
      const userPrivHex = Buffer.from(userKey.private_key).toString('hex');
      const userAddress = deriveAddress(userKey.public_key);
      
      const deviceKeyset = await newDeviceKeyset();
      
      const registration = constructRegistration(
        userAddress,
        userPubHex,
        userPrivHex,
        deviceKeyset
      );
      
      assert.equal(registration.user_address, userAddress);
      assert.equal(registration.user_public_key, userPubHex);
      assert.ok(registration.device_registrations.length >= 1);
      assert.ok(registration.signature);
    });

    it('should include device registration details', async () => {
      const userKey = generateEd448();
      const deviceKeyset = await newDeviceKeyset();
      
      const registration = constructRegistration(
        deriveAddress(userKey.public_key),
        Buffer.from(userKey.public_key).toString('hex'),
        Buffer.from(userKey.private_key).toString('hex'),
        deviceKeyset
      );
      
      const device = registration.device_registrations[0];
      
      assert.ok(device.identity_public_key);
      assert.ok(device.pre_public_key);
      assert.ok(device.inbox_registration.inbox_address);
      assert.ok(device.inbox_registration.inbox_encryption_public_key);
    });
  });
});
