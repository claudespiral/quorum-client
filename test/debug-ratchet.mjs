#!/usr/bin/env node
/**
 * Debug script for Double Ratchet encryption/decryption
 * Tests the raw crypto primitives without network involvement
 * 
 * Based on quilibrium-js-sdk-channels patterns
 */

import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, '..');

const { 
  initCrypto, 
  generateX448, 
  senderX3DH, 
  receiverX3DH, 
  newDoubleRatchet, 
  doubleRatchetEncrypt,
  doubleRatchetDecrypt 
} = await import(join(PROJECT_ROOT, 'src/crypto.mjs'));

async function main() {
  console.log('🔬 Double Ratchet Debug Test (SDK Pattern)\n');
  
  await initCrypto();
  console.log('✅ Crypto initialized\n');
  
  // Generate keys for Alice and Bob
  const aliceIdentity = generateX448();
  const aliceEphemeral = generateX448();
  const bobIdentity = generateX448();
  const bobPreKey = generateX448();
  
  console.log('📝 Keys generated');
  console.log('  Alice identity:', Buffer.from(new Uint8Array(aliceIdentity.public_key)).toString('hex').substring(0, 32) + '...');
  console.log('  Bob identity:', Buffer.from(new Uint8Array(bobIdentity.public_key)).toString('hex').substring(0, 32) + '...');
  console.log();
  
  // === Alice (Sender) Side ===
  console.log('=== Alice (Sender) Side ===');
  
  const aliceSessionKey = senderX3DH(
    aliceIdentity.private_key,
    aliceEphemeral.private_key,
    bobIdentity.public_key,
    bobPreKey.public_key,
    96
  );
  
  const aliceRootKey = [...Buffer.from(aliceSessionKey, 'base64')];
  console.log('Session key length:', aliceRootKey.length);
  
  // Sender ratchet params (from SDK)
  const aliceRatchetParams = {
    session_key: aliceRootKey.slice(0, 32),
    sending_header_key: aliceRootKey.slice(32, 64),
    next_receiving_header_key: aliceRootKey.slice(64, 96),
    is_sender: true,
    sending_ephemeral_private_key: aliceEphemeral.private_key,
    receiving_ephemeral_key: bobPreKey.public_key,  // Bob's pre-key
  };
  
  let aliceRatchet;
  try {
    aliceRatchet = newDoubleRatchet(aliceRatchetParams);
    // Check for error in result
    if (aliceRatchet.includes('missing field') || aliceRatchet.includes('invalid')) {
      throw new Error(aliceRatchet);
    }
    JSON.parse(aliceRatchet); // Force early failure
    console.log('✅ Alice ratchet created');
  } catch (e) {
    console.error('❌ Alice ratchet creation failed:', e.message);
    return;
  }
  
  // Encrypt message
  const testMessage = JSON.stringify({
    messageId: 'test-123',
    content: { type: 'post', text: 'Hello Bob!' }
  });
  
  let encryptResult;
  try {
    encryptResult = doubleRatchetEncrypt(aliceRatchet, testMessage);
    console.log('✅ Message encrypted');
    console.log('  envelope type:', typeof encryptResult.envelope);
  } catch (e) {
    console.error('❌ Encryption failed:', e.message);
    return;
  }
  
  // === Bob (Receiver) Side ===
  console.log('\n=== Bob (Receiver) Side ===');
  
  const bobSessionKey = receiverX3DH(
    bobIdentity.private_key,
    bobPreKey.private_key,
    aliceIdentity.public_key,
    aliceEphemeral.public_key,
    96
  );
  
  if (aliceSessionKey === bobSessionKey) {
    console.log('✅ Session keys match!');
  } else {
    console.log('❌ Session keys DO NOT match!');
    return;
  }
  
  const bobRootKey = [...Buffer.from(bobSessionKey, 'base64')];
  
  // Receiver ratchet params (from SDK)
  // KEY INSIGHT: Header keys are NOT swapped! WASM handles perspective via is_sender
  // KEY INSIGHT: sending_ephemeral_private_key = pre_key for receiver
  // KEY INSIGHT: receiving_ephemeral_key = sender's ephemeral (Alice's)
  const bobRatchetParams = {
    session_key: bobRootKey.slice(0, 32),
    sending_header_key: bobRootKey.slice(32, 64),      // SAME as sender!
    next_receiving_header_key: bobRootKey.slice(64, 96),  // SAME as sender!
    is_sender: false,
    sending_ephemeral_private_key: bobPreKey.private_key,  // Bob's pre-key (used in X3DH)
    receiving_ephemeral_key: aliceEphemeral.public_key,    // Alice's ephemeral
  };
  
  let bobRatchet;
  try {
    bobRatchet = newDoubleRatchet(bobRatchetParams);
    if (bobRatchet.includes('missing field') || bobRatchet.includes('invalid')) {
      throw new Error(bobRatchet);
    }
    JSON.parse(bobRatchet);
    console.log('✅ Bob ratchet created');
  } catch (e) {
    console.error('❌ Bob ratchet creation failed:', e.message);
    return;
  }
  
  // Decrypt message
  console.log('\n=== Decryption ===');
  
  // KEY INSIGHT: envelope should stay as STRING (from SDK pattern)
  const envelope = encryptResult.envelope;
  console.log('Envelope is string:', typeof envelope === 'string');
  
  try {
    const decryptResult = doubleRatchetDecrypt(bobRatchet, envelope);
    
    // Check for error messages
    if (decryptResult.message.includes('Decryption failed') || 
        decryptResult.message.includes('aead') ||
        decryptResult.message.includes('invalid')) {
      throw new Error(decryptResult.message);
    }
    
    console.log('✅ Message decrypted!');
    console.log('  Content:', decryptResult.message);
    
    // Verify
    const parsed = JSON.parse(decryptResult.message);
    if (parsed.content.text === 'Hello Bob!') {
      console.log('\n🎉 SUCCESS! Round-trip encryption working!');
    }
    
    // Test bidirectional - Bob replies to Alice
    console.log('\n=== Bob replies to Alice ===');
    
    const replyMessage = JSON.stringify({
      messageId: 'reply-456',
      content: { type: 'post', text: 'Hi Alice, got it!' }
    });
    
    const replyEncrypt = doubleRatchetEncrypt(decryptResult.ratchet_state, replyMessage);
    console.log('✅ Bob encrypted reply');
    
    // Alice decrypts with her updated state
    const aliceDecrypt = doubleRatchetDecrypt(encryptResult.ratchet_state, replyEncrypt.envelope);
    
    if (aliceDecrypt.message.includes('Decryption failed')) {
      throw new Error(aliceDecrypt.message);
    }
    
    console.log('✅ Alice decrypted reply:', JSON.parse(aliceDecrypt.message).content.text);
    console.log('\n🎉 BIDIRECTIONAL SUCCESS!');
    
  } catch (e) {
    console.error('\n❌ Decryption failed:', e.message);
    
    // Debug output
    console.log('\nDebug info:');
    console.log('  Alice ratchet (parsed):');
    const ar = JSON.parse(aliceRatchet);
    console.log('    sending_ephemeral_private_key:', ar.sending_ephemeral_private_key?.substring(0, 20) + '...');
    console.log('    receiving_ephemeral_key:', ar.receiving_ephemeral_key?.substring(0, 20) + '...');
    
    console.log('  Bob ratchet (parsed):');
    const br = JSON.parse(bobRatchet);
    console.log('    sending_ephemeral_private_key:', br.sending_ephemeral_private_key?.substring(0, 20) + '...');
    console.log('    receiving_ephemeral_key:', br.receiving_ephemeral_key?.substring(0, 20) + '...');
    
    // Check if ephemeral keys match up
    console.log('\n  Key correspondence check:');
    console.log('    Alice sending_ephemeral matches Bob receiving_ephemeral:', 
      ar.sending_ephemeral_private_key && br.receiving_ephemeral_key);
  }
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
