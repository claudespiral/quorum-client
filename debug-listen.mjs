#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const WebSocket = require('ws');
import { join } from 'path';
import { homedir } from 'os';
import { initCrypto, safeDecryptInboxMessage, receiverX3DH, newDoubleRatchet, doubleRatchetDecrypt } from './src/crypto.mjs';
import { createSecureStore } from './src/secure-store.mjs';

const DATA_DIR = process.env.QUORUM_DATA_DIR || join(homedir(), '.quorum-client');
await initCrypto();

const store = await createSecureStore(DATA_DIR);
const deviceKeyset = await store.getDeviceKeyset();
const INBOX = deviceKeyset.inbox_address;

console.log('DEBUG Listening on:', INBOX);

const ws = new WebSocket('wss://api.quorummessenger.com/ws');
ws.on('open', () => {
  ws.send(JSON.stringify({ type: 'listen', inbox_addresses: [INBOX] }));
  console.log('Connected...\n');
});

ws.on('message', async (data) => {
  try {
    const parsed = JSON.parse(data.toString());
    if (parsed.type === 'ack') return;
    if (!parsed.encryptedContent) return;
    
    const sealed = JSON.parse(parsed.encryptedContent);
    const ephPubKey = sealed.ephemeral_public_key ? 
      [...Buffer.from(sealed.ephemeral_public_key, 'hex')] : null;
    
    if (!ephPubKey || !sealed.envelope) return;
    
    const result = safeDecryptInboxMessage(
      deviceKeyset.inbox_encryption_key.private_key,
      ephPubKey,
      sealed.envelope
    );
    
    if (!result.success) {
      console.log('Inbox decrypt failed');
      return;
    }
    
    const envelope = JSON.parse(Buffer.from(new Uint8Array(result.data)).toString('utf-8'));
    
    // Check if Type 1 (has user_address) or Type 2 (has protocol_identifier)
    if (envelope.user_address) {
      // Type 1 - DM with identity info
      const senderAddress = envelope.user_address;
      console.log('\n--- DM from', envelope.display_name || senderAddress.substring(0, 12), '---');
      
      // Check if we have an existing session for this sender
      let session = store.getSession(senderAddress);
      
      try {
        let drResult;
        
        if (session && session.ratchet_state) {
          // Use existing session ratchet
          console.log('(Using existing session)');
          drResult = doubleRatchetDecrypt(session.ratchet_state, envelope.message);
          // Update session with new ratchet state
          session.ratchet_state = drResult.ratchet_state;
          if (envelope.return_inbox_address) {
            session.sending_inbox = {
              inbox_address: envelope.return_inbox_address,
              inbox_encryption_key: envelope.return_inbox_encryption_key,
            };
          }
          store.saveSession(senderAddress, session);
        } else {
          // New session - do X3DH
          console.log('(Creating new session via X3DH)');
          const senderIdentityKey = [...Buffer.from(envelope.identity_public_key, 'hex')];
          const senderEphemeralKey = ephPubKey;
          
          const sessionKeyB64 = receiverX3DH(
            deviceKeyset.identity_key.private_key,
            deviceKeyset.pre_key.private_key,
            senderIdentityKey,
            senderEphemeralKey,
            96
          );
          
          const rootKey = [...Buffer.from(sessionKeyB64, 'base64')];
          const ratchetState = newDoubleRatchet({
            session_key: rootKey.slice(0, 32),
            sending_header_key: rootKey.slice(32, 64),
            next_receiving_header_key: rootKey.slice(64, 96),
            is_sender: false,
            sending_ephemeral_private_key: deviceKeyset.pre_key.private_key,
            receiving_ephemeral_key: senderEphemeralKey,
          });
          
          drResult = doubleRatchetDecrypt(ratchetState, envelope.message);
          
          // Save new session
          session = {
            ratchet_state: drResult.ratchet_state,
            sending_inbox: {
              inbox_address: envelope.return_inbox_address,
              inbox_encryption_key: envelope.return_inbox_encryption_key,
            },
            recipient_address: senderAddress,
            sender_name: envelope.display_name || senderAddress.substring(0, 12),
          };
          store.saveSession(senderAddress, session);
        }
        
        const msg = JSON.parse(drResult.message);
        console.log('Message ID:', msg.messageId);
        console.log('Content:', JSON.stringify(msg.content, null, 2));
        
      } catch (e) {
        console.log('Inner decrypt failed:', e.message);
      }
      
    } else if (envelope.protocol_identifier) {
      // Type 2 - continuation message
      console.log('\n--- TYPE 2 (Continuation) ---');
      
      const sessions = store.listSessions();
      for (const addr of sessions) {
        const session = store.getSession(addr);
        try {
          const drResult = doubleRatchetDecrypt(session.ratchet_state, JSON.stringify(envelope));
          // Update session
          session.ratchet_state = drResult.ratchet_state;
          store.saveSession(addr, session);
          
          const msg = JSON.parse(drResult.message);
          console.log('From session:', addr.substring(0, 20));
          console.log('Message ID:', msg.messageId);
          console.log('Content:', JSON.stringify(msg.content, null, 2));
          break;
        } catch (e) {
          // Try next session
        }
      }
    }
    
  } catch (e) {
    console.error('Parse error:', e.message);
  }
});

ws.on('error', (e) => console.error('WebSocket error:', e.message));
ws.on('close', () => console.log('Disconnected'));
