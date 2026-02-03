#!/usr/bin/env node
import WebSocket from 'ws';
import { readFileSync } from 'fs';
import { initCrypto, decryptInboxMessage } from './src/crypto.mjs';

const SPACE_ID = process.argv[2] || 'QmaQqr719AQNnMUxzqiwEpzJEWFuJwRQdsr2K3D3aZvVoa';

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

async function main() {
  await initCrypto();
  
  const spaceKeys = JSON.parse(readFileSync(
    `${process.env.HOME}/.quorum-client/spaces/${SPACE_ID}.json`
  ));
  
  console.log('Space:', SPACE_ID);
  console.log('Inbox:', spaceKeys.inboxAddress);
  console.log('Config key available:', !!spaceKeys.configPrivateKey);
  
  const ws = new WebSocket('wss://api.quorummessenger.com/ws');
  
  ws.on('open', () => {
    console.log('\nConnected! Subscribing to inbox...');
    ws.send(JSON.stringify({
      type: 'listen',
      inbox_addresses: [spaceKeys.inboxAddress]
    }));
  });
  
  ws.on('message', async (data) => {
    try {
      const msg = JSON.parse(data.toString());
      if (!msg.encryptedContent) {
        console.log('Non-message:', msg);
        return;
      }
      
      const envelope = JSON.parse(msg.encryptedContent);
      console.log('\n--- Encrypted message from hub ---');
      console.log('Hub:', envelope.hub_address);
      
      // Parse the inner envelope
      const innerEnvelope = JSON.parse(envelope.envelope);
      
      // Decrypt using config key
      const configPrivKey = hexToBytes(spaceKeys.configPrivateKey);
      const ephPubKey = hexToBytes(envelope.ephemeral_public_key);
      
      const decrypted = await decryptInboxMessage(
        [...configPrivKey],
        [...ephPubKey],
        innerEnvelope
      );
      
      const plaintext = new TextDecoder().decode(new Uint8Array(decrypted));
      console.log('Decrypted:', plaintext.substring(0, 500));
      
      // Parse the message
      const parsed = JSON.parse(plaintext);
      if (parsed.type === 'message' && parsed.message?.content) {
        console.log('\n📨 MESSAGE:');
        console.log('  From:', parsed.message.content.senderId?.substring(0, 20) + '...');
        console.log('  Text:', parsed.message.content.text);
      }
    } catch (err) {
      console.error('Decrypt error:', err.message);
    }
  });
  
  ws.on('error', (err) => console.error('WS Error:', err.message));
  ws.on('close', () => console.log('Disconnected'));
  
  console.log('Listening for messages... (Ctrl+C to stop)');
}

main().catch(console.error);
