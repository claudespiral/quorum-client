#!/usr/bin/env node
import WebSocket from 'ws';
import { createHash, randomBytes } from 'crypto';
import path from 'path';
import { initCrypto, generateX448, encryptInboxMessageBytes, signEd448, getX448PubKey } from './src/crypto.mjs';
import { createSecureStore } from './src/secure-store.mjs';

const SPACE_ID = process.argv[2] || 'QmaQqr719AQNnMUxzqiwEpzJEWFuJwRQdsr2K3D3aZvVoa';
const MESSAGE_TEXT = process.argv[3] || 'Hello from Claude!';
const DATA_DIR = path.join(process.env.HOME, '.quorum-client', 'keys');

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

async function main() {
  await initCrypto();
  
  const store = await createSecureStore(DATA_DIR);
  const spaceKeys = await store.getSpaceKeys(SPACE_ID);
  if (!spaceKeys) {
    throw new Error(`Space not found: ${SPACE_ID}. Join it first.`);
  }
  
  // Parse template to get channel ID
  const template = JSON.parse(spaceKeys.template);
  
  // Get channel ID from space manifest or use a known one
  // From the received message, channel was: QmZWt1AYqsAMLuLg8iwmhmVqRjQnbAAWF7AHGPkWPNXEoc
  const channelId = 'QmZWt1AYqsAMLuLg8iwmhmVqRjQnbAAWF7AHGPkWPNXEoc';
  
  const timestamp = Date.now();
  const nonce = bytesToHex(randomBytes(16));
  
  // Generate message ID from hash
  const idContent = `${SPACE_ID}:${channelId}:${spaceKeys.inboxAddress}:${nonce}:${timestamp}`;
  const messageId = bytesToHex(createHash('sha256').update(idContent).digest());
  
  // Build message object
  const message = {
    channelId,
    spaceId: SPACE_ID,
    messageId,
    digestAlgorithm: 'sha256',
    nonce,
    createdDate: timestamp,
    modifiedDate: timestamp,
    lastModifiedHash: '',
    content: {
      type: 'post',
      senderId: spaceKeys.inboxAddress,
      text: MESSAGE_TEXT,
    },
    reactions: [],
    mentions: { memberIds: [], roleIds: [], channelIds: [] },
    publicKey: spaceKeys.inboxSigningKey.public_key,
  };
  
  // Sign the message
  const messageJson = JSON.stringify(message);
  const messageBytes = new TextEncoder().encode(messageJson);
  const signature = signEd448(
    bytesToBase64(hexToBytes(spaceKeys.inboxSigningKey.private_key)),
    bytesToBase64(messageBytes)
  );
  message.signature = bytesToHex(base64ToBytes(signature));
  
  console.log('Message built:');
  console.log('  Text:', MESSAGE_TEXT);
  console.log('  From:', spaceKeys.inboxAddress);
  console.log('  Channel:', channelId);
  
  // Wrap in hub message payload
  const hubPayload = JSON.stringify({
    type: 'message',
    message,
  });
  
  // Encrypt with config key (sealHubEnvelope)
  // Generate ephemeral X448 keypair
  const ephemeral = await generateX448();
  
  // Get config public key from config private key
  const configPrivKey = hexToBytes(spaceKeys.configPrivateKey);
  const configPubKeyB64 = getX448PubKey(bytesToBase64(configPrivKey));
  const configPubKey = base64ToBytes(configPubKeyB64);
  
  // Encrypt the payload
  const encrypted = encryptInboxMessageBytes(
    [...configPubKey],
    ephemeral.private_key,
    [...new TextEncoder().encode(hubPayload)]
  );
  
  // Sign with hub key
  const hubPrivKey = hexToBytes(spaceKeys.hubPrivateKey);
  const envelopeBytes = new TextEncoder().encode(encrypted);
  const hubSignature = signEd448(
    bytesToBase64(hubPrivKey),
    bytesToBase64(envelopeBytes)
  );
  
  // Build sealed message
  const sealedMessage = {
    hub_address: spaceKeys.hubAddress,
    hub_public_key: spaceKeys.hubPublicKey,
    ephemeral_public_key: bytesToHex(new Uint8Array(ephemeral.public_key)),
    envelope: encrypted,
    hub_signature: bytesToHex(base64ToBytes(hubSignature)),
  };
  
  // Wrap for WebSocket
  const wsEnvelope = JSON.stringify({
    type: 'group',
    ...sealedMessage,
  });
  
  console.log('\nSending via WebSocket...');
  
  const ws = new WebSocket('wss://api.quorummessenger.com/ws');
  
  ws.on('open', () => {
    console.log('Connected, sending message...');
    ws.send(wsEnvelope);
    console.log('Sent! Waiting for confirmation...');
  });
  
  ws.on('message', (data) => {
    console.log('Response:', data.toString().substring(0, 200));
  });
  
  ws.on('error', (err) => console.error('Error:', err.message));
  
  setTimeout(() => {
    ws.close();
    console.log('Done');
    process.exit(0);
  }, 3000);
}

main().catch(console.error);
