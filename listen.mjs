import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const WebSocket = require('ws');

const INBOX = 'QmetLMWHRnvRfyLqwNeMRVcnNaFxNGxkUGEv6r7GeCz7vs';
console.log('Listening on inbox:', INBOX);

const ws = new WebSocket('wss://api.quorummessenger.com/ws');

ws.on('open', () => {
  console.log('Connected — waiting for messages...');
  ws.send(JSON.stringify({ type: 'listen', inbox_addresses: [INBOX] }));
});

ws.on('message', (data) => {
  const raw = data.toString();
  console.log('\n📨 MESSAGE RECEIVED at', new Date().toISOString());
  console.log('Raw length:', raw.length);
  try {
    const parsed = JSON.parse(raw);
    console.log('Keys:', Object.keys(parsed));
    if (parsed.inbox_address) console.log('To inbox:', parsed.inbox_address);
    if (parsed.ephemeral_public_key) console.log('Ephemeral key:', parsed.ephemeral_public_key.substring(0, 32) + '...');
    if (parsed.envelope) console.log('Envelope length:', parsed.envelope.length);
    if (parsed.timestamp) console.log('Timestamp:', parsed.timestamp);
    // Save for decryption
    require('fs').writeFileSync('/tmp/quorum-incoming.json', raw);
    console.log('Saved to /tmp/quorum-incoming.json');
  } catch {
    console.log('Raw:', raw.substring(0, 500));
  }
});

ws.on('error', (err) => console.error('Error:', err.message));
ws.on('close', () => { console.log('Disconnected'); process.exit(0); });

// Keep alive for 2 minutes
setTimeout(() => { console.log('Timeout — closing'); ws.close(); }, 120000);
