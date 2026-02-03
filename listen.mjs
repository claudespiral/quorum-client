#!/usr/bin/env node
/**
 * Listen for incoming Quorum messages on your inbox
 * Usage: node listen.mjs [timeout_seconds]
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const os = require('os');

const DATA_DIR = path.join(os.homedir(), '.quorum-client');
const TIMEOUT = (parseInt(process.argv[2]) || 120) * 1000;

// Load identity
const deviceKeysetPath = path.join(DATA_DIR, 'device-keyset.json');
if (!fs.existsSync(deviceKeysetPath)) {
  console.error('No identity found. Run: node cli.mjs register <name>');
  process.exit(1);
}

const deviceKeyset = JSON.parse(fs.readFileSync(deviceKeysetPath, 'utf-8'));
const INBOX = deviceKeyset.inbox_address;

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
    if (parsed.timestamp) console.log('Timestamp:', parsed.timestamp);
    fs.writeFileSync('/tmp/quorum-incoming.json', raw);
    console.log('Saved to /tmp/quorum-incoming.json');
  } catch {
    console.log('Raw:', raw.substring(0, 500));
  }
});

ws.on('error', (err) => console.error('Error:', err.message));
ws.on('close', () => { console.log('Disconnected'); process.exit(0); });

setTimeout(() => { console.log('Timeout — closing'); ws.close(); }, TIMEOUT);
