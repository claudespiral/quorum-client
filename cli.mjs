#!/usr/bin/env node

/**
 * Quorum Headless Client CLI
 * 
 * Commands:
 *   init                       Initialize crypto engine
 *   register <name>            Create new identity and register
 *   identity                   Show current identity info
 *   send <address> <message>   Send an encrypted DM
 *   contacts                   List known contacts
 *   poll                       Poll for new messages
 */

import { QuorumClient } from './src/client.mjs';
import { join } from 'path';
import { homedir } from 'os';

const DATA_DIR = process.env.QUORUM_DATA_DIR || join(homedir(), '.quorum-client');
const args = process.argv.slice(2);
const command = args[0];

async function main() {
  const client = new QuorumClient({
    dataDir: DATA_DIR,
    displayName: 'Claude',
  });

  if (!command || command === 'help') {
    console.log(`
Quorum Headless Client — E2EE messenger for Quilibrium

Usage: quorum <command> [args]

Commands:
  register <name>            Create new identity and register with Quorum
  identity                   Show your identity (address, keys)
  send <address> <message>   Send an encrypted direct message
  contacts                   List known conversation partners
  poll                       Poll inbox for new messages
  lookup <address>           Fetch a user's public registration
  keychain                   Check keychain status and migrate keys

Data directory: ${DATA_DIR}
`);
    return;
  }

  // Initialize
  const status = await client.init();

  switch (command) {
    case 'register': {
      if (status.hasIdentity) {
        console.log('Already registered!');
        console.log('Address:', status.address);
        return;
      }
      const name = args[1] || 'Quorum User';
      console.log(`Registering as "${name}"...`);
      try {
        const result = await client.register(name);
        console.log('✅ Registered successfully!');
        console.log('Address:', result.address);
        console.log('Inbox:', result.inboxAddress);
        console.log(`\nKeys saved to ${DATA_DIR}/keys/`);
      } catch (e) {
        console.error('❌ Registration failed:', e.message);
        process.exit(1);
      }
      break;
    }

    case 'identity':
    case 'id': {
      const id = client.getIdentity();
      if (!id) {
        console.log('No identity. Run: quorum register <name>');
        return;
      }
      console.log('Address:     ', id.address);
      console.log('Public Key:  ', id.publicKey?.substring(0, 32) + '...');
      console.log('Inbox:       ', id.inboxAddress);
      console.log('Display Name:', id.displayName || '(none)');
      break;
    }

    case 'send': {
      if (!status.hasIdentity) {
        console.log('Not registered. Run: quorum register <name>');
        process.exit(1);
      }
      const recipient = args[1];
      const message = args.slice(2).join(' ');
      if (!recipient || !message) {
        console.error('Usage: quorum send <address> <message>');
        process.exit(1);
      }
      console.log(`Sending to ${recipient.substring(0, 20)}...`);
      try {
        const result = await client.sendMessage(recipient, message);
        console.log(result.firstMessage ? '✅ Sent (new session established)' : '✅ Sent');
      } catch (e) {
        console.error('❌ Send failed:', e.message);
        process.exit(1);
      }
      break;
    }

    case 'contacts': {
      if (!status.hasIdentity) {
        console.log('Not registered.');
        return;
      }
      const contacts = client.listContacts();
      if (!contacts.length) {
        console.log('No contacts yet.');
        return;
      }
      for (const c of contacts) {
        console.log(`${c.displayName || '(unknown)'} — ${c.address}`);
      }
      break;
    }

    case 'poll': {
      if (!status.hasIdentity) {
        console.log('Not registered.');
        return;
      }
      console.log('Polling inbox...');
      const messages = await client.pollMessages();
      if (!messages.length) {
        console.log('No new messages.');
      } else {
        for (const m of messages) {
          console.log(`[${m.from}] ${m.message}`);
        }
      }
      break;
    }

    case 'lookup': {
      const addr = args[1];
      if (!addr) {
        console.error('Usage: quorum lookup <address>');
        process.exit(1);
      }
      try {
        const user = await client.api.getUser(addr);
        console.log('Address:', user.user_address);
        console.log('Public Key:', user.user_public_key?.substring(0, 32) + '...');
        console.log('Peer Key:', user.peer_public_key?.substring(0, 32) + '...');
        console.log('Devices:', user.device_registrations?.length || 0);
        for (const d of user.device_registrations || []) {
          console.log('  Inbox:', d.inbox_registration?.inbox_address);
        }
      } catch (e) {
        console.error('❌ Lookup failed:', e.message);
        process.exit(1);
      }
      break;
    }

    case 'keychain': {
      const subCmd = args[1];
      if (status.usingKeychain) {
        console.log('✅ Using OS keychain for key storage');
        if (subCmd === 'verify') {
          try {
            await client.store.removePlaintextKeys();
          } catch (e) {
            console.error('❌', e.message);
          }
        } else {
          console.log('\nRun `quorum keychain verify` to check keychain access');
          console.log('and get instructions for removing plaintext key files.');
        }
      } else {
        console.log('⚠️  OS keychain not available');
        console.log('Keys are stored in plaintext at:', DATA_DIR + '/keys/');
        console.log('\nTo enable keychain on macOS: just run the app, approve the prompt');
        console.log('To enable keychain on Linux: ensure gnome-keyring or kwallet is running');
      }
      break;
    }

    default:
      console.error(`Unknown command: ${command}`);
      console.error('Run: quorum help');
      process.exit(1);
  }
}

main().catch(e => {
  console.error('Fatal:', e.message);
  process.exit(1);
});
