# quorum-client

Headless E2EE client for [Quorum](https://quilibrium.com) messenger, the Quilibrium-powered encrypted messaging platform.

**Zero dependencies** beyond Node.js 20+ — cryptography runs via bundled WASM (Decaf448 curves, Double Ratchet, X3DH).

## What is this?

A command-line / programmatic client for Quorum messenger that handles:

- **Identity generation** — Ed448 user keys, X448 device keys, inbox keypairs
- **Registration** — Posts your public keys to the Quorum API
- **E2EE messaging** — X3DH key exchange → Double Ratchet encrypted DMs
- **State persistence** — Keys and ratchet states saved to disk

Think of it as a headless version of the Quorum mobile/desktop app.

## Quick Start

```bash
# Register a new identity
node cli.mjs register "MyName"

# Show your identity
node cli.mjs identity

# Look up a user
node cli.mjs lookup <address>

# Send an encrypted DM
node cli.mjs send <recipient-address> Hello from the command line!

# List contacts
node cli.mjs contacts
```

## Programmatic Usage

```javascript
import { QuorumClient } from './src/client.mjs';

const client = new QuorumClient({
  dataDir: './my-quorum-data',
  displayName: 'My Bot',
});

await client.init();

// Register (first time only)
const { address } = await client.register('My Bot');
console.log('Registered as:', address);

// Send a message
await client.sendMessage(recipientAddress, 'Hello!');

// Process incoming messages
const envelope = client.decryptInboxMessage(sealedMessage);
const result = await client.processInitMessage(envelope);
console.log(`${result.displayName}: ${result.message}`);
```

## Architecture

```
cli.mjs            — CLI interface
src/
  client.mjs       — Main client (orchestrates everything)
  crypto.mjs       — WASM crypto wrapper (X448, Ed448, X3DH, Double Ratchet)
  api.mjs          — Quorum REST API client
  store.mjs        — Disk persistence for keys and sessions
  wasm/            — Quilibrium channel WASM (from quilibrium-js-sdk-channels)
```

## E2EE Protocol

1. **Key Generation**: Ed448 (signing) + X448 (key exchange) via Decaf448 curves
2. **Registration**: Public keys posted to `api.quorummessenger.com`
3. **First Message**: X3DH key agreement → establishes shared secret
4. **Ongoing**: Double Ratchet protocol (forward secrecy per message)
5. **Transport**: Messages sealed with inbox encryption keys, relayed via Quorum API

The same protocol used by the official Quorum mobile and desktop apps.

## Data Storage

Keys and state are stored in `~/.quorum-client/` (configurable):

```
keys/
  user-keyset.json      — Ed448 user identity (KEEP SECRET)
  device-keyset.json    — X448 device keys + inbox keys (KEEP SECRET)
  registration.json     — Public registration (safe to share)
sessions/
  <hex>.json            — Double Ratchet state per conversation
conversations/
  <id>.json             — Conversation metadata
profile.json            — Display name, creation date
```

⚠️ **Back up your `keys/` directory** — losing it means losing your identity and all active conversations.

## Crypto Credits

The WASM cryptography module is from [quilibrium-js-sdk-channels](https://github.com/QuilibriumNetwork/quilibrium-js-sdk-channels) by Quilibrium Inc, licensed under MIT.

## Status

🚧 **Early experimental** — This is a proof-of-concept headless client.

- [x] Identity generation and registration
- [x] X3DH key exchange (sender side)
- [x] Double Ratchet encryption/decryption
- [x] Sealed inbox message encryption
- [ ] Message polling / WebSocket receive
- [ ] Session confirmation (bidirectional ratchet)
- [ ] Group messaging (Triple Ratchet / Spaces)
- [ ] Message deletion acknowledgment

## License

MIT
