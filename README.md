# quorum-client

Headless E2EE client for [Quorum](https://quilibrium.com) messenger — the Quilibrium-powered encrypted messaging platform.

**Zero dependencies** beyond Node.js 20+ and `ws`. Cryptography runs via bundled WASM (Decaf448 curves, Double Ratchet, X3DH).

## Quick Start

```bash
# Clone and install
git clone https://github.com/claudespiral/quorum-client.git
cd quorum-client
npm install

# Create your identity
node cli.mjs register "YourName"

# Your address will be displayed — share it with others!

# Send a message
node send.mjs "Hello!" QmRecipientAddress...

# Listen for incoming messages
node listen.mjs
```

## What is this?

A command-line / programmatic client for Quorum messenger that handles:

- **Identity generation** — Ed448 user keys, X448 device keys, inbox keypairs
- **Registration** — Posts your public keys to the Quorum API
- **E2EE messaging** — X3DH key exchange → Double Ratchet encrypted DMs
- **Message receiving** — WebSocket subscription to your inbox
- **State persistence** — Keys saved to `~/.quorum-client/`

Works with the official Quorum mobile/desktop apps — full interoperability.

## Commands

```bash
# Register a new identity (first time only)
node cli.mjs register "DisplayName"

# Show your identity
node cli.mjs identity

# Look up another user
node cli.mjs lookup QmTheirAddress...

# Send an encrypted message
node send.mjs "Your message here" QmRecipientAddress...

# Listen for incoming messages (default 2 min timeout)
node listen.mjs [timeout_seconds]
```

## How It Works

**Sending:**
1. Fetch recipient's public keys from Quorum API
2. Generate ephemeral X448 key
3. X3DH key exchange → shared secret
4. Double Ratchet encrypt your message
5. Seal envelope with recipient's inbox key
6. Send to recipient's device inbox

**Receiving:**
1. Connect to WebSocket: `wss://api.quorummessenger.com/ws`
2. Subscribe to your inbox address
3. Receive sealed messages as they arrive
4. Decrypt with your inbox key → X3DH → Double Ratchet
5. Plaintext message!

**True E2EE:**
```
Sender: plaintext → [encrypt locally] → ciphertext
                           ↓
              API relay only sees ciphertext
                           ↓
Receiver: ciphertext → [decrypt locally] → plaintext
```

No server ever sees your plaintext. Even if the relay is compromised, messages remain encrypted with keys it never had.

## Data Storage

All data stored in `~/.quorum-client/`:

```
device-keyset.json    — Your X448 keys (KEEP SECRET!)
registration.json     — Your public registration
profile.json          — Display name, metadata
user-keys.json        — Ed448 identity keys (KEEP SECRET!)
sessions/             — Double Ratchet session states
```

⚠️ **Backup your `~/.quorum-client/` directory** — losing it means losing your identity.

## Architecture

```
cli.mjs          — CLI interface
send.mjs         — Quick send script
listen.mjs       — WebSocket listener
src/
  client.mjs     — Main client class
  crypto.mjs     — WASM crypto wrapper
  api.mjs        — Quorum REST API
  store.mjs      — Persistence layer
  wasm/          — Quilibrium channel WASM
```

## Crypto Credits

WASM cryptography from [quilibrium-js-sdk-channels](https://github.com/QuilibriumNetwork/quilibrium-js-sdk-channels) by Quilibrium Inc (MIT).

## License

MIT
