# quorum-client

Headless E2EE client for [Quorum](https://quilibrium.com) messenger — the Quilibrium-powered encrypted messaging platform.

Cryptography runs via bundled WASM (Decaf448 curves, Double Ratchet, X3DH).

## Dependencies

- Node.js 20+
- `ws` — WebSocket client
- `keytar` — OS keychain access (macOS Keychain, Linux libsecret, Windows Credential Vault)

On Linux, you may need to install libsecret: `sudo apt install libsecret-1-dev`

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

### Direct Messages

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

### Spaces (Group Chat)

```bash
# Join a space from invite link
node space.mjs join "https://app.quorummessenger.com/#spaceId=..."

# List joined spaces
node space.mjs list

# Send to a space
node space.mjs send QmSpaceId... "Hello everyone!"

# Listen for space messages
node space.mjs listen QmSpaceId...

# List channels in a space
node space.mjs channels QmSpaceId...
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

**Sensitive keys** are stored in your OS keychain (encrypted at rest):
- Identity keys (Ed448 user keys, X448 device keys)
- Space keys (hub keys, config keys, inbox keys)

**Session state** stored in `~/.quorum-client/` (0600 permissions):
```
keys/registration.json  — Public registration info
sessions/               — Double Ratchet session states
profile.json            — Display name, metadata
```

⚠️ **Your keychain contains your identity** — if you need to migrate machines, export keys first.

Falls back to plaintext files if keychain is unavailable (with a warning).

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
