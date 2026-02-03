# Quorum Headless Client

E2E encrypted messaging client for Quilibrium's Quorum protocol.

## Setup

```bash
npm install
```

## Commands

### Direct Messages (DMs)

```bash
# Send a message
node dm.mjs send <address> <text> [-r reply-to-id]

# Send an image
node dm.mjs embed <address> /path/to/image.png [-r reply-to-id]

# Edit a message
node dm.mjs edit <address> <msg-id> <new-text>

# React to a message
node dm.mjs react <address> <msg-id> <emoji>

# Remove a reaction
node dm.mjs unreact <address> <msg-id> <emoji>

# Delete a message
node dm.mjs delete <address> <msg-id>

# Listen for incoming DMs
node dm.mjs listen

# List conversations
node dm.mjs conversations
```

### Spaces (Group Chats)

```bash
# Send to a space channel
node space.mjs send <space-id> <text> [-r reply-to-id]

# React in a space
node space.mjs react <space-id> <msg-id> <emoji>

# Listen to a space
node space.mjs listen <space-id>

# List joined spaces
node space.mjs list
```

### Testing with Second Identity

Use `dm2.mjs` to run commands with a separate identity (stored in `~/.quorum-client-2`):

```bash
node dm2.mjs send <address> "Hello from identity 2"
```

## Data Storage

- Keys stored in macOS Keychain (with file fallback)
- Sessions: `~/.quorum-client/sessions/`
- Spaces: `~/.quorum-client/spaces/`

## Protocol

Uses Quilibrium's Double Ratchet E2E encryption for DMs and Triple Ratchet for Spaces.
