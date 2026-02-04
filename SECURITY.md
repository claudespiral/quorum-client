# Security Considerations

## Overview

This document outlines security considerations for the Quorum headless client.

## Cryptographic Implementation

### ✅ Strengths

1. **E2EE Protocol**: Uses X3DH key exchange + Double Ratchet (same as Signal), implemented in Quilibrium's audited WASM module.

2. **Strong Curves**: Ed448/X448 (224-bit security level) vs typical Ed25519/X25519 (128-bit).

3. **Forward Secrecy**: Double Ratchet provides forward secrecy - compromising current keys doesn't expose past messages.

4. **Post-Compromise Security**: Ratchet rotation means future messages become secure again after a key compromise.

### ⚠️ Considerations

1. **WASM Trust**: Crypto operations are in a precompiled WASM blob (`channelwasm_bg.wasm`). We trust Quilibrium's build. Source: https://github.com/QuilibriumNetwork/quilibrium

2. **No Constant-Time Guarantees**: JavaScript/WASM timing varies. Sensitive to timing side-channels in theory, though practical exploitation is difficult over network.

## Key Storage

### ✅ Strengths

1. **OS Keychain Integration**: Uses `keytar` for platform-native secure storage (macOS Keychain, Linux libsecret, Windows Credential Vault).

2. **File Permissions**: Fallback file storage uses `0o700` directories and `0o600` files (owner-only).

3. **Atomic Writes**: Key files are written atomically (write temp → fsync → rename) to prevent corruption.

### ⚠️ Considerations

1. **Migration Period**: During keychain migration, keys exist in both plaintext files and keychain. User must manually delete plaintext files after confirming keychain access.

2. **Memory Persistence**: JavaScript doesn't provide secure memory wiping. Private keys may persist in V8 heap until GC.

3. **Swap/Hibernate**: Keys in memory could be written to swap or hibernation files. Consider disabling swap on sensitive systems.

## Protocol Design Notes

### Conversation Inbox Key Sharing

The `return_inbox_private_key` is intentionally shared with conversation partners. This is a Quilibrium design decision:

- Each conversation creates a NEW inbox (not your personal device inbox)
- Both parties receive the inbox signing key
- This allows either party to delete messages from the shared conversation inbox
- Your identity keys and device inbox keys are NEVER shared

**Implication**: If the initialization envelope were somehow decrypted by an attacker, they could potentially delete messages from that conversation inbox (but not read encrypted messages or impersonate users).

## Network Security

### ✅ Strengths

1. **TLS Only**: API base URL is `https://api.quorummessenger.com` (HTTPS enforced).

2. **E2EE Payloads**: Message content is encrypted before leaving the client. API only sees sealed envelopes.

3. **No Server Trust**: Server cannot read message content. Only provides routing and storage.

### ⚠️ Considerations

1. **Metadata**: Server sees inbox addresses, timing, and message sizes. Metadata analysis is possible.

2. **Certificate Pinning**: No certificate pinning implemented. Relies on system CA trust.

## Error Handling

### ✅ Strengths

1. **Categorized Errors**: Crypto errors are categorized (DECRYPTION_FAILED, SIGNATURE_INVALID, etc.) without leaking sensitive details.

2. **Debug Mode Only**: Detailed errors require `DEBUG=1` environment variable.

### ⚠️ Considerations

1. **Timing Differences**: Decrypt failures may have different timing than successes. Not constant-time.

## Input Validation

### ⚠️ Considerations

1. **JSON Parsing**: Multiple `JSON.parse()` calls on network data. Malformed JSON throws but is caught.

2. **Address Validation**: Minimal validation of Qm... addresses before use.

3. **Message Size**: No explicit size limits on messages/images. Large payloads accepted.

## Recommendations

### For Users

1. After confirming keychain works, delete plaintext key files:
   ```bash
   rm ~/.quorum-client/keys/user-keyset.json
   rm ~/.quorum-client/keys/device-keyset.json
   ```

2. Use full-disk encryption on your system.

3. Avoid running on shared/multi-user systems.

### For Development

1. **Consider adding**:
   - Message size limits
   - Rate limiting for send operations
   - Certificate pinning for API requests
   - Address format validation

2. **Memory handling**: Investigate `sodium-native` or similar for secure memory allocation if handling extremely sensitive data.

3. **Audit trail**: Consider optional logging of security events (key rotations, session resets) without logging sensitive data.

## Threat Model

This client is designed for:
- ✅ Protection against passive network eavesdropping
- ✅ Protection against compromised server
- ✅ Forward secrecy for message content
- ⚠️ Limited protection against compromised endpoint (if attacker has device access)
- ⚠️ Limited metadata protection (timing, sizes visible to server)
- ❌ No protection against state-level adversaries with endpoint access

## Version

Security review date: 2026-02-03
Client version: 0.1.0
