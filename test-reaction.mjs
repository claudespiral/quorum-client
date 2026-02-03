import { join } from 'path';
import { homedir } from 'os';
import { randomUUID } from 'crypto';
import { initCrypto } from './src/crypto.mjs';
import { createSecureStore } from './src/secure-store.mjs';

const DATA_DIR = join(homedir(), '.quorum-client');
await initCrypto();
const store = await createSecureStore(DATA_DIR);
const deviceKeyset = await store.getDeviceKeyset();
const registration = store.getRegistration();

const recipientAddress = "QmRgPaapcYgaKrQWVENTfn14hBfkbqAD4htwJpVH5VzKYz";
const targetMessageId = "bbcacee22f8086b8521ab9ae774bdfce7043419d32415e502cbe15827a126869";
const emoji = "🎉";

// Build content like cmdReact does
const content = {
  type: 'reaction',
  reaction: emoji,
  messageId: targetMessageId,
};

// Build full message like sendFollowUpMessage does
const messageId = randomUUID();
const now = Date.now();
const messagePayload = {
  messageId: `${messageId}-${now}`,
  channelId: recipientAddress,
  spaceId: recipientAddress,
  digestAlgorithm: "SHA-256",
  nonce: messageId,
  createdDate: now,
  modifiedDate: now,
  lastModifiedHash: "",
  content: { ...content, senderId: registration.user_address },
  reactions: [],
  mentions: { memberIds: [], roleIds: [], channelIds: [] },
};

console.log("MY REACTION MESSAGE:");
console.log(JSON.stringify(messagePayload, null, 2));

console.log("\nJACK'S REACTION (for comparison):");
const jackReaction = {
  "messageId": "71c4cca3-62f4-4d95-b641-b2ce7f8dc707-1770147064737",
  "channelId": "QmafL6zcuBtKgvSR3pHtKoCiqkK263G1jCmrgQrNpeAv89",
  "spaceId": "QmafL6zcuBtKgvSR3pHtKoCiqkK263G1jCmrgQrNpeAv89",
  "digestAlgorithm": "SHA-256",
  "nonce": "71c4cca3-62f4-4d95-b641-b2ce7f8dc707",
  "createdDate": 1770147064737,
  "modifiedDate": 1770147064737,
  "lastModifiedHash": "",
  "content": {
    "type": "reaction",
    "senderId": "QmRgPaapcYgaKrQWVENTfn14hBfkbqAD4htwJpVH5VzKYz",
    "messageId": "6952766f-0c72-4cc4-83a9-e37ae2ea91fe",
    "reaction": "👍"
  },
  "reactions": [],
  "mentions": {"memberIds":[],"roleIds":[],"channelIds":[]}
};
console.log(JSON.stringify(jackReaction, null, 2));
