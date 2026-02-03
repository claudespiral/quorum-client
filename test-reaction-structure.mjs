import { createSecureStore } from './src/secure-store.mjs';
import { getRegistration, getDeviceKeyset, initCrypto } from './src/crypto.mjs';
import { randomUUID } from 'crypto';

await initCrypto();
const store = await createSecureStore();
const deviceKeyset = await store.getDeviceKeyset();
const registration = await getRegistration(deviceKeyset);

// Simulate what we send for a reaction
const messageId = randomUUID();
const now = Date.now();
const targetMessageId = 'b1efa22c-2a2c-4725-ad64-9903d8e70928';

const content = {
  type: 'reaction',
  senderId: registration.user_address,
  messageId: targetMessageId,
  reaction: '👍',
};

const messagePayload = {
  messageId: `${messageId}-${now}`,
  channelId: 'QmRgPaapcYgaKrQWVENTfn14hBfkbqAD4htwJpVH5VzKYz',
  spaceId: 'QmRgPaapcYgaKrQWVENTfn14hBfkbqAD4htwJpVH5VzKYz',
  digestAlgorithm: "SHA-256",
  nonce: messageId,
  createdDate: now,
  modifiedDate: now,
  lastModifiedHash: "",
  content: content,
  reactions: [],
  mentions: { memberIds: [], roleIds: [], channelIds: [] },
};

console.log('\n=== Full Message Payload ===');
console.log(JSON.stringify(messagePayload, null, 2));

console.log('\n=== Content Structure ===');
console.log(JSON.stringify(content, null, 2));
