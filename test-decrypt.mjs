import { join } from 'path';
import { homedir } from 'os';
import { initCrypto, doubleRatchetDecrypt } from './src/crypto.mjs';
import { createSecureStore } from './src/secure-store.mjs';

const DATA_DIR = join(homedir(), '.quorum-client');
await initCrypto();

const store = await createSecureStore(DATA_DIR);

// Get Jack's session
const sessions = store.listSessions();
console.log('Sessions:', sessions);

for (const addr of sessions) {
  const session = store.getSession(addr);
  console.log('\nSession for:', addr.substring(0, 20));
  console.log('Has ratchet:', !!session.ratchet_state);
  
  // Try to decrypt a Type 2 message using this session
  const type2Envelope = {
    "protocol_identifier": 512,
    "message_header": {
      "ciphertext": "9FeXLmQsNl3jl8mU2cwHINZzfkh/DD9NYXEarNplKMo6ASJER0JXnQJYZ9MCGbI3GLTAbejz9eh5SZJNVTusyMWKUNQrm6/ml4iERE2Wev48",
      "initialization_vector": "9SAfoo+n5E45uP7F",
      "associated_data": "PeOd2FjsD05vFv3jd6rs8ppzTejmiF22oNGbM1F0BBU="
    },
    "message_body": {
      "ciphertext": "mCEZtkuclXaWxTvIZtJD2MomjUbmi195Hu7Epdl9incM93asqeaqfEtawhEB+Oag0HR8w5/CgPXssNAZIEECOYC1U0jjx2tIT+bBAa1pA05fK8lpKm59rs9DSQArH9Nn+QXGaD4Kw1zUHkwZXYI6sIOUeXFVK5LVzybHt/P4/h/eFVVyMxtgSs9AFgveatgHrvBUXpai1wKJpYqqzvsoxJ1qtZxS+H+zkWqaE2WXDRhC8MnQD5Tdi91jI0tAdKdB1YpP2WPW7IwE9gKGLt3Q1l5OBSx0Fe0OGTZRiPAJ4A7+/uqsZ9z9kwP8zrI3YNCHmNK0X+mNm6LDoqQowB6Pl9AuFV77PsTFilJwgyvAmgbYBgTjy+hqj+4t2LDaxgq0kRXItzWDfltuqiXLD1qsWLWkohTyFWkB5xRcXBgVALB5wqA8UKrPAGBgqM5FO1Mu3OgjcptMNB/EFVHxJ0J7rsGUNot0hgw4SqkROJxPshbLzWQvEKaDI+3GE4Jvf0njy8kBX8sRyG5f5IQr+XvvXwLCojxyMpnYC5aMQ9bqxWl9DXmtp+5vECl9W6wbf1ccyEWF3IqMENSZhP/KdBS2CznCKyVLGh40RSK8wILjBxrkzNZBxMY2ezPpeQiv1wim1B5dsCl0sMP1UPmAFLdvBU4zk4FIqaoI6LC6H5oOMNXLI7MObxLvSk1GGeS6iXneX4k8KQxLh44aS9lGoeHd2OekWuehAkHuU/jhjB5Xq9QVmfGPq8LquJYWIhQ0HPgqGBT9RvzJGTzcceE=",
      "initialization_vector": "7p5gEGS0g4o5RfDF",
      "associated_data": "DOWdCnpssTZwaxZZ22yp13YUMwCseuc/1EKTjf6Yn5T0V5cuZCw2XeOXyZTZzAcg1nN+SH8MP01hcRqs2mUoyjoBIkRHQledAlhn0wIZsjcYtMBt6PP16HlJkk1VO6zIxYpQ1Cubr+aXiIRETZZ6/jw="
    }
  };
  
  try {
    const result = doubleRatchetDecrypt(session.ratchet_state, JSON.stringify(type2Envelope));
    console.log('Decrypted!', result);
  } catch (e) {
    console.log('Decrypt failed:', e.message);
  }
}
