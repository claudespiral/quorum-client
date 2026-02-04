/**
 * Unit tests for src/api.mjs
 * 
 * Tests HTTP client for Quorum API:
 * - Request construction
 * - Error handling
 * - Timeout handling
 * - Response parsing
 * 
 * Note: These tests mock fetch to avoid network calls.
 */

import { describe, it, beforeEach, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, '..', '..');

const { QuorumAPI } = await import(join(PROJECT_ROOT, 'src/api.mjs'));

// ============ Mock Fetch ============

let originalFetch;
let mockFetchFn;

function mockFetch(responseFn) {
  mockFetchFn = responseFn;
  global.fetch = async (url, options) => mockFetchFn(url, options);
}

function restoreFetch() {
  global.fetch = originalFetch;
}

function createMockResponse(body, status = 200, contentType = 'application/json') {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get: (name) => name.toLowerCase() === 'content-type' ? contentType : null,
    },
    json: async () => body,
    text: async () => typeof body === 'string' ? body : JSON.stringify(body),
  };
}

// ============ Tests ============

describe('QuorumAPI', () => {
  beforeEach(() => {
    originalFetch = global.fetch;
  });

  afterEach(() => {
    restoreFetch();
  });

  describe('constructor', () => {
    it('should use default base URL', () => {
      const api = new QuorumAPI();
      assert.equal(api.baseUrl, 'https://api.quorummessenger.com');
    });

    it('should accept custom base URL', () => {
      const api = new QuorumAPI('https://custom.api.com');
      assert.equal(api.baseUrl, 'https://custom.api.com');
    });
  });

  describe('request', () => {
    it('should make GET request by default', async () => {
      const api = new QuorumAPI();
      let capturedOptions;
      
      mockFetch((url, options) => {
        capturedOptions = options;
        return createMockResponse({ success: true });
      });
      
      await api.request('/test');
      
      assert.equal(capturedOptions.method, 'GET');
    });

    it('should set Content-Type header', async () => {
      const api = new QuorumAPI();
      let capturedOptions;
      
      mockFetch((url, options) => {
        capturedOptions = options;
        return createMockResponse({ success: true });
      });
      
      await api.request('/test');
      
      assert.equal(capturedOptions.headers['Content-Type'], 'application/json; charset=utf-8');
    });

    it('should construct correct URL', async () => {
      const api = new QuorumAPI('https://test.api.com');
      let capturedUrl;
      
      mockFetch((url, options) => {
        capturedUrl = url;
        return createMockResponse({ success: true });
      });
      
      await api.request('/users/123');
      
      assert.equal(capturedUrl, 'https://test.api.com/users/123');
    });

    it('should make POST request with body', async () => {
      const api = new QuorumAPI();
      let capturedOptions;
      
      mockFetch((url, options) => {
        capturedOptions = options;
        return createMockResponse({ success: true });
      });
      
      const body = { name: 'test', value: 42 };
      await api.request('/test', { method: 'POST', body });
      
      assert.equal(capturedOptions.method, 'POST');
      assert.equal(capturedOptions.body, JSON.stringify(body));
    });

    it('should parse JSON response', async () => {
      const api = new QuorumAPI();
      const responseData = { id: 1, name: 'test' };
      
      mockFetch(() => createMockResponse(responseData));
      
      const result = await api.request('/test');
      
      assert.deepEqual(result, responseData);
    });

    it('should return text for non-JSON response', async () => {
      const api = new QuorumAPI();
      
      mockFetch(() => createMockResponse('plain text', 200, 'text/plain'));
      
      const result = await api.request('/test');
      
      assert.equal(result, 'plain text');
    });

    it('should throw on HTTP error', async () => {
      const api = new QuorumAPI();
      
      mockFetch(() => createMockResponse('Not Found', 404, 'text/plain'));
      
      await assert.rejects(
        () => api.request('/test'),
        (err) => {
          assert.ok(err.message.includes('404'));
          assert.equal(err.status, 404);
          return true;
        }
      );
    });

    it('should throw on 500 error', async () => {
      const api = new QuorumAPI();
      
      mockFetch(() => createMockResponse('Internal Server Error', 500, 'text/plain'));
      
      await assert.rejects(
        () => api.request('/test'),
        (err) => {
          assert.ok(err.message.includes('500'));
          return true;
        }
      );
    });

    it('should handle timeout', async () => {
      const api = new QuorumAPI();
      
      mockFetch(async (url, options) => {
        // Check if abort signal is used
        return new Promise((resolve, reject) => {
          const timer = setTimeout(() => {
            resolve(createMockResponse({ success: true }));
          }, 100);
          
          // Listen to abort signal if present
          if (options?.signal) {
            options.signal.addEventListener('abort', () => {
              clearTimeout(timer);
              const err = new Error('Request timeout');
              err.name = 'AbortError';
              reject(err);
            });
          }
        });
      });
      
      await assert.rejects(
        () => api.request('/test', { timeout: 10 }), // 10ms timeout
        (err) => {
          assert.ok(err.message.includes('timeout') || err.message.includes('abort') || err.name === 'AbortError', err.message);
          return true;
        }
      );
    });
  });

  describe('registerUser', () => {
    it('should POST to /users/:address', async () => {
      const api = new QuorumAPI();
      let capturedUrl;
      let capturedBody;
      
      mockFetch((url, options) => {
        capturedUrl = url;
        capturedBody = JSON.parse(options.body);
        return createMockResponse({ status: 'ok' });
      });
      
      const registration = {
        user_address: 'QmTestUser123',
        user_public_key: 'abcdef',
        peer_public_key: 'fedcba',
        device_registrations: [],
        signature: 'sig123',
      };
      
      await api.registerUser(registration);
      
      assert.ok(capturedUrl.endsWith('/users/QmTestUser123'));
      assert.deepEqual(capturedBody, registration);
    });
  });

  describe('getUser', () => {
    it('should GET from /users/:address', async () => {
      const api = new QuorumAPI();
      let capturedUrl;
      let capturedMethod;
      
      mockFetch((url, options) => {
        capturedUrl = url;
        capturedMethod = options.method;
        return createMockResponse({
          user_address: 'QmTestUser',
          device_registrations: [],
        });
      });
      
      await api.getUser('QmTestUser');
      
      assert.ok(capturedUrl.endsWith('/users/QmTestUser'));
      assert.equal(capturedMethod, 'GET');
    });

    it('should return user data', async () => {
      const api = new QuorumAPI();
      const userData = {
        user_address: 'QmTestUser',
        display_name: 'Test User',
        device_registrations: [{
          identity_public_key: 'abc',
          pre_public_key: 'def',
          inbox_registration: {
            inbox_address: 'QmInbox',
            inbox_encryption_public_key: 'xyz',
          },
        }],
      };
      
      mockFetch(() => createMockResponse(userData));
      
      const result = await api.getUser('QmTestUser');
      
      assert.deepEqual(result, userData);
    });
  });

  describe('sendSealedMessage', () => {
    it('should POST to /inbox', async () => {
      const api = new QuorumAPI();
      let capturedUrl;
      let capturedBody;
      
      mockFetch((url, options) => {
        capturedUrl = url;
        capturedBody = JSON.parse(options.body);
        return createMockResponse({ status: 'ok' });
      });
      
      const sealedMessage = {
        inbox_address: 'QmInbox',
        ephemeral_public_key: 'ephkey',
        envelope: '{"ciphertext": "..."}',
      };
      
      await api.sendSealedMessage(sealedMessage);
      
      assert.ok(capturedUrl.endsWith('/inbox'));
      assert.deepEqual(capturedBody, sealedMessage);
    });
  });

  describe('deleteInboxMessages', () => {
    it('should POST to /inbox/delete with signature', async () => {
      const api = new QuorumAPI();
      let capturedBody;
      
      mockFetch((url, options) => {
        capturedBody = JSON.parse(options.body);
        return createMockResponse({ status: 'ok' });
      });
      
      await api.deleteInboxMessages('QmInbox', [123, 456], 'pubkey', 'signature');
      
      assert.equal(capturedBody.inbox_address, 'QmInbox');
      assert.deepEqual(capturedBody.timestamps, [123, 456]);
      assert.equal(capturedBody.inbox_public_key, 'pubkey');
      assert.equal(capturedBody.inbox_signature, 'signature');
    });
  });

  describe('hub operations', () => {
    it('hubAdd should POST to /hub/add', async () => {
      const api = new QuorumAPI();
      let capturedUrl;
      
      mockFetch((url) => {
        capturedUrl = url;
        return createMockResponse({ status: 'ok' });
      });
      
      await api.hubAdd({ hub_address: 'hub', inbox_public_key: 'inbox' });
      
      assert.ok(capturedUrl.endsWith('/hub/add'));
    });

    it('hubDelete should POST to /hub/delete', async () => {
      const api = new QuorumAPI();
      let capturedUrl;
      
      mockFetch((url) => {
        capturedUrl = url;
        return createMockResponse({ status: 'ok' });
      });
      
      await api.hubDelete({ hub_address: 'hub', inbox_public_key: 'inbox' });
      
      assert.ok(capturedUrl.endsWith('/hub/delete'));
    });

    it('hubSend should POST to /hub', async () => {
      const api = new QuorumAPI();
      let capturedUrl;
      
      mockFetch((url) => {
        capturedUrl = url;
        return createMockResponse({ status: 'ok' });
      });
      
      await api.hubSend({ hub_address: 'hub', envelope: 'encrypted' });
      
      assert.ok(capturedUrl.endsWith('/hub'));
    });
  });

  describe('getSpaces', () => {
    it('should GET from /users/:address/spaces', async () => {
      const api = new QuorumAPI();
      let capturedUrl;
      
      mockFetch((url) => {
        capturedUrl = url;
        return createMockResponse({ spaces: [] });
      });
      
      await api.getSpaces('QmUser');
      
      assert.ok(capturedUrl.endsWith('/users/QmUser/spaces'));
    });

    it('should return spaces array', async () => {
      const api = new QuorumAPI();
      
      mockFetch(() => createMockResponse({ 
        spaces: [{ id: 'space1' }, { id: 'space2' }] 
      }));
      
      const result = await api.getSpaces('QmUser');
      
      assert.equal(result.length, 2);
    });

    it('should return empty array if no spaces', async () => {
      const api = new QuorumAPI();
      
      mockFetch(() => createMockResponse({}));
      
      const result = await api.getSpaces('QmUser');
      
      assert.deepEqual(result, []);
    });
  });

  describe('getSpace', () => {
    it('should GET from /spaces/:id', async () => {
      const api = new QuorumAPI();
      let capturedUrl;
      
      mockFetch((url) => {
        capturedUrl = url;
        return createMockResponse({ space_address: 'QmSpace' });
      });
      
      await api.getSpace('QmSpace123');
      
      assert.ok(capturedUrl.endsWith('/spaces/QmSpace123'));
    });
  });

  describe('getUserConfig', () => {
    it('should GET from /users/:address/config', async () => {
      const api = new QuorumAPI();
      let capturedUrl;
      
      mockFetch((url) => {
        capturedUrl = url;
        return createMockResponse({ config: 'data' });
      });
      
      await api.getUserConfig('QmUser');
      
      assert.ok(capturedUrl.endsWith('/users/QmUser/config'));
    });

    it('should return null on 404', async () => {
      const api = new QuorumAPI();
      
      mockFetch(() => createMockResponse('Not Found', 404, 'text/plain'));
      
      const result = await api.getUserConfig('QmUser');
      
      assert.equal(result, null);
    });

    it('should throw on other errors', async () => {
      const api = new QuorumAPI();
      
      mockFetch(() => createMockResponse('Error', 500, 'text/plain'));
      
      await assert.rejects(() => api.getUserConfig('QmUser'));
    });
  });

  describe('postUserConfig', () => {
    it('should POST to /users/:address/config', async () => {
      const api = new QuorumAPI();
      let capturedUrl;
      let capturedBody;
      
      mockFetch((url, options) => {
        capturedUrl = url;
        capturedBody = JSON.parse(options.body);
        return createMockResponse({ status: 'ok' });
      });
      
      const payload = { setting: 'value' };
      await api.postUserConfig('QmUser', payload);
      
      assert.ok(capturedUrl.endsWith('/users/QmUser/config'));
      assert.deepEqual(capturedBody, payload);
    });
  });
});

// ============ Network Error Handling ============

describe('QuorumAPI - Network Errors', () => {
  beforeEach(() => {
    originalFetch = global.fetch;
  });

  afterEach(() => {
    restoreFetch();
  });

  it('should handle network failure', async () => {
    const api = new QuorumAPI();
    
    global.fetch = async () => {
      throw new Error('Network error');
    };
    
    await assert.rejects(
      () => api.request('/test'),
      (err) => {
        assert.ok(err.message.includes('Network error'));
        return true;
      }
    );
  });

  it('should handle DNS failure', async () => {
    const api = new QuorumAPI();
    
    global.fetch = async () => {
      const err = new Error('getaddrinfo ENOTFOUND');
      err.code = 'ENOTFOUND';
      throw err;
    };
    
    await assert.rejects(
      () => api.request('/test'),
      (err) => {
        assert.ok(err.message.includes('ENOTFOUND'));
        return true;
      }
    );
  });
});
