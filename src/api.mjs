/**
 * Quorum API Client
 * 
 * HTTP client for the Quorum messenger REST API.
 * Handles user registration, conversations, messaging, and inbox operations.
 */

const DEFAULT_BASE_URL = 'https://api.quorummessenger.com';
const DEFAULT_TIMEOUT = 30000;

export class QuorumAPI {
  constructor(baseUrl = DEFAULT_BASE_URL) {
    this.baseUrl = baseUrl;
  }

  async request(endpoint, options = {}) {
    const { method = 'GET', body, timeout = DEFAULT_TIMEOUT } = options;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      const res = await fetch(`${this.baseUrl}${endpoint}`, {
        method,
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (!res.ok) {
        const text = await res.text();
        const err = new Error(`HTTP ${res.status}: ${text}`);
        err.status = res.status;
        throw err;
      }

      const ct = res.headers.get('content-type');
      if (ct?.includes('application/json')) return res.json();
      return res.text();
    } catch (e) {
      clearTimeout(timer);
      if (e.name === 'AbortError') throw new Error('Request timeout');
      throw e;
    }
  }

  // ============ User Registration ============

  async registerUser(registration) {
    return this.request(`/users/${registration.user_address}`, {
      method: 'POST',
      body: registration,
    });
  }

  async getUser(address) {
    return this.request(`/users/${address}`);
  }

  // ============ Inbox (E2EE Layer) ============

  async sendSealedMessage(sealedMessage) {
    return this.request('/inbox', {
      method: 'POST',
      body: sealedMessage,
    });
  }

  /**
   * Delete messages from inbox after decryption.
   * Requires Ed448 signature to prove inbox ownership.
   */
  async deleteInboxMessages(inboxAddress, timestamps, inboxPublicKeyHex, signatureHex) {
    return this.request('/inbox/delete', {
      method: 'POST',
      body: {
        inbox_address: inboxAddress,
        timestamps,
        inbox_public_key: inboxPublicKeyHex,
        inbox_signature: signatureHex,
      },
    });
  }

  // ============ Hub (Group Messaging) ============

  async hubAdd(params) {
    return this.request('/hub/add', { method: 'POST', body: params });
  }

  async hubDelete(params) {
    return this.request('/hub/delete', { method: 'POST', body: params });
  }

  async hubSend(message) {
    return this.request('/hub', { method: 'POST', body: message });
  }

  // ============ Spaces ============

  async getSpaces(userAddress) {
    const res = await this.request(`/users/${userAddress}/spaces`);
    return res.spaces || [];
  }

  async getSpace(spaceId) {
    return this.request(`/spaces/${spaceId}`);
  }

  // ============ User Config ============

  async getUserConfig(address) {
    try {
      return await this.request(`/users/${address}/config`);
    } catch (e) {
      if (e.status === 404) return null;
      throw e;
    }
  }

  async postUserConfig(address, payload) {
    return this.request(`/users/${address}/config`, {
      method: 'POST',
      body: payload,
    });
  }
}
