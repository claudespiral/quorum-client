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

  /** Register user encryption keys */
  async registerUser(registration) {
    return this.request(`/users/${registration.user_address}`, {
      method: 'POST',
      body: registration,
    });
  }

  /** Fetch a user's registration (keys for X3DH) */
  async getUser(address) {
    return this.request(`/users/${address}`);
  }

  // ============ Conversations ============

  /** List conversations for a user */
  async getConversations(userAddress) {
    const res = await this.request(`/users/${userAddress}/conversations`);
    return res.conversations || [];
  }

  /** Create a new conversation */
  async createConversation(address) {
    return this.request('/conversations', {
      method: 'POST',
      body: { address },
    });
  }

  // ============ Direct Messages ============

  /** Send a direct message (plaintext — encryption happens in client layer) */
  async sendDirectMessage(conversationId, text, repliesToMessageId) {
    return this.request(`/conversations/${conversationId}/messages`, {
      method: 'POST',
      body: { text, repliesToMessageId },
    });
  }

  /** Fetch direct messages */
  async getDirectMessages(conversationId, options = {}) {
    const params = new URLSearchParams();
    if (options.cursor) params.set('cursor', options.cursor);
    if (options.limit) params.set('limit', String(options.limit));
    const qs = params.toString();
    return this.request(`/conversations/${conversationId}/messages${qs ? `?${qs}` : ''}`);
  }

  // ============ Inbox (E2EE Layer) ============

  /** Send a sealed (encrypted) message to an inbox */
  async sendSealedMessage(sealedMessage) {
    return this.request('/inbox', {
      method: 'POST',
      body: sealedMessage,
    });
  }

  /** Delete messages from inbox after decryption */
  async deleteInboxMessages(params) {
    return this.request('/inbox/delete', {
      method: 'POST',
      body: params,
    });
  }

  // ============ Hub (Group Messaging) ============

  /** Add inbox to a hub */
  async hubAdd(params) {
    return this.request('/hub/add', { method: 'POST', body: params });
  }

  /** Remove inbox from a hub */
  async hubDelete(params) {
    return this.request('/hub/delete', { method: 'POST', body: params });
  }

  /** Send sealed message to hub */
  async hubSend(message) {
    return this.request('/hub', { method: 'POST', body: message });
  }

  // ============ Spaces ============

  /** Fetch user's spaces */
  async getSpaces(userAddress) {
    const res = await this.request(`/users/${userAddress}/spaces`);
    return res.spaces || [];
  }

  /** Fetch space info */
  async getSpace(spaceId) {
    return this.request(`/spaces/${spaceId}`);
  }

  // ============ User Config ============

  /** Fetch encrypted user config */
  async getUserConfig(address) {
    try {
      return await this.request(`/users/${address}/config`);
    } catch (e) {
      if (e.status === 404) return null;
      throw e;
    }
  }

  /** Upload encrypted user config */
  async postUserConfig(address, payload) {
    return this.request(`/users/${address}/config`, {
      method: 'POST',
      body: payload,
    });
  }
}
