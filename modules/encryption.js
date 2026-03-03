/**
 * Devise Encryption Module
 * AES-256-GCM encryption for all event data
 * Provides end-to-end encryption with key rotation
 */

export class EncryptionManager {
  constructor() {
    this.algorithm = 'AES-GCM';
    this.keyLength = 256;
    this.ivLength = 12;
    this.saltLength = 16;
    this.currentKeyId = null;
    this.keyCache = new Map();
    this.keyRotationInterval = 24 * 60 * 60 * 1000; // 24 hours
  }

  /**
   * Initialize encryption with organization key or generate new
   */
  async initialize(orgKey = null) {
    try {
      // Check for existing keys
      const stored = await chrome.storage.local.get(['encryptionKeys', 'currentKeyId']);
      
      if (stored.encryptionKeys && Object.keys(stored.encryptionKeys).length > 0) {
        this.currentKeyId = stored.currentKeyId || Object.keys(stored.encryptionKeys)[0];
        
        // Load keys into cache
        for (const [keyId, keyData] of Object.entries(stored.encryptionKeys)) {
          const key = await this.importKey(keyData.rawKey);
          this.keyCache.set(keyId, {
            key,
            createdAt: keyData.createdAt,
            version: keyData.version
          });
        }
        
        // Check if rotation needed
        await this.checkKeyRotation();
      } else {
        // Generate initial key
        await this.generateNewKey(orgKey);
      }
      
      console.log('[Encryption] Initialized with key:', this.currentKeyId);
      return true;
    } catch (error) {
      console.error('[Encryption] Initialization failed:', error);
      return false;
    }
  }

  /**
   * Generate new encryption key
   */
  async generateNewKey(seedKey = null) {
    try {
      let rawKey;
      
      if (seedKey) {
        // Derive from seed key
        const encoder = new TextEncoder();
        const seedData = encoder.encode(seedKey);
        const hashBuffer = await crypto.subtle.digest('SHA-256', seedData);
        rawKey = new Uint8Array(hashBuffer);
      } else {
        // Generate random key
        rawKey = crypto.getRandomValues(new Uint8Array(32));
      }
      
      const key = await this.importKey(rawKey);
      const keyId = this.generateKeyId();
      const now = Date.now();
      
      // Store key info
      const keyData = {
        rawKey: Array.from(rawKey),
        createdAt: now,
        version: 1
      };
      
      // Get existing keys
      const stored = await chrome.storage.local.get('encryptionKeys');
      const keys = stored.encryptionKeys || {};
      keys[keyId] = keyData;
      
      // Save to storage
      await chrome.storage.local.set({
        encryptionKeys: keys,
        currentKeyId: keyId
      });
      
      // Cache the key
      this.keyCache.set(keyId, {
        key,
        createdAt: now,
        version: 1
      });
      
      this.currentKeyId = keyId;
      
      console.log('[Encryption] Generated new key:', keyId);
      return keyId;
    } catch (error) {
      console.error('[Encryption] Key generation failed:', error);
      throw error;
    }
  }

  /**
   * Import raw key to CryptoKey
   */
  async importKey(rawKey) {
    const keyBuffer = rawKey instanceof Uint8Array ? rawKey : new Uint8Array(rawKey);
    
    return await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: this.algorithm },
      true,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Generate unique key ID
   */
  generateKeyId() {
    const timestamp = Date.now().toString(36);
    const random = crypto.getRandomValues(new Uint8Array(4));
    const randomHex = Array.from(random).map(b => b.toString(16).padStart(2, '0')).join('');
    return `key_${timestamp}_${randomHex}`;
  }

  /**
   * Encrypt data
   */
  async encrypt(data) {
    try {
      const keyInfo = this.keyCache.get(this.currentKeyId);
      if (!keyInfo) {
        throw new Error('No encryption key available');
      }
      
      // Convert data to string if needed
      const plaintext = typeof data === 'string' ? data : JSON.stringify(data);
      const encoder = new TextEncoder();
      const dataBuffer = encoder.encode(plaintext);
      
      // Generate IV
      const iv = crypto.getRandomValues(new Uint8Array(this.ivLength));
      
      // Generate salt for additional security
      const salt = crypto.getRandomValues(new Uint8Array(this.saltLength));
      
      // Encrypt
      const ciphertext = await crypto.subtle.encrypt(
        {
          name: this.algorithm,
          iv: iv
        },
        keyInfo.key,
        dataBuffer
      );
      
      // Combine: salt + iv + ciphertext
      const combined = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
      combined.set(salt, 0);
      combined.set(iv, salt.length);
      combined.set(new Uint8Array(ciphertext), salt.length + iv.length);
      
      // Return encrypted package
      return {
        encrypted: true,
        keyId: this.currentKeyId,
        version: keyInfo.version,
        algorithm: this.algorithm,
        data: this.arrayBufferToBase64(combined),
        checksum: await this.generateChecksum(dataBuffer)
      };
    } catch (error) {
      console.error('[Encryption] Encryption failed:', error);
      throw error;
    }
  }

  /**
   * Decrypt data
   */
  async decrypt(encryptedPackage) {
    try {
      if (!encryptedPackage.encrypted) {
        return encryptedPackage.data || encryptedPackage;
      }
      
      const { keyId, data } = encryptedPackage;
      
      // Get key
      let keyInfo = this.keyCache.get(keyId);
      
      if (!keyInfo) {
        // Try to load from storage
        const stored = await chrome.storage.local.get('encryptionKeys');
        if (stored.encryptionKeys && stored.encryptionKeys[keyId]) {
          const key = await this.importKey(stored.encryptionKeys[keyId].rawKey);
          keyInfo = {
            key,
            createdAt: stored.encryptionKeys[keyId].createdAt,
            version: stored.encryptionKeys[keyId].version
          };
          this.keyCache.set(keyId, keyInfo);
        } else {
          throw new Error(`Key not found: ${keyId}`);
        }
      }
      
      // Decode base64
      const combined = this.base64ToArrayBuffer(data);
      
      // Extract salt, iv, ciphertext
      const salt = combined.slice(0, this.saltLength);
      const iv = combined.slice(this.saltLength, this.saltLength + this.ivLength);
      const ciphertext = combined.slice(this.saltLength + this.ivLength);
      
      // Decrypt
      const decrypted = await crypto.subtle.decrypt(
        {
          name: this.algorithm,
          iv: iv
        },
        keyInfo.key,
        ciphertext
      );
      
      // Convert to string
      const decoder = new TextDecoder();
      const plaintext = decoder.decode(decrypted);
      
      // Try to parse as JSON
      try {
        return JSON.parse(plaintext);
      } catch {
        return plaintext;
      }
    } catch (error) {
      console.error('[Encryption] Decryption failed:', error);
      throw error;
    }
  }

  /**
   * Generate checksum for data integrity
   */
  async generateChecksum(data) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16);
  }

  /**
   * Check and perform key rotation if needed
   */
  async checkKeyRotation() {
    const keyInfo = this.keyCache.get(this.currentKeyId);
    if (!keyInfo) return;
    
    const age = Date.now() - keyInfo.createdAt;
    
    if (age > this.keyRotationInterval) {
      console.log('[Encryption] Key rotation needed');
      await this.rotateKey();
    }
  }

  /**
   * Rotate encryption key
   */
  async rotateKey() {
    try {
      // Generate new key
      const newKeyId = await this.generateNewKey();
      
      // Keep old keys for decryption
      // Re-encrypt pending events with new key
      const stored = await chrome.storage.local.get('eventQueue');
      if (stored.eventQueue && stored.eventQueue.length > 0) {
        const reEncrypted = [];
        for (const event of stored.eventQueue) {
          if (event.encrypted && event.keyId !== newKeyId) {
            // Decrypt with old key and re-encrypt with new
            const decrypted = await this.decrypt(event);
            const newEncrypted = await this.encrypt(decrypted);
            reEncrypted.push({ ...event, ...newEncrypted });
          } else {
            reEncrypted.push(event);
          }
        }
        await chrome.storage.local.set({ eventQueue: reEncrypted });
      }
      
      // Clean up old keys (keep last 3)
      const keys = Object.keys(this.keyCache.getMap ? this.keyCache : Array.from(this.keyCache.keys()));
      if (keys.length > 3) {
        const sortedKeys = keys.sort((a, b) => {
          const aInfo = this.keyCache.get(a);
          const bInfo = this.keyCache.get(b);
          return (aInfo?.createdAt || 0) - (bInfo?.createdAt || 0);
        });
        
        const keysToDelete = sortedKeys.slice(0, keys.length - 3);
        for (const keyId of keysToDelete) {
          this.keyCache.delete(keyId);
        }
        
        // Update storage
        const stored = await chrome.storage.local.get('encryptionKeys');
        if (stored.encryptionKeys) {
          for (const keyId of keysToDelete) {
            delete stored.encryptionKeys[keyId];
          }
          await chrome.storage.local.set({ encryptionKeys: stored.encryptionKeys });
        }
      }
      
      console.log('[Encryption] Key rotated to:', newKeyId);
      return newKeyId;
    } catch (error) {
      console.error('[Encryption] Key rotation failed:', error);
      throw error;
    }
  }

  /**
   * Utility: ArrayBuffer to Base64
   */
  arrayBufferToBase64(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Utility: Base64 to ArrayBuffer
   */
  base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Export public key info (for backend verification)
   */
  async exportKeyInfo() {
    return {
      currentKeyId: this.currentKeyId,
      algorithm: this.algorithm,
      keyLength: this.keyLength
    };
  }

  /**
   * Check if encryption is active
   */
  isActive() {
    return this.currentKeyId !== null && this.keyCache.size > 0;
  }
}

// Singleton instance
export const encryptionManager = new EncryptionManager();
