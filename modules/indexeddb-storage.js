/**
 * Devise IndexedDB Storage Module
 * Handles large data storage with IndexedDB
 */

const DB_NAME = 'DeviseDB';
const DB_VERSION = 1;

export class IndexedDBStorage {
  constructor() {
    this.db = null;
    this.stores = {
    events: 'events',
    threats: 'threats',
    violations: 'violations',
    behavior: 'behavior',
    analytics: 'analytics'
  };
  }

  /**
   * Initialize IndexedDB
   */
  async initialize() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION, (event) => {
        const db = event.target.result;
        
        // Create stores if needed
        if (event.oldVersion < 1) {
          // Events store
          if (!db.objectStoreNames.contains(this.stores.events)) {
            const eventsStore = db.createObjectStore(this.stores.events, { keyPath: 'id' });
            eventsStore.createIndex('timestamp', 'timestamp', { unique: false });
            eventsStore.createIndex('type', 'type', { unique: false });
            eventsStore.createIndex('userId', 'userId', { unique: false });
          }
          
          // Threats store
          if (!db.objectStoreNames.contains(this.stores.threats)) {
            const threatsStore = db.createObjectStore(this.stores.threats, { keyPath: 'id' });
            threatsStore.createIndex('timestamp', 'timestamp', { unique: false });
            threatsStore.createIndex('severity', 'severity', { unique: false });
          }
          
          // Violations store
          if (!db.objectStoreNames.contains(this.stores.violations)) {
            const violationsStore = db.createObjectStore(this.stores.violations, { keyPath: 'id' });
            violationsStore.createIndex('timestamp', 'timestamp', { unique: false });
            violationsStore.createIndex('type', 'type', { unique: false });
          }
          
          // Behavior store
          if (!db.objectStoreNames.contains(this.stores.behavior)) {
            const behaviorStore = db.createObjectStore(this.stores.behavior, { keyPath: 'sessionId' });
            behaviorStore.createIndex('timestamp', 'startTime', { unique: false });
          }
          
          // Analytics store
          if (!db.objectStoreNames.contains(this.stores.analytics)) {
            const analyticsStore = db.createObjectStore(this.stores.analytics, { keyPath: 'id' });
            analyticsStore.createIndex('timestamp', 'timestamp', { unique: false });
            analyticsStore.createIndex('category', 'category', { unique: false });
          }
        }
      });
      
      request.onsuccess = (event) => {
        this.db = event.target.result;
        console.log('[IndexedDB] Initialized');
        resolve(true);
      };
      
      request.onerror = (event) => {
        console.error('[IndexedDB] Initialization failed:', event.target.error);
        reject(event.target.error);
      };
    });
  }

  /**
   * Add item to store
   */
  async add(storeName, item) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([storeName], 'readwrite');
      const store = transaction.objectStore(storeName);
      const request = store.add(item);
      
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Put item (add or update)
   */
  async put(storeName, item) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([storeName], 'readwrite');
      const store = transaction.objectStore(storeName);
      const request = store.put(item);
      
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get item by key
   */
  async get(storeName, key) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([storeName], 'readonly');
      const store = transaction.objectStore(storeName);
      const request = store.get(key);
      
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get all items from store
   */
  async getAll(storeName) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([storeName], 'readonly');
      const store = transaction.objectStore(storeName);
      const request = store.getAll();
      
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get items by index
   */
  async getByIndex(storeName, indexName, value) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([storeName], 'readonly');
      const store = transaction.objectStore(storeName);
      const index = store.index(indexName);
      const request = index.getAll(value);
      
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get items in range
   */
  async getRange(storeName, indexName, lower, upper) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([storeName], 'readonly');
      const store = transaction.objectStore(storeName);
      const index = store.index(indexName);
      const range = IDBKeyRange.bound(lower, upper);
      const request = index.getAll(range);
      
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Delete item by key
   */
  async delete(storeName, key) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([storeName], 'readwrite');
      const store = transaction.objectStore(storeName);
      const request = store.delete(key);
      
      request.onsuccess = () => resolve(true);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Clear all items from store
   */
  async clear(storeName) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([storeName], 'readwrite');
      const store = transaction.objectStore(storeName);
      const request = store.clear();
      
      request.onsuccess = () => resolve(true);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Count items in store
   */
  async count(storeName) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([storeName], 'readonly');
      const store = transaction.objectStore(storeName);
      const request = store.count();
      
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Add event with encryption
   */
  async addEvent(event, encrypted = false) {
    const item = {
      ...event,
      id: event.id || `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: event.timestamp || Date.now(),
      encrypted
    };
    
    return this.add(this.stores.events, item);
  }

  /**
   * Get events in time range
   */
  async getEventsByTimeRange(startTime, endTime) {
    return this.getRange(this.stores.events, 'timestamp', startTime, endTime);
  }

  /**
   * Add threat
   */
  async addThreat(threat) {
    return this.add(this.stores.threats, threat);
  }

  /**
   * Get threats by severity
   */
  async getThreatsBySeverity(severity) {
    return this.getByIndex(this.stores.threats, 'severity', severity);
  }

  /**
   * Add behavior session
   */
  async addBehaviorSession(session) {
    return this.put(this.stores.behavior, session);
  }

  /**
   * Export all data
   */
  async exportAll() {
    const data = {
      events: await this.getAll(this.stores.events),
      threats: await this.getAll(this.stores.threats),
      violations: await this.getAll(this.stores.violations),
      behavior: await this.getAll(this.stores.behavior),
      analytics: await this.getAll(this.stores.analytics),
      exportedAt: new Date().toISOString()
    };
    
    return data;
  }

  /**
   * Get storage stats
   */
  async getStats() {
    return {
      events: await this.count(this.stores.events),
      threats: await this.count(this.stores.threats),
      violations: await this.count(this.stores.violations),
      behavior: await this.count(this.stores.behavior),
      analytics: await this.count(this.stores.analytics)
    };
  }
}

// Singleton instance
export const indexedDBStorage = new IndexedDBStorage();
