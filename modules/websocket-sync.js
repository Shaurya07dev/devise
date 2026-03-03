/**
 * Devise WebSocket Sync Module
 * Real-time synchronization with backend
 */

export class WebSocketSync {
  constructor() {
    this.ws = null;
    this.config = {
      enabled: true,
      reconnectInterval: 5000, // 5 seconds
      maxReconnectAttempts: 5,
      heartbeatInterval: 30000, // 30 seconds
      queue: [],
      isConnected: false,
      reconnectAttempts: 0,
      lastMessageTime: null,
      messageCount: 0,
      bytesTransferred: 0
    };
  }

  /**
   * Initialize WebSocket connection
   */
  async initialize(endpoint) {
    this.endpoint = endpoint || 'wss://api.devi.se/sync';
    
    if (this.config.enabled) {
      this.connect();
    }
    
    return true;
  }

  /**
   * Connect to WebSocket
   */
  connect() {
    if (this.ws) {
      this.ws.close();
    }
    
    try {
      this.ws = new WebSocket(this.endpoint);
      
      this.ws.onopen = () => {
        this.onOpen();
      };
      
      this.ws.onclose = (event) => {
        this.onClose(event);
      };
      
      this.ws.onerror = (error) => {
        this.onError(error);
      });
      
      this.ws.onmessage = (event) => {
        this.onMessage(event);
      };
      
      console.log('[WebSocket] Connecting to:', this.endpoint);
    } catch (error) {
      console.error('[WebSocket] Connection failed:', error);
      this.scheduleReconnect();
    }
  }

  /**
   * Handle open event
   */
  onOpen() {
    this.isConnected = true;
    this.reconnectAttempts = 0;
    
    // Start heartbeat
    this.startHeartbeat();
    
    // Send queued messages
    this.flushQueue();
    
    // Notify background
    chrome.runtime.sendMessage({
      action: 'websocketConnected',
      endpoint: this.endpoint
    });
    
    console.log('[WebSocket] Connected');
  }

  /**
   * Handle close event
   */
  onClose(event) {
    this.isConnected = false;
    console.log('[WebSocket] Disconnected:', event.code, event.reason);
    
    this.scheduleReconnect();
    
    // Notify background
    chrome.runtime.sendMessage({
      action: 'websocketDisconnected',
      reason: event.reason
    });
  }

  /**
   * Handle error event
   */
  onError(error) {
    this.isConnected = false;
    console.error('[WebSocket] Error:', error);
    
    this.scheduleReconnect();
  }

  /**
   * Handle incoming message
   */
  onMessage(event) {
    try {
      const data = JSON.parse(event.data);
      this.messageCount++;
      this.bytesTransferred += event.data.length;
      
      // Handle different message types
      switch (data.type) {
        case 'events':
          this.handleEventsMessage(data.events);
          break;
        case 'policy':
          this.handlePolicyUpdate(data.policy);
          break;
        case 'command':
          this.handleCommand(data);
          break;
        case 'ack':
          // Acknowledge received
          this.sendAck(data.id);
          break;
        default:
          // Forward to background
          chrome.runtime.sendMessage({
            action: 'websocketMessage',
            data
          });
      }
    } catch (e) {
      console.error('[WebSocket] Failed to parse message:', e);
    }
  }

  /**
   * Schedule reconnection
   */
  scheduleReconnect() {
    if (this.reconnectAttempts >= this.config.maxReconnectAttempts) {
      console.log('[WebSocket] Max reconnect attempts reached');
      return;
    }
    
    this.reconnectAttempts++;
    
    setTimeout(() => {
      if (!this.isConnected) {
        console.log('[WebSocket] Reconnecting... attempt', this.reconnectAttempts);
        this.connect();
      }
    }, this.config.reconnectInterval * this.reconnectAttempts * 1000);
  }

  /**
   * Start heartbeat
   */
  startHeartbeat() {
    if (!this.ws || !this.isConnected) return;
    
    this.ws.send(JSON.stringify({
      type: 'heartbeat',
      timestamp: Date.now()
    }));
  }

  /**
   * Send event
   */
  send(event) {
    if (!this.ws || !this.isConnected) {
      this.queue.push(event);
      return false;
    }
    
    try {
      const message = {
        type: 'event',
        id: `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: Date.now(),
        ...event
      };
      
      this.ws.send(JSON.stringify(message));
      this.bytesTransferred += JSON.stringify(message).length;
      
      return true;
    } catch (e) {
      console.error('[WebSocket] Failed to send:', e);
      this.queue.push(event);
      return false;
    }
  }

  /**
   * Send acknowledgment
   */
  sendAck(messageId) {
    if (!this.ws || !this.isConnected) return;
    
    try {
      this.ws.send(JSON.stringify({
        type: 'ack',
        id: messageId,
        timestamp: Date.now()
      }));
    } catch (e) {
      console.error('[WebSocket] Failed to send ack:', e);
    }
  }

  /**
   * Flush queued messages
   */
  flushQueue() {
    if (this.queue.length === 0) || !this.isConnected) return;
    
    console.log('[WebSocket] Flushing', this.queue.length, 'queued messages');
    
    const messages = [...this.queue];
    this.queue = [];
    
    for (const msg of messages) {
      this.send(msg);
    }
  }

  /**
   * Handle events batch
   */
  handleEventsMessage(events) {
    // Process events locally
    for (const event of events) {
      // Could trigger local processing
      console.log('[WebSocket] Received event:', event.eventType);
    }
  }

  /**
   * Handle policy update
   */
  handlePolicyUpdate(policy) {
    console.log('[WebSocket] Policy update received');
    
    // Store policy
    chrome.storage.local.set({ syncPolicy: policy });
    
    // Notify background
    chrome.runtime.sendMessage({
      action: 'policyUpdate',
      policy
    });
  }

  /**
   * Handle command
   */
  handleCommand(data) {
    switch (data.command) {
      case 'reset':
        this.reset();
        break;
      default:
        console.log('[WebSocket] Command:', data.command);
    }
  }

  /**
   * Get connection status
   */
  getStatus() {
    return {
      connected: this.isConnected,
      endpoint: this.endpoint,
      queueLength: this.queue.length,
      messageCount: this.messageCount,
      bytesTransferred: this.bytesTransferred,
      reconnectAttempts: this.reconnectAttempts
    };
  }

  /**
   * Reset connection
   */
  reset() {
    if (this.ws) {
      this.ws.close();
    }
    
    this.ws = null;
    this.isConnected = false;
    this.queue = [];
    this.reconnectAttempts = 0;
    this.messageCount = 0;
    this.bytesTransferred = 0;
    
    console.log('[WebSocket] Reset');
  }

  /**
   * Cleanup
   */
  cleanup() {
    if (this.ws) {
      this.ws.close();
    }
  }
}

// Singleton instance
export const webSocketSync = new WebSocketSync();
