/**
 * Devise Integrations Module
 * Webhooks, SIEM, and external system integrations
 */

export class IntegrationManager {
  constructor() {
    this.config = {
      enabled: true,
      webhooks: [],
      siemIntegrations: [],
      retryAttempts: 3,
      retryDelay: 5000
    };
    
    this.queue = [];
    this.isProcessing = false;
  }

  /**
   * Initialize integrations
   */
  async initialize() {
    // Load configuration
    const stored = await chrome.storage.local.get('integrationConfig');
    if (stored.integrationConfig) {
      this.config = { ...this.config, ...stored.integrationConfig };
    }
    
    // Start queue processor
    this.startQueueProcessor();
    
    console.log('[Integrations] Initialized');
    return true;
  }

  /**
   * Configure webhook
   */
  async configureWebhook(config) {
    const webhook = {
      id: `wh_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      name: config.name,
      url: config.url,
      method: config.method || 'POST',
      headers: config.headers || {},
      events: config.events || ['*'],
      enabled: config.enabled !== false,
      secret: config.secret,
      createdAt: Date.now()
    };
    
    this.config.webhooks.push(webhook);
    await this.saveConfig();
    
    return webhook;
  }

  /**
   * Configure SIEM integration
   */
  async configureSIEM(config) {
    const siem = {
      id: `siem_${Date.now()}`,
      type: config.type, // splunk, sentinel, qradar, etc.
      endpoint: config.endpoint,
      credentials: config.credentials,
      format: config.format || 'json',
      events: config.events || ['*'],
      enabled: config.enabled !== false,
      createdAt: Date.now()
    };
    
    this.config.siemIntegrations.push(siem);
    await this.saveConfig();
    
    return siem;
  }

  /**
   * Send event to all integrations
   */
  async sendEvent(event) {
    if (!this.config.enabled) return;
    
    // Add to queue
    this.queue.push({
      ...event,
      queuedAt: Date.now()
    });
    
    // Process if not already processing
    if (!this.isProcessing) {
      this.processQueue();
    }
  }

  /**
   * Start queue processor
   */
  startQueueProcessor() {
    setInterval(() => {
      if (this.queue.length > 0 && !this.isProcessing) {
        this.processQueue();
      }
    }, 10000); // Every 10 seconds
  }

  /**
   * Process queue
   */
  async processQueue() {
    if (this.isProcessing || this.queue.length === 0) return;
    
    this.isProcessing = true;
    
    try {
      const batch = this.queue.splice(0, 50); // Process up to 50 at a time
      
      for (const event of batch) {
        await this.deliverEvent(event);
      }
    } finally {
      this.isProcessing = false;
    }
  }

  /**
   * Deliver event to integrations
   */
  async deliverEvent(event) {
    // Send to webhooks
    for (const webhook of this.config.webhooks.filter(w => w.enabled)) {
      if (this.shouldSendToWebhook(event, webhook)) {
        await this.sendToWebhook(event, webhook);
      }
    }
    
    // Send to SIEM
    for (const siem of this.config.siemIntegrations.filter(s => s.enabled)) {
      if (this.shouldSendToSIEM(event, siem)) {
        await this.sendToSIEM(event, siem);
      }
    }
  }

  /**
   * Check if event should go to webhook
   */
  shouldSendToWebhook(event, webhook) {
    if (webhook.events.includes('*')) return true;
    return webhook.events.some(e => 
      event.type === e || event.eventType === e
    );
  }

  /**
   * Check if event should go to SIEM
   */
  shouldSendToSIEM(event, siem) {
    if (siem.events.includes('*')) return true;
    return siem.events.some(e => 
      event.type === e || event.eventType === e
    );
  }

  /**
   * Send to webhook
   */
  async sendToWebhook(event, webhook) {
    const payload = {
      id: event.id || `evt_${Date.now()}`,
      timestamp: event.timestamp || Date.now(),
      type: event.type || event.eventType,
      data: event,
      signature: this.generateSignature(event, webhook.secret)
    };
    
    try {
      const response = await fetch(webhook.url, {
        method: webhook.method,
        headers: {
          'Content-Type': 'application/json',
          ...webhook.headers
        },
        body: JSON.stringify(payload)
      });
      
      if (!response.ok) {
        console.warn('[Integrations] Webhook failed:', response.status);
        await this.logDeliveryFailure('webhook', webhook.id, response.status);
      }
    } catch (error) {
      console.error('[Integrations] Webhook error:', error);
      await this.logDeliveryFailure('webhook', webhook.id, error.message);
    }
  }

  /**
   * Send to SIEM
   */
  async sendToSIEM(event, siem) {
    const payload = this.formatForSIEM(event, siem);
    
    try {
      let response;
      
      switch (siem.type) {
        case 'splunk':
          response = await this.sendToSplunk(payload, siem);
          break;
        case 'sentinel':
          response = await this.sendToSentinel(payload, siem);
          break;
        case 'qradar':
          response = await this.sendToQRadar(payload, siem);
          break;
        default:
          response = await fetch(siem.endpoint, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${siem.credentials.token}`
            },
            body: JSON.stringify(payload)
          });
      }
      
      if (response && !response.ok) {
        await this.logDeliveryFailure('siem', siem.id, response.status);
      }
    } catch (error) {
      console.error('[Integrations] SIEM error:', error);
      await this.logDeliveryFailure('siem', siem.id, error.message);
    }
  }

  /**
   * Format event for SIEM
   */
  formatForSIEM(event, siem) {
    switch (siem.type) {
      case 'splunk':
        return {
          time: new Date(event.timestamp || Date.now()).getTime() / 1000,
          host: 'devise-extension',
          source: 'devise',
          sourcetype: 'httpevent',
          event: {
            ...event,
            _time: new Date().toISOString()
          }
        };
      
      case 'sentinel':
        return {
          RecordType: 'DeviseEvent',
          TimeGenerated: new Date().toISOString(),
          Source: 'Devise Extension',
          EventData: JSON.stringify(event)
        };
      
      case 'qradar':
        return {
          ...event,
          devicetime: new Date().toISOString(),
          deviceproduct: 'Devise Extension'
        };
      
      default:
        return event;
    }
  }

  /**
   * Send to Splunk
   */
  async sendToSplunk(payload, siem) {
    return fetch(`${siem.endpoint}/services/collector/event`, {
      method: 'POST',
      headers: {
        'Authorization': `Splunk ${siem.credentials.token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });
  }

  /**
   * Send to Azure Sentinel
   */
  async sendToSentinel(payload, siem) {
    return fetch(`${siem.endpoint}/api/logs`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${siem.credentials.token}`,
        'Content-Type': 'application/json',
        'Log-Type': 'DeviseEvents'
      },
      body: JSON.stringify(payload)
    });
  }

  /**
   * Send to QRadar
   */
  async sendToQRadar(payload, siem) {
    return fetch(`${siem.endpoint}/api/siem/events`, {
      method: 'POST',
      headers: {
        'SEC': siem.credentials.token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });
  }

  /**
   * Generate signature for webhook
   */
  generateSignature(event, secret) {
    if (!secret) return null;
    
    const payload = JSON.stringify(event);
    // In real implementation, use HMAC-SHA256
    return `sha256=${payload.length}`;
  }

  /**
   * Log delivery failure
   */
  async logDeliveryFailure(type, id, error) {
    const failure = {
      type,
      integrationId: id,
      error,
      timestamp: Date.now()
    };
    
    const stored = await chrome.storage.local.get('integrationFailures') || [];
    stored.push(failure);
    await chrome.storage.local.set({ integrationFailures: stored.slice(-100) });
  }

  /**
   * Save configuration
   */
  async saveConfig() {
    await chrome.storage.local.set({ integrationConfig: this.config });
  }

  /**
   * Test webhook
   */
  async testWebhook(webhookId) {
    const webhook = this.config.webhooks.find(w => w.id === webhookId);
    if (!webhook) return { success: false, error: 'Webhook not found' };
    
    const testEvent = {
      type: 'test',
      timestamp: Date.now(),
      message: 'Test event from Devise Extension'
    };
    
    try {
      await this.sendToWebhook(testEvent, webhook);
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Get integration status
   */
  getStatus() {
    return {
      enabled: this.config.enabled,
      webhooks: this.config.webhooks.map(w => ({
        id: w.id,
        name: w.name,
        enabled: w.enabled
      })),
      siemIntegrations: this.config.siemIntegrations.map(s => ({
        id: s.id,
        type: s.type,
        enabled: s.enabled
      })),
      queueLength: this.queue.length
    };
  }

  /**
   * Remove integration
   */
  async removeIntegration(type, id) {
    if (type === 'webhook') {
      this.config.webhooks = this.config.webhooks.filter(w => w.id !== id);
    } else if (type === 'siem') {
      this.config.siemIntegrations = this.config.siemIntegrations.filter(s => s.id !== id);
    }
    
    await this.saveConfig();
  }
}

// Singleton instance
export const integrationManager = new IntegrationManager();
