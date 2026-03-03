/**
 * Devise Network Interceptor Module
 * Intercepts and logs network requests to AI services
 */

export class NetworkInterceptor {
  constructor() {
    this.config = {
      enabled: true,
      captureRequestBodies: true,
      captureResponseBodies: true,
      maxBodySize: 1024 * 1024, // 1MB
      targetDomains: [
        'openai.com', 'chatgpt.com', 'anthropic.com', 'claude.ai',
        'googleapis.com', 'gemini.google.com', 'perplexity.ai',
        'poe.com', 'character.ai', 'huggingface.co'
      ]
    };
    
    this.capturedRequests = [];
    this.sessionStats = {
      totalRequests: 0,
      aiRequests: 0,
      totalBytesSent: 0,
      totalBytesReceived: 0,
      requestTypes: {}
    };
  }

  /**
   * Initialize network interceptor
   */
  async initialize() {
    this.setupRequestListener();
    this.setupPerformanceObserver();
    
    console.log('[NetworkInterceptor] Initialized');
    return true;
  }

  /**
   * Setup webRequest listener for request capture
   */
  setupRequestListener() {
    // Note: MV3 has limited webRequest API
    // Use declarativeNetRequest for rules
    // For actual capture, we use Performance API and content script injection
    
    // Monitor performance entries
    if (typeof PerformanceObserver !== 'undefined') {
      try {
        const observer = new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) {
            if (entry.initiatorType === 'fetch' || entry.initiatorType === 'xmlhttprequest') {
              this.handleNetworkEntry(entry);
            }
          }
        });
        
        observer.observe({ entryTypes: ['resource'] });
      } catch (e) {
        console.warn('[NetworkInterceptor] PerformanceObserver not supported:', e);
      }
    }
  }

  /**
   * Setup Performance Observer
   */
  setupPerformanceObserver() {
    // Intercept fetch
    this.interceptFetch();
    
    // Intercept XMLHttpRequest
    this.interceptXHR();
  }

  /**
   * Intercept fetch API
   */
  interceptFetch() {
    const originalFetch = window.fetch;
    const self = this;
    
    window.fetch = async function(input, init = {}) {
      const url = typeof input === 'string' ? input : input.url;
      const method = init.method || 'GET';
      const startTime = Date.now();
      
      // Check if it's an AI service
      const isAITarget = self.config.targetDomains.some(domain => 
        url && url.includes(domain)
      );
      
      const requestInfo = {
        id: `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        url,
        method,
        type: 'fetch',
        isAI: isAITarget,
        timestamp: startTime,
        requestBody: null,
        requestHeaders: {},
        responseStatus: null,
        responseBody: null,
        responseHeaders: {},
        duration: 0,
        bytesSent: 0,
        bytesReceived: 0
      };
      
      // Capture request body
      if (self.config.captureRequestBodies && init.body) {
        try {
          if (typeof init.body === 'string') {
            requestInfo.requestBody = init.body.substring(0, self.config.maxBodySize);
            requestInfo.bytesSent = init.body.length;
          } else if (init.body instanceof FormData) {
            requestInfo.requestBody = '[FormData]';
          } else if (init.body instanceof Blob) {
            requestInfo.requestBody = '[Blob]';
            requestInfo.bytesSent = init.body.size;
          }
        } catch (e) {
          requestInfo.requestBody = '[Unable to capture]';
        }
      }
      
      // Capture headers
      if (init.headers) {
        try {
          if (init.headers instanceof Headers) {
            init.headers.forEach((value, key) => {
              requestInfo.requestHeaders[key] = self.maskSensitiveHeader(key, value);
            });
          } else if (typeof init.headers === 'object') {
            for (const [key, value] of Object.entries(init.headers)) {
              requestInfo.requestHeaders[key] = self.maskSensitiveHeader(key, value);
            }
          }
        } catch (e) {
          // Ignore header capture errors
        }
      }
      
      try {
        const response = await originalFetch.apply(this, arguments);
        const endTime = Date.now();
        
        requestInfo.duration = endTime - startTime;
        requestInfo.responseStatus = response.status;
        
        // Capture response headers
        response.headers.forEach((value, key) => {
          requestInfo.responseHeaders[key] = self.maskSensitiveHeader(key, value);
        });
        
        // Clone response to capture body without consuming
        if (self.config.captureResponseBodies && isAITarget) {
          try {
            const clonedResponse = response.clone();
            const text = await clonedResponse.text();
            requestInfo.responseBody = text.substring(0, self.config.maxBodySize);
            requestInfo.bytesReceived = text.length;
          } catch (e) {
            requestInfo.responseBody = '[Unable to capture]';
          }
        }
        
        // Process the captured request
        self.processRequest(requestInfo);
        
        return response;
      } catch (error) {
        requestInfo.error = error.message;
        requestInfo.duration = Date.now() - startTime;
        self.processRequest(requestInfo);
        throw error;
      }
    };
  }

  /**
   * Intercept XMLHttpRequest
   */
  interceptXHR() {
    const originalXHROpen = XMLHttpRequest.prototype.open;
    const originalXHRSend = XMLHttpRequest.prototype.send;
    const self = this;
    
    XMLHttpRequest.prototype.open = function(method, url) {
      this._deviseRequestInfo = {
        method,
        url,
        type: 'xhr',
        timestamp: Date.now()
      };
      return originalXHROpen.apply(this, arguments);
    };
    
    XMLHttpRequest.prototype.send = function(body) {
      const xhr = this;
      const requestInfo = xhr._deviseRequestInfo || {
        id: `req_${Date.now()}`,
        type: 'xhr'
      };
      
      requestInfo.id = requestInfo.id || `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      requestInfo.isAI = self.config.targetDomains.some(domain => 
        requestInfo.url && requestInfo.url.includes(domain)
      );
      
      // Capture request body
      if (self.config.captureRequestBodies && body) {
        try {
          if (typeof body === 'string') {
            requestInfo.requestBody = body.substring(0, self.config.maxBodySize);
            requestInfo.bytesSent = body.length;
          } else {
            requestInfo.requestBody = '[Binary/FormData]';
          }
        } catch (e) {
          requestInfo.requestBody = '[Unable to capture]';
        }
      }
      
      // Setup response handler
      xhr.addEventListener('load', function() {
        requestInfo.responseStatus = xhr.status;
        requestInfo.duration = Date.now() - requestInfo.timestamp;
        
        if (self.config.captureResponseBodies && requestInfo.isAI) {
          try {
            requestInfo.responseBody = xhr.responseText.substring(0, self.config.maxBodySize);
            requestInfo.bytesReceived = xhr.responseText.length;
          } catch (e) {
            requestInfo.responseBody = '[Unable to capture]';
          }
        }
        
        self.processRequest(requestInfo);
      });
      
      xhr.addEventListener('error', function() {
        requestInfo.error = 'Request failed';
        requestInfo.duration = Date.now() - requestInfo.timestamp;
        self.processRequest(requestInfo);
      });
      
      return originalXHRSend.apply(this, arguments);
    };
  }

  /**
   * Handle network entry from Performance API
   */
  handleNetworkEntry(entry) {
    const url = entry.name;
    
    const isAITarget = this.config.targetDomains.some(domain => 
      url && url.includes(domain)
    );
    
    if (isAITarget) {
      const requestInfo = {
        id: `perf_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        url,
        type: entry.initiatorType,
        isAI: true,
        duration: entry.duration,
        transferSize: entry.transferSize,
        encodedBodySize: entry.encodedBodySize,
        decodedBodySize: entry.decodedBodySize,
        timestamp: Date.now()
      };
      
      this.processRequest(requestInfo);
    }
  }

  /**
   * Process captured request
   */
  processRequest(requestInfo) {
    // Update session stats
    this.sessionStats.totalRequests++;
    if (requestInfo.isAI) {
      this.sessionStats.aiRequests++;
    }
    
    this.sessionStats.totalBytesSent += requestInfo.bytesSent || 0;
    this.sessionStats.totalBytesReceived += requestInfo.bytesReceived || 0;
    
    const type = requestInfo.type || 'other';
    this.sessionStats.requestTypes[type] = (this.sessionStats.requestTypes[type] || 0) + 1;
    
    // Store request
    this.capturedRequests.push(requestInfo);
    
    // Limit stored requests
    if (this.capturedRequests.length > 500) {
      this.capturedRequests = this.capturedRequests.slice(-500);
    }
    
    // Send to background if AI request
    if (requestInfo.isAI) {
      this.sendToBackground(requestInfo);
    }
    
    console.log('[NetworkInterceptor] Captured:', requestInfo.url, requestInfo.duration + 'ms');
  }

  /**
   * Send request to background script
   */
  sendToBackground(requestInfo) {
    try {
      chrome.runtime.sendMessage({
        action: 'networkRequest',
        data: requestInfo
      });
    } catch (e) {
      console.warn('[NetworkInterceptor] Failed to send to background:', e);
    }
  }

  /**
   * Mask sensitive headers
   */
  maskSensitiveHeader(key, value) {
    const sensitiveKeys = ['authorization', 'cookie', 'x-api-key', 'api-key', 'token'];
    const lowerKey = key.toLowerCase();
    
    if (sensitiveKeys.some(sk => lowerKey.includes(sk))) {
      return '***REDACTED***';
    }
    
    return value;
  }

  /**
   * Get captured requests
   */
  getCapturedRequests(filter = {}) {
    let requests = [...this.capturedRequests];
    
    if (filter.aiOnly) {
      requests = requests.filter(r => r.isAI);
    }
    
    if (filter.url) {
      requests = requests.filter(r => r.url && r.url.includes(filter.url));
    }
    
    return requests;
  }

  /**
   * Get session stats
   */
  getSessionStats() {
    return { ...this.sessionStats };
  }

  /**
   * Extract token usage from response
   */
  extractTokenUsage(responseBody, url) {
    try {
      if (!responseBody) return null;
      
      const data = typeof responseBody === 'string' ? JSON.parse(responseBody) : responseBody;
      
      // OpenAI format
      if (data.usage) {
        return {
          promptTokens: data.usage.prompt_tokens,
          completionTokens: data.usage.completion_tokens,
          totalTokens: data.usage.total_tokens
        };
      }
      
      // Anthropic format
      if (data.usage?.input_tokens) {
        return {
          promptTokens: data.usage.input_tokens,
          completionTokens: data.usage.output_tokens,
          totalTokens: (data.usage.input_tokens || 0) + (data.usage.output_tokens || 0)
        };
      }
      
      return null;
    } catch (e) {
      return null;
    }
  }

  /**
   * Reset session
   */
  resetSession() {
    this.capturedRequests = [];
    this.sessionStats = {
      totalRequests: 0,
      aiRequests: 0,
      totalBytesSent: 0,
      totalBytesReceived: 0,
      requestTypes: {}
    };
  }
}

// Singleton instance
export const networkInterceptor = new NetworkInterceptor();
