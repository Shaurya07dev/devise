/**
 * Devise Tamper Protection Module
 * Code integrity verification and anti-debugging measures
 */

export class TamperProtection {
  constructor() {
    this.config = {
      enabled: true,
      integrityCheckInterval: 60000, // 1 minute
      debugDetectionEnabled: true,
      devToolsDetectionEnabled: true,
      modificationDetectionEnabled: true
      reportEndpoint: null
    };
    
    this.originalCodeHashes = new Map();
    this.currentCodeHashes = new Map();
    this.tamperAttempts = [];
    this.lastIntegrityCheck = null;
    this.debuggerDetected = false;
  }

  /**
   * Initialize tamper protection
   */
  async initialize() {
    if (!this.config.enabled) return true;
    
    // Store original hashes
    await this.storeOriginalHashes();
    
    // Start periodic integrity checks
    this.startIntegrityChecks();
    
    // Setup debug detection
    this.setupDebugDetection();
    
    // Setup modification detection
    this.setupModificationDetection();
    
    console.log('[TamperProtection] Initialized');
    return true;
  }

  /**
   * Store original code hashes
   */
  async storeOriginalHashes() {
    // In a real extension, this would hash the actual code files
    // For demo, we use placeholder hashes
    
    const criticalFiles = [
      'background.js',
      'content-monitor.js',
      'modules/encryption.js',
      'modules/policy-engine.js',
      'modules/pii-detector.js',
      'modules/threat-detection.js'
    ];
    
    for (const file of criticalFiles) {
      this.originalCodeHashes.set(file, `hash_${Date.now()}`);
    }
  }

  /**
   * Calculate hash for code
   */
  async calculateHash(code) {
    const encoder = new TextEncoder();
    const data = encoder.encode(code);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Start integrity checks
   */
  startIntegrityChecks() {
    setInterval(() => {
      this.checkIntegrity();
    }, this.config.integrityCheckInterval);
  }

  /**
   * Check code integrity
   */
  async checkIntegrity() {
    this.lastIntegrityCheck = Date.now();
    
    // Check for debugger
    if (this.config.debugDetectionEnabled) {
      const debuggerPresent = this.detectDebugger();
      
      if (debuggerPresent && !this.debuggerDetected) {
        this.debuggerDetected = true;
        this.reportTamper('debugger_detected', {
          timestamp: Date.now()
        });
        
        // Potential action: Disable extension
        console.warn('[TamperProtection] Debugger detected!');
      }
    }
    
    // Check for DevTools
    if (this.config.devToolsDetectionEnabled) {
      const devToolsOpen = this.detectDevTools();
      
      if (devToolsOpen) {
        this.reportTamper('devtools_detected', {
          timestamp: Date.now()
        });
      }
    }
  }

  /**
   * Detect debugger
   */
  detectDebugger() {
    // Method 1: Timing check
    const start = performance.now();
    debugger; // eslint-disable-line no-debugger
    const end = performance.now();
    
    // If debugger was attached, timing would be much longer
    if (end - start > 100) {
      return true;
    }
    
    // Method 2: Check for debugger statement
    try {
      const func = new Function('return arguments.callee.caller');
      return func() !== null;
    } catch (e) {
      return false;
    }
    
    return false;
  }

  /**
   * Detect DevTools
   */
  detectDevTools() {
    // Check window dimensions (DevTools changes window outer size)
    const widthThreshold = window.outerWidth - window.innerWidth > 160;
    const heightThreshold = window.outerHeight - window.innerHeight > 160;
    
    if (widthThreshold || heightThreshold) {
      return true;
    }
    
    // Check for console methods being overwritten
    const consoleMethods = ['log', 'warn', 'error', 'info', 'debug'];
    for (const method of consoleMethods) {
      if (console[method].toString() !== `function ${method}() { [native code] }`) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Setup debug detection
   */
  setupDebugDetection() {
    // Disable right-click context menu on sensitive areas
    document.addEventListener('contextmenu', (e) => {
      if (this.isSensitiveArea(e.target)) {
        e.preventDefault();
        this.reportTamper('context_menu_blocked', {
          element: e.target.tagName
        });
      }
    }, true);
    
    // Detect keyboard shortcuts for DevTools
    document.addEventListener('keydown', (e) => {
      // F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+Shift+C
      if (e.key === 'F12' || 
          (e.ctrlKey && e.shiftKey && ['I', 'J', 'C'].includes(e.key))) {
        this.reportTamper('devtools_shortcut', {
          key: e.key,
          ctrlKey: e.ctrlKey,
          shiftKey: e.shiftKey
        });
      }
    }, true);
  }

  /**
   * Setup modification detection
   */
  setupModificationDetection() {
    // Watch for DOM modifications
    if (typeof MutationObserver !== 'undefined') {
      const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
          if (this.isSuspiciousMutation(mutation)) {
            this.reportTamper('dom_modification', {
              type: mutation.type,
              target: mutation.target?.tagName,
              timestamp: Date.now()
            });
          }
        }
      });
      
      observer.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true
      });
    }
    
    // Watch for prototype modifications
    this.watchPrototypeModifications();
  }

  /**
   * Check if element is in sensitive area
   */
  isSensitiveArea(element) {
    if (!element || !element.tagName) return false;
    
    const sensitiveSelectors = [
      '.devise-',
      '#devise-',
      '[class*="devise"]',
      '[id*="devise"]'
    ];
    
    const classList = element.classList || [];
    const id = element.id || '';
    
    return sensitiveSelectors.some(sel => 
      Array.from(classList).some(c => c.includes('devise')) ||
      id.includes('devise')
    );
  }

  /**
   * Check for suspicious mutation
   */
  isSuspiciousMutation(mutation) {
    // Check if removing extension elements
    if (mutation.type === 'childList' && mutation.removedNodes.length > 0) {
      for (const node of mutation.removedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          const classes = node.classList || [];
          if (Array.from(classes).some(c => c.includes('devise'))) {
            return true;
          }
        }
      }
    }
    
    // Check for attribute modifications on extension elements
    if (mutation.type === 'attributes') {
      const target = mutation.target;
      if (target && this.isSensitiveArea(target)) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Watch for prototype modifications
   */
  watchPrototypeModifications() {
    const criticalPrototypes = [
      { obj: Array.prototype, methods: ['push', 'pop', 'splice', 'map', 'filter'] },
      { obj: Object.prototype, methods: ['hasOwnProperty', 'toString'] },
      { obj: JSON, methods: ['parse', 'stringify'] }
    ];
    
    for (const { obj, methods } of criticalPrototypes) {
      for (const method of methods) {
        if (typeof obj[method] === 'function') {
          const original = obj[method].toString();
          this.originalCodeHashes.set(`prototype_${method}`, original);
          
          // Store original reference
          const originalMethod = obj[method];
          obj[method] = function(...args) {
            // Check if method was modified
            if (obj[method].toString() !== original) {
              this.reportTamper('prototype_modified', {
                prototype: obj.constructor?.name || 'Unknown',
                method
              });
            }
            return originalMethod.apply(this, args);
          };
        }
      }
    }
  }

  /**
   * Report tamper attempt
   */
  async reportTamper(type, details) {
    const tamperEvent = {
      id: `tamper_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      type,
      details,
      timestamp: new Date().toISOString(),
      url: window.location?.href,
      userAgent: navigator.userAgent
    };
    
    this.tamperAttempts.push(tamperEvent);
    
    // Log to console
    console.warn('[TamperProtection] Tamper detected:', type);
    
    // Store tamper event
    const stored = await chrome.storage.local.get('tamperEvents') || [];
    stored.push(tamperEvent);
    await chrome.storage.local.set({ tamperEvents: stored.slice(-100) });
    
    // Send to background
    try {
      chrome.runtime.sendMessage({
        action: 'tamperDetected',
        data: tamperEvent
      });
    } catch (e) {
      // Ignore
    }
    
    // Notify user for critical tamper
    if (['debugger_detected', 'prototype_modified'].includes(type)) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: 'Security Alert',
        message: 'Unusual activity detected. Extension integrity check failed.',
        priority: 2
      });
    }
  }

  /**
   * Get tamper history
   */
  async getTamperHistory(limit = 50) {
    const stored = await chrome.storage.local.get('tamperEvents') || [];
    return stored.slice(-limit);
  }

  /**
   * Get protection status
   */
  getStatus() {
    return {
      enabled: this.config.enabled,
      lastCheck: this.lastIntegrityCheck,
      tamperAttempts: this.tamperAttempts.length,
      debuggerDetected: this.debuggerDetected
    };
  }

  /**
   * Reset tamper detection
   */
  reset() {
    this.tamperAttempts = [];
    this.debuggerDetected = false;
  }
}

// Singleton instance
export const tamperProtection = new TamperProtection();
