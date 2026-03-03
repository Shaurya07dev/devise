/**
 * Devise Policy Engine
 * Controls AI tool access, content filtering, and compliance rules
 */

// Default Policy Configuration
const DEFAULT_POLICIES = {
  // Tool Access Policies
  toolAccess: {
    enabled: true,
    mode: 'allowlist', // 'allowlist', 'blocklist', 'department'
    blockUnknown: false,
    blockByCategory: [],
    allowByCategory: [],
    blocklist: [],
    allowlist: [
      'chat.openai.com',
      'chatgpt.com',
      'claude.ai',
      'gemini.google.com',
      'copilot.microsoft.com',
      'notion.so',
      'grammarly.com',
      'github.com',
      'cursor.sh',
      'figma.com'
    ]
  },
  
  // Content Policies
  contentFilter: {
    enabled: true,
    blockPII: true,
    blockSensitiveKeywords: true,
    blockCodeUpload: false,
    blockFileTypes: ['.exe', '.bat', '.sh', '.ps1'],
    maxFileSize: 10 * 1024 * 1024, // 10MB
    sensitiveKeywords: [
      'confidential', 'internal only', 'restricted', 'classified',
      'trade secret', 'proprietary', 'nda', 'top secret',
      'password', 'credential', 'api key', 'private key'
    ],
    regexPatterns: [
      // SSN pattern
      { name: 'ssn', pattern: '\\d{3}[-\\s]?\\d{2}[-\\s]?\\d{4}', action: 'block' },
      // Credit card
      { name: 'credit_card', pattern: '\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}', action: 'warn' },
      // API keys
      { name: 'api_key', pattern: '(sk-|api[_-]?key)[a-zA-Z0-9_-]{20,}', action: 'block' }
    ]
  },
  
  // Department Policies
  departmentPolicies: {
    Engineering: {
      allowedTools: ['*'],
      blockedTools: [],
      allowCodeUpload: true,
      maxRiskLevel: 'high'
    },
    Product: {
      allowedTools: ['*'],
      blockedTools: [],
      allowCodeUpload: false,
      maxRiskLevel: 'medium'
    },
    Marketing: {
      allowedTools: ['chat.openai.com', 'claude.ai', 'gemini.google.com', 'notion.so'],
      blockedTools: [],
      allowCodeUpload: false,
      maxRiskLevel: 'low'
    },
    Sales: {
      allowedTools: ['chat.openai.com', 'claude.ai', 'notion.so'],
      blockedTools: [],
      allowCodeUpload: false,
      maxRiskLevel: 'low'
    },
    Finance: {
      allowedTools: ['notion.so'],
      blockedTools: ['*'],
      allowCodeUpload: false,
      maxRiskLevel: 'low'
    },
    Legal: {
      allowedTools: ['chat.openai.com', 'claude.ai'],
      blockedTools: [],
      allowCodeUpload: false,
      maxRiskLevel: 'medium'
    },
    HR: {
      allowedTools: ['notion.so'],
      blockedTools: ['*'],
      allowCodeUpload: false,
      maxRiskLevel: 'low'
    }
  },
  
  // Time-based Policies
  timePolicies: {
    enabled: false,
    allowedHours: { start: 8, end: 18 },
    timezone: 'local',
    blockWeekends: false
  },
  
  // Rate Limiting
  rateLimiting: {
    enabled: true,
    maxPromptsPerHour: 100,
    maxPromptsPerDay: 500,
    maxTokensPerDay: 100000,
    cooldownMinutes: 5
  },
  
  // Notification Policies
  notifications: {
    onBlockedAccess: true,
    onPIIDetected: true,
    onSensitiveContent: true,
    onPolicyViolation: true,
    onRateLimitExceeded: true
  },
  
  // Audit Settings
  audit: {
    logAllAccess: true,
    logBlockedAttempts: true,
    logContentAnalysis: true,
    retentionDays: 90
  }
};

/**
 * PolicyEngine Class
 */
export class PolicyEngine {
  constructor() {
    this.policies = null;
    this.violations = [];
    this.rateLimitCounters = new Map();
    this.cache = new Map();
    this.lastUpdate = null;
  }

  /**
   * Initialize policy engine
   */
  async initialize() {
    try {
      // Load policies from storage or use defaults
      const stored = await chrome.storage.local.get(['policies', 'policyVersion']);
      
      if (stored.policies) {
        this.policies = this.mergePolicies(DEFAULT_POLICIES, stored.policies);
      } else {
        this.policies = { ...DEFAULT_POLICIES };
      }
      
      this.lastUpdate = stored.policyVersion || Date.now();
      
      // Start rate limit cleanup
      this.startRateLimitCleanup();
      
      console.log('[PolicyEngine] Initialized');
      return true;
    } catch (error) {
      console.error('[PolicyEngine] Initialization failed:', error);
      this.policies = { ...DEFAULT_POLICIES };
      return false;
    }
  }

  /**
   * Merge custom policies with defaults
   */
  mergePolicies(defaults, custom) {
    return {
      ...defaults,
      ...custom,
      toolAccess: { ...defaults.toolAccess, ...(custom.toolAccess || {}) },
      contentFilter: { ...defaults.contentFilter, ...(custom.contentFilter || {}) },
      departmentPolicies: { ...defaults.departmentPolicies, ...(custom.departmentPolicies || {}) }
    };
  }

  /**
   * Check if tool access is allowed
   */
  checkToolAccess(domain, userInfo = {}) {
    const result = {
      allowed: true,
      reason: null,
      action: 'allow',
      warnings: [],
      policy: null
    };
    
    if (!this.policies.toolAccess.enabled) {
      return result;
    }
    
    const { toolAccess, departmentPolicies } = this.policies;
    const department = userInfo.department || 'default';
    
    // Check department-specific policies first
    const deptPolicy = departmentPolicies[department];
    if (deptPolicy) {
      result.policy = deptPolicy;
      
      // Check if tool is in department blocked list
      if (deptPolicy.blockedTools.includes('*')) {
        if (!deptPolicy.allowedTools.includes(domain) && !deptPolicy.allowedTools.includes('*')) {
          result.allowed = false;
          result.reason = `Tool not allowed for ${department} department`;
          result.action = 'block';
          this.logViolation('tool_blocked_department', domain, userInfo);
          return result;
        }
      }
      
      if (deptPolicy.blockedTools.includes(domain)) {
        result.allowed = false;
        result.reason = `Tool blocked for ${department} department`;
        result.action = 'block';
        this.logViolation('tool_blocked_department', domain, userInfo);
        return result;
      }
    }
    
    // Check global mode
    if (toolAccess.mode === 'allowlist') {
      const isAllowed = toolAccess.allowlist.some(allowed => 
        domain === allowed || domain.includes(allowed)
      );
      
      if (!isAllowed) {
        result.allowed = false;
        result.reason = 'Tool not in allowlist';
        result.action = toolAccess.blockUnknown ? 'block' : 'warn';
        result.warnings.push(`Tool ${domain} is not in the approved list`);
        this.logViolation('tool_not_allowed', domain, userInfo);
      }
    } else if (toolAccess.mode === 'blocklist') {
      const isBlocked = toolAccess.blocklist.some(blocked =>
        domain === blocked || domain.includes(blocked)
      );
      
      if (isBlocked) {
        result.allowed = false;
        result.reason = 'Tool is blocked';
        result.action = 'block';
        this.logViolation('tool_blocked', domain, userInfo);
      }
    }
    
    // Check category blocks
    if (toolAccess.blockByCategory.length > 0) {
      // Would need to look up tool category from config
      // For now, pass through
    }
    
    return result;
  }

  /**
   * Check content against policies
   */
  checkContent(content, context = {}) {
    const result = {
      allowed: true,
      action: 'allow',
      violations: [],
      warnings: [],
      redactedContent: content,
      riskScore: 0,
     piiDetected: false,
      sensitiveDetected: false
    };
    
    if (!this.policies.contentFilter.enabled) {
      return result;
    }
    
    const { contentFilter } = this.policies;
    
    // Check for sensitive keywords
    if (contentFilter.blockSensitiveKeywords) {
      const lowerContent = content.toLowerCase();
      const foundKeywords = contentFilter.sensitiveKeywords.filter(kw => 
        lowerContent.includes(kw.toLowerCase())
      );
      
      if (foundKeywords.length > 0) {
        result.sensitiveDetected = true;
        result.warnings.push(`Sensitive keywords detected: ${foundKeywords.join(', ')}`);
        result.riskScore += foundKeywords.length * 10;
        
        // Redact keywords
        let redacted = result.redactedContent;
        for (const kw of foundKeywords) {
          const regex = new RegExp(kw, 'gi');
          redacted = redacted.replace(regex, '[REDACTED]');
        }
        result.redactedContent = redacted;
      }
    }
    
    // Check regex patterns
    for (const pattern of contentFilter.regexPatterns) {
      const regex = new RegExp(pattern.pattern, 'gi');
      const matches = content.match(regex);
      
      if (matches && matches.length > 0) {
        result.violations.push({
          type: pattern.name,
          action: pattern.action,
          count: matches.length,
          matches: matches.map(m => this.maskValue(m))
        });
        
        if (pattern.action === 'block') {
          result.allowed = false;
          result.action = 'block';
          result.piiDetected = true;
          result.riskScore += 50;
        } else if (pattern.action === 'warn') {
          result.warnings.push(`${pattern.name} pattern detected`);
          result.riskScore += 20;
        }
        
        // Redact matches
        result.redactedContent = result.redactedContent.replace(regex, `[${pattern.name.toUpperCase()}_REDACTED]`);
      }
    }
    
    // Log if violations found
    if (result.violations.length > 0) {
      this.logViolation('content_violation', context.url || 'unknown', {
        violations: result.violations,
        riskScore: result.riskScore
      });
    }
    
    return result;
  }

  /**
   * Check rate limits
   */
  checkRateLimit(userId) {
    const result = {
      allowed: true,
      remaining: { hourly: 0, daily: 0 },
      resetIn: 0,
      reason: null
    };
    
    if (!this.policies.rateLimiting.enabled) {
      return result;
    }
    
    const { maxPromptsPerHour, maxPromptsPerDay, cooldownMinutes } = this.policies.rateLimiting;
    const now = Date.now();
    const hourKey = `${userId}_hour_${Math.floor(now / (60 * 60 * 1000))}`;
    const dayKey = `${userId}_day_${Math.floor(now / (24 * 60 * 60 * 1000))}`;
    
    const hourCount = this.rateLimitCounters.get(hourKey) || 0;
    const dayCount = this.rateLimitCounters.get(dayKey) || 0;
    
    result.remaining.hourly = Math.max(0, maxPromptsPerHour - hourCount);
    result.remaining.daily = Math.max(0, maxPromptsPerDay - dayCount);
    
    if (hourCount >= maxPromptsPerHour) {
      result.allowed = false;
      result.reason = 'Hourly rate limit exceeded';
      result.resetIn = (Math.ceil(now / (60 * 60 * 1000)) * 60 * 60 * 1000) - now;
      return result;
    }
    
    if (dayCount >= maxPromptsPerDay) {
      result.allowed = false;
      result.reason = 'Daily rate limit exceeded';
      result.resetIn = (Math.ceil(now / (24 * 60 * 60 * 1000)) * 24 * 60 * 60 * 1000) - now;
      return result;
    }
    
    return result;
  }

  /**
   * Increment rate limit counter
   */
  incrementRateLimit(userId) {
    const now = Date.now();
    const hourKey = `${userId}_hour_${Math.floor(now / (60 * 60 * 1000))}`;
    const dayKey = `${userId}_day_${Math.floor(now / (24 * 60 * 60 * 1000))}`;
    
    this.rateLimitCounters.set(hourKey, (this.rateLimitCounters.get(hourKey) || 0) + 1);
    this.rateLimitCounters.set(dayKey, (this.rateLimitCounters.get(dayKey) || 0) + 1);
  }

  /**
   * Check time-based access
   */
  checkTimeAccess() {
    if (!this.policies.timePolicies.enabled) {
      return { allowed: true };
    }
    
    const { allowedHours, blockWeekends, timezone } = this.policies.timePolicies;
    const now = new Date();
    const hour = now.getHours();
    const dayOfWeek = now.getDay();
    
    if (blockWeekends && (dayOfWeek === 0 || dayOfWeek === 6)) {
      return {
        allowed: false,
        reason: 'Access blocked on weekends'
      };
    }
    
    if (hour < allowedHours.start || hour >= allowedHours.end) {
      return {
        allowed: false,
        reason: `Access only allowed between ${allowedHours.start}:00 and ${allowedHours.end}:00`
      };
    }
    
    return { allowed: true };
  }

  /**
   * Log policy violation
   */
  logViolation(type, target, details = {}) {
    const violation = {
      id: `viol_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      type,
      target,
      details,
      timestamp: new Date().toISOString()
    };
    
    this.violations.push(violation);
    
    // Keep only last 1000 violations in memory
    if (this.violations.length > 1000) {
      this.violations = this.violations.slice(-1000);
    }
    
    // Store violation
    this.storeViolation(violation);
    
    console.log('[PolicyEngine] Violation logged:', type, target);
    return violation;
  }

  /**
   * Store violation to IndexedDB
   */
  async storeViolation(violation) {
    try {
      const stored = await chrome.storage.local.get('policyViolations');
      const violations = stored.policyViolations || [];
      violations.push(violation);
      
      // Keep only last 500 violations in storage
      const trimmed = violations.slice(-500);
      await chrome.storage.local.set({ policyViolations: trimmed });
    } catch (error) {
      console.error('[PolicyEngine] Failed to store violation:', error);
    }
  }

  /**
   * Get violation history
   */
  async getViolationHistory(limit = 50) {
    try {
      const stored = await chrome.storage.local.get('policyViolations');
      const violations = stored.policyViolations || [];
      return violations.slice(-limit);
    } catch (error) {
      console.error('[PolicyEngine] Failed to get violations:', error);
      return [];
    }
  }

  /**
   * Update policies
   */
  async updatePolicies(newPolicies) {
    this.policies = this.mergePolicies(this.policies, newPolicies);
    await chrome.storage.local.set({
      policies: this.policies,
      policyVersion: Date.now()
    });
    this.lastUpdate = Date.now();
    this.cache.clear();
    console.log('[PolicyEngine] Policies updated');
  }

  /**
   * Get current policies
   */
  getPolicies() {
    return { ...this.policies };
  }

  /**
   * Emergency lockdown - block all AI tools
   */
  async emergencyLockdown(reason = 'Emergency lockdown activated') {
    await this.updatePolicies({
      toolAccess: {
        enabled: true,
        mode: 'blocklist',
        blocklist: ['*'],
        blockUnknown: true
      }
    });
    
    this.logViolation('emergency_lockdown', 'all', { reason });
    
    // Notify user
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'Devise - Emergency Lockdown',
      message: reason,
      priority: 2
    });
  }

  /**
   * Mask sensitive value
   */
  maskValue(value) {
    if (!value || value.length <= 4) return '****';
    return value.substring(0, 2) + '*'.repeat(value.length - 4) + value.substring(value.length - 2);
  }

  /**
   * Start rate limit cleanup timer
   */
  startRateLimitCleanup() {
    // Clean up old counters every hour
    setInterval(() => {
      const now = Date.now();
      for (const [key, value] of this.rateLimitCounters.entries()) {
        // Remove entries older than 24 hours
        const timestamp = parseInt(key.split('_').pop()) * (key.includes('hour') ? 3600000 : 86400000);
        if (now - timestamp > 24 * 60 * 60 * 1000) {
          this.rateLimitCounters.delete(key);
        }
      }
    }, 60 * 60 * 1000);
  }

  /**
   * Generate policy report
   */
  generateReport() {
    return {
      timestamp: new Date().toISOString(),
      policyVersion: this.lastUpdate,
      settings: {
        toolAccessMode: this.policies.toolAccess.mode,
        contentFilterEnabled: this.policies.contentFilter.enabled,
        rateLimitingEnabled: this.policies.rateLimiting.enabled,
        timePoliciesEnabled: this.policies.timePolicies.enabled
      },
      stats: {
        totalViolations: this.violations.length,
        rateLimitCounters: this.rateLimitCounters.size
      }
    };
  }
}

// Singleton instance
export const policyEngine = new PolicyEngine();
