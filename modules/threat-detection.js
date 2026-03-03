/**
 * Devise Threat Detection Module
 * Anomaly detection, shadow AI detection, and security analysis
 */

// Threat Types and Severities
const THREAT_TYPES = {
  // Data Exfiltration
  data_exfiltration: {
    name: 'Data Exfiltration Attempt',
    severity: 'critical',
    description: 'Potential unauthorized data transfer detected'
  },
  bulk_data_copy: {
    name: 'Bulk Data Copy',
    severity: 'high',
    description: 'Large amount of data copied to clipboard'
  },
  sensitive_upload: {
    name: 'Sensitive File Upload',
    severity: 'high',
    description: 'Upload of potentially sensitive files to AI tool'
  },
  
  // Shadow AI
  shadow_ai_access: {
    name: 'Shadow AI Tool Access',
    severity: 'high',
    description: 'Access to unapproved AI tool detected'
  },
  unauthorized_tool: {
    name: 'Unauthorized AI Tool',
    severity: 'medium',
    description: 'AI tool not in approved list'
  },
  
  // Behavioral Anomalies
  unusual_usage_pattern: {
    name: 'Unusual Usage Pattern',
    severity: 'medium',
    description: 'Deviation from normal usage behavior'
  },
  after_hours_access: {
    name: 'After Hours AI Access',
    severity: 'low',
    description: 'AI tool accessed outside normal hours'
  },
  rapid_prompt_submission: {
    name: 'Rapid Prompt Submission',
    severity: 'medium',
    description: 'Unusually high prompt frequency'
  },
  
  // Content Threats
  pii_in_prompt: {
    name: 'PII in AI Prompt',
    severity: 'high',
    description: 'Personally identifiable information detected in prompt'
  },
  credential_exposure: {
    name: 'Credential Exposure',
    severity: 'critical',
    description: 'Potential credentials shared with AI'
  },
  code_leak: {
    name: 'Code Leak Risk',
    severity: 'high',
    description: 'Proprietary code shared with AI'
  },
  
  // Compliance
  policy_violation: {
    name: 'Policy Violation',
    severity: 'medium',
    description: 'Usage violates organizational policy'
  },
  compliance_risk: {
    name: 'Compliance Risk',
    severity: 'high',
    description: 'Activity may violate compliance requirements'
  }
};

// Baseline behavior thresholds
const BEHAVIOR_THRESHOLDS = {
  maxPromptsPerMinute: 10,
  maxPromptsPerHour: 100,
  maxClipboardSize: 100000, // characters
  maxFileSize: 50 * 1024 * 1024, // 50MB
  unusualHourThreshold: { start: 22, end: 6 }, // 10PM - 6AM
  rapidSubmissionMs: 500, // ms between prompts
  maxConsecutiveAITools: 5,
  maxDataVolume: 1024 * 1024 // 1MB in prompts
};

/**
 * ThreatDetector Class
 */
export class ThreatDetector {
  constructor() {
    this.behaviorBaseline = new Map();
    this.sessionMetrics = {
      promptsSubmitted: 0,
      dataVolume: 0,
      clipboardOps: 0,
      fileUploads: 0,
      toolsAccessed: new Set(),
      lastPromptTime: null,
      rapidSubmissions: 0,
      threatsDetected: []
    };
    this.alertQueue = [];
    this.threatHistory = [];
    this.isMonitoring = false;
  }

  /**
   * Initialize threat detection
   */
  async initialize() {
    // Load baseline behavior from storage
    const stored = await chrome.storage.local.get('behaviorBaseline');
    if (stored.behaviorBaseline) {
      this.behaviorBaseline = new Map(Object.entries(stored.behaviorBaseline));
    }
    
    // Load threat history
    const history = await chrome.storage.local.get('threatHistory');
    if (history.threatHistory) {
      this.threatHistory = history.threatHistory;
    }
    
    this.isMonitoring = true;
    console.log('[ThreatDetector] Initialized');
    return true;
  }

  /**
   * Analyze user activity for threats
   */
  analyzeActivity(activity) {
    const threats = [];
    const { type, data, context } = activity;
    
    switch (type) {
      case 'prompt_submitted':
        threats.push(...this.analyzePrompt(data, context));
        break;
      case 'clipboard_copy':
        threats.push(...this.analyzeClipboard(data, context));
        break;
      case 'file_upload':
        threats.push(...this.analyzeFileUpload(data, context));
        break;
      case 'tool_access':
        threats.push(...this.analyzeToolAccess(data, context));
        break;
      case 'page_navigation':
        threats.push(...this.analyzeNavigation(data, context));
        break;
    }
    
    // Update session metrics
    this.updateMetrics(type, data);
    
    // Process threats
    for (const threat of threats) {
      this.processThreat(threat);
    }
    
    return threats;
  }

  /**
   * Analyze prompt for threats
   */
  analyzePrompt(prompt, context) {
    const threats = [];
    const now = Date.now();
    
    // Check for rapid submission
    if (this.sessionMetrics.lastPromptTime) {
      const timeSinceLast = now - this.sessionMetrics.lastPromptTime;
      if (timeSinceLast < BEHAVIOR_THRESHOLDS.rapidSubmissionMs) {
        this.sessionMetrics.rapidSubmissions++;
        if (this.sessionMetrics.rapidSubmissions >= 3) {
          threats.push(this.createThreat('rapid_prompt_submission', {
            submissions: this.sessionMetrics.rapidSubmissions,
            timeWindow: timeSinceLast
          }, context));
        }
      } else {
        this.sessionMetrics.rapidSubmissions = 0;
      }
    }
    this.sessionMetrics.lastPromptTime = now;
    
    // Check prompt volume
    this.sessionMetrics.dataVolume += prompt.length;
    if (this.sessionMetrics.dataVolume > BEHAVIOR_THRESHOLDS.maxDataVolume) {
      threats.push(this.createThreat('data_exfiltration', {
        volume: this.sessionMetrics.dataVolume,
        threshold: BEHAVIOR_THRESHOLDS.maxDataVolume
      }, context));
    }
    
    // Check for PII patterns
    if (this.containsPII(prompt)) {
      threats.push(this.createThreat('pii_in_prompt', {
        detected: true,
        promptLength: prompt.length
      }, context));
    }
    
    // Check for credentials
    if (this.containsCredentials(prompt)) {
      threats.push(this.createThreat('credential_exposure', {
        detected: true
      }, context));
    }
    
    // Check for code patterns
    if (this.containsCode(prompt)) {
      threats.push(this.createThreat('code_leak', {
        detected: true,
        hasCodeBlocks: true
      }, context));
    }
    
    // Check time of access
    const hour = new Date().getHours();
    if (hour >= BEHAVIOR_THRESHOLDS.unusualHourThreshold.start || 
        hour < BEHAVIOR_THRESHOLDS.unusualHourThreshold.end) {
      threats.push(this.createThreat('after_hours_access', {
        hour,
        threshold: BEHAVIOR_THRESHOLDS.unusualHourThreshold
      }, context));
    }
    
    return threats;
  }

  /**
   * Analyze clipboard operations
   */
  analyzeClipboard(data, context) {
    const threats = [];
    
    // Check clipboard size
    if (data.text && data.text.length > BEHAVIOR_THRESHOLDS.maxClipboardSize) {
      threats.push(this.createThreat('bulk_data_copy', {
        size: data.text.length,
        threshold: BEHAVIOR_THRESHOLDS.maxClipboardSize
      }, context));
    }
    
    // Check for sensitive content in clipboard
    if (data.text && this.containsPII(data.text)) {
      threats.push(this.createThreat('data_exfiltration', {
        type: 'clipboard_pii',
        size: data.text.length
      }, context));
    }
    
    return threats;
  }

  /**
   * Analyze file uploads
   */
  analyzeFileUpload(data, context) {
    const threats = [];
    
    // Check file size
    if (data.size > BEHAVIOR_THRESHOLDS.maxFileSize) {
      threats.push(this.createThreat('sensitive_upload', {
        fileName: data.name,
        size: data.size,
        threshold: BEHAVIOR_THRESHOLDS.maxFileSize
      }, context));
    }
    
    // Check file type
    const sensitiveTypes = ['.env', '.pem', '.key', '.secret', '.credentials', '.config'];
    const ext = data.name.substring(data.name.lastIndexOf('.')).toLowerCase();
    if (sensitiveTypes.includes(ext)) {
      threats.push(this.createThreat('credential_exposure', {
        type: 'file_upload',
        fileName: data.name,
        extension: ext
      }, context));
    }
    
    return threats;
  }

  /**
   * Analyze tool access
   */
  analyzeToolAccess(data, context) {
    const threats = [];
    
    // Track tools accessed
    this.sessionMetrics.toolsAccessed.add(data.domain);
    
    // Check for shadow AI (unapproved tools)
    const approvedTools = [
      'chat.openai.com', 'chatgpt.com', 'claude.ai', 
      'gemini.google.com', 'copilot.microsoft.com'
    ];
    
    if (!approvedTools.some(tool => data.domain.includes(tool))) {
      threats.push(this.createThreat('shadow_ai_access', {
        domain: data.domain,
        approved: false
      }, context));
    }
    
    // Check for consecutive different AI tools (potential tool hopping)
    if (this.sessionMetrics.toolsAccessed.size > BEHAVIOR_THRESHOLDS.maxConsecutiveAITools) {
      threats.push(this.createThreat('unusual_usage_pattern', {
        toolsCount: this.sessionMetrics.toolsAccessed.size,
        tools: Array.from(this.sessionMetrics.toolsAccessed)
      }, context));
    }
    
    return threats;
  }

  /**
   * Analyze navigation patterns
   */
  analyzeNavigation(data, context) {
    const threats = [];
    
    // Check for unusual navigation patterns
    // Could detect rapid switching between tools, etc.
    
    return threats;
  }

  /**
   * Create threat object
   */
  createThreat(type, details, context) {
    const threatInfo = THREAT_TYPES[type] || {
      name: type,
      severity: 'medium',
      description: 'Unknown threat type'
    };
    
    return {
      id: `threat_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      type,
      name: threatInfo.name,
      severity: threatInfo.severity,
      description: threatInfo.description,
      details,
      context: {
        url: context?.url,
        tool: context?.tool,
        timestamp: new Date().toISOString()
      },
      acknowledged: false,
      resolved: false
    };
  }

  /**
   * Process detected threat
   */
  async processThreat(threat) {
    // Add to session threats
    this.sessionMetrics.threatsDetected.push(threat);
    
    // Add to history
    this.threatHistory.push(threat);
    if (this.threatHistory.length > 500) {
      this.threatHistory = this.threatHistory.slice(-500);
    }
    
    // Store threat
    await chrome.storage.local.set({ threatHistory: this.threatHistory });
    
    // Add to alert queue
    this.alertQueue.push(threat);
    
    // Send notification for high severity
    if (threat.severity === 'critical' || threat.severity === 'high') {
      this.sendThreatNotification(threat);
    }
    
    console.log('[ThreatDetector] Threat detected:', threat.type, threat.severity);
  }

  /**
   * Send threat notification
   */
  sendThreatNotification(threat) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: `Devise Security Alert: ${threat.name}`,
      message: threat.description,
      priority: threat.severity === 'critical' ? 2 : 1,
      requireInteraction: threat.severity === 'critical'
    });
  }

  /**
   * Check if text contains PII
   */
  containsPII(text) {
    const piiPatterns = [
      /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/, // SSN
      /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/, // Credit card
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, // Email
      /\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/ // Phone
    ];
    
    return piiPatterns.some(pattern => pattern.test(text));
  }

  /**
   * Check if text contains credentials
   */
  containsCredentials(text) {
    const credentialPatterns = [
      /password\s*[=:]\s*\S+/i,
      /api[_-]?key\s*[=:]\s*\S+/i,
      /secret[_-]?key\s*[=:]\s*\S+/i,
      /token\s*[=:]\s*\S+/i,
      /-----BEGIN.*PRIVATE KEY-----/,
      /Bearer\s+[A-Za-z0-9_-]+/,
      /Authorization:\s*Basic/i
    ];
    
    return credentialPatterns.some(pattern => pattern.test(text));
  }

  /**
   * Check if text contains code
   */
  containsCode(text) {
    const codePatterns = [
      /```[\s\S]*?```/,
      /function\s+\w+\s*\(/,
      /class\s+\w+[\s\{]/,
      /import\s+\w+\s+from/,
      /const\s+\w+\s*=/,
      /def\s+\w+\s*\(/,
      /public\s+class/,
      /private\s+\w+/
    ];
    
    return codePatterns.some(pattern => pattern.test(text));
  }

  /**
   * Update session metrics
   */
  updateMetrics(type, data) {
    switch (type) {
      case 'prompt_submitted':
        this.sessionMetrics.promptsSubmitted++;
        break;
      case 'clipboard_copy':
        this.sessionMetrics.clipboardOps++;
        break;
      case 'file_upload':
        this.sessionMetrics.fileUploads++;
        break;
    }
  }

  /**
   * Get risk score for current session
   */
  calculateSessionRiskScore() {
    let score = 0;
    
    const threats = this.sessionMetrics.threatsDetected;
    
    for (const threat of threats) {
      switch (threat.severity) {
        case 'critical': score += 50; break;
        case 'high': score += 25; break;
        case 'medium': score += 10; break;
        case 'low': score += 5; break;
      }
    }
    
    // Add behavioral risk factors
    if (this.sessionMetrics.promptsSubmitted > BEHAVIOR_THRESHOLDS.maxPromptsPerHour) {
      score += 20;
    }
    
    if (this.sessionMetrics.dataVolume > BEHAVIOR_THRESHOLDS.maxDataVolume) {
      score += 30;
    }
    
    return Math.min(100, score);
  }

  /**
   * Get threat summary
   */
  getThreatSummary() {
    const threats = this.sessionMetrics.threatsDetected;
    
    return {
      totalThreats: threats.length,
      critical: threats.filter(t => t.severity === 'critical').length,
      high: threats.filter(t => t.severity === 'high').length,
      medium: threats.filter(t => t.severity === 'medium').length,
      low: threats.filter(t => t.severity === 'low').length,
      riskScore: this.calculateSessionRiskScore(),
      topThreatTypes: this.getTopThreatTypes(threats),
      sessionMetrics: {
        promptsSubmitted: this.sessionMetrics.promptsSubmitted,
        dataVolume: this.sessionMetrics.dataVolume,
        toolsAccessed: this.sessionMetrics.toolsAccessed.size,
        clipboardOps: this.sessionMetrics.clipboardOps,
        fileUploads: this.sessionMetrics.fileUploads
      }
    };
  }

  /**
   * Get top threat types
   */
  getTopThreatTypes(threats) {
    const counts = {};
    for (const threat of threats) {
      counts[threat.type] = (counts[threat.type] || 0) + 1;
    }
    
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([type, count]) => ({ type, count }));
  }

  /**
   * Get threat history
   */
  async getThreatHistory(limit = 50) {
    return this.threatHistory.slice(-limit);
  }

  /**
   * Reset session metrics
   */
  resetSession() {
    this.sessionMetrics = {
      promptsSubmitted: 0,
      dataVolume: 0,
      clipboardOps: 0,
      fileUploads: 0,
      toolsAccessed: new Set(),
      lastPromptTime: null,
      rapidSubmissions: 0,
      threatsDetected: []
    };
    console.log('[ThreatDetector] Session reset');
  }

  /**
   * Acknowledge threat
   */
  async acknowledgeThreat(threatId) {
    const threat = this.threatHistory.find(t => t.id === threatId);
    if (threat) {
      threat.acknowledged = true;
      threat.acknowledgedAt = new Date().toISOString();
      await chrome.storage.local.set({ threatHistory: this.threatHistory });
    }
  }

  /**
   * Resolve threat
   */
  async resolveThreat(threatId, resolution) {
    const threat = this.threatHistory.find(t => t.id === threatId);
    if (threat) {
      threat.resolved = true;
      threat.resolution = resolution;
      threat.resolvedAt = new Date().toISOString();
      await chrome.storage.local.set({ threatHistory: this.threatHistory });
    }
  }

  /**
   * Generate threat report
   */
  generateReport() {
    const summary = this.getThreatSummary();
    
    return {
      generatedAt: new Date().toISOString(),
      summary,
      recentThreats: this.threatHistory.slice(-20),
      recommendations: this.generateRecommendations(summary)
    };
  }

  /**
   * Generate recommendations based on threats
   */
  generateRecommendations(summary) {
    const recommendations = [];
    
    if (summary.critical > 0) {
      recommendations.push({
        priority: 'immediate',
        message: 'Critical threats detected. Review and address immediately.'
      });
    }
    
    if (summary.topThreatTypes.some(t => t.type === 'shadow_ai_access')) {
      recommendations.push({
        priority: 'high',
        message: 'Shadow AI access detected. Update approved tools policy.'
      });
    }
    
    if (summary.sessionMetrics.dataVolume > BEHAVIOR_THRESHOLDS.maxDataVolume) {
      recommendations.push({
        priority: 'medium',
        message: 'High data volume to AI tools. Review data sharing policies.'
      });
    }
    
    return recommendations;
  }
}

// Singleton instance
export const threatDetector = new ThreatDetector();
