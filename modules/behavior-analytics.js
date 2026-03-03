/**
 * Devise Behavior Analytics Module
 * Mouse tracking, heatmaps, scroll depth, and user behavior analysis
 */

/**
 * BehaviorAnalytics Class
 * Tracks and analyzes user behavior on AI tool pages
 */
export class BehaviorAnalytics {
  constructor() {
    this.config = {
      enabled: true,
      sampleRate: 100, // Sample every Nth event
      mouseTrackingEnabled: true,
      scrollTrackingEnabled: true,
      clickTrackingEnabled: true,
      keystrokeTrackingEnabled: true,
      heatmapResolution: 50, // Grid size for heatmap
      sessionTimeoutMs: 30 * 60 * 1000, // 30 minutes
      maxEventsInMemory: 10000,
      flushIntervalMs: 30000 // 30 seconds
    };
    
    this.sessionData = {
      id: null,
      startTime: null,
      url: null,
      pageTitle: null,
      events: [],
      heatmapData: null,
      scrollData: null,
      clickData: null,
      keystrokeData: null,
      metrics: null
    };
    
    this.heatmapGrid = new Map();
    this.scrollMilestones = new Set();
    this.clickCounts = new Map();
    this.keystrokeTimings = [];
    this.eventCount = 0;
    this.flushTimer = null;
  }

  /**
   * Initialize behavior analytics
   */
  async initialize() {
    this.startNewSession();
    this.setupEventListeners();
    this.startFlushTimer();
    
    console.log('[BehaviorAnalytics] Initialized');
    return true;
  }

  /**
   * Start new session
   */
  startNewSession() {
    this.sessionData = {
      id: `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      startTime: Date.now(),
      url: window.location.href,
      pageTitle: document.title,
      events: [],
      heatmapData: null,
      scrollData: { maxScroll: 0, milestones: [] },
      clickData: { totalClicks: 0, elementClicks: {} },
      keystrokeData: { count: 0, wpm: 0, timingDistribution: [] },
      metrics: this.initMetrics()
    };
    
    this.heatmapGrid = new Map();
    this.scrollMilestones = new Set();
    this.clickCounts = new Map();
    this.keystrokeTimings = [];
    this.eventCount = 0;
  }

  /**
   * Initialize metrics object
   */
  initMetrics() {
    return {
      totalTimeOnPage: 0,
      activeTimeOnPage: 0,
      scrollDepth: 0,
      maxScrollDepth: 0,
      mouseDistance: 0,
      clickCount: 0,
      keystrokeCount: 0,
      wordsTyped: 0,
      estimatedWPM: 0,
      focusEvents: 0,
      blurEvents: 0,
      pageVisibilityChanges: 0,
      interactionRate: 0,
      engagementScore: 0
    };
  }

  /**
   * Setup event listeners
   */
  setupEventListeners() {
    // Mouse tracking
    if (this.config.mouseTrackingEnabled) {
      document.addEventListener('mousemove', this.handleMouseMove.bind(this), { passive: true });
      document.addEventListener('mouseenter', this.handleMouseEnter.bind(this), { passive: true });
      document.addEventListener('mouseleave', this.handleMouseLeave.bind(this), { passive: true });
    }
    
    // Scroll tracking
    if (this.config.scrollTrackingEnabled) {
      document.addEventListener('scroll', this.handleScroll.bind(this), { passive: true });
    }
    
    // Click tracking
    if (this.config.clickTrackingEnabled) {
      document.addEventListener('click', this.handleClick.bind(this), { passive: true });
      document.addEventListener('contextmenu', this.handleRightClick.bind(this), { passive: true });
    }
    
    // Keystroke tracking
    if (this.config.keystrokeTrackingEnabled) {
      document.addEventListener('keydown', this.handleKeystroke.bind(this), { passive: true });
    }
    
    // Focus/blur tracking
    window.addEventListener('focus', this.handleFocus.bind(this));
    window.addEventListener('blur', this.handleBlur.bind(this));
    
    // Visibility tracking
    document.addEventListener('visibilitychange', this.handleVisibilityChange.bind(this));
    
    // Page unload
    window.addEventListener('beforeunload', this.handleUnload.bind(this));
    window.addEventListener('pagehide', this.handleUnload.bind(this));
  }

  /**
   * Handle mouse movement
   */
  handleMouseMove(event) {
    if (++this.eventCount % this.config.sampleRate !== 0) return;
    
    const { clientX, clientY, pageX, pageY } = event;
    
    // Update heatmap grid
    const gridX = Math.floor(clientX / this.config.heatmapResolution);
    const gridY = Math.floor(clientY / this.config.heatmapResolution);
    const gridKey = `${gridX},${gridY}`;
    
    this.heatmapGrid.set(gridKey, (this.heatmapGrid.get(gridKey) || 0) + 1);
    
    // Calculate mouse distance
    if (this.lastMousePos) {
      const dx = clientX - this.lastMousePos.x;
      const dy = clientY - this.lastMousePos.y;
      this.sessionData.metrics.mouseDistance += Math.sqrt(dx * dx + dy * dy);
    }
    
    this.lastMousePos = { x: clientX, y: clientY };
    
    // Buffer event
    this.bufferEvent('mousemove', {
      x: clientX,
      y: clientY,
      pageX,
      pageY,
      timestamp: Date.now()
    });
  }

  /**
   * Handle mouse enter
   */
  handleMouseEnter(event) {
    this.bufferEvent('mouseenter', {
      timestamp: Date.now()
    });
  }

  /**
   * Handle mouse leave
   */
  handleMouseLeave(event) {
    this.bufferEvent('mouseleave', {
      timestamp: Date.now()
    });
  }

  /**
   * Handle scroll
   */
  handleScroll(event) {
    const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
    const scrollHeight = document.documentElement.scrollHeight - window.innerHeight;
    const scrollPercent = scrollHeight > 0 ? Math.round((scrollTop / scrollHeight) * 100) : 0;
    
    // Update scroll data
    this.sessionData.scrollData.maxScroll = Math.max(this.sessionData.scrollData.maxScroll, scrollTop);
    this.sessionData.metrics.scrollDepth = scrollPercent;
    this.sessionData.metrics.maxScrollDepth = Math.max(this.sessionData.metrics.maxScrollDepth, scrollPercent);
    
    // Track milestones (25%, 50%, 75%, 100%)
    const milestones = [25, 50, 75, 100];
    for (const milestone of milestones) {
      if (scrollPercent >= milestone && !this.scrollMilestones.has(milestone)) {
        this.scrollMilestones.add(milestone);
        this.sessionData.scrollData.milestones.push({
          percent: milestone,
          timestamp: Date.now()
        });
        
        this.bufferEvent('scroll_milestone', {
          percent: milestone,
          scrollTop
        });
      }
    }
    
    // Buffer scroll event (sampled)
    if (++this.eventCount % (this.config.sampleRate * 10) === 0) {
      this.bufferEvent('scroll', {
        scrollTop,
        scrollPercent,
        scrollHeight: document.documentElement.scrollHeight
      });
    }
  }

  /**
   * Handle click
   */
  handleClick(event) {
    const { clientX, clientY, target } = event;
    
    // Get element info
    const elementInfo = this.getElementInfo(target);
    
    // Update click counts
    const elementKey = elementInfo.selector || 'unknown';
    this.clickCounts.set(elementKey, (this.clickCounts.get(elementKey) || 0) + 1);
    
    this.sessionData.clickData.totalClicks++;
    this.sessionData.clickData.elementClicks[elementKey] = 
      (this.sessionData.clickData.elementClicks[elementKey] || 0) + 1;
    
    this.sessionData.metrics.clickCount++;
    
    this.bufferEvent('click', {
      x: clientX,
      y: clientY,
      element: elementInfo,
      button: event.button,
      timestamp: Date.now()
    });
  }

  /**
   * Handle right click
   */
  handleRightClick(event) {
    this.bufferEvent('right_click', {
      x: event.clientX,
      y: event.clientY,
      timestamp: Date.now()
    });
  }

  /**
   * Handle keystroke
   */
  handleKeystroke(event) {
    const now = Date.now();
    
    this.sessionData.metrics.keystrokeCount++;
    this.sessionData.keystrokeData.count++;
    
    // Track timing for WPM calculation
    this.keystrokeTimings.push(now);
    
    // Keep only last 100 timings
    if (this.keystrokeTimings.length > 100) {
      this.keystrokeTimings.shift();
    }
    
    // Calculate WPM (assuming average word length of 5)
    if (this.keystrokeTimings.length >= 5) {
      const timeDiff = now - this.keystrokeTimings[0];
      if (timeDiff > 0) {
        const keystrokesPerMinute = (this.keystrokeTimings.length / timeDiff) * 60000;
        this.sessionData.metrics.estimatedWPM = Math.round(keystrokesPerMinute / 5);
        this.sessionData.keystrokeData.wpm = this.sessionData.metrics.estimatedWPM;
      }
    }
    
    // Buffer event (sampled)
    if (this.eventCount++ % (this.config.sampleRate * 5) === 0) {
      this.bufferEvent('keystroke', {
        key: event.key.length === 1 ? '*' : event.key, // Mask actual keys
        timestamp: now
      });
    }
  }

  /**
   * Handle focus
   */
  handleFocus() {
    this.sessionData.metrics.focusEvents++;
    this.bufferEvent('focus', { timestamp: Date.now() });
  }

  /**
   * Handle blur
   */
  handleBlur() {
    this.sessionData.metrics.blurEvents++;
    this.bufferEvent('blur', { timestamp: Date.now() });
  }

  /**
   * Handle visibility change
   */
  handleVisibilityChange() {
    this.sessionData.metrics.pageVisibilityChanges++;
    this.bufferEvent('visibility_change', {
      hidden: document.hidden,
      timestamp: Date.now()
    });
  }

  /**
   * Handle page unload
   */
  handleUnload() {
    this.flush();
    this.sendData();
  }

  /**
   * Get element information
   */
  getElementInfo(element) {
    if (!element || !element.tagName) return { selector: 'unknown' };
    
    const info = {
      tag: element.tagName.toLowerCase(),
      id: element.id || null,
      classes: element.className ? element.className.split(' ') : [],
      type: element.type || null,
      name: element.name || null,
      placeholder: element.placeholder || null,
      text: element.textContent ? element.textContent.trim().substring(0, 50) : null,
      href: element.href || null,
      selector: null
    };
    
    // Generate CSS selector
    if (element.id) {
      info.selector = `#${element.id}`;
    } else if (element.name) {
      info.selector = `[name="${element.name}"]`;
    } else if (info.classes.length > 0) {
      info.selector = `${info.tag}.${info.classes.slice(0, 2).join('.')}`;
    } else {
      info.selector = info.tag;
    }
    
    return info;
  }

  /**
   * Buffer event
   */
  bufferEvent(type, data) {
    if (!this.config.enabled) return;
    
    const event = {
      type,
      ...data,
      sessionId: this.sessionData.id,
      url: window.location.href
    };
    
    this.sessionData.events.push(event);
    
    // Limit events in memory
    if (this.sessionData.events.length > this.config.maxEventsInMemory) {
      this.sessionData.events = this.sessionData.events.slice(-this.config.maxEventsInMemory);
    }
  }

  /**
   * Start flush timer
   */
  startFlushTimer() {
    this.flushTimer = setInterval(() => {
      this.flush();
    }, this.config.flushIntervalMs);
  }

  /**
   * Flush data to storage
   */
  async flush() {
    if (this.sessionData.events.length === 0) return;
    
    // Calculate engagement score
    this.calculateEngagementScore();
    
    // Update session metrics
    this.sessionData.metrics.totalTimeOnPage = Date.now() - this.sessionData.startTime;
    
    // Convert heatmap to serializable format
    this.sessionData.heatmapData = Object.fromEntries(this.heatmapGrid);
    
    // Prepare data
    const data = {
      ...this.sessionData,
      timestamp: Date.now()
    };
    
    // Send to background
    try {
      chrome.runtime.sendMessage({
        action: 'behaviorAnalytics',
        data
      });
    } catch (e) {
      console.warn('[BehaviorAnalytics] Failed to send data:', e);
    }
    
    console.log('[BehaviorAnalytics] Flushed', this.sessionData.events.length, 'events');
  }

  /**
   * Send data to backend
   */
  async sendData() {
    this.flush();
    
    // Store locally
    try {
      const stored = await chrome.storage.local.get('behaviorData');
      const allData = stored.behaviorData || [];
      allData.push(this.sessionData);
      
      // Keep only last 100 sessions
      const trimmed = allData.slice(-100);
      await chrome.storage.local.set({ behaviorData: trimmed });
    } catch (e) {
      console.warn('[BehaviorAnalytics] Failed to store data:', e);
    }
  }

  /**
   * Calculate engagement score
   */
  calculateEngagementScore() {
    const metrics = this.sessionData.metrics;
    
    // Base score components
    const timeScore = Math.min(metrics.totalTimeOnPage / 60000, 10) * 5; // Max 50 points for time
    const scrollScore = metrics.maxScrollDepth / 2; // Max 50 points for scroll
    const clickScore = Math.min(metrics.clickCount, 50); // Max 50 points for clicks
    const keystrokeScore = Math.min(metrics.keystrokeCount / 2, 50); // Max 50 points for keystrokes
    
    // Calculate interaction rate
    const totalTime = Date.now() - this.sessionData.startTime;
    if (totalTime > 0) {
      metrics.interactionRate = ((metrics.clickCount + metrics.keystrokeCount) / totalTime) * 60000;
    }
    
    // Total engagement score (0-100)
    metrics.engagementScore = Math.min(100, Math.round(
      (timeScore * 0.2) +
      (scrollScore * 0.2) +
      (clickScore * 0.3) +
      (keystrokeScore * 0.3)
    ));
    
    return metrics.engagementScore;
  }

  /**
   * Get heatmap data
   */
  getHeatmapData() {
    const data = [];
    
    for (const [key, count] of this.heatmapGrid.entries()) {
      const [x, y] = key.split(',').map(Number);
      data.push({
        x: x * this.config.heatmapResolution,
        y: y * this.config.heatmapResolution,
        count,
        intensity: count
      });
    }
    
    return data;
  }

  /**
   * Get session summary
   */
  getSessionSummary() {
    return {
      sessionId: this.sessionData.id,
      url: this.sessionData.url,
      duration: Date.now() - this.sessionData.startTime,
      metrics: { ...this.sessionData.metrics },
      eventCount: this.sessionData.events.length,
      heatmapPoints: this.heatmapGrid.size,
      scrollMilestones: Array.from(this.scrollMilestones),
      topClickedElements: this.getTopClickedElements(5)
    };
  }

  /**
   * Get top clicked elements
   */
  getTopClickedElements(limit = 5) {
    return Array.from(this.clickCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([selector, count]) => ({ selector, count }));
  }

  /**
   * Reset session
   */
  reset() {
    this.flush();
    this.startNewSession();
  }

  /**
   * Enable/disable tracking
   */
  setEnabled(enabled) {
    this.config.enabled = enabled;
  }

  /**
   * Update configuration
   */
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Cleanup
   */
  cleanup() {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
    }
    
    this.flush();
  }
}

// Singleton instance
export const behaviorAnalytics = new BehaviorAnalytics();
