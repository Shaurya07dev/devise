/**
 * Devise Content Monitor - Comprehensive Page Monitoring
 * 
 * This script runs on ALL pages and captures:
 * - Keystrokes (input, textarea, contenteditable)
 * - Form submissions
 * - Clipboard operations (copy, cut, paste)
 * - DOM mutations
 * - Input field values on AI tool pages
 * - Text selections
 * - Mouse interactions
 * - Scroll behavior
 * - Page visibility changes
 */

(function() {
  'use strict';
  
  // Prevent duplicate injection
  if (window.__DEVISE_MONITOR__) return;
  window.__DEVISE_MONITOR__ = true;
  
  // ============================================================
  // CONFIGURATION
  // ============================================================
  
  const CONFIG = {
    // AI tool patterns for enhanced monitoring
    AI_PATTERNS: [
      'chat.openai.com', 'chatgpt.com', 'claude.ai', 'gemini.google.com',
      'perplexity.ai', 'copilot.microsoft.com', 'poe.com', 'character.ai',
      'midjourney.com', 'leonardo.ai', 'runway.com', 'elevenlabs.io',
      'cursor.sh', 'replit.com', 'codeium.com', 'github.com/copilot'
    ],
    
    // Sensitive field patterns (will be flagged but not captured fully)
    SENSITIVE_PATTERNS: [
      'password', 'credit', 'card', 'cvv', 'ssn', 'social.security',
      'api.key', 'secret', 'token', 'auth', 'private'
    ],
    
    // Batch settings
    BATCH_SIZE: 50,
    FLUSH_INTERVAL: 5000, // 5 seconds
    
    // Monitoring flags
    CAPTURE_KEYSTROKES: true,
    CAPTURE_CLIPBOARD: true,
    CAPTURE_FORMS: true,
    CAPTURE_MUTATIONS: true,
    CAPTURE_SELECTIONS: true,
    CAPTURE_SCROLL: false, // Disabled by default (too noisy)
    MASK_SENSITIVE: true
  };
  
  // State
  const state = {
    sessionId: `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    pageLoadTime: Date.now(),
    eventBuffer: [],
    isAIToolPage: false,
    inputTracking: new Map(),
    lastKeystroke: null,
    keystrokeBuffer: [],
    flushTimer: null
  };
  
  // Check if current page is an AI tool
  state.isAIToolPage = CONFIG.AI_PATTERNS.some(pattern => 
    window.location.hostname.includes(pattern)
  );
  
  // ============================================================
  // EVENT TYPES
  // ============================================================
  
  const EVENT_TYPES = {
    KEYSTROKE: 'keystroke',
    INPUT_CHANGE: 'input_change',
    FORM_SUBMIT: 'form_submit',
    CLIPBOARD_COPY: 'clipboard_copy',
    CLIPBOARD_CUT: 'clipboard_cut',
    CLIPBOARD_PASTE: 'clipboard_paste',
    TEXT_SELECTION: 'text_selection',
    DOM_MUTATION: 'dom_mutation',
    PAGE_VISIBILITY: 'page_visibility',
    MOUSE_CLICK: 'mouse_click',
    SCROLL: 'scroll',
    AI_PROMPT: 'ai_prompt',
    AI_RESPONSE: 'ai_response',
    SCREENSHOT: 'screenshot'
  };
  
  // ============================================================
  // UTILITY FUNCTIONS
  // ============================================================
  
  function generateId() {
    return `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  
  function isSensitiveField(element) {
    const name = (element.name || '').toLowerCase();
    const id = (element.id || '').toLowerCase();
    const placeholder = (element.placeholder || '').toLowerCase();
    const ariaLabel = (element.getAttribute('aria-label') || '').toLowerCase();
    const combined = `${name} ${id} ${placeholder} ${ariaLabel}`;
    
    return CONFIG.SENSITIVE_PATTERNS.some(pattern => combined.includes(pattern));
  }
  
  function maskSensitiveData(value, isSensitive) {
    if (!CONFIG.MASK_SENSITIVE || !isSensitive) return value;
    if (!value) return value;
    
    // Show first 2 and last 2 characters
    if (value.length <= 4) return '****';
    return value.substring(0, 2) + '*'.repeat(value.length - 4) + value.substring(value.length - 2);
  }
  
  function getElementSelector(element) {
    if (!element) return null;
    
    // Try ID first
    if (element.id) return `#${element.id}`;
    
    // Try unique attributes
    if (element.name) return `[name="${element.name}"]`;
    if (element.getAttribute('data-testid')) return `[data-testid="${element.getAttribute('data-testid')}"]`;
    if (element.getAttribute('aria-label')) return `[aria-label="${element.getAttribute('aria-label')}"]`;
    
    // Fall back to tag + class
    const classes = element.className ? `.${element.className.trim().split(/\s+/).join('.')}` : '';
    return `${element.tagName.toLowerCase()}${classes}`;
  }
  
  function getElementInfo(element) {
    if (!element) return null;
    
    return {
      tag: element.tagName?.toLowerCase(),
      type: element.type,
      name: element.name,
      id: element.id,
      className: element.className,
      placeholder: element.placeholder,
      selector: getElementSelector(element),
      isSensitive: isSensitiveField(element),
      isVisible: element.offsetParent !== null,
      rect: element.getBoundingClientRect ? {
        x: element.getBoundingClientRect().x,
        y: element.getBoundingClientRect().y,
        width: element.getBoundingClientRect().width,
        height: element.getBoundingClientRect().height
      } : null
    };
  }
  
  function truncateText(text, maxLength = 5000) {
    if (!text) return text;
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...[truncated]';
  }
  
  // ============================================================
  // EVENT BUFFERING
  // ============================================================
  
  function bufferEvent(eventType, data) {
    const event = {
      id: generateId(),
      type: eventType,
      timestamp: Date.now(),
      isoTimestamp: new Date().toISOString(),
      sessionId: state.sessionId,
      url: window.location.href,
      domain: window.location.hostname,
      pathname: window.location.pathname,
      pageTitle: document.title,
      ...data
    };
    
    state.eventBuffer.push(event);
    
    // Flush if buffer is full
    if (state.eventBuffer.length >= CONFIG.BATCH_SIZE) {
      flushEvents();
    }
  }
  
  function flushEvents() {
    if (state.eventBuffer.length === 0) return;
    
    const events = [...state.eventBuffer];
    state.eventBuffer = [];
    
    // Send to background script
    try {
      chrome.runtime.sendMessage({
        action: 'monitoringEvents',
        events: events,
        isAIToolPage: state.isAIToolPage
      }, (response) => {
        if (chrome.runtime.lastError) {
          // Re-add events to buffer if send failed
          state.eventBuffer = [...events, ...state.eventBuffer];
          console.warn('[Devise] Event flush failed:', chrome.runtime.lastError);
        }
      });
    } catch (e) {
      // Extension context might be invalidated
      state.eventBuffer = [...events, ...state.eventBuffer];
    }
  }
  
  // Set up periodic flush
  function startFlushTimer() {
    if (state.flushTimer) clearInterval(state.flushTimer);
    state.flushTimer = setInterval(flushEvents, CONFIG.FLUSH_INTERVAL);
  }
  
  // Flush on page unload
  function flushBeforeUnload() {
    flushEvents();
  }
  
  // ============================================================
  // KEYSTROKE MONITORING
  // ============================================================
  
  function captureKeystroke(event) {
    if (!CONFIG.CAPTURE_KEYSTROKES) return;
    
    const target = event.target;
    if (!target) return;
    
    // Skip if target is not an input field
    const isInput = ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName) ||
                    target.isContentEditable ||
                    target.getAttribute('contenteditable') === 'true';
    
    if (!isInput) return;
    
    const elementInfo = getElementInfo(target);
    const isSensitive = isSensitiveField(target);
    
    // Capture keystroke
    const keystroke = {
      key: event.key,
      code: event.code,
      keyCode: event.keyCode,
      ctrlKey: event.ctrlKey,
      altKey: event.altKey,
      shiftKey: event.shiftKey,
      metaKey: event.metaKey,
      isComposing: event.isComposing,
      element: elementInfo,
      value: maskSensitiveData(target.value, isSensitive),
      valueLength: target.value?.length || 0,
      selectionStart: target.selectionStart,
      selectionEnd: target.selectionEnd
    };
    
    // Detect special keys
    if (event.key === 'Enter') {
      keystroke.isSubmit = true;
    }
    
    bufferEvent(EVENT_TYPES.KEYSTROKE, keystroke);
    
    // Track for AI prompt detection
    if (state.isAIToolPage) {
      trackAIPrompt(target, event);
    }
  }
  
  // ============================================================
  // INPUT CHANGE MONITORING
  // ============================================================
  
  function captureInputChange(event) {
    if (!CONFIG.CAPTURE_FORMS) return;
    
    const target = event.target;
    if (!target) return;
    
    const isSensitive = isSensitiveField(target);
    const elementInfo = getElementInfo(target);
    
    // Track input changes with deduplication
    const inputId = elementInfo.selector || generateId();
    const lastValue = state.inputTracking.get(inputId);
    
    if (lastValue !== target.value) {
      state.inputTracking.set(inputId, target.value);
      
      bufferEvent(EVENT_TYPES.INPUT_CHANGE, {
        element: elementInfo,
        value: maskSensitiveData(target.value, isSensitive),
        valueLength: target.value?.length || 0,
        previousValueLength: lastValue?.length || 0,
        inputType: event.inputType,
        isSensitive: isSensitive
      });
    }
  }
  
  // ============================================================
  // FORM SUBMISSION MONITORING
  // ============================================================
  
  function captureFormSubmit(event) {
    if (!CONFIG.CAPTURE_FORMS) return;
    
    const form = event.target;
    if (!form || form.tagName !== 'FORM') return;
    
    const formData = new FormData(form);
    const data = {};
    
    formData.forEach((value, key) => {
      const isSensitive = CONFIG.SENSITIVE_PATTERNS.some(p => key.toLowerCase().includes(p));
      data[key] = maskSensitiveData(value, isSensitive);
    });
    
    bufferEvent(EVENT_TYPES.FORM_SUBMIT, {
      formAction: form.action,
      formMethod: form.method,
      formId: form.id,
      formName: form.name,
      fieldCount: formData.keys.length,
      data: data
    });
  }
  
  // ============================================================
  // CLIPBOARD MONITORING
  // ============================================================
  
  function captureClipboard(event, action) {
    if (!CONFIG.CAPTURE_CLIPBOARD) return;
    
    let clipboardData = '';
    
    try {
      if (action === 'paste') {
        clipboardData = event.clipboardData?.getData('text') || '';
      } else {
        // For copy/cut, try to get selection
        const selection = window.getSelection();
        clipboardData = selection?.toString() || '';
      }
    } catch (e) {
      clipboardData = '[unable to access]';
    }
    
    bufferEvent(action === 'copy' ? EVENT_TYPES.CLIPBOARD_COPY : 
                action === 'cut' ? EVENT_TYPES.CLIPBOARD_CUT : 
                EVENT_TYPES.CLIPBOARD_PASTE, {
      text: truncateText(clipboardData, 1000),
      textLength: clipboardData.length,
      targetElement: getElementInfo(event.target),
      isSensitive: CONFIG.SENSITIVE_PATTERNS.some(p => clipboardData.toLowerCase().includes(p))
    });
  }
  
  // ============================================================
  // TEXT SELECTION MONITORING
  // ============================================================
  
  function captureSelection() {
    if (!CONFIG.CAPTURE_SELECTIONS) return;
    
    const selection = window.getSelection();
    if (!selection || selection.isCollapsed) return;
    
    const selectedText = selection.toString();
    if (selectedText.length < 3) return; // Ignore very short selections
    
    bufferEvent(EVENT_TYPES.TEXT_SELECTION, {
      text: truncateText(selectedText, 1000),
      textLength: selectedText.length,
      rangeCount: selection.rangeCount,
      anchorElement: getElementInfo(selection.anchorNode?.parentElement)
    });
  }
  
  // ============================================================
  // DOM MUTATION MONITORING
  // ============================================================
  
  function setupMutationObserver() {
    if (!CONFIG.CAPTURE_MUTATIONS) return;
    
    const observer = new MutationObserver((mutations) => {
      // Only capture significant mutations on AI tool pages
      if (!state.isAIToolPage) return;
      
      const significantMutations = mutations.filter(m => {
        // Filter out noise
        const target = m.target;
        if (!target || !target.tagName) return false;
        
        // Focus on specific elements
        const tag = target.tagName.toLowerCase();
        return ['div', 'span', 'p', 'pre', 'code', 'article', 'section'].includes(tag);
      });
      
      if (significantMutations.length > 0) {
        bufferEvent(EVENT_TYPES.DOM_MUTATION, {
          mutationCount: significantMutations.length,
          types: [...new Set(significantMutations.map(m => m.type))],
          addedNodes: significantMutations.reduce((count, m) => count + m.addedNodes.length, 0),
          removedNodes: significantMutations.reduce((count, m) => count + m.removedNodes.length, 0)
        });
      }
    });
    
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: false,
      characterData: true
    });
  }
  
  // ============================================================
  // AI PROMPT DETECTION
  // ============================================================
  
  function trackAIPrompt(element, event) {
    // Detect Enter key in prompt input fields
    if (event.key === 'Enter' && !event.shiftKey) {
      const promptText = element.value || element.textContent;
      
      if (promptText && promptText.length > 0) {
        bufferEvent(EVENT_TYPES.AI_PROMPT, {
          prompt: truncateText(promptText, 2000),
          promptLength: promptText.length,
          element: getElementInfo(element),
          isSensitive: CONFIG.SENSITIVE_PATTERNS.some(p => promptText.toLowerCase().includes(p))
        });
        
        // Clear tracking after prompt submission
        state.inputTracking.clear();
      }
    }
  }
  
  // AI Response detection (for chat interfaces)
  function detectAIResponses() {
    if (!state.isAIToolPage) return;
    
    // Common AI response containers
    const responseSelectors = [
      '[data-testid*="response"]',
      '[data-testid*="answer"]',
      '[class*="response"]',
      '[class*="answer"]',
      '[class*="message"]',
      '.markdown',
      '.prose',
      'article',
      '[role="log"]',
      '[role="article"]'
    ];
    
    // Set up observers for each potential response container
    responseSelectors.forEach(selector => {
      document.querySelectorAll(selector).forEach(el => {
        if (!el.__devise_observed) {
          el.__devise_observed = true;
          
          const observer = new MutationObserver(() => {
            const text = el.textContent || el.innerText;
            if (text && text.length > 50) {
              bufferEvent(EVENT_TYPES.AI_RESPONSE, {
                responseText: truncateText(text, 5000),
                responseLength: text.length,
                container: getElementInfo(el)
              });
            }
          });
          
          observer.observe(el, { childList: true, subtree: true, characterData: true });
        }
      });
    });
  }
  
  // ============================================================
  // PAGE VISIBILITY MONITORING
  // ============================================================
  
  function captureVisibilityChange() {
    bufferEvent(EVENT_TYPES.PAGE_VISIBILITY, {
      visibilityState: document.visibilityState,
      hidden: document.hidden,
      wasVisible: !document.hidden
    });
  }
  
  // ============================================================
  // MOUSE CLICK MONITORING
  // ============================================================
  
  function captureClick(event) {
    const target = event.target;
    if (!target) return;
    
    // Only capture significant clicks on AI tool pages
    if (!state.isAIToolPage) return;
    
    const elementInfo = getElementInfo(target);
    
    // Filter out noise - only capture clicks on interactive elements
    const isInteractive = ['A', 'BUTTON', 'INPUT', 'SELECT', 'TEXTAREA'].includes(target.tagName) ||
                          target.isContentEditable ||
                          target.onclick ||
                          target.getAttribute('role') === 'button';
    
    if (isInteractive) {
      bufferEvent(EVENT_TYPES.MOUSE_CLICK, {
        element: elementInfo,
        text: truncateText(target.textContent?.trim(), 200),
        href: target.href,
        button: event.button,
        ctrlKey: event.ctrlKey,
        altKey: event.altKey,
        shiftKey: event.shiftKey,
        metaKey: event.metaKey
      });
    }
  }
  
  // ============================================================
  // SCREENSHOT CAPTURE
  // ============================================================
  
  function requestScreenshot() {
    chrome.runtime.sendMessage({
      action: 'captureScreenshot',
      url: window.location.href
    });
  }
  
  // ============================================================
  // INITIALIZATION
  // ============================================================
  
  function initialize() {
    console.log('[Devise] Content monitor initializing on:', window.location.href);
    
    // Start flush timer
    startFlushTimer();
    
    // Event listeners
    document.addEventListener('keydown', captureKeystroke, true);
    document.addEventListener('input', captureInputChange, true);
    document.addEventListener('submit', captureFormSubmit, true);
    document.addEventListener('copy', (e) => captureClipboard(e, 'copy'), true);
    document.addEventListener('cut', (e) => captureClipboard(e, 'cut'), true);
    document.addEventListener('paste', (e) => captureClipboard(e, 'paste'), true);
    document.addEventListener('mouseup', () => setTimeout(captureSelection, 100), true);
    document.addEventListener('click', captureClick, true);
    document.addEventListener('visibilitychange', captureVisibilityChange, true);
    
    // Set up mutation observer
    if (document.body) {
      setupMutationObserver();
    } else {
      document.addEventListener('DOMContentLoaded', setupMutationObserver);
    }
    
    // AI response detection
    if (state.isAIToolPage) {
      setTimeout(detectAIResponses, 2000);
    }
    
    // Flush on unload
    window.addEventListener('beforeunload', flushBeforeUnload);
    window.addEventListener('unload', flushBeforeUnload);
    document.addEventListener('pagehide', flushBeforeUnload);
    
    // Initial page load event
    bufferEvent('page_load', {
      referrer: document.referrer,
      viewportWidth: window.innerWidth,
      viewportHeight: window.innerHeight,
      screenWidth: window.screen.width,
      screenHeight: window.screen.height,
      language: navigator.language,
      userAgent: navigator.userAgent,
      cookiesEnabled: navigator.cookieEnabled,
      doNotTrack: navigator.doNotTrack
    });
    
    console.log('[Devise] Content monitor active. AI tool page:', state.isAIToolPage);
  }
  
  // Listen for messages from background
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.action) {
      case 'getMonitoringStatus':
        sendResponse({
          active: true,
          isAIToolPage: state.isAIToolPage,
          eventCount: state.eventBuffer.length,
          sessionId: state.sessionId
        });
        break;
        
      case 'capturePageContent':
        sendResponse({
          title: document.title,
          url: window.location.href,
          content: truncateText(document.body?.innerText, 10000),
          html: truncateText(document.body?.innerHTML, 50000)
        });
        break;
        
      case 'captureScreenshot':
        requestScreenshot();
        sendResponse({ success: true });
        break;
        
      case 'flushEvents':
        flushEvents();
        sendResponse({ success: true });
        break;
        
      default:
        sendResponse({ error: 'Unknown action' });
    }
    return true;
  });
  
  // Start monitoring
  initialize();
  
})();
