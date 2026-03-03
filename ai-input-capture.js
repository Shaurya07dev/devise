/**
 * Devise AI Input Capture - Specialized AI Tool Monitoring
 * 
 * This script specifically targets AI tool interfaces to capture:
 * - Prompts sent to AI assistants
 * - AI responses received
 * - Conversation history
 * - Model selections
 * - Token usage indicators
 * - File uploads
 */

(function() {
  'use strict';
  
  // Prevent duplicate injection
  if (window.__DEVISE_AI_CAPTURE__) return;
  window.__DEVISE_AI_CAPTURE__ = true;
  
  // ============================================================
  // AI TOOL CONFIGURATIONS
  // ============================================================
  
  const AI_CONFIGS = {
    'chat.openai.com': {
      name: 'ChatGPT',
      promptSelector: '#prompt-textarea, textarea[placeholder*="Message"], div[contenteditable="true"]',
      responseSelector: '[data-message-author-role="assistant"], .markdown',
      submitSelector: 'button[data-testid="send-button"]',
      conversationContainer: '[data-testid="conversation-turn"]',
      modelSelector: '[data-testid="model-selector"]'
    },
    'chatgpt.com': {
      name: 'ChatGPT',
      promptSelector: '#prompt-textarea, textarea[placeholder*="Message"], div[contenteditable="true"]',
      responseSelector: '[data-message-author-role="assistant"], .markdown',
      submitSelector: 'button[data-testid="send-button"]',
      conversationContainer: '[data-testid="conversation-turn"]',
      modelSelector: '[data-testid="model-selector"]'
    },
    'claude.ai': {
      name: 'Claude',
      promptSelector: 'div[contenteditable="true"], textarea',
      responseSelector: '[data-testid="assistant-message"], .prose',
      submitSelector: 'button[aria-label="Send"]',
      conversationContainer: '[data-testid="conversation"]',
      modelSelector: '[class*="model-selector"]'
    },
    'gemini.google.com': {
      name: 'Gemini',
      promptSelector: 'textarea, div[contenteditable="true"]',
      responseSelector: '[class*="response"], .markdown',
      submitSelector: 'button[aria-label*="Send"]',
      conversationContainer: '[class*="conversation"]'
    },
    'perplexity.ai': {
      name: 'Perplexity',
      promptSelector: 'textarea, input[type="text"]',
      responseSelector: '[class*="answer"], .prose',
      submitSelector: 'button[type="submit"]',
      conversationContainer: '[class*="thread"]'
    },
    'copilot.microsoft.com': {
      name: 'Microsoft Copilot',
      promptSelector: 'textarea, input[type="text"]',
      responseSelector: '[class*="response"], [class*="answer"]',
      submitSelector: 'button[type="submit"]'
    },
    'poe.com': {
      name: 'Poe',
      promptSelector: 'textarea, div[contenteditable="true"]',
      responseSelector: '[class*="message"], [class*="response"]',
      submitSelector: 'button[type="submit"]'
    }
  };
  
  // Current AI tool configuration
  const currentHost = window.location.hostname;
  const aiConfig = Object.entries(AI_CONFIGS).find(([domain]) => 
    currentHost.includes(domain)
  )?.[1];
  
  if (!aiConfig) {
    console.log('[Devise] Not an AI tool page, skipping specialized capture');
    return;
  }
  
  console.log('[Devise] AI tool detected:', aiConfig.name);
  
  // ============================================================
  // STATE
  // ============================================================
  
  const state = {
    lastPrompt: '',
    lastResponse: '',
    conversationHistory: [],
    pendingPrompts: new Map(),
    observers: [],
    isCapturing: true
  };
  
  // ============================================================
  // UTILITY FUNCTIONS
  // ============================================================
  
  function generateId() {
    return `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  
  function truncateText(text, maxLength = 5000) {
    if (!text) return '';
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...[truncated]';
  }
  
  function extractText(element) {
    if (!element) return '';
    return element.value || element.textContent || element.innerText || '';
  }
  
  function captureElementContent(selector, description) {
    const element = document.querySelector(selector);
    if (!element) return null;
    
    return {
      text: truncateText(extractText(element)),
      html: truncateText(element.innerHTML, 10000),
      tagName: element.tagName,
      className: element.className,
      id: element.id
    };
  }
  
  function sendToBackground(eventType, data) {
    try {
      chrome.runtime.sendMessage({
        action: 'aiInteraction',
        tool: aiConfig.name,
        type: eventType,
        timestamp: Date.now(),
        url: window.location.href,
        ...data
      });
    } catch (e) {
      console.error('[Devise] Failed to send to background:', e);
    }
  }
  
  // ============================================================
  // PROMPT CAPTURE
  // ============================================================
  
  function capturePrompt() {
    const promptElement = document.querySelector(aiConfig.promptSelector);
    if (!promptElement) return;
    
    const promptText = extractText(promptElement).trim();
    
    // Skip if empty or same as last
    if (!promptText || promptText === state.lastPrompt) return;
    
    state.lastPrompt = promptText;
    
    // Create prompt ID for tracking
    const promptId = generateId();
    state.pendingPrompts.set(promptId, {
      text: promptText,
      timestamp: Date.now(),
      sent: false
    });
    
    sendToBackground('prompt_captured', {
      promptId,
      prompt: truncateText(promptText, 5000),
      promptLength: promptText.length,
      elementInfo: {
        tag: promptElement.tagName,
        type: promptElement.type,
        placeholder: promptElement.placeholder,
        id: promptElement.id,
        className: promptElement.className
      }
    });
    
    // Track when prompt is submitted
    trackPromptSubmission(promptId, promptText);
  }
  
  function trackPromptSubmission(promptId, promptText) {
    const submitButton = document.querySelector(aiConfig.submitSelector);
    
    if (submitButton) {
      const originalHandler = submitButton.onclick;
      
      submitButton.addEventListener('click', () => {
        setTimeout(() => {
          if (state.pendingPrompts.has(promptId)) {
            const promptData = state.pendingPrompts.get(promptId);
            promptData.sent = true;
            promptData.sentAt = Date.now();
            
            sendToBackground('prompt_submitted', {
              promptId,
              prompt: truncateText(promptText, 5000)
            });
            
            // Start watching for response
            watchForResponse(promptId);
          }
        }, 100);
      }, { once: false });
    }
    
    // Also track Enter key submission
    const promptElement = document.querySelector(aiConfig.promptSelector);
    if (promptElement) {
      promptElement.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
          setTimeout(() => {
            if (state.pendingPrompts.has(promptId)) {
              const promptData = state.pendingPrompts.get(promptId);
              promptData.sent = true;
              promptData.sentAt = Date.now();
              
              sendToBackground('prompt_submitted', {
                promptId,
                prompt: truncateText(promptText, 5000)
              });
              
              watchForResponse(promptId);
            }
          }, 100);
        }
      });
    }
  }
  
  // ============================================================
  // RESPONSE CAPTURE
  // ============================================================
  
  function watchForResponse(promptId) {
    const responseSelector = aiConfig.responseSelector;
    if (!responseSelector) return;
    
    let attempts = 0;
    const maxAttempts = 60; // 30 seconds max
    const checkInterval = 500;
    
    const checkForResponse = () => {
      attempts++;
      
      const responseElements = document.querySelectorAll(responseSelector);
      const lastResponse = responseElements[responseElements.length - 1];
      
      if (lastResponse) {
        const responseText = extractText(lastResponse).trim();
        
        if (responseText && responseText !== state.lastResponse && responseText.length > 10) {
          // Found new response
          state.lastResponse = responseText;
          
          sendToBackground('response_captured', {
            promptId,
            response: truncateText(responseText, 10000),
            responseLength: responseText.length,
            responseHtml: truncateText(lastResponse.innerHTML, 20000)
          });
          
          // Update conversation history
          state.conversationHistory.push({
            role: 'user',
            content: state.pendingPrompts.get(promptId)?.text || ''
          });
          state.conversationHistory.push({
            role: 'assistant',
            content: responseText
          });
          
          state.pendingPrompts.delete(promptId);
          return;
        }
      }
      
      if (attempts < maxAttempts) {
        setTimeout(checkForResponse, checkInterval);
      } else {
        sendToBackground('response_timeout', { promptId });
      }
    };
    
    // Start checking after a short delay
    setTimeout(checkForResponse, 1000);
  }
  
  // ============================================================
  // CONVERSATION CAPTURE
  // ============================================================
  
  function captureFullConversation() {
    const containerSelector = aiConfig.conversationContainer;
    if (!containerSelector) return;
    
    const containers = document.querySelectorAll(containerSelector);
    const conversation = [];
    
    containers.forEach((container, index) => {
      // Try to determine if this is user or assistant message
      const isUser = container.querySelector('[data-message-author-role="user"]') ||
                     container.className.includes('user') ||
                     container.getAttribute('data-author') === 'user';
      
      const isAssistant = container.querySelector('[data-message-author-role="assistant"]') ||
                          container.className.includes('assistant') ||
                          container.getAttribute('data-author') === 'assistant';
      
      const text = extractText(container).trim();
      
      if (text) {
        conversation.push({
          index,
          role: isUser ? 'user' : isAssistant ? 'assistant' : 'unknown',
          text: truncateText(text, 5000),
          timestamp: Date.now()
        });
      }
    });
    
    if (conversation.length > 0) {
      sendToBackground('conversation_captured', {
        messageCount: conversation.length,
        conversation: conversation
      });
    }
  }
  
  // ============================================================
  // MODEL SELECTION CAPTURE
  // ============================================================
  
  function captureModelSelection() {
    const modelSelector = aiConfig.modelSelector;
    if (!modelSelector) return;
    
    const modelElement = document.querySelector(modelSelector);
    if (!modelElement) return;
    
    const modelName = extractText(modelElement).trim();
    
    if (modelName) {
      sendToBackground('model_selected', {
        model: modelName,
        element: {
          tag: modelElement.tagName,
          text: modelName
        }
      });
    }
  }
  
  // ============================================================
  // FILE UPLOAD CAPTURE
  // ============================================================
  
  function monitorFileUploads() {
    const fileInputs = document.querySelectorAll('input[type="file"]');
    
    fileInputs.forEach(input => {
      input.addEventListener('change', (e) => {
        const files = e.target.files;
        if (!files || files.length === 0) return;
        
        const fileList = Array.from(files).map(file => ({
          name: file.name,
          size: file.size,
          type: file.type,
          lastModified: file.lastModified
        }));
        
        sendToBackground('file_uploaded', {
          files: fileList,
          fileCount: files.length,
          totalSize: Array.from(files).reduce((sum, f) => sum + f.size, 0)
        });
      });
    });
  }
  
  // ============================================================
  // MUTATION OBSERVER FOR DYNAMIC CONTENT
  // ============================================================
  
  function setupObservers() {
    // Observe prompt input for changes
    const promptElement = document.querySelector(aiConfig.promptSelector);
    if (promptElement) {
      const promptObserver = new MutationObserver(() => {
        capturePrompt();
      });
      
      promptObserver.observe(promptElement, {
        childList: true,
        subtree: true,
        characterData: true
      });
      
      state.observers.push(promptObserver);
    }
    
    // Observe response container for new responses
    if (aiConfig.responseSelector) {
      const responseObserver = new MutationObserver((mutations) => {
        mutations.forEach(mutation => {
          mutation.addedNodes.forEach(node => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              const text = extractText(node);
              if (text && text.length > 10 && text !== state.lastResponse) {
                state.lastResponse = text;
                
                sendToBackground('response_streaming', {
                  text: truncateText(text, 5000),
                  isStreaming: true
                });
              }
            }
          });
        });
      });
      
      responseObserver.observe(document.body, {
        childList: true,
        subtree: true
      });
      
      state.observers.push(responseObserver);
    }
  }
  
  // ============================================================
  // PERIODIC CAPTURE
  // ============================================================
  
  function startPeriodicCapture() {
    // Capture conversation every 30 seconds
    setInterval(() => {
      captureFullConversation();
    }, 30000);
    
    // Check model selection every minute
    setInterval(() => {
      captureModelSelection();
    }, 60000);
  }
  
  // ============================================================
  // INITIALIZATION
  // ============================================================
  
  function initialize() {
    console.log('[Devise] Initializing AI capture for:', aiConfig.name);
    
    // Wait for page to be fully loaded
    const startCapture = () => {
      capturePrompt();
      monitorFileUploads();
      setupObservers();
      startPeriodicCapture();
      
      // Initial captures
      setTimeout(() => {
        captureFullConversation();
        captureModelSelection();
      }, 2000);
    };
    
    if (document.readyState === 'complete') {
      startCapture();
    } else {
      window.addEventListener('load', startCapture);
    }
    
    // Handle dynamic page changes (SPA)
    let lastUrl = window.location.href;
    new MutationObserver(() => {
      if (window.location.href !== lastUrl) {
        lastUrl = window.location.href;
        console.log('[Devise] URL changed, reinitializing capture');
        setTimeout(startCapture, 1000);
      }
    }).observe(document.body, { childList: true, subtree: true });
  }
  
  // Listen for messages from background
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.action) {
      case 'captureCurrentPrompt':
        const promptElement = document.querySelector(aiConfig.promptSelector);
        sendResponse({
          prompt: promptElement ? extractText(promptElement) : null
        });
        break;
        
      case 'captureCurrentConversation':
        sendResponse({
          history: state.conversationHistory,
          pendingPrompts: Array.from(state.pendingPrompts.entries())
        });
        break;
        
      case 'toggleCapture':
        state.isCapturing = !state.isCapturing;
        sendResponse({ capturing: state.isCapturing });
        break;
        
      default:
        sendResponse({ error: 'Unknown action' });
    }
    return true;
  });
  
  initialize();
  
})();
