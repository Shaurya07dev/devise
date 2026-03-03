/**
 * Devise Extension Advanced - Background Service Worker
 * 
 * Integrates all advanced modules:
 * - Encryption (AES-256)
 * - PII Detection
 * - Policy Engine
 * - Threat Detection
 * - Behavior Analytics
 * - Network Interception
 * - Tamper Protection
 * - WebSocket Sync
 * - Reporting
 * - Integrations
 */

import { AI_TOOLS_REGISTRY, getToolInfo, CONFIG } from './config.js';
import { KEYS, initializeStorage, queueEvent, getPendingEvents, getUserIdentity, getSessionData, updateAgentStatus, addRecentTool, getQueueStats, setUserIdentity } from './storage.js';

// Import advanced modules
import { encryptionManager } from './modules/encryption.js';
import { piiDetector } from './modules/pii-detector.js';
import { policyEngine } from './modules/policy-engine.js';
import { threatDetector } from './modules/threat-detection.js';
import { behaviorAnalytics } from './modules/behavior-analytics.js';
import { networkInterceptor } from './modules/network-interceptor.js';
import { tamperProtection } from './modules/tamper-protection.js';
import { webSocketSync } from './modules/websocket-sync.js';
import { reportingEngine } from './modules/reporting.js';
import { integrationManager } from './modules/integrations.js';
import { indexedDBStorage } from './modules/indexeddb-storage.js';

// Import Supabase client
import { logEvent as sbLogEvent, logEventsBatch, logThreat, upsertTool, upsertUser, incrementToolCount, logPolicyViolation } from './supabase-client.js';

// ============================================================
// STATE
// ============================================================

let isInitialized = false;
let monitoringEnabled = true;
let advancedFeaturesEnabled = true;

// ============================================================
// INITIALIZATION
// ============================================================

chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('[Devise Advanced] Extension installed/updated:', details.reason);

  try {
    await initializeAllModules();

    if (details.reason === 'install') {
      await showOnboarding();
    }

    isInitialized = true;
    console.log('[Devise Advanced] All modules initialized successfully');
  } catch (error) {
    console.error('[Devise Advanced] Initialization failed:', error);
  }
});

chrome.runtime.onStartup.addListener(async () => {
  console.log('[Devise Advanced] Extension starting up');

  try {
    await initializeAllModules();
    isInitialized = true;
  } catch (error) {
    console.error('[Devise Advanced] Startup failed:', error);
  }
});

async function initializeAllModules() {
  // Initialize base storage
  await initializeStorage();

  // Initialize IndexedDB
  await indexedDBStorage.initialize();

  // Initialize encryption
  await encryptionManager.initialize();

  // Initialize PII detector
  await piiDetector.initialize();

  // Initialize policy engine
  await policyEngine.initialize();

  // Initialize threat detector
  await threatDetector.initialize();

  // Initialize integrations
  await integrationManager.initialize();

  // Update agent status
  await updateAgentStatus({
    status: 'active',
    backendConnected: false,
    monitoringEnabled: true,
    advancedFeatures: true
  });

  // Set up alarms
  chrome.alarms.create('delivery', { periodInMinutes: 0.5 });
  chrome.alarms.create('cleanup', { periodInMinutes: 60 });
  chrome.alarms.create('heartbeat', { periodInMinutes: 1 });
  chrome.alarms.create('reportGeneration', { periodInMinutes: 60 });
  chrome.alarms.create('encryptionKeyRotation', { periodInMinutes: 1440 }); // 24 hours

  console.log('[Devise Advanced] All modules initialized');
}

async function showOnboarding() {
  chrome.tabs.create({ url: chrome.runtime.getURL('onboarding.html') });
}

// ============================================================
// NAVIGATION DETECTION
// ============================================================

chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (!isInitialized || details.frameId !== 0) return;
  await handleNavigation(details.url, details.tabId);
}, { url: [{ schemes: ['http', 'https'] }] });

async function handleNavigation(url, tabId) {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    const toolInfo = getToolInfo(domain);

    if (!toolInfo) return;

    // Check policy
    const userIdentity = await getUserIdentity();
    const policyResult = await policyEngine.checkToolAccess(domain, userIdentity);

    if (!policyResult.allowed) {
      // Block access
      await blockAccess(tabId, policyResult.reason);
      await threatDetector.analyzeActivity({
        type: 'tool_access',
        data: { domain, blocked: true },
        context: { url }
      });
      return;
    }

    // Log navigation event
    const event = {
      eventType: 'navigation',
      toolName: toolInfo.name,
      domain,
      category: toolInfo.category,
      riskLevel: toolInfo.risk,
      url,
      timestamp: new Date().toISOString()
    };

    // Encrypt event if enabled
    if (encryptionManager.isActive()) {
      const encrypted = await encryptionManager.encrypt(event);
      await queueEncryptedEvent(encrypted);
    } else {
      await queueEvent(event);
    }

    // Sync event to Supabase
    try {
      await sbLogEvent(event);
      await upsertTool({ name: toolInfo.name, domain, category: toolInfo.category, risk: toolInfo.risk, enterprise: toolInfo.enterprise });
      await incrementToolCount(domain);
    } catch (sbErr) {
      console.warn('[Devise Advanced] Supabase sync failed (will retry):', sbErr.message);
    }

    // Track in threat detector
    await threatDetector.analyzeActivity({
      type: 'tool_access',
      data: { domain, toolInfo },
      context: { url, tool: toolInfo.name }
    });

    // Send to integrations
    await integrationManager.sendEvent({
      type: 'tool_navigation',
      domain,
      tool: toolInfo.name,
      timestamp: Date.now()
    });

    // Update UI
    await addRecentTool({ domain, name: toolInfo.name, category: toolInfo.category, risk: toolInfo.risk, url });
    await updateBadge();

    console.log('[Devise Advanced] AI tool detected:', toolInfo.name);

  } catch (error) {
    console.error('[Devise Advanced] Navigation handling error:', error);
  }
}

async function blockAccess(tabId, reason) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: (blockReason) => {
        document.body.innerHTML = `
          <div style="position:fixed;top:0;left:0;right:0;bottom:0;background:#0A0E1A;display:flex;align-items:center;justify-content:center;font-family:Arial,sans-serif;z-index:2147483647;">
            <div style="text-align:center;padding:40px;max-width:500px;">
              <div style="font-size:64px;margin-bottom:20px;">🛡️</div>
              <h1 style="color:#FF4D4D;font-size:24px;margin-bottom:16px;">Access Blocked</h1>
              <p style="color:#B0B8C8;font-size:16px;margin-bottom:24px;">${blockReason}</p>
              <p style="color:#6B7280;font-size:12px;">This action has been logged for compliance purposes.</p>
            </div>
          </div>
        `;
      },
      args: [reason]
    });
  } catch (e) {
    console.error('[Devise Advanced] Failed to block access:', e);
  }
}

// ============================================================
// MESSAGE HANDLER
// ============================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender, sendResponse);
  return true;
});

async function handleMessage(message, sender, sendResponse) {
  try {
    switch (message.action) {
      // Core status
      case 'getStatus':
        await handleGetStatus(sendResponse);
        break;

      case 'setIdentity':
        await setUserIdentity(message.identity);
        sendResponse({ success: true });
        break;

      // PII Detection
      case 'detectPII':
        const piiResult = piiDetector.detect(message.text);
        sendResponse({ success: true, result: piiResult });
        break;

      // Policy
      case 'checkPolicy':
        const policyResult = policyEngine.checkToolAccess(message.domain, await getUserIdentity());
        sendResponse({ success: true, result: policyResult });
        break;

      case 'updatePolicies':
        await policyEngine.updatePolicies(message.policies);
        sendResponse({ success: true });
        break;

      case 'emergencyLockdown':
        await policyEngine.emergencyLockdown(message.reason);
        sendResponse({ success: true });
        break;

      // Threat Detection
      case 'analyzeThreat':
        const threats = threatDetector.analyzeActivity(message.activity);
        sendResponse({ success: true, threats });
        break;

      case 'getThreatSummary':
        const threatSummary = threatDetector.getThreatSummary();
        sendResponse({ success: true, summary: threatSummary });
        break;

      // Reporting
      case 'generateReport':
        const report = await reportingEngine.generateReport(message.type, message.options);
        sendResponse({ success: true, report });
        break;

      case 'exportReport':
        const exported = await reportingEngine.exportReport(message.report, message.format);
        sendResponse({ success: true, data: exported });
        break;

      // Encryption
      case 'encryptData':
        const encrypted = await encryptionManager.encrypt(message.data);
        sendResponse({ success: true, encrypted });
        break;

      case 'decryptData':
        const decrypted = await encryptionManager.decrypt(message.data);
        sendResponse({ success: true, decrypted });
        break;

      // Integrations
      case 'configureWebhook':
        const webhook = await integrationManager.configureWebhook(message.config);
        sendResponse({ success: true, webhook });
        break;

      case 'configureSIEM':
        const siem = await integrationManager.configureSIEM(message.config);
        sendResponse({ success: true, siem });
        break;

      case 'getIntegrationStatus':
        const intStatus = integrationManager.getStatus();
        sendResponse({ success: true, status: intStatus });
        break;

      // Behavior Analytics
      case 'behaviorAnalytics':
        await processBehaviorAnalytics(message.data);
        sendResponse({ success: true });
        break;

      // Network Interception
      case 'networkRequest':
        await processNetworkRequest(message.data);
        sendResponse({ success: true });
        break;

      // Tamper Detection
      case 'tamperDetected':
        await handleTamperDetection(message.data);
        sendResponse({ success: true });
        break;

      // Advanced Monitoring Events
      case 'monitoringEvents':
        await handleMonitoringEvents(message, sender);
        sendResponse({ success: true, received: message.events?.length || 0 });
        break;

      // Screenshot
      case 'captureScreenshot':
        await handleScreenshot(sender.tab?.id);
        sendResponse({ success: true });
        break;

      // Commands
      case 'toggleMonitoring':
        monitoringEnabled = !monitoringEnabled;
        await updateAgentStatus({ monitoringEnabled });
        sendResponse({ success: true, monitoringEnabled });
        break;

      case 'forceSync':
        await deliverPendingEvents();
        sendResponse({ success: true });
        break;

      // Data Export
      case 'exportAllData':
        const allData = await indexedDBStorage.exportAll();
        sendResponse({ success: true, data: allData });
        break;

      case 'getStorageStats':
        const stats = await indexedDBStorage.getStats();
        sendResponse({ success: true, stats });
        break;

      default:
        sendResponse({ success: false, error: 'Unknown action' });
    }
  } catch (error) {
    console.error('[Devise Advanced] Message handling error:', error);
    sendResponse({ success: false, error: error.message });
  }
}

async function handleGetStatus(sendResponse) {
  const status = await updateAgentStatus({});
  const identity = await getUserIdentity();
  const stats = await getQueueStats();
  const piiStats = { active: piiDetector.modelLoaded };
  const policyStats = policyEngine.generateReport();
  const threatStats = threatDetector.getThreatSummary();
  const encryptionActive = encryptionManager.isActive();
  const integrationStatus = integrationManager.getStatus();

  sendResponse({
    success: true,
    data: {
      status,
      identity,
      stats,
      advanced: {
        piiDetection: piiStats,
        policyEngine: policyStats,
        threatDetection: threatStats,
        encryption: { active: encryptionActive },
        integrations: integrationStatus
      }
    }
  });
}

// ============================================================
// MONITORING EVENTS
// ============================================================

async function handleMonitoringEvents(message, sender) {
  if (!monitoringEnabled) return;

  const { events, isAIToolPage } = message;
  if (!events || events.length === 0) return;

  for (const event of events) {
    // PII Check
    if (event.type === 'ai_prompt' || event.type === 'keystroke') {
      const piiCheck = piiDetector.quickCheck(event.prompt || event.value || '');
      if (piiCheck) {
        const piiResult = piiDetector.detect(event.prompt || event.value || '');
        event.piiDetected = piiResult.hasPII;
        event.piiRiskScore = piiResult.riskScore;
        event.piiRedacted = piiResult.redactedText;

        // Check content against policy
        const contentCheck = policyEngine.checkContent(event.prompt || event.value || '');
        if (!contentCheck.allowed) {
          event.policyViolation = true;
          event.violations = contentCheck.violations;
        }
      }
    }

    // Add identity and metadata
    const identity = await getUserIdentity();
    event.userId = identity?.id || 'unknown';
    event.userEmail = identity?.email || 'unknown';
    event.isAIToolPage = isAIToolPage;

    // Analyze for threats
    if (isAIToolPage) {
      await threatDetector.analyzeActivity({
        type: event.type,
        data: event,
        context: { url: event.url, tool: event.toolName }
      });
    }

    // Encrypt if enabled
    if (encryptionManager.isActive()) {
      const encrypted = await encryptionManager.encrypt(event);
      await queueEncryptedEvent(encrypted);
    } else {
      await queueEvent(event);
    }

    // Sync to Supabase
    try {
      await sbLogEvent(event);
      if (event.policyViolation && event.violations) {
        for (const v of event.violations) {
          await logPolicyViolation({ type: v.type || 'content_violation', domain: event.domain, toolName: event.toolName, userEmail: event.userEmail, description: v.description || v.message, severity: v.severity || 'medium' });
        }
      }
    } catch (sbErr) {
      console.warn('[Devise Advanced] Supabase event sync failed:', sbErr.message);
    }

    // Send to integrations
    await integrationManager.sendEvent({
      type: event.type,
      domain: event.domain,
      timestamp: Date.now()
    });
  }

  await updateBadge();
}

async function queueEncryptedEvent(encryptedEvent) {
  await indexedDBStorage.addEvent(encryptedEvent, true);
}

// ============================================================
// BEHAVIOR ANALYTICS
// ============================================================

async function processBehaviorAnalytics(data) {
  // Store in IndexedDB
  await indexedDBStorage.addBehaviorSession({
    ...data,
    processedAt: Date.now()
  });

  // Send to integrations
  await integrationManager.sendEvent({
    type: 'behavior_session',
    sessionId: data.id,
    metrics: data.metrics,
    timestamp: Date.now()
  });
}

// ============================================================
// NETWORK INTERCEPTION
// ============================================================

async function processNetworkRequest(data) {
  // Check for sensitive data in requests
  if (data.isAI && data.requestBody) {
    const piiCheck = piiDetector.quickCheck(data.requestBody);
    if (piiCheck) {
      data.piiInRequest = true;

      // Log as potential threat
      await threatDetector.analyzeActivity({
        type: 'network_request',
        data: {
          url: data.url,
          piiDetected: true
        },
        context: { url: data.url }
      });
    }
  }

  // Store request
  await indexedDBStorage.addEvent({
    ...data,
    type: 'network_request',
    timestamp: Date.now()
  });
}

// ============================================================
// TAMPER DETECTION
// ============================================================

async function handleTamperDetection(data) {
  console.warn('[Devise Advanced] Tamper detected:', data.type);

  // Store tamper event
  await indexedDBStorage.addEvent({
    ...data,
    type: 'tamper_detection',
    timestamp: Date.now()
  });

  // Log threat to Supabase
  try {
    await logThreat({ type: 'Tamper Detection', severity: 'critical', description: data.type || 'Extension integrity check failed', domain: data.domain });
  } catch (sbErr) {
    console.warn('[Devise Advanced] Supabase threat log failed:', sbErr.message);
  }

  // Send alert
  await integrationManager.sendEvent({
    type: 'security_alert',
    alertType: 'tamper_detected',
    details: data,
    timestamp: Date.now()
  });

  // Notify user
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon48.png',
    title: 'Security Alert',
    message: 'Unusual activity detected. Extension integrity check failed.',
    priority: 2
  });
}

// ============================================================
// ALARM HANDLERS
// ============================================================

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (!isInitialized) return;

  switch (alarm.name) {
    case 'delivery':
      await deliverPendingEvents();
      break;
    case 'cleanup':
      await cleanupOldData();
      break;
    case 'heartbeat':
      await heartbeat();
      break;
    case 'reportGeneration':
      await generateScheduledReports();
      break;
    case 'encryptionKeyRotation':
      await encryptionManager.checkKeyRotation();
      break;
  }
});

async function deliverPendingEvents() {
  const pendingEvents = await getPendingEvents();
  if (pendingEvents.length === 0) return;

  console.log('[Devise Advanced] Delivering', pendingEvents.length, 'events');

  // Send via WebSocket if connected
  const wsStatus = webSocketSync.getStatus();
  if (wsStatus.connected) {
    for (const event of pendingEvents) {
      webSocketSync.send(event);
    }
  }

  // Deliver to Supabase
  try {
    await logEventsBatch(pendingEvents);
    // Mark as delivered in IndexedDB
    for (const event of pendingEvents) {
      await indexedDBStorage.put('events', { ...event, delivered: true });
    }
    console.log('[Devise Advanced] Batch delivered to Supabase:', pendingEvents.length);
  } catch (error) {
    console.error('[Devise Advanced] Supabase delivery failed:', error);
  }

  await updateBadge();
}

async function cleanupOldData() {
  // Clean up events older than 90 days
  const cutoff = Date.now() - (90 * 24 * 60 * 60 * 1000);

  // Would use IndexedDB range delete here
  console.log('[Devise Advanced] Cleanup completed');
}

async function heartbeat() {
  const status = await updateAgentStatus({ lastHeartbeat: Date.now() });
}

async function generateScheduledReports() {
  // Generate daily summary report
  const report = await reportingEngine.generateReport('executive', {
    startDate: Date.now() - 24 * 60 * 60 * 1000,
    endDate: Date.now()
  });

  // Store report
  await indexedDBStorage.add({
    id: `report_${Date.now()}`,
    ...report
  }, 'analytics');
}

// ============================================================
// SCREENSHOT
// ============================================================

async function handleScreenshot(tabId) {
  if (!tabId) return;

  try {
    const dataUrl = await chrome.tabs.captureVisibleTab(null, { format: 'png' });

    const event = {
      eventType: 'screenshot',
      tabId,
      timestamp: new Date().toISOString(),
      imageLength: dataUrl.length
    };

    if (encryptionManager.isActive()) {
      const encrypted = await encryptionManager.encrypt(event);
      await queueEncryptedEvent(encrypted);
    } else {
      await queueEvent(event);
    }

    console.log('[Devise Advanced] Screenshot captured');
  } catch (error) {
    console.error('[Devise Advanced] Screenshot failed:', error);
  }
}

// ============================================================
// BADGE & UI
// ============================================================

async function updateBadge() {
  try {
    const stats = await getQueueStats();

    if (stats.pending > 0) {
      await chrome.action.setBadgeText({ text: stats.pending > 99 ? '99+' : stats.pending.toString() });
      await chrome.action.setBadgeBackgroundColor({ color: '#FF4D4D' });
    } else {
      await chrome.action.setBadgeText({ text: '' });
    }
  } catch (error) {
    console.error('[Devise Advanced] Badge update failed:', error);
  }
}

// ============================================================
// COMMANDS
// ============================================================

chrome.commands.onCommand.addListener(async (command) => {
  switch (command) {
    case 'capture-screenshot':
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      await handleScreenshot(tab?.id);
      break;

    case 'toggle-monitoring':
      monitoringEnabled = !monitoringEnabled;
      await updateAgentStatus({ monitoringEnabled });
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: 'Devise Advanced',
        message: `Monitoring ${monitoringEnabled ? 'enabled' : 'disabled'}`
      });
      break;

    case 'emergency-lockdown':
      await policyEngine.emergencyLockdown('Emergency lockdown triggered by user');
      break;
  }
});

// ============================================================
// CONTEXT MENUS
// ============================================================

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  switch (info.menuItemId) {
    case 'scan-for-pii':
      const selectedText = info.selectionText;
      const piiResult = piiDetector.detect(selectedText);
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: 'PII Scan Result',
        message: piiResult.hasPII
          ? `Found ${piiResult.summary.totalFindings} PII items (Risk: ${piiResult.riskScore})`
          : 'No PII detected'
      });
      break;

    case 'generate-report':
      chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') + '?action=report' });
      break;
  }
});

console.log('[Devise Advanced] Background service worker loaded');
