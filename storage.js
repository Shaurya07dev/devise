/**
 * Devise Storage Module
 * Manages offline event queue, user identity, and session state
 * Uses chrome.storage.local for persistence
 */

import { CONFIG } from './config.js';

// Storage keys
export const KEYS = {
  EVENT_QUEUE: 'devise_event_queue',
  USER_IDENTITY: 'devise_user_identity',
  SESSION_DATA: 'devise_session_data',
  LAST_SYNC: 'devise_last_sync',
  REGISTRY_VERSION: 'devise_registry_version',
  AGENT_STATUS: 'devise_agent_status',
  RECENT_TOOLS: 'devise_recent_tools',
  SETTINGS: 'devise_settings'
};

/**
 * Initialize storage with default values
 */
export async function initializeStorage() {
  const data = await chrome.storage.local.get([
    KEYS.EVENT_QUEUE,
    KEYS.USER_IDENTITY,
    KEYS.SESSION_DATA,
    KEYS.AGENT_STATUS,
    KEYS.RECENT_TOOLS,
    KEYS.SETTINGS
  ]);

  // Initialize empty queue if not exists
  if (!data[KEYS.EVENT_QUEUE]) {
    await chrome.storage.local.set({
      [KEYS.EVENT_QUEUE]: []
    });
  }

  // Initialize recent tools if not exists
  if (!data[KEYS.RECENT_TOOLS]) {
    await chrome.storage.local.set({
      [KEYS.RECENT_TOOLS]: []
    });
  }

  // Initialize agent status if not exists
  if (!data[KEYS.AGENT_STATUS]) {
    await chrome.storage.local.set({
      [KEYS.AGENT_STATUS]: {
        status: 'initializing',
        lastHeartbeat: Date.now(),
        backendConnected: false
      }
    });
  }

  // Initialize settings if not exists
  if (!data[KEYS.SETTINGS]) {
    await chrome.storage.local.set({
      [KEYS.SETTINGS]: {
        notificationsEnabled: true,
        debugMode: false,
        deduplicationWindow: CONFIG.DEDUPLICATION_WINDOW
      }
    });
  }

  console.log('[Devise] Storage initialized');
}

/**
 * Event Queue Management
 */

// Add event to the offline queue
export async function queueEvent(event) {
  const data = await chrome.storage.local.get(KEYS.EVENT_QUEUE);
  const queue = data[KEYS.EVENT_QUEUE] || [];

  // Check queue size limit
  if (queue.length >= CONFIG.MAX_QUEUE_SIZE) {
    console.warn('[Devise] Event queue full, removing oldest event');
    queue.shift(); // Remove oldest event
  }

  // Add event with timestamp and retry count
  const queuedEvent = {
    ...event,
    id: generateEventId(),
    queuedAt: Date.now(),
    retryCount: 0,
    status: 'pending'
  };

  queue.push(queuedEvent);
  await chrome.storage.local.set({ [KEYS.EVENT_QUEUE]: queue });

  console.log('[Devise] Event queued:', queuedEvent.id);
  return queuedEvent.id;
}

// Get all pending events from queue
export async function getPendingEvents() {
  const data = await chrome.storage.local.get(KEYS.EVENT_QUEUE);
  const queue = data[KEYS.EVENT_QUEUE] || [];
  return queue.filter(e => e.status === 'pending');
}

// Get all events (for debugging)
export async function getAllQueuedEvents() {
  const data = await chrome.storage.local.get(KEYS.EVENT_QUEUE);
  return data[KEYS.EVENT_QUEUE] || [];
}

// Mark event as delivered
export async function markEventDelivered(eventId) {
  const data = await chrome.storage.local.get(KEYS.EVENT_QUEUE);
  const queue = data[KEYS.EVENT_QUEUE] || [];
  const index = queue.findIndex(e => e.id === eventId);

  if (index !== -1) {
    queue[index].status = 'delivered';
    queue[index].deliveredAt = Date.now();
    await chrome.storage.local.set({ [KEYS.EVENT_QUEUE]: queue });
    console.log('[Devise] Event delivered:', eventId);
  }
}

// Mark event as failed and increment retry count
export async function markEventFailed(eventId) {
  const data = await chrome.storage.local.get(KEYS.EVENT_QUEUE);
  const queue = data[KEYS.EVENT_QUEUE] || [];
  const index = queue.findIndex(e => e.id === eventId);

  if (index !== -1) {
    queue[index].retryCount++;
    queue[index].lastRetry = Date.now();

    // Remove if max retries exceeded
    if (queue[index].retryCount >= CONFIG.MAX_RETRIES) {
      queue[index].status = 'failed_permanent';
      console.error('[Devise] Event failed permanently:', eventId);
    }

    await chrome.storage.local.set({ [KEYS.EVENT_QUEUE]: queue });
  }
}

// Remove delivered events older than 24 hours
export async function cleanupDeliveredEvents() {
  const data = await chrome.storage.local.get(KEYS.EVENT_QUEUE);
  const queue = data[KEYS.EVENT_QUEUE] || [];
  const cutoff = Date.now() - (24 * 60 * 60 * 1000);

  const cleanedQueue = queue.filter(e => {
    // Keep pending events
    if (e.status === 'pending') return true;
    // Keep recently delivered events (for debugging)
    if (e.status === 'delivered' && e.deliveredAt > cutoff) return true;
    // Keep failed events for review
    if (e.status === 'failed_permanent') return true;
    return false;
  });

  if (cleanedQueue.length !== queue.length) {
    await chrome.storage.local.set({ [KEYS.EVENT_QUEUE]: cleanedQueue });
    console.log('[Devise] Cleaned up', queue.length - cleanedQueue.length, 'old events');
  }
}

// Clear entire queue (use with caution)
export async function clearQueue() {
  await chrome.storage.local.set({ [KEYS.EVENT_QUEUE]: [] });
  console.log('[Devise] Event queue cleared');
}

/**
 * User Identity Management
 */

// Get user identity (from MDM, SSO, or stored)
export async function getUserIdentity() {
  // First check managed storage (MDM deployed)
  try {
    const managedData = await chrome.storage.managed.get([
      'userId', 'userEmail', 'userName', 'department', 'organizationId'
    ]);
    
    if (managedData.userEmail) {
      return {
        id: managedData.userId || managedData.userEmail,
        email: managedData.userEmail,
        name: managedData.userName || managedData.userEmail.split('@')[0],
        department: managedData.department || 'Unknown',
        organizationId: managedData.organizationId,
        source: 'mdm'
      };
    }
  } catch (e) {
    // Managed storage not available, continue to other methods
  }

  // Check stored identity (from SSO or onboarding)
  const data = await chrome.storage.local.get(KEYS.USER_IDENTITY);
  if (data[KEYS.USER_IDENTITY]) {
    return data[KEYS.USER_IDENTITY];
  }

  return null;
}

// Set user identity (from SSO or onboarding)
export async function setUserIdentity(identity) {
  await chrome.storage.local.set({
    [KEYS.USER_IDENTITY]: {
      ...identity,
      setAt: Date.now(),
      source: identity.source || 'manual'
    }
  });
  console.log('[Devise] User identity set:', identity.email);
}

// Clear user identity
export async function clearUserIdentity() {
  await chrome.storage.local.remove(KEYS.USER_IDENTITY);
  console.log('[Devise] User identity cleared');
}

/**
 * Session Management
 */

// Get session data (deduplication state)
export async function getSessionData() {
  const data = await chrome.storage.local.get(KEYS.SESSION_DATA);
  return data[KEYS.SESSION_DATA] || {
    startTime: Date.now(),
    visitedTools: {},
    lastActivity: Date.now()
  };
}

// Update session data
export async function updateSessionData(updates) {
  const current = await getSessionData();
  await chrome.storage.local.set({
    [KEYS.SESSION_DATA]: {
      ...current,
      ...updates,
      lastActivity: Date.now()
    }
  });
}

// Record tool visit for deduplication
export async function recordToolVisit(domain) {
  const session = await getSessionData();
  const visitedTools = session.visitedTools || {};

  visitedTools[domain] = {
    firstVisit: visitedTools[domain]?.firstVisit || Date.now(),
    lastVisit: Date.now(),
    visitCount: (visitedTools[domain]?.visitCount || 0) + 1
  };

  await updateSessionData({ visitedTools });
}

// Check if tool was recently visited (within deduplication window)
export async function wasRecentlyVisited(domain) {
  const session = await getSessionData();
  const visitedTools = session.visitedTools || {};
  const visit = visitedTools[domain];

  if (!visit) return false;

  const timeSinceLastVisit = Date.now() - visit.lastVisit;
  return timeSinceLastVisit < CONFIG.DEDUPLICATION_WINDOW;
}

// Clear session data (on logout or session end)
export async function clearSessionData() {
  await chrome.storage.local.set({
    [KEYS.SESSION_DATA]: {
      startTime: Date.now(),
      visitedTools: {},
      lastActivity: Date.now()
    }
  });
  console.log('[Devise] Session data cleared');
}

/**
 * Agent Status Management
 */

// Get current agent status
export async function getAgentStatus() {
  const data = await chrome.storage.local.get(KEYS.AGENT_STATUS);
  return data[KEYS.AGENT_STATUS] || {
    status: 'unknown',
    lastHeartbeat: null,
    backendConnected: false
  };
}

// Update agent status
export async function updateAgentStatus(status) {
  await chrome.storage.local.set({
    [KEYS.AGENT_STATUS]: {
      ...status,
      lastHeartbeat: Date.now()
    }
  });
}

/**
 * Recent Tools Management
 */

// Add tool to recent list (for popup display)
export async function addRecentTool(toolData) {
  const data = await chrome.storage.local.get(KEYS.RECENT_TOOLS);
  let recentTools = data[KEYS.RECENT_TOOLS] || [];

  // Remove if already exists
  recentTools = recentTools.filter(t => t.domain !== toolData.domain);

  // Add to front
  recentTools.unshift({
    ...toolData,
    visitedAt: Date.now()
  });

  // Keep only last 10
  recentTools = recentTools.slice(0, 10);

  await chrome.storage.local.set({ [KEYS.RECENT_TOOLS]: recentTools });
}

// Get recent tools
export async function getRecentTools(limit = 5) {
  const data = await chrome.storage.local.get(KEYS.RECENT_TOOLS);
  const tools = data[KEYS.RECENT_TOOLS] || [];
  return tools.slice(0, limit);
}

/**
 * Settings Management
 */

// Get settings
export async function getSettings() {
  const data = await chrome.storage.local.get(KEYS.SETTINGS);
  return data[KEYS.SETTINGS] || {
    notificationsEnabled: true,
    debugMode: false,
    deduplicationWindow: CONFIG.DEDUPLICATION_WINDOW
  };
}

// Update settings
export async function updateSettings(updates) {
  const current = await getSettings();
  await chrome.storage.local.set({
    [KEYS.SETTINGS]: {
      ...current,
      ...updates
    }
  });
}

/**
 * API Configuration
 */

// Get API endpoint (from MDM or default)
export async function getApiEndpoint() {
  try {
    const managedData = await chrome.storage.managed.get('apiEndpoint');
    if (managedData.apiEndpoint) {
      return managedData.apiEndpoint;
    }
  } catch (e) {
    // Managed storage not available
  }
  return CONFIG.API_ENDPOINT;
}

// Get API key (from MDM)
export async function getApiKey() {
  try {
    const managedData = await chrome.storage.managed.get('apiKey');
    return managedData.apiKey;
  } catch (e) {
    return null;
  }
}

/**
 * Utility Functions
 */

// Generate unique event ID
function generateEventId() {
  return `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

// Get queue statistics
export async function getQueueStats() {
  const data = await chrome.storage.local.get(KEYS.EVENT_QUEUE);
  const queue = data[KEYS.EVENT_QUEUE] || [];

  return {
    total: queue.length,
    pending: queue.filter(e => e.status === 'pending').length,
    delivered: queue.filter(e => e.status === 'delivered').length,
    failed: queue.filter(e => e.status === 'failed_permanent').length,
    oldestPending: queue.find(e => e.status === 'pending')?.queuedAt || null
  };
}

// Export all data (for debugging/export)
export async function exportAllData() {
  const data = await chrome.storage.local.get(null);
  return {
    exportedAt: new Date().toISOString(),
    ...data
  };
}

// Clear all storage (for logout/reset)
export async function clearAllStorage() {
  await chrome.storage.local.clear();
  console.log('[Devise] All storage cleared');
  await initializeStorage();
}
