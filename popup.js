/**
 * Devise Extension - Premium Popup Controller
 */

class PopupController {
  constructor() {
    this.elements = {};
    this.state = {
      monitoring: true,
      stats: { events: 0, threats: 0, risk: '—' },
      tools: [],
      activities: []
    };
  }

  async initialize() {
    this.cacheElements();
    this.setupListeners();
    await this.loadData();
    this.startPolling();
  }

  cacheElements() {
    this.elements = {
      statusIndicator: document.getElementById('statusIndicator'),
      eventCount: document.getElementById('eventCount'),
      threatCount: document.getElementById('threatCount'),
      riskScore: document.getElementById('riskScore'),
      toolCount: document.getElementById('toolCount'),
      toolsList: document.getElementById('toolsList'),
      activityList: document.getElementById('activityList'),
      identityBar: document.getElementById('identityBar'),
      identityAvatar: document.getElementById('identityAvatar'),
      identityName: document.getElementById('identityName'),
      identityEmail: document.getElementById('identityEmail'),
      syncBtn: document.getElementById('syncBtn'),
      dashboardBtn: document.getElementById('dashboardBtn'),
      settingsBtn: document.getElementById('settingsBtn'),
      encryptionIcon: document.getElementById('encryptionIcon'),
      policyIcon: document.getElementById('policyIcon'),
      syncIcon: document.getElementById('syncIcon')
    };
  }

  setupListeners() {
    // Sync button
    this.elements.syncBtn?.addEventListener('click', () => {
      this.animateIcon(this.elements.syncBtn);
      this.syncData();
    });

    // Dashboard button
    this.elements.dashboardBtn?.addEventListener('click', () => {
      chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
    });

    // Settings button
    this.elements.settingsBtn?.addEventListener('click', () => {
      chrome.runtime.openOptionsPage();
    });

    // Identity bar
    this.elements.identityBar?.addEventListener('click', () => {
      chrome.runtime.openOptionsPage();
    });
  }

  async loadData() {
    try {
      const response = await this.sendMessage({ action: 'getStatus' });

      if (response?.success) {
        const { status, identity, stats, advanced, recentTools } = response.data;

        this.updateStatus(status);
        this.updateIdentity(identity);
        this.updateStats(stats, advanced);
        this.updateTools(recentTools);
        this.updateSecurity(advanced);
      }
    } catch (error) {
      console.error('[Popup] Chrome runtime failed, trying Supabase:', error);
      await this.loadFromSupabase();
    }
  }

  async loadFromSupabase() {
    const SB_URL = 'https://dsoqjhlkcslsxbgrdntz.supabase.co/rest/v1';
    const SB_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRzb3FqaGxrY3Nsc3hiZ3JkbnR6Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI1MTMyMTIsImV4cCI6MjA4ODA4OTIxMn0.afQ2_AOE39j5dDjOEiC36Lp5kg3iMz_XlLJEKbBgShQ';
    const h = { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` };

    try {
      const [events, threats, tools] = await Promise.all([
        fetch(`${SB_URL}/events?select=id&limit=100`, { headers: h }).then(r => r.json()),
        fetch(`${SB_URL}/threats?order=created_at.desc&limit=10`, { headers: h }).then(r => r.json()),
        fetch(`${SB_URL}/tools?order=event_count.desc&limit=5`, { headers: h }).then(r => r.json())
      ]);

      if (this.elements.eventCount) this.elements.eventCount.textContent = this.formatNumber(events.length);
      if (this.elements.threatCount) this.elements.threatCount.textContent = threats.length;
      if (this.elements.riskScore) {
        const risk = threats.filter(t => t.severity === 'critical').length * 25 + threats.filter(t => t.severity === 'high').length * 15;
        this.elements.riskScore.textContent = risk > 0 ? risk : '—';
      }

      const categoryIcons = { conversational: '💬', coding: '💻', image: '🎨', video: '🎬', audio: '🎵', productivity: '📝', search: '🔍', default: '🔧' };
      if (this.elements.toolCount) this.elements.toolCount.textContent = tools.length;
      if (this.elements.toolsList && tools.length > 0) {
        this.elements.toolsList.innerHTML = tools.map(t => `
          <div class="tool-item">
            <div class="tool-icon">${categoryIcons[t.category] || categoryIcons.default}</div>
            <div class="tool-info">
              <span class="tool-name">${this.escapeHtml(t.name)}</span>
              <span class="tool-domain">${this.escapeHtml(t.domain)}</span>
            </div>
            <span class="tool-badge ${(t.risk || 'Medium').toLowerCase()}">${t.risk || 'Med'}</span>
          </div>
        `).join('');
      }

      console.log('[Popup] Data loaded from Supabase fallback');
    } catch (sbErr) {
      console.error('[Popup] Supabase fallback also failed:', sbErr);
      this.showError();
    }
  }

  updateStatus(status) {
    const indicator = this.elements.statusIndicator;
    if (!indicator) return;

    const isMonitoring = status?.monitoringEnabled !== false;
    const isBackendConnected = status?.backendConnected;

    indicator.classList.toggle('inactive', !isMonitoring);
    indicator.querySelector('.status-text').textContent = isMonitoring ? 'Active' : 'Paused';
  }

  updateIdentity(identity) {
    if (!identity) return;

    const { name, email } = identity;

    if (this.elements.identityName) {
      this.elements.identityName.textContent = name || 'Unknown';
    }
    if (this.elements.identityEmail) {
      this.elements.identityEmail.textContent = email || 'No email';
    }
    if (this.elements.identityAvatar) {
      this.elements.identityAvatar.textContent = this.getInitials(name || email);
    }
  }

  updateStats(stats, advanced) {
    // Main stats
    if (this.elements.eventCount) {
      this.elements.eventCount.textContent = this.formatNumber(stats?.total || 0);
    }
    if (this.elements.threatCount) {
      const threats = advanced?.threatDetection?.summary?.totalThreats || 0;
      this.elements.threatCount.textContent = threats;
    }
    if (this.elements.riskScore) {
      const risk = advanced?.threatDetection?.summary?.riskScore || 0;
      this.elements.riskScore.textContent = risk > 0 ? risk : '—';
    }
  }

  updateTools(tools) {
    if (!this.elements.toolsList) return;

    const toolCount = tools?.length || 0;
    if (this.elements.toolCount) {
      this.elements.toolCount.textContent = toolCount;
    }

    if (!tools || tools.length === 0) {
      this.elements.toolsList.innerHTML = this.renderEmptyState('No AI tools detected');
      return;
    }

    const categoryIcons = {
      conversational: '💬', coding: '💻', image: '🎨', video: '🎬',
      audio: '🎵', productivity: '📝', search: '🔍', default: '🔧'
    };

    this.elements.toolsList.innerHTML = tools.slice(0, 5).map(tool => {
      const icon = categoryIcons[tool.category] || categoryIcons.default;
      const riskClass = (tool.risk || 'MEDIUM').toLowerCase();

      return `
        <div class="tool-item">
          <div class="tool-icon">${icon}</div>
          <div class="tool-info">
            <span class="tool-name">${this.escapeHtml(tool.name)}</span>
            <span class="tool-domain">${this.escapeHtml(tool.domain)}</span>
          </div>
          <span class="tool-badge ${riskClass}">${tool.risk || 'Med'}</span>
        </div>
      `;
    }).join('');
  }

  updateSecurity(advanced) {
    const icons = {
      encryption: this.elements.encryptionIcon,
      policy: this.elements.policyIcon,
      sync: this.elements.syncIcon
    };

    // Encryption status
    if (icons.encryption) {
      const active = advanced?.encryption?.active;
      icons.encryption.textContent = active ? '◉' : '○';
      icons.encryption.classList.toggle('active', active);
    }

    // Policy status
    if (icons.policy) {
      icons.policy.textContent = '◉';
      icons.policy.classList.add('active');
    }

    // Sync status
    if (icons.sync) {
      const connected = advanced?.integrations?.queueLength !== undefined;
      icons.sync.textContent = connected ? '◉' : '○';
      icons.sync.classList.toggle('active', connected);
    }
  }

  renderEmptyState(text) {
    return `
      <div class="empty-state">
        <span class="empty-icon">◯</span>
        <span class="empty-text">${text}</span>
      </div>
    `;
  }

  async syncData() {
    try {
      await this.sendMessage({ action: 'forceSync' });
      await this.loadData();
    } catch (error) {
      console.error('[Popup] Sync failed:', error);
    }
  }

  animateIcon(element) {
    const svg = element?.querySelector('svg');
    if (svg) {
      svg.style.animation = 'none';
      svg.offsetHeight; // Trigger reflow
      svg.style.animation = 'spin 1s linear infinite';
      setTimeout(() => {
        svg.style.animation = '';
      }, 1000);
    }
  }

  startPolling() {
    // Refresh every 5 seconds
    setInterval(() => this.loadData(), 5000);
  }

  sendMessage(message) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          reject(chrome.runtime.lastError);
        } else {
          resolve(response);
        }
      });
    });
  }

  getInitials(name) {
    if (!name) return '?';
    const parts = name.split(/[\s@.]+/).filter(Boolean);
    if (parts.length >= 2) {
      return (parts[0][0] + parts[1][0]).toUpperCase();
    }
    return (parts[0] || name).substring(0, 2).toUpperCase();
  }

  formatNumber(num) {
    if (num >= 1000) {
      return (num / 1000).toFixed(1) + 'k';
    }
    return num.toString();
  }

  escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  showError() {
    const indicator = this.elements.statusIndicator;
    if (indicator) {
      indicator.classList.add('inactive');
      indicator.querySelector('.status-text').textContent = 'Error';
    }
  }
}

// Add spin animation
const style = document.createElement('style');
style.textContent = `
  @keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }
`;
document.head.appendChild(style);

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  const popup = new PopupController();
  popup.initialize();
});
