/**
 * Devise Dashboard Controller
 * Premium Analytics Dashboard — powered by Supabase
 */

// Supabase REST config (inline to avoid ES module issues in file:// context)
const SUPABASE_URL = 'https://dsoqjhlkcslsxbgrdntz.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRzb3FqaGxrY3Nsc3hiZ3JkbnR6Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI1MTMyMTIsImV4cCI6MjA4ODA4OTIxMn0.afQ2_AOE39j5dDjOEiC36Lp5kg3iMz_XlLJEKbBgShQ';
const REST_URL = `${SUPABASE_URL}/rest/v1`;
const sbHeaders = {
  'apikey': SUPABASE_KEY,
  'Authorization': `Bearer ${SUPABASE_KEY}`,
  'Content-Type': 'application/json'
};

async function sbSelect(table, query = '') {
  const res = await fetch(`${REST_URL}/${table}?${query}`, { headers: sbHeaders });
  if (!res.ok) throw new Error(`Supabase ${table}: ${res.status}`);
  return res.json();
}

function getRelativeTime(isoString) {
  const diff = Date.now() - new Date(isoString).getTime();
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
  const days = Math.floor(hours / 24);
  return `${days} day${days > 1 ? 's' : ''} ago`;
}

class DashboardController {
  constructor() {
    this.charts = {};
    this.refreshInterval = null;
    this.data = {
      stats: { events: 0, threats: 0, violations: 0, riskScore: 0 },
      tools: [],
      threats: [],
      compliance: { gdpr: 95, hipaa: 88, pci: 92, soc2: 97 }
    };
  }

  async initialize() {
    await this.loadData();
    this.setupCharts();
    this.setupListeners();
    this.startPolling();
    this.render();
  }

  async loadData() {
    try {
      // Fetch all data from Supabase in parallel
      const [events, threats, tools, compliance, violations] = await Promise.all([
        sbSelect('events', 'order=created_at.desc&limit=100'),
        sbSelect('threats', 'order=created_at.desc&limit=20'),
        sbSelect('tools', 'order=event_count.desc&limit=10'),
        sbSelect('compliance_scores', 'order=framework.asc'),
        sbSelect('policy_violations', 'select=id')
      ]);

      // Threat stats
      const threatStats = {
        total: threats.length,
        critical: threats.filter(t => t.severity === 'critical').length,
        high: threats.filter(t => t.severity === 'high').length,
        medium: threats.filter(t => t.severity === 'medium').length,
        low: threats.filter(t => t.severity === 'low').length
      };

      // Risk score: weighted
      const riskScore = Math.min(100,
        threatStats.critical * 25 +
        threatStats.high * 15 +
        threatStats.medium * 5 +
        threatStats.low * 1
      );

      // Compliance map
      const complianceMap = {};
      compliance.forEach(c => {
        const key = c.framework.toLowerCase().replace(/[\s\-]/g, '');
        complianceMap[key] = c.score;
      });

      this.data = {
        stats: {
          events: events.length,
          threats: threatStats.total,
          violations: violations.length,
          riskScore
        },
        tools: tools.map(t => ({
          name: t.name,
          domain: t.domain,
          category: t.category,
          count: t.event_count,
          risk: t.risk
        })),
        threats: threats.slice(0, 6).map(t => ({
          type: t.type,
          severity: t.severity,
          time: getRelativeTime(t.created_at)
        })),
        compliance: {
          gdpr: complianceMap.gdpr || 0,
          hipaa: complianceMap.hipaa || 0,
          pci: complianceMap.pcidss || complianceMap['pcidss'] || 0,
          soc2: complianceMap.soc2 || complianceMap['soc2'] || 0
        },
        threatStats
      };

      console.log('[Dashboard] Data loaded from Supabase:', this.data.stats);
    } catch (error) {
      console.error('[Dashboard] Supabase load failed, using sample data:', error);
      this.loadSampleData();
    }
  }

  loadSampleData() {
    this.data = {
      stats: { events: 2847, threats: 12, violations: 3, riskScore: 24 },
      tools: [
        { name: 'ChatGPT', domain: 'chat.openai.com', category: 'conversational', count: 1253, risk: 'Medium' },
        { name: 'Claude', domain: 'claude.ai', category: 'conversational', count: 892, risk: 'Low' },
        { name: 'Gemini', domain: 'gemini.google.com', category: 'conversational', count: 456, risk: 'Low' },
        { name: 'Cursor', domain: 'cursor.sh', category: 'coding', count: 234, risk: 'Medium' },
        { name: 'Midjourney', domain: 'midjourney.com', category: 'image', count: 12, risk: 'High' }
      ],
      threats: [
        { type: 'PII Exposure', severity: 'high', time: '2 min ago' },
        { type: 'Shadow AI Access', severity: 'critical', time: '15 min ago' },
        { type: 'Policy Violation', severity: 'medium', time: '1 hour ago' },
        { type: 'Unusual Activity', severity: 'low', time: '2 hours ago' }
      ],
      compliance: { gdpr: 95, hipaa: 88, pci: 92, soc2: 97 },
      threatStats: { total: 4, critical: 1, high: 1, medium: 1, low: 1 }
    };
  }

  setupCharts() {
    this.drawActivityChart();
  }

  drawActivityChart() {
    const canvas = document.getElementById('activityChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const rect = canvas.parentElement.getBoundingClientRect();

    canvas.width = rect.width;
    canvas.height = rect.height;

    // Generate data
    const points = [];
    for (let i = 23; i >= 0; i--) {
      points.push({
        hour: i,
        value: Math.floor(Math.random() * 150) + 50
      });
    }

    this.drawLineChart(ctx, points, canvas.width, canvas.height);
  }

  drawLineChart(ctx, points, width, height) {
    const padding = { top: 20, right: 20, bottom: 30, left: 50 };
    const chartWidth = width - padding.left - padding.right;
    const chartHeight = height - padding.top - padding.bottom;

    ctx.clearRect(0, 0, width, height);

    const maxValue = Math.max(...points.map(p => p.value));

    // Grid lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.lineWidth = 1;

    for (let i = 0; i <= 4; i++) {
      const y = padding.top + (chartHeight / 4) * i;
      ctx.beginPath();
      ctx.moveTo(padding.left, y);
      ctx.lineTo(width - padding.right, y);
      ctx.stroke();

      ctx.fillStyle = 'rgba(255, 255, 255, 0.35)';
      ctx.font = '10px -apple-system, sans-serif';
      ctx.textAlign = 'right';
      ctx.fillText(Math.round(maxValue - (maxValue / 4) * i), padding.left - 10, y + 4);
    }

    // Area gradient
    const gradient = ctx.createLinearGradient(0, padding.top, 0, height - padding.bottom);
    gradient.addColorStop(0, 'rgba(99, 102, 241, 0.2)');
    gradient.addColorStop(1, 'rgba(99, 102, 241, 0)');

    ctx.fillStyle = gradient;
    ctx.beginPath();
    ctx.moveTo(padding.left, height - padding.bottom);

    points.forEach((point, i) => {
      const x = padding.left + (i / (points.length - 1)) * chartWidth;
      const y = padding.top + chartHeight - (point.value / maxValue) * chartHeight;
      ctx.lineTo(x, y);
    });

    ctx.lineTo(width - padding.right, height - padding.bottom);
    ctx.closePath();
    ctx.fill();

    // Line
    ctx.strokeStyle = '#6366F1';
    ctx.lineWidth = 2;
    ctx.lineJoin = 'round';
    ctx.beginPath();

    points.forEach((point, i) => {
      const x = padding.left + (i / (points.length - 1)) * chartWidth;
      const y = padding.top + chartHeight - (point.value / maxValue) * chartHeight;

      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });

    ctx.stroke();

    // Dots
    points.forEach((point, i) => {
      const x = padding.left + (i / (points.length - 1)) * chartWidth;
      const y = padding.top + chartHeight - (point.value / maxValue) * chartHeight;

      ctx.fillStyle = '#6366F1';
      ctx.beginPath();
      ctx.arc(x, y, 3, 0, Math.PI * 2);
      ctx.fill();
    });

    // X-axis labels
    ctx.fillStyle = 'rgba(255, 255, 255, 0.35)';
    ctx.font = '10px -apple-system, sans-serif';
    ctx.textAlign = 'center';

    for (let i = 0; i < points.length; i += 6) {
      const x = padding.left + (i / (points.length - 1)) * chartWidth;
      ctx.fillText(`${points[i].hour}h`, x, height - 10);
    }
  }

  setupListeners() {
    // Refresh button
    document.getElementById('refreshBtn')?.addEventListener('click', async () => {
      const btn = document.getElementById('refreshBtn');
      btn.classList.add('loading');
      await this.loadData();
      this.render();
      this.drawActivityChart();
      btn.classList.remove('loading');
    });

    // Export button
    document.getElementById('exportBtn')?.addEventListener('click', () => {
      this.exportData();
    });

    // Time range
    document.getElementById('timeRange')?.addEventListener('change', () => {
      this.drawActivityChart();
    });

    // Window resize
    window.addEventListener('resize', () => {
      this.drawActivityChart();
    });

    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', (e) => {
        document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
        item.classList.add('active');
      });
    });
  }

  render() {
    this.renderStats();
    this.renderTools();
    this.renderThreats();
    this.renderCompliance();
    this.renderRiskBars();
  }

  renderStats() {
    const { stats } = this.data;

    document.getElementById('totalEvents').textContent = this.formatNumber(stats.events);
    document.getElementById('threatsDetected').textContent = stats.threats;
    document.getElementById('violations').textContent = stats.violations;
    document.getElementById('riskScore').textContent = stats.riskScore || '—';
  }

  renderTools() {
    const tbody = document.getElementById('toolsTableBody');
    if (!tbody) return;

    const categoryIcons = {
      conversational: '💬', coding: '💻', image: '🎨', video: '🎬',
      audio: '🎵', productivity: '📝', search: '🔍', default: '🔧'
    };

    tbody.innerHTML = this.data.tools.map(tool => `
      <tr>
        <td>
          <div class="table-tool">
            <div class="tool-icon-sm">${categoryIcons[tool.category] || categoryIcons.default}</div>
            <div>
              <div style="font-weight: 500; color: var(--text-primary)">${this.escapeHtml(tool.name)}</div>
              <div style="font-size: 11px; color: var(--text-muted)">${this.escapeHtml(tool.domain)}</div>
            </div>
          </div>
        </td>
        <td style="text-transform: capitalize">${tool.category}</td>
        <td>${this.formatNumber(tool.count)}</td>
        <td><span class="severity-badge ${tool.risk.toLowerCase()}">${tool.risk}</span></td>
      </tr>
    `).join('');
  }

  renderThreats() {
    const tbody = document.getElementById('threatsTableBody');
    if (!tbody) return;

    tbody.innerHTML = this.data.threats.map(threat => `
      <tr>
        <td style="font-weight: 500; color: var(--text-primary)">${this.escapeHtml(threat.type)}</td>
        <td><span class="severity-badge ${threat.severity}">${threat.severity}</span></td>
        <td style="color: var(--text-muted)">${this.escapeHtml(threat.time)}</td>
      </tr>
    `).join('');
  }

  renderCompliance() {
    const { compliance } = this.data;

    const scores = [
      { id: 'gdpr', value: compliance.gdpr },
      { id: 'hipaa', value: compliance.hipaa },
      { id: 'pci', value: compliance.pci },
      { id: 'soc2', value: compliance.soc2 }
    ];

    scores.forEach(score => {
      const ring = document.getElementById(`${score.id}Ring`);
      const valueEl = document.getElementById(`${score.id}Score`);

      if (ring) {
        const offset = 100 - score.value;
        ring.style.strokeDashoffset = offset;
      }

      if (valueEl) {
        valueEl.textContent = score.value;
      }
    });
  }

  renderRiskBars() {
    const ts = this.data.threatStats;
    if (!ts) return;

    const total = Math.max(ts.total, 1);
    const items = [
      { id: 'critical', count: ts.critical },
      { id: 'high', count: ts.high },
      { id: 'medium', count: ts.medium },
      { id: 'low', count: ts.low }
    ];

    items.forEach(item => {
      const bar = document.getElementById(`${item.id}Bar`);
      const val = document.getElementById(`${item.id}Count`);
      if (bar) bar.style.width = `${Math.max((item.count / total) * 100, 5)}%`;
      if (val) val.textContent = item.count;
    });
  }

  async exportData() {
    try {
      const blob = new Blob([JSON.stringify(this.data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `devise-export-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('[Dashboard] Export failed:', error);
    }
  }

  startPolling() {
    this.refreshInterval = setInterval(async () => {
      await this.loadData();
      this.render();
    }, 30000);
  }

  formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'k';
    return num.toString();
  }

  escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  const dashboard = new DashboardController();
  dashboard.initialize();
});
