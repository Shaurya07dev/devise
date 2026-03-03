/**
 * Devise Reporting & Audit Module
 * Generate reports and audit trails
 */

export class ReportingEngine {
  constructor() {
    this.reportTemplates = {
      executive: this.generateExecutiveReport.bind(this),
      compliance: this.generateComplianceReport.bind(this),
      security: this.generateSecurityReport.bind(this),
      usage: this.generateUsageReport.bind(this),
      risk: this.generateRiskReport.bind(this)
    };
    
    this.exportFormats = {
      json: this.exportAsJSON.bind(this),
      csv: this.exportAsCSV.bind(this),
      pdf: this.exportAsPDF.bind(this)
    };
  }

  /**
   * Generate report
   */
  async generateReport(type, options = {}) {
    const generator = this.reportTemplates[type];
    if (!generator) {
      throw new Error(`Unknown report type: ${type}`);
    }
    
    return generator(options);
  }

  /**
   * Generate Executive Summary Report
   */
  async generateExecutiveReport(options) {
    const { startDate, endDate } = this.getDateRange(options);
    
    // Get data
    const [events, threats, violations] = await Promise.all([
      this.getEvents(startDate, endDate),
      this.getThreats(startDate, endDate),
      this.getViolations(startDate, endDate)
    ]);
    
    // Calculate metrics
    const totalEvents = events.length;
    const uniqueUsers = new Set(events.map(e => e.userId)).size;
    const uniqueTools = new Set(events.map(e => e.domain)).size;
    const criticalThreats = threats.filter(t => t.severity === 'critical').length;
    const policyViolations = violations.length;
    
    // Calculate risk score
    const riskScore = this.calculateOverallRisk(events, threats, violations);
    
    return {
      reportType: 'executive',
      generatedAt: new Date().toISOString(),
      period: {
        start: startDate,
        end: endDate
      },
      summary: {
        totalEvents,
        uniqueUsers,
        uniqueTools,
        criticalThreats,
        policyViolations,
        riskScore
      },
      trends: this.calculateTrends(events),
      topTools: this.getTopItems(events, 'domain', 5),
      topUsers: this.getTopItems(events, 'userId', 5),
      recommendations: this.generateExecutiveRecommendations(riskScore, criticalThreats)
    };
  }

  /**
   * Generate Compliance Report
   */
  async generateComplianceReport(options) {
    const { startDate, endDate, standards = ['gdpr', 'hipaa', 'pci', 'soc2'] } = options;
    
    const [events, violations] = await Promise.all([
      this.getEvents(startDate, endDate),
      this.getViolations(startDate, endDate)
    ]);
    
    const complianceChecks = {};
    
    for (const standard of standards) {
      complianceChecks[standard] = this.checkCompliance(standard, events, violations);
    }
    
    return {
      reportType: 'compliance',
      generatedAt: new Date().toISOString(),
      period: { start: startDate, end: endDate },
      standards: complianceChecks,
      violations: violations.map(v => ({
        id: v.id,
        type: v.type,
        timestamp: v.timestamp,
        severity: v.severity || 'medium'
      })),
      complianceScore: this.calculateComplianceScore(complianceChecks),
      recommendations: this.generateComplianceRecommendations(complianceChecks)
    };
  }

  /**
   * Generate Security Report
   */
  async generateSecurityReport(options) {
    const { startDate, endDate } = this.getDateRange(options);
    
    const threats = await this.getThreats(startDate, endDate);
    
    const threatsByType = {};
    const threatsBySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    
    for (const threat of threats) {
      threatsByType[threat.type] = (threatsByType[threat.type] || 0) + 1;
      threatsBySeverity[threat.severity]++;
    }
    
    return {
      reportType: 'security',
      generatedAt: new Date().toISOString(),
      period: { start: startDate, end: endDate },
      summary: {
        totalThreats: threats.length,
        criticalCount: threatsBySeverity.critical,
        highCount: threatsBySeverity.high,
        resolvedCount: threats.filter(t => t.resolved).length
      },
      threatsByType,
      threatsBySeverity,
      topThreats: threats.slice(-20),
      timeline: this.createTimeline(threats),
      recommendations: this.generateSecurityRecommendations(threats)
    };
  }

  /**
   * Generate Usage Report
   */
  async generateUsageReport(options) {
    const { startDate, endDate } = this.getDateRange(options);
    
    const events = await this.getEvents(startDate, endDate);
    
    const usageByHour = {};
    const usageByDay = {};
    const usageByTool = {};
    const usageByCategory = {};
    
    for (const event of events) {
      const date = new Date(event.timestamp);
      const hour = date.getHours();
      const day = date.toISOString().split('T')[0];
      
      usageByHour[hour] = (usageByHour[hour] || 0) + 1;
      usageByDay[day] = (usageByDay[day] || 0) + 1;
      usageByTool[event.domain] = (usageByTool[event.domain] || 0) + 1;
      
      if (event.category) {
        usageByCategory[event.category] = (usageByCategory[event.category] || 0) + 1;
      }
    }
    
    return {
      reportType: 'usage',
      generatedAt: new Date().toISOString(),
      period: { start: startDate, end: endDate },
      summary: {
        totalEvents: events.length,
        peakHour: this.getPeak(usageByHour),
        peakDay: this.getPeak(usageByDay)
      },
      usageByHour,
      usageByDay,
      usageByTool,
      usageByCategory,
      trends: this.calculateTrends(events)
    };
  }

  /**
   * Generate Risk Report
   */
  async generateRiskReport(options) {
    const { startDate, endDate } = this.getDateRange(options);
    
    const [events, threats, = await Promise.all([
      this.getEvents(startDate, endDate),
      this.getThreats(startDate, endDate)
    ]);
    
    const riskAnalysis = this.analyzeRisks(events, threats);
    
    return {
      reportType: 'risk',
      generatedAt: new Date().toISOString(),
      period: { start: startDate, end: endDate },
      overallRiskScore: riskAnalysis.score,
      riskFactors: riskAnalysis.factors,
      highRiskUsers: riskAnalysis.highRiskUsers,
      highRiskTools: riskAnalysis.highRiskTools,
      recommendations: riskAnalysis.recommendations
    };
  }

  /**
   * Export report
   */
  async exportReport(report, format = 'json') {
    const exporter = this.exportFormats[format];
    if (!exporter) {
      throw new Error(`Unknown format: ${format}`);
    }
    
    return exporter(report);
  }

  /**
   * Export as JSON
   */
  exportAsJSON(report) {
    return JSON.stringify(report, null, 2);
  }

  /**
   * Export as CSV
   */
  exportAsCSV(report) {
    const rows = [];
    
    // Headers based on report type
    switch (report.reportType) {
      case 'executive':
        rows.push(['Metric', 'Value']);
        for (const [key, value] of Object.entries(report.summary)) {
          rows.push([key, String(value)]);
        }
        break;
      case 'security':
        rows.push(['Threat Type', 'Count', 'Severity']);
        for (const [type, count] of Object.entries(report.threatsByType)) {
          rows.push([type, String(count), '']);
        }
        break;
      default:
        rows.push(['Field', 'Value']);
        rows.push(['Report Type', report.reportType]);
        rows.push(['Generated', report.generatedAt]);
    }
    
    return rows.map(row => row.join(',')).join('\n');
  }

  /**
   * Export as PDF (returns HTML for browser to print)
   */
  exportAsPDF(report) {
    return `
<!DOCTYPE html>
<html>
<head>
  <title>Devise Report - ${report.reportType}</title>
  <style>
    body { font-family: Arial, sans-serif; padding: 20px; }
    h1 { color: #0A0E1A; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background: #0A0E1A; color: white; }
  </style>
</head>
<body>
  <h1>Devise ${report.reportType.charAt(0).toUpperCase() + report.reportType.slice(1)} Report</h1>
  <p>Generated: ${report.generatedAt}</p>
  <pre>${JSON.stringify(report, null, 2)}</pre>
</body>
</html>
    `;
  }

  /**
   * Helper: Get date range
   */
  getDateRange(options) {
    const endDate = options.endDate ? new Date(options.endDate) : new Date();
    const startDate = options.startDate ? new Date(options.startDate) : 
      new Date(endDate.getTime() - 30 * 24 * 60 * 60 * 1000); // 30 days
    
    return { startDate: startDate.toISOString(), endDate: endDate.toISOString() };
  }

  /**
   * Helper: Get events from storage
   */
  async getEvents(startDate, endDate) {
    const stored = await chrome.storage.local.get('eventQueue') || [];
    return stored.filter(e => 
      e.timestamp >= new Date(startDate).getTime() && 
      e.timestamp <= new Date(endDate).getTime()
    );
  }

  /**
   * Helper: Get threats from storage
   */
  async getThreats(startDate, endDate) {
    const stored = await chrome.storage.local.get('threatHistory') || [];
    return stored.filter(t => 
      new Date(t.timestamp) >= new Date(startDate) && 
      new Date(t.timestamp) <= new Date(endDate)
    );
  }

  /**
   * Helper: Get violations from storage
   */
  async getViolations(startDate, endDate) {
    const stored = await chrome.storage.local.get('policyViolations') || [];
    return stored.filter(v => 
      new Date(v.timestamp) >= new Date(startDate) && 
      new Date(v.timestamp) <= new Date(endDate)
    );
  }

  /**
   * Helper: Calculate overall risk
   */
  calculateOverallRisk(events, threats, violations) {
    let score = 0;
    
    score += Math.min(events.length / 100, 30);
    score += threats.filter(t => t.severity === 'critical').length * 10;
    score += threats.filter(t => t.severity === 'high').length * 5;
    score += violations.length * 2;
    
    return Math.min(100, Math.round(score));
  }

  /**
   * Helper: Calculate trends
   */
  calculateTrends(events) {
    // Group by day
    const byDay = {};
    for (const event of events) {
      const day = new Date(event.timestamp).toISOString().split('T')[0];
      byDay[day] = (byDay[day] || 0) + 1;
    }
    
    const days = Object.keys(byDay).sort();
    if (days.length < 2) return 'stable';
    
    const lastDay = byDay[days[days.length - 1]];
    const prevDay = byDay[days[days.length - 2]];
    
    if (lastDay > prevDay * 1.2) return 'increasing';
    if (lastDay < prevDay * 0.8) return 'decreasing';
    return 'stable';
  }

  /**
   * Helper: Get top items
   */
  getTopItems(items, field, limit) {
    const counts = {};
    for (const item of items) {
      if (item[field]) {
        counts[item[field]] = (counts[item[field]] || 0) + 1;
      }
    }
    
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([value, count]) => ({ [field]: value, count }));
  }

  /**
   * Helper: Check compliance with standard
   */
  checkCompliance(standard, events, violations) {
    switch (standard) {
      case 'gdpr':
        return {
          compliant: violations.filter(v => v.type.includes('pii')).length === 0,
          issues: violations.filter(v => v.type.includes('pii'))
        };
      case 'hipaa':
        return {
          compliant: violations.filter(v => v.type.includes('medical')).length === 0,
          issues: violations.filter(v => v.type.includes('medical'))
        };
      case 'pci':
        return {
          compliant: violations.filter(v => v.type.includes('credit') || v.type.includes('card')).length === 0,
          issues: violations.filter(v => v.type.includes('credit') || v.type.includes('card'))
        };
      case 'soc2':
        return {
          compliant: violations.length < 10,
          issues: violations.slice(0, 10)
        };
      default:
        return { compliant: true, issues: [] };
    }
  }

  /**
   * Helper: Calculate compliance score
   */
  calculateComplianceScore(checks) {
    const standards = Object.keys(checks);
    const compliantCount = standards.filter(s => checks[s].compliant).length;
    return Math.round((compliantCount / standards.length) * 100);
  }

  /**
   * Helper: Create timeline
   */
  createTimeline(threats) {
    const timeline = {};
    for (const threat of threats) {
      const hour = new Date(threat.timestamp).toISOString().split('T')[1].split(':')[0];
      timeline[hour] = (timeline[hour] || 0) + 1;
    }
    return timeline;
  }

  /**
   * Helper: Get peak
   */
  getPeak(data) {
    let maxKey = null;
    let maxValue = 0;
    for (const [key, value] of Object.entries(data)) {
      if (value > maxValue) {
        maxValue = value;
        maxKey = key;
      }
    }
    return { key: maxKey, value: maxValue };
  }

  /**
   * Helper: Analyze risks
   */
  analyzeRisks(events, threats) {
    const score = this.calculateOverallRisk(events, threats, []);
    const factors = [];
    
    if (threats.filter(t => t.severity === 'critical').length > 0) {
      factors.push({ type: 'critical_threats', severity: 'high' });
    }
    
    return {
      score,
      factors,
      highRiskUsers: [],
      highRiskTools: [],
      recommendations: []
    };
  }

  /**
   * Helper: Generate executive recommendations
   */
  generateExecutiveRecommendations(riskScore, criticalThreats) {
    const recommendations = [];
    
    if (criticalThreats > 0) {
      recommendations.push({
        priority: 'immediate',
        message: 'Review and address critical security threats immediately'
      });
    }
    
    if (riskScore > 70) {
      recommendations.push({
        priority: 'high',
        message: 'Consider implementing stricter AI tool access policies'
      });
    }
    
    return recommendations;
  }

  /**
   * Helper: Generate compliance recommendations
   */
  generateComplianceRecommendations(checks) {
    const recommendations = [];
    
    for (const [standard, check] of Object.entries(checks)) {
      if (!check.compliant) {
        recommendations.push({
          priority: 'high',
          message: `Address ${standard.toUpperCase()} compliance issues`
        });
      }
    }
    
    return recommendations;
  }

  /**
   * Helper: Generate security recommendations
   */
  generateSecurityRecommendations(threats) {
    const recommendations = [];
    
    if (threats.filter(t => t.type === 'shadow_ai_access').length > 0) {
      recommendations.push({
        priority: 'high',
        message: 'Update approved AI tools list and block shadow AI access'
      });
    }
    
    return recommendations;
  }
}

// Singleton instance
export const reportingEngine = new ReportingEngine();
