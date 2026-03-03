/**
 * Devise Supabase Client
 * Lightweight REST client for Supabase — no npm dependencies.
 * Uses the PostgREST API via fetch().
 */

import { CONFIG } from './config.js';

const SUPABASE_URL = CONFIG.SUPABASE_URL;
const SUPABASE_KEY = CONFIG.SUPABASE_ANON_KEY;
const REST_URL = `${SUPABASE_URL}/rest/v1`;

const headers = {
    'apikey': SUPABASE_KEY,
    'Authorization': `Bearer ${SUPABASE_KEY}`,
    'Content-Type': 'application/json',
    'Prefer': 'return=representation'
};

// ============================================================
// GENERIC REST HELPERS
// ============================================================

async function supabaseSelect(table, query = '') {
    const res = await fetch(`${REST_URL}/${table}?${query}`, { headers });
    if (!res.ok) throw new Error(`Supabase SELECT ${table} failed: ${res.status}`);
    return res.json();
}

async function supabaseInsert(table, data) {
    const res = await fetch(`${REST_URL}/${table}`, {
        method: 'POST',
        headers,
        body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error(`Supabase INSERT ${table} failed: ${res.status}`);
    return res.json();
}

async function supabaseUpsert(table, data) {
    const res = await fetch(`${REST_URL}/${table}`, {
        method: 'POST',
        headers: { ...headers, 'Prefer': 'return=representation,resolution=merge-duplicates' },
        body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error(`Supabase UPSERT ${table} failed: ${res.status}`);
    return res.json();
}

async function supabaseUpdate(table, query, data) {
    const res = await fetch(`${REST_URL}/${table}?${query}`, {
        method: 'PATCH',
        headers,
        body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error(`Supabase UPDATE ${table} failed: ${res.status}`);
    return res.json();
}

// ============================================================
// EVENTS
// ============================================================

export async function logEvent(event) {
    return supabaseInsert('events', {
        event_type: event.eventType || event.type || 'unknown',
        tool_name: event.toolName || event.tool_name || null,
        domain: event.domain || null,
        category: event.category || null,
        risk_level: event.riskLevel || event.risk_level || null,
        url: event.url || null,
        user_id: event.userId || null,
        user_email: event.userEmail || null,
        pii_detected: event.piiDetected || false,
        pii_risk_score: event.piiRiskScore || 0,
        policy_violation: event.policyViolation || false,
        encrypted: event.encrypted || false,
        metadata: event.metadata || {}
    });
}

export async function logEventsBatch(events) {
    const rows = events.map(e => ({
        event_type: e.eventType || e.type || 'unknown',
        tool_name: e.toolName || e.tool_name || null,
        domain: e.domain || null,
        category: e.category || null,
        risk_level: e.riskLevel || e.risk_level || null,
        url: e.url || null,
        user_id: e.userId || null,
        user_email: e.userEmail || null,
        pii_detected: e.piiDetected || false,
        pii_risk_score: e.piiRiskScore || 0,
        policy_violation: e.policyViolation || false,
        encrypted: e.encrypted || false,
        metadata: e.metadata || {}
    }));
    return supabaseInsert('events', rows);
}

export async function getEvents(limit = 50) {
    return supabaseSelect('events', `order=created_at.desc&limit=${limit}`);
}

export async function getEventStats() {
    const events = await supabaseSelect('events', 'select=id');
    const piiEvents = await supabaseSelect('events', 'pii_detected=eq.true&select=id');
    const violations = await supabaseSelect('events', 'policy_violation=eq.true&select=id');
    return {
        total: events.length,
        piiDetected: piiEvents.length,
        policyViolations: violations.length
    };
}

// ============================================================
// THREATS
// ============================================================

export async function logThreat(threat) {
    return supabaseInsert('threats', {
        type: threat.type,
        severity: threat.severity,
        description: threat.description || null,
        domain: threat.domain || null,
        user_email: threat.userEmail || threat.user_email || null,
        metadata: threat.metadata || {}
    });
}

export async function getThreats(limit = 20) {
    return supabaseSelect('threats', `order=created_at.desc&limit=${limit}`);
}

export async function getThreatStats() {
    const all = await supabaseSelect('threats', 'select=id,severity');
    return {
        total: all.length,
        critical: all.filter(t => t.severity === 'critical').length,
        high: all.filter(t => t.severity === 'high').length,
        medium: all.filter(t => t.severity === 'medium').length,
        low: all.filter(t => t.severity === 'low').length
    };
}

// ============================================================
// TOOLS
// ============================================================

export async function upsertTool(tool) {
    return supabaseUpsert('tools', {
        name: tool.name,
        domain: tool.domain,
        category: tool.category || null,
        risk: tool.risk || 'Medium',
        enterprise: tool.enterprise || false,
        event_count: tool.event_count || tool.count || 0,
        last_seen: new Date().toISOString()
    });
}

export async function getTools(limit = 20) {
    return supabaseSelect('tools', `order=event_count.desc&limit=${limit}`);
}

export async function incrementToolCount(domain) {
    const tools = await supabaseSelect('tools', `domain=eq.${domain}&select=event_count`);
    if (tools.length > 0) {
        await supabaseUpdate('tools', `domain=eq.${domain}`, {
            event_count: (tools[0].event_count || 0) + 1,
            last_seen: new Date().toISOString()
        });
    }
}

// ============================================================
// COMPLIANCE
// ============================================================

export async function getComplianceScores() {
    return supabaseSelect('compliance_scores', 'order=framework.asc');
}

export async function setComplianceScore(framework, score) {
    return supabaseUpsert('compliance_scores', { framework, score, updated_at: new Date().toISOString() });
}

// ============================================================
// POLICY VIOLATIONS
// ============================================================

export async function logPolicyViolation(violation) {
    return supabaseInsert('policy_violations', {
        violation_type: violation.type || violation.violation_type,
        domain: violation.domain || null,
        tool_name: violation.toolName || violation.tool_name || null,
        user_email: violation.userEmail || violation.user_email || null,
        description: violation.description || null,
        severity: violation.severity || 'medium',
        metadata: violation.metadata || {}
    });
}

export async function getPolicyViolations(limit = 20) {
    return supabaseSelect('policy_violations', `order=created_at.desc&limit=${limit}`);
}

// ============================================================
// USERS
// ============================================================

export async function upsertUser(user) {
    return supabaseUpsert('users', {
        email: user.email,
        name: user.name || user.email.split('@')[0],
        department: user.department || 'Unknown',
        organization_id: user.organizationId || user.organization_id || null,
        source: user.source || 'manual',
        updated_at: new Date().toISOString()
    });
}

export async function getUsers() {
    return supabaseSelect('users', 'order=created_at.desc');
}

// ============================================================
// DASHBOARD HELPER (aggregated stats)
// ============================================================

export async function getDashboardData() {
    try {
        const [events, threats, tools, compliance] = await Promise.all([
            getEvents(100),
            getThreats(20),
            getTools(10),
            getComplianceScores()
        ]);

        const eventStats = {
            total: events.length,
            piiDetected: events.filter(e => e.pii_detected).length,
            policyViolations: events.filter(e => e.policy_violation).length
        };

        const threatStats = {
            total: threats.length,
            critical: threats.filter(t => t.severity === 'critical').length,
            high: threats.filter(t => t.severity === 'high').length,
            medium: threats.filter(t => t.severity === 'medium').length,
            low: threats.filter(t => t.severity === 'low').length
        };

        // Calculate risk score: weighted sum
        const riskScore = Math.min(100,
            threatStats.critical * 25 +
            threatStats.high * 15 +
            threatStats.medium * 5 +
            threatStats.low * 1 +
            eventStats.policyViolations * 3
        );

        const complianceMap = {};
        compliance.forEach(c => {
            const key = c.framework.toLowerCase().replace(/[\s-]/g, '');
            complianceMap[key] = c.score;
        });

        return {
            stats: {
                events: eventStats.total,
                threats: threatStats.total,
                violations: eventStats.policyViolations,
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
                pci: complianceMap.pcidss || complianceMap['pci-dss'] || complianceMap.pci || 0,
                soc2: complianceMap.soc2 || 0
            }
        };
    } catch (error) {
        console.error('[Supabase Client] getDashboardData failed:', error);
        throw error;
    }
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
