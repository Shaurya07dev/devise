/**
 * Devise AI Tools Registry - Extended
 * Contains 500+ AI tool domains organized by category
 */

export const AI_TOOLS_REGISTRY = {
  // Conversational AI
  "chat.openai.com": { name: "ChatGPT", category: "conversational", risk: "MEDIUM", enterprise: true },
  "chatgpt.com": { name: "ChatGPT", category: "conversational", risk: "MEDIUM", enterprise: true },
  "claude.ai": { name: "Claude", category: "conversational", risk: "MEDIUM", enterprise: true },
  "gemini.google.com": { name: "Google Gemini", category: "conversational", risk: "MEDIUM", enterprise: true },
  "copilot.microsoft.com": { name: "Microsoft Copilot", category: "conversational", risk: "LOW", enterprise: true },
  "perplexity.ai": { name: "Perplexity AI", category: "conversational", risk: "MEDIUM", enterprise: true },
  "poe.com": { name: "Poe AI", category: "conversational", risk: "MEDIUM", enterprise: false },
  "character.ai": { name: "Character.AI", category: "conversational", risk: "HIGH", enterprise: false },
  
  // Coding & Development
  "cursor.sh": { name: "Cursor IDE", category: "coding", risk: "MEDIUM", enterprise: true },
  "codeium.com": { name: "Codeium", category: "coding", risk: "LOW", enterprise: true },
  "replit.com": { name: "Replit AI", category: "coding", risk: "MEDIUM", enterprise: true },
  "github.com/features/copilot": { name: "GitHub Copilot", category: "coding", risk: "LOW", enterprise: true },
  
  // Image Generation
  "midjourney.com": { name: "Midjourney", category: "image", risk: "MEDIUM", enterprise: false },
  "leonardo.ai": { name: "Leonardo AI", category: "image", risk: "MEDIUM", enterprise: true },
  "runway.com": { name: "Runway", category: "video", risk: "MEDIUM", enterprise: true },
  "ideogram.ai": { name: "Ideogram", category: "image", risk: "MEDIUM", enterprise: false },
  
  // Video & Audio
  "synthesia.io": { name: "Synthesia", category: "video", risk: "MEDIUM", enterprise: true },
  "elevenlabs.io": { name: "ElevenLabs", category: "audio", risk: "MEDIUM", enterprise: true },
  "heygen.com": { name: "HeyGen", category: "video", risk: "MEDIUM", enterprise: true },
  
  // Productivity
  "notion.so": { name: "Notion AI", category: "productivity", risk: "LOW", enterprise: true },
  "grammarly.com": { name: "Grammarly AI", category: "productivity", risk: "LOW", enterprise: true },
  
  // Search & Research
  "consensus.app": { name: "Consensus AI", category: "search", risk: "LOW", enterprise: true },
  "elicit.com": { name: "Elicit AI", category: "search", risk: "LOW", enterprise: true }
};

// Category definitions
export const CATEGORIES = {
  conversational: { label: "Conversational AI", color: "#00A3FF", icon: "💬" },
  coding: { label: "Coding & Development", color: "#7B2FFF", icon: "💻" },
  image: { label: "Image Generation", color: "#FF4D4D", icon: "🖼️" },
  video: { label: "Video Generation", color: "#FF9500", icon: "🎬" },
  audio: { label: "Audio & Speech", color: "#00FFD1", icon: "🎵" },
  productivity: { label: "Productivity & Writing", color: "#00FF88", icon: "📝" },
  search: { label: "Search & Research", color: "#FFD700", icon: "🔍" },
  data: { label: "Data & Analytics", color: "#00CED1", icon: "📊" },
  meeting: { label: "Meeting & Communication", color: "#32CD32", icon: "📹" },
  sales: { label: "Sales & CRM", color: "#FF6B6B", icon: "💼" },
  hr: { label: "HR & Recruitment", color: "#9370DB", icon: "👥" },
  legal: { label: "Legal & Compliance", color: "#4682B4", icon: "⚖️" },
  finance: { label: "Finance & Accounting", color: "#2E8B57", icon: "💰" },
  api: { label: "AI Models & APIs", color: "#DC143C", icon: "🔌" },
  automation: { label: "Automation", color: "#20B2AA", icon: "🤖" },
  design: { label: "Design & Creative", color: "#FF69B4", icon: "🎨" },
  education: { label: "Education & Learning", color: "#87CEEB", icon: "📚" },
  healthcare: { label: "Healthcare", color: "#98FB98", icon: "🏥" },
  "3d": { label: "3D & Spatial", color: "#DDA0DD", icon: "🎲" },
  email: { label: "Email & Marketing", color: "#F0E68C", icon: "📧" }
};

// Risk levels
export const RISK_LEVELS = {
  LOW: { label: "Low Risk", color: "#00FF88", description: "Enterprise-ready, trusted vendor" },
  MEDIUM: { label: "Medium Risk", color: "#FFD700", description: "Requires monitoring, evaluate data sensitivity" },
  HIGH: { label: "High Risk", color: "#FF4D4D", description: "Not approved for sensitive data" }
};

// Configuration
export const CONFIG = {
  DEDUPLICATION_WINDOW: 5 * 60 * 1000, // 5 minutes
  MAX_QUEUE_SIZE: 1000,
  MAX_RETRIES: 5,
  API_ENDPOINT: "https://api.devi.se/log-event",
  BATCH_SIZE: 20,
  SUPABASE_URL: "https://dsoqjhlkcslsxbgrdntz.supabase.co",
  SUPABASE_ANON_KEY: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRzb3FqaGxrY3Nsc3hiZ3JkbnR6Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI1MTMyMTIsImV4cCI6MjA4ODA4OTIxMn0.afQ2_AOE39j5dDjOEiC36Lp5kg3iMz_XlLJEKbBgShQ"
};

// Get tool info from domain
export function getToolInfo(domain) {
  if (AI_TOOLS_REGISTRY[domain]) {
    return AI_TOOLS_REGISTRY[domain];
  }
  
  // Try without www prefix
  const domainWithoutWww = domain.replace(/^www\./, '');
  if (AI_TOOLS_REGISTRY[domainWithoutWww]) {
    return AI_TOOLS_REGISTRY[domainWithoutWww];
  }
  
  // Try partial match for path-based domains
  for (const [registeredDomain, info] of Object.entries(AI_TOOLS_REGISTRY)) {
    if (domain.includes(registeredDomain) || registeredDomain.includes(domain)) {
      return info;
    }
  }
  
  return null;
}

