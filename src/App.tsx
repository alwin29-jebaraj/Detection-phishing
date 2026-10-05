/**
 * Phishing Detector & Safety Lab
 * User-Friendly Phishing Checker with PDF Generation & Gemini Security Chatbot
 */

import React, { useState, useEffect, useRef } from 'react';
import { jsPDF } from 'jspdf';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Terminal,
  History as HistoryIcon,
  BookOpen,
  Copy,
  Check,
  Download,
  Trash2,
  Play,
  RefreshCw,
  Search,
  ExternalLink,
  Lock,
  Globe,
  Mail,
  Info,
  AlertCircle,
  Cpu,
  BarChart3,
  Layers,
  Sparkles,
  ClipboardPaste,
  Eye,
  X,
  ArrowRight,
  HelpCircle,
  Lightbulb,
  CheckCircle2,
  MessageSquare,
  Send,
  FileDown,
  Bot,
  User,
  Zap,
  Clock,
  MousePointerClick,
  KeyRound,
  Calculator,
  Scale
} from 'lucide-react';

interface Indicator {
  indicator: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  points: number;
  evidence: string;
  category: string;
}

interface ScoreItem {
  indicator: string;
  category: string;
  severity: string;
  points: number;
  evidence: string;
}

interface URLAnalysis {
  url: string;
  scheme: string;
  is_https: boolean;
  domain: string;
  subdomains: string[];
  subdomain_count: number;
  domain_length: number;
  tld: string;
  path: string;
  path_length: number;
  query_params_count: number;
  has_ip_address: boolean;
  has_suspicious_characters: boolean;
  suspicious_character_details: string[];
  hyphen_count: number;
  dot_count: number;
  has_excessive_hyphens: boolean;
  has_excessive_dots: boolean;
  has_unusual_port: boolean;
  port: number | null;
  matched_keywords: string[];
  indicators: Indicator[];
}

interface AiExplanation {
  short_explanation?: string;
  main_suspicious_behavior?: string;
  most_important_indicators?: string[];
  recommended_action?: string;
  provider?: string;
}

interface AnalysisResult {
  id?: number;
  input_type: 'email' | 'url';
  input_data: string;
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  indicators: Indicator[];
  score_breakdown: ScoreItem[];
  extracted_urls?: string[];
  url_analysis?: URLAnalysis | null;
  ai_explanation?: AiExplanation;
  recommendation: string;
  ascii_report?: string;
  created_at?: string;
}

interface HistoryItem {
  id: number;
  input_type: 'email' | 'url';
  input_data: string;
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  indicators: Indicator[];
  score_breakdown: ScoreItem[];
  url_analysis?: URLAnalysis | null;
  ai_explanation?: AiExplanation;
  recommendation: string;
  created_at: string;
}

interface DashboardStats {
  total: number;
  high_risk: number;
  medium_risk: number;
  low_risk: number;
  avg_score: number;
}

interface TestCase {
  id: string;
  title: string;
  type: 'email' | 'url';
  badge: string;
  expected_tier: 'HIGH' | 'MEDIUM' | 'LOW';
  simple_description: string;
  content: string;
}

interface ChatMessage {
  id: string;
  role: 'user' | 'model';
  content: string;
  timestamp: string;
}

interface ThreatCategoryAnalysis {
  id: string;
  name: string;
  categoryLabel: string;
  flagged: boolean;
  points: number;
  evidence: string[];
  whyAttackersUseThis: string;
  howToIdentify: string;
  details: string;
}

function getThreatCategoryAnalysis(result: AnalysisResult | null): ThreatCategoryAnalysis[] {
  if (!result) return [];

  const indicators = result.indicators || [];

  // 1. Urgent language
  const urgentInds = indicators.filter(
    (i) =>
      i.category === 'urgency' ||
      /urgent|immediate|right now|deadline|countdown|expires today|act now|hours?/i.test(i.indicator)
  );
  const urgentFlagged = urgentInds.length > 0;
  const urgentPoints = urgentInds.reduce((sum, i) => sum + i.points, 0);

  // 2. Account threat
  const threatInds = indicators.filter(
    (i) =>
      i.category === 'threat' ||
      /suspend|threat|lock|block|terminate|unusual activity|unrecognized|security violation|punitive|punishment/i.test(
        i.indicator
      )
  );
  const threatFlagged = threatInds.length > 0;
  const threatPoints = threatInds.reduce((sum, i) => sum + i.points, 0);

  // 3. Login request & Call-to-Action
  const loginInds = indicators.filter(
    (i) =>
      i.category === 'call_to_action' ||
      /login|sign[- ]in|click here|cta|action demand|portal|review activity/i.test(i.indicator)
  );
  const loginFlagged = loginInds.length > 0;
  const loginPoints = loginInds.reduce((sum, i) => sum + i.points, 0);

  // 4. Credential request
  const credInds = indicators.filter(
    (i) =>
      i.category === 'credential' ||
      i.category === 'financial' ||
      /credential|password|passcode|verify account|pin|bank|card|cvv|refund/i.test(i.indicator)
  );
  const credFlagged = credInds.length > 0;
  const credPoints = credInds.reduce((sum, i) => sum + i.points, 0);

  // 5. Suspicious URL / Link tactics
  const urlInds = indicators.filter(
    (i) =>
      i.category === 'url' ||
      i.category === 'security' ||
      /url|domain|subdomain|ip|hyphen|tld|http|port/i.test(i.indicator)
  );
  const urlFlagged =
    urlInds.length > 0 || Boolean(result.url_analysis && result.url_analysis.indicators && result.url_analysis.indicators.length > 0);
  const urlPoints = urlInds.reduce((sum, i) => sum + i.points, 0);

  return [
    {
      id: 'urgent_language',
      name: 'Urgent Language',
      categoryLabel: 'Psychological Panic',
      flagged: urgentFlagged,
      points: urgentPoints,
      evidence: urgentInds.map((i) => i.evidence),
      whyAttackersUseThis:
        'Scammers use artificial deadlines (e.g. "immediately", "within 24 hours") to induce panic so victims react before evaluating legitimacy.',
      howToIdentify: 'Look for words like "urgent", "immediate action required", or ticking countdown timers.',
      details: urgentFlagged
        ? `Found ${urgentInds.length} urgency signal(s) demanding rapid compliance (+${urgentPoints} pts).`
        : 'No artificial panic markers or artificial countdown pressure detected.',
    },
    {
      id: 'account_threat',
      name: 'Account Threat / Suspension',
      categoryLabel: 'Fear & Loss Intimidation',
      flagged: threatFlagged,
      points: threatPoints,
      evidence: threatInds.map((i) => i.evidence),
      whyAttackersUseThis:
        'Threatening account suspension, termination, or penalties triggers an emotional panic response to force quick action.',
      howToIdentify: 'Statements claiming "your account will be suspended today" or "access will be permanently revoked".',
      details: threatFlagged
        ? `Found ${threatInds.length} threat signal(s) warning of punitive account loss (+${threatPoints} pts).`
        : 'No threats of account cancellation, lockout, or penalties detected.',
    },
    {
      id: 'login_request',
      name: 'Login Request / Call-to-Action',
      categoryLabel: 'Deceptive Redirection',
      flagged: loginFlagged,
      points: loginPoints,
      evidence: loginInds.map((i) => i.evidence),
      whyAttackersUseThis:
        'Phishers provide convenient "Click Here" or "Log In Now" links to channel victims directly into attacker-controlled phishing portals.',
      howToIdentify: 'Generic "Click Here to update" links instead of asking you to visit official websites independently.',
      details: loginFlagged
        ? `Found ${loginInds.length} call-to-action link solicitation(s) (+${loginPoints} pts).`
        : 'No deceptive "Click Here" links or urgent sign-in solicitations found.',
    },
    {
      id: 'credential_request',
      name: 'Credential Harvesting',
      categoryLabel: 'Secret Theft',
      flagged: credFlagged,
      points: credPoints,
      evidence: credInds.map((i) => i.evidence),
      whyAttackersUseThis:
        'The primary goal of phishing is stealing secret credentials—passwords, account verifications, or banking details—to take over accounts.',
      howToIdentify: 'Direct prompts to verify passwords, confirm security questions, or submit payment card numbers.',
      details: credFlagged
        ? `Found ${credInds.length} credential or account verification prompt(s) (+${credPoints} pts).`
        : 'No prompts asking for passwords, credentials, or sensitive banking details.',
    },
    {
      id: 'suspicious_url',
      name: 'Suspicious Web Link / URL',
      categoryLabel: 'Domain Deception',
      flagged: urlFlagged,
      points: urlPoints,
      evidence: urlInds.map((i) => i.evidence),
      whyAttackersUseThis:
        'Attackers register misleading domains with hyphens, copied brand names in subdomains, or raw IP addresses to impersonate legitimate services.',
      howToIdentify: 'Check the real domain before the first single slash (e.g., brand.attacker-site.com belongs to attacker-site.com).',
      details: urlFlagged
        ? `Found ${urlInds.length} suspicious link characteristic(s) or structural deception marker(s) (+${urlPoints} pts).`
        : 'No suspicious URL structural tricks, raw numerical IP hosts, or brand spoofing found.',
    },
  ];
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'check' | 'chat' | 'history' | 'tests' | 'guide'>('check');
  const [inputMode, setInputMode] = useState<'email' | 'url'>('email');
  const [emailText, setEmailText] = useState('');
  const [urlText, setUrlText] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [copiedReport, setCopiedReport] = useState(false);
  const [selectedClue, setSelectedClue] = useState<string | null>(null);
  const [resultTab, setResultTab] = useState<'summary' | 'clues' | 'link_details' | 'score_math'>('summary');
  const [showFullReportModal, setShowFullReportModal] = useState(false);
  const [showBenchmarkComparison, setShowBenchmarkComparison] = useState(false);
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);

  // Chatbot State
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      role: 'model',
      content: "Hello! I'm your Gemini Security Assistant. You can ask me anything about phishing scams, email warning signs, or questions about your current check. How can I help you stay safe today?",
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [isChatSending, setIsChatSending] = useState(false);
  const [selectedChatModel, setSelectedChatModel] = useState<'gemini-3.5-flash' | 'gemini-3.1-flash-lite'>('gemini-3.5-flash');
  const chatBottomRef = useRef<HTMLDivElement>(null);

  const [stats, setStats] = useState<DashboardStats>({
    total: 0,
    high_risk: 0,
    medium_risk: 0,
    low_risk: 0,
    avg_score: 0
  });

  // History State
  const [historyItems, setHistoryItems] = useState<HistoryItem[]>([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const [historySearch, setHistorySearch] = useState('');
  const [historyRiskFilter, setHistoryRiskFilter] = useState<string>('ALL');
  const [selectedHistoryItem, setSelectedHistoryItem] = useState<HistoryItem | null>(null);

  // Unit Test Runner State
  const [isRunningTests, setIsRunningTests] = useState(false);
  const [testResultOutput, setTestResultOutput] = useState<{
    success: boolean;
    stdout: string;
    stderr: string;
    duration_ms: number;
    exit_code: number;
  } | null>(null);

  const testCases: TestCase[] = [
    {
      id: "high-risk-urgent-suspension",
      title: "Fake Suspension Warning",
      type: "email",
      expected_tier: "HIGH",
      badge: "Dangerous Scam",
      simple_description: "Tells the user their account will be closed today unless they click a fake verification link.",
      content: `Subject: Urgent: Your Account Will Be Suspended

Dear Customer,

Your account will be suspended today due to unusual activity. Verify your account immediately using the link below:

https://secure-account-verification.example.com/login

Failure to verify will result in permanent suspension.`
    },
    {
      id: "medium-risk-activity-review",
      title: "Suspicious Login Alert",
      type: "email",
      expected_tier: "MEDIUM",
      badge: "Caution / Warning",
      simple_description: "Warns of a login from a new device and urges you to click a button to review your activity.",
      content: `Subject: Account Security Review Notification

Hello user,

We noticed a login from an unfamiliar device. Please review your account activity. 
Click here to update your information if this was not you:
https://portal-notice.example.com/security/review`
    },
    {
      id: "low-risk-engineering-memo",
      title: "Normal Team Newsletter",
      type: "email",
      expected_tier: "LOW",
      badge: "Safe Email",
      simple_description: "A friendly, routine work email that does not rush you or ask for passwords.",
      content: `Subject: Weekly Team Engineering Digest #42

Hello everyone,

Here is our weekly project digest. Sprint planning begins Tuesday at 10:00 AM UTC.
Please review the architectural RFC doc on our internal engineering wiki when you have time.

Best regards,
Engineering Operations Team`
    },
    {
      id: "url-suspicious-ip-host",
      title: "Suspicious Link with Numbers",
      type: "url",
      expected_tier: "HIGH",
      badge: "Dangerous Link",
      simple_description: "Uses a raw numerical IP address instead of a real company website name to hide where it goes.",
      content: "http://192.168.1.100/secure-account/verify/login.php"
    },
    {
      id: "url-brand-impersonation",
      title: "Imposter Brand Website",
      type: "url",
      expected_tier: "HIGH",
      badge: "Copied Brand Name",
      simple_description: "Contains 'paypal' in the link name, but the real website belongs to someone else.",
      content: "https://paypal-security-account-verification.attacker-host.com/signin"
    },
    {
      id: "url-clean-official",
      title: "Safe Official Website",
      type: "url",
      expected_tier: "LOW",
      badge: "Safe Link",
      simple_description: "A normal, clean HTTPS web link that goes directly to official documentation.",
      content: "https://example.com/resources/documentation"
    }
  ];

  useEffect(() => {
    fetchStats();
  }, []);

  useEffect(() => {
    if (activeTab === 'chat') {
      chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [chatMessages, activeTab]);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage(null);
    }, 2800);
  };

  const fetchStats = async () => {
    try {
      const res = await fetch('/api/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (err) {
      console.error('Failed to load stats', err);
    }
  };

  const fetchHistory = async () => {
    setIsLoadingHistory(true);
    try {
      const res = await fetch('/api/history?limit=100');
      if (res.ok) {
        const data = await res.json();
        setHistoryItems(data);
      }
    } catch (err) {
      console.error('Failed to fetch history', err);
    } finally {
      setIsLoadingHistory(false);
    }
  };

  const handleRunAnalysis = async () => {
    setErrorMsg(null);
    const content = inputMode === 'email' ? emailText.trim() : urlText.trim();
    if (!content) {
      setErrorMsg(inputMode === 'email' ? 'Please paste an email message to check.' : 'Please enter a web link to check.');
      return;
    }

    setIsAnalyzing(true);
    try {
      const endpoint = inputMode === 'email' ? '/api/analyze/email' : '/api/analyze/url';
      const body = inputMode === 'email' ? { content } : { url: content };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Check failed');
      }

      setAnalysisResult(data);
      setSelectedClue(null);
      setResultTab('summary');
      fetchStats();
      showToast(`Check finished: Risk Score is ${data.risk_score} / 100 (${getFriendlyLevelName(data.risk_level)})`);
    } catch (err: any) {
      setErrorMsg(err.message || 'Error checking for phishing');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleLoadSample = (sample: TestCase) => {
    setInputMode(sample.type);
    if (sample.type === 'email') {
      setEmailText(sample.content);
    } else {
      setUrlText(sample.content);
    }
    setErrorMsg(null);
    showToast(`Loaded example: ${sample.title}`);
  };

  const handleRunTestCase = async (sample: TestCase) => {
    setInputMode(sample.type);
    if (sample.type === 'email') {
      setEmailText(sample.content);
    } else {
      setUrlText(sample.content);
    }
    setErrorMsg(null);
    setIsAnalyzing(true);
    try {
      const endpoint = sample.type === 'email' ? '/api/analyze/email' : '/api/analyze/url';
      const payload = sample.type === 'email' ? { content: sample.content } : { url: sample.content };
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Check failed');
      }

      setAnalysisResult(data);
      setSelectedClue(null);
      setResultTab('summary');
      fetchStats();
      showToast(`Demonstrated: ${sample.title} (${data.risk_score} / 100 - ${getFriendlyLevelName(data.risk_level)})`);
    } catch (err: any) {
      setErrorMsg(err.message || 'Error checking benchmark sample');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handlePasteClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        if (inputMode === 'email') {
          setEmailText(text);
        } else {
          setUrlText(text.trim());
        }
        showToast('Pasted text from clipboard');
      }
    } catch {
      showToast('Clipboard access unavailable. Please use Ctrl+V or Cmd+V to paste.');
    }
  };

  const handleClear = () => {
    setEmailText('');
    setUrlText('');
    setAnalysisResult(null);
    setErrorMsg(null);
    setSelectedClue(null);
    showToast('Cleared input');
  };

  const handleDeleteHistory = async (id: number) => {
    try {
      const res = await fetch(`/api/history/${id}`, { method: 'DELETE' });
      if (res.ok) {
        setHistoryItems(prev => prev.filter(item => item.id !== id));
        if (selectedHistoryItem?.id === id) {
          setSelectedHistoryItem(null);
        }
        fetchStats();
        showToast(`Saved check #${id} deleted`);
      }
    } catch (err) {
      console.error('Failed to delete history item', err);
    }
  };

  const handleCopyReport = () => {
    if (!analysisResult?.ascii_report) return;
    navigator.clipboard.writeText(analysisResult.ascii_report);
    setCopiedReport(true);
    showToast('Report copied to clipboard');
    setTimeout(() => setCopiedReport(false), 2000);
  };

  const handleDownloadTxt = () => {
    if (!analysisResult?.ascii_report) return;
    const blob = new Blob([analysisResult.ascii_report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishing_check_report_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Downloaded text report');
  };

  // Professional PDF Report Generator using jsPDF and ascii_report data
  const handleDownloadPdf = () => {
    if (!analysisResult) return;
    setIsGeneratingPdf(true);
    try {
      const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
      const pageWidth = doc.internal.pageSize.getWidth();
      const margin = 15;
      const contentWidth = pageWidth - margin * 2;
      let y = 18;

      // Header Banner
      doc.setFillColor(15, 23, 42); // slate-900
      doc.rect(0, 0, pageWidth, 32, 'F');

      doc.setTextColor(255, 255, 255);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(16);
      doc.text('PHISHING INCIDENT & THREAT ANALYSIS REPORT', margin, y);

      y += 6;
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      doc.setTextColor(148, 163, 184); // slate-400
      doc.text('AI-Powered Phishing Investigation Lab · Forensic Security Documentation', margin, y);

      const timestamp = new Date().toLocaleString();
      doc.text(`Generated: ${timestamp}`, pageWidth - margin - doc.getTextWidth(`Generated: ${timestamp}`), y);

      y = 40;

      // Risk Score Summary Card
      let scoreColor: [number, number, number] = [16, 185, 129]; // emerald
      if (analysisResult.risk_score >= 75) scoreColor = [225, 29, 72]; // rose
      else if (analysisResult.risk_score >= 50) scoreColor = [234, 88, 12]; // orange
      else if (analysisResult.risk_score >= 25) scoreColor = [217, 119, 6]; // amber

      doc.setDrawColor(...scoreColor);
      doc.setLineWidth(0.8);
      doc.setFillColor(248, 250, 252);
      doc.roundedRect(margin, y, contentWidth, 34, 3, 3, 'FD');

      doc.setTextColor(...scoreColor);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(24);
      doc.text(`${analysisResult.risk_score} / 100`, margin + 6, y + 15);

      doc.setFontSize(11);
      doc.text(`${analysisResult.risk_level} RISK - ${getFriendlyLevelName(analysisResult.risk_level)}`, margin + 6, y + 25);

      // Metadata on right of summary card
      doc.setTextColor(71, 85, 105);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      const rightMetaX = pageWidth - margin - 80;
      doc.text(`Input Vector: ${analysisResult.input_type.toUpperCase()}`, rightMetaX, y + 10);
      doc.text(`Detected Clues: ${analysisResult.indicators.length} indicators flagged`, rightMetaX, y + 16);
      doc.text(`Record ID: #${analysisResult.id || 'Active Check'}`, rightMetaX, y + 22);

      y += 42;

      // Section: Executive Threat Summary
      doc.setTextColor(15, 23, 42);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(12);
      doc.text('1. EXECUTIVE SUMMARY & FORENSIC ADVICE', margin, y);
      y += 6;

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9.5);
      doc.setTextColor(51, 65, 85);
      const summaryText = analysisResult.ai_explanation?.short_explanation ||
        `Evaluated ${analysisResult.input_type} yielded a score of ${analysisResult.risk_score}/100.`;
      const splitSummary = doc.splitTextToSize(summaryText, contentWidth);
      doc.text(splitSummary, margin, y);
      y += splitSummary.length * 5 + 4;

      // Recommended Action Box
      doc.setFillColor(240, 249, 255);
      doc.setDrawColor(186, 230, 253);
      doc.setLineWidth(0.4);
      const recLines = doc.splitTextToSize(`Defensive Action: ${analysisResult.recommendation}`, contentWidth - 8);
      const recHeight = recLines.length * 5 + 6;
      doc.roundedRect(margin, y, contentWidth, recHeight, 2, 2, 'FD');

      doc.setTextColor(3, 105, 161);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9);
      doc.text(recLines, margin + 4, y + 5);
      y += recHeight + 6;

      // Disclaimer Box in PDF
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(203, 213, 225);
      doc.setLineWidth(0.3);
      const disclaimerPdfText = 'DISCLAIMER: This report is an automated heuristic and AI-assisted analysis for educational and threat-detection guidance. It is an indication and not a 100% guarantee that a message or link is safe or malicious. Always exercise caution and verify unexpected requests through trusted channels.';
      const discPdfLines = doc.splitTextToSize(disclaimerPdfText, contentWidth - 8);
      const discPdfHeight = discPdfLines.length * 3.8 + 5;
      doc.roundedRect(margin, y, contentWidth, discPdfHeight, 2, 2, 'FD');
      doc.setTextColor(100, 116, 139);
      doc.setFont('helvetica', 'italic');
      doc.setFontSize(7.5);
      doc.text(discPdfLines, margin + 4, y + 4);
      y += discPdfHeight + 8;

      // Section: Flagged Threat Indicators
      doc.setTextColor(15, 23, 42);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(12);
      doc.text(`2. DETECTED INDICATORS & EVIDENCE (${analysisResult.indicators.length} FLAGS)`, margin, y);
      y += 6;

      if (analysisResult.indicators.length === 0) {
        doc.setFont('helvetica', 'italic');
        doc.setFontSize(9);
        doc.setTextColor(100, 116, 139);
        doc.text('No suspicious indicators or deception markers were detected in this sample.', margin, y);
        y += 8;
      } else {
        analysisResult.indicators.forEach((ind, i) => {
          if (y > 260) {
            doc.addPage();
            y = 20;
          }
          doc.setFillColor(248, 250, 252);
          doc.setDrawColor(226, 232, 240);
          doc.setLineWidth(0.3);

          const indTitle = `${i + 1}. ${ind.indicator} (+${ind.points} pts) [${ind.severity.toUpperCase()}]`;
          const evidenceStr = `Matched Evidence: ${ind.evidence}`;
          const splitEvidence = doc.splitTextToSize(evidenceStr, contentWidth - 8);
          const boxHeight = 12 + splitEvidence.length * 4.5;

          doc.roundedRect(margin, y, contentWidth, boxHeight, 2, 2, 'FD');

          doc.setTextColor(15, 23, 42);
          doc.setFont('helvetica', 'bold');
          doc.setFontSize(9);
          doc.text(indTitle, margin + 4, y + 5);

          doc.setFont('helvetica', 'normal');
          doc.setFontSize(8);
          doc.setTextColor(71, 85, 105);
          doc.text(ind.description, margin + 4, y + 10);

          doc.setTextColor(2, 132, 199);
          doc.setFont('courier', 'normal');
          doc.text(splitEvidence, margin + 4, y + 15);

          y += boxHeight + 4;
        });
      }

      y += 4;

      // Page break check for ASCII Report section
      if (y > 230) {
        doc.addPage();
        y = 20;
      }

      // Section: Complete ASCII Archival Report
      doc.setTextColor(15, 23, 42);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(12);
      doc.text('3. STANDARDIZED ASCII AUDIT RECORD', margin, y);
      y += 6;

      doc.setFillColor(15, 23, 42);
      doc.rect(margin, y, contentWidth, 2, 'F');
      y += 4;

      if (analysisResult.ascii_report) {
        doc.setFont('courier', 'normal');
        doc.setFontSize(7.5);
        doc.setTextColor(51, 65, 85);
        const asciiLines = doc.splitTextToSize(analysisResult.ascii_report, contentWidth);

        asciiLines.forEach((line: string) => {
          if (y > 280) {
            doc.addPage();
            y = 20;
          }
          doc.text(line, margin, y);
          y += 3.8;
        });
      }

      // Page numbering footer
      const totalPages = doc.getNumberOfPages();
      for (let i = 1; i <= totalPages; i++) {
        doc.setPage(i);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8);
        doc.setTextColor(148, 163, 184);
        doc.text(
          `Page ${i} of ${totalPages} · Confidential Security Analysis Documentation`,
          pageWidth / 2,
          290,
          { align: 'center' }
        );
      }

      doc.save(`Phishing_Report_${analysisResult.risk_level.toLowerCase()}_${Date.now()}.pdf`);
      showToast('PDF Report generated and downloaded successfully!');
    } catch (err: any) {
      console.error('PDF generation error:', err);
      showToast('Failed to create PDF document. Please try again.');
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  // Chat message send handler
  const handleSendChatMessage = async (presetPrompt?: string) => {
    const textToSend = presetPrompt || chatInput.trim();
    if (!textToSend || isChatSending) return;

    const userMsg: ChatMessage = {
      id: String(Date.now()),
      role: 'user',
      content: textToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    const newHistory = [...chatMessages, userMsg];
    setChatMessages(newHistory);
    setChatInput('');
    setIsChatSending(true);

    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: newHistory.map(m => ({ role: m.role, content: m.content })),
          currentAnalysis: analysisResult,
          model: selectedChatModel
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to get answer');
      }

      const assistantMsg: ChatMessage = {
        id: String(Date.now() + 1),
        role: 'model',
        content: data.reply || 'I checked your question. Stay cautious and verify any unexpected emails.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };

      setChatMessages(prev => [...prev, assistantMsg]);
    } catch (err: any) {
      const errMsg: ChatMessage = {
        id: String(Date.now() + 1),
        role: 'model',
        content: `Error: ${err.message || 'Could not connect to AI assistant'}. Please try again.`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      setChatMessages(prev => [...prev, errMsg]);
    } finally {
      setIsChatSending(false);
    }
  };

  const handleRunTests = async () => {
    setIsRunningTests(true);
    try {
      const res = await fetch('/api/run-tests', { method: 'POST' });
      const data = await res.json();
      setTestResultOutput(data);
      if (data.success) {
        showToast('All 18 automated detection tests passed!');
      } else {
        showToast('Test execution encountered issues');
      }
    } catch (err) {
      console.error('Failed to run test suite', err);
    } finally {
      setIsRunningTests(false);
    }
  };

  // Keyboard shortcut Ctrl/Cmd + Enter
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        if (activeTab === 'check') {
          handleRunAnalysis();
        } else if (activeTab === 'chat' && chatInput.trim()) {
          handleSendChatMessage();
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [emailText, urlText, inputMode, activeTab, chatInput]);

  const getFriendlyLevelName = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return 'Dangerous Scam (High Risk)';
      case 'HIGH':
        return 'Likely Phishing (High Risk)';
      case 'MEDIUM':
        return 'Caution Needed (Medium Risk)';
      case 'LOW':
      default:
        return 'Safe Baseline (Low Risk)';
    }
  };

  const getRiskColorPalette = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return {
          textColor: 'text-rose-400',
          borderColor: 'border-rose-500/40',
          bgColor: 'bg-rose-500/10',
          badgeClass: 'bg-rose-950 text-rose-300 border border-rose-800',
          bannerBg: 'from-rose-950/40 to-slate-900 border-rose-800/50',
          barColor: 'bg-rose-500',
          headline: 'High Danger: Strong Signs of Phishing'
        };
      case 'HIGH':
        return {
          textColor: 'text-orange-400',
          borderColor: 'border-orange-500/40',
          bgColor: 'bg-orange-500/10',
          badgeClass: 'bg-orange-950 text-orange-300 border border-orange-800',
          bannerBg: 'from-orange-950/40 to-slate-900 border-orange-800/50',
          barColor: 'bg-orange-500',
          headline: 'High Risk: Likely an Account Attack'
        };
      case 'MEDIUM':
        return {
          textColor: 'text-amber-400',
          borderColor: 'border-amber-500/40',
          bgColor: 'bg-amber-500/10',
          badgeClass: 'bg-amber-950 text-amber-300 border border-amber-800',
          bannerBg: 'from-amber-950/40 to-slate-900 border-amber-800/50',
          barColor: 'bg-amber-500',
          headline: 'Caution: Suspicious Signs Found'
        };
      case 'LOW':
      default:
        return {
          textColor: 'text-emerald-400',
          borderColor: 'border-emerald-500/40',
          bgColor: 'bg-emerald-500/10',
          badgeClass: 'bg-emerald-950 text-emerald-300 border border-emerald-800',
          bannerBg: 'from-emerald-950/40 to-slate-900 border-emerald-800/50',
          barColor: 'bg-emerald-500',
          headline: 'Looks Safe: No Red Flags Found'
        };
    }
  };

  const filteredHistory = historyItems.filter(item => {
    const matchesSearch = !historySearch.trim() ||
      item.input_data.toLowerCase().includes(historySearch.toLowerCase()) ||
      item.risk_level.toLowerCase().includes(historySearch.toLowerCase()) ||
      String(item.id).includes(historySearch);

    const matchesTier = historyRiskFilter === 'ALL' || item.risk_level === historyRiskFilter;

    return matchesSearch && matchesTier;
  });

  return (
    <div className="min-h-screen bg-[#0b1120] text-slate-100 flex flex-col font-sans bg-friendly-gradient">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 px-4 py-2.5 rounded-lg bg-slate-900 border border-blue-500/50 text-blue-200 text-xs font-medium shadow-2xl flex items-center gap-2 animate-bounce">
          <Info className="w-4 h-4 text-blue-400 shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Warm & Welcoming Header */}
      <header className="border-b border-slate-800/80 bg-slate-900/90 backdrop-blur sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-blue-600/15 border border-blue-500/30 text-blue-400 shadow-sm">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-white text-base tracking-tight">
                  Phishing Detector & Safety Lab
                </span>
                <span className="text-slate-500 text-xs hidden sm:inline">·</span>
                <span className="text-xs text-blue-400 font-medium hidden sm:inline">
                  Easy Phishing Analysis
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Check emails and web links for scams with clear explanations and AI assistance
              </p>
            </div>
          </div>

          {/* Friendly Navigation Tabs */}
          <nav className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-lg">
            <button
              onClick={() => setActiveTab('check')}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-all flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'check'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Search className="w-3.5 h-3.5" />
              Check a Message
            </button>
            <button
              onClick={() => setActiveTab('chat')}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-all flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'chat'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <MessageSquare className="w-3.5 h-3.5 text-blue-400" />
              Security AI Chat
            </button>
            <button
              onClick={() => {
                setActiveTab('history');
                fetchHistory();
              }}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-all flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'history'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <HistoryIcon className="w-3.5 h-3.5" />
              History ({stats.total})
            </button>
            <button
              onClick={() => setActiveTab('tests')}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-all flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'tests'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              Detection Tests
            </button>
            <button
              onClick={() => setActiveTab('guide')}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-all flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'guide'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <BookOpen className="w-3.5 h-3.5" />
              Safety Guide
            </button>
          </nav>
        </div>
      </header>

      {/* Main Workspace Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Friendly Overview Banner */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400 shrink-0">
              <Lightbulb className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-white">How This Tool Helps You</h2>
              <p className="text-xs text-slate-300 mt-0.5 leading-relaxed">
                Paste any suspicious email or web address below. Our tool inspects urgency, threats, password requests, and fake link tricks—giving you an easy-to-understand safety score, safe advice, and professional PDF reports.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400 shrink-0 pl-10 md:pl-0">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Safe Educational Mode Active</span>
          </div>
        </div>

        {/* TAB 1: MAIN CHECKER */}
        {activeTab === 'check' && (
          <div className="space-y-6">
            {/* Demonstration & Benchmark Cases Showcase */}
            <div className="rounded-xl bg-slate-900 border border-slate-800 p-4 shadow-xl space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-800">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-blue-400 flex items-center gap-1.5">
                      <Sparkles className="w-3.5 h-3.5" />
                      Live Demonstration Cases (Test & Compare)
                    </span>
                    <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-blue-950 text-blue-300 border border-blue-900">
                      3 Benchmarks
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Test and demonstrate the system against the 3 standard security tiers: High-risk phishing, Medium-risk suspicious, and Low-risk/benign message.
                  </p>
                </div>
                <button
                  onClick={() => setShowBenchmarkComparison(true)}
                  className="px-3 py-1.5 rounded-lg bg-slate-850 hover:bg-slate-800 text-slate-200 text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer border border-slate-700 shrink-0 self-start sm:self-auto"
                >
                  <Scale className="w-3.5 h-3.5 text-blue-400" />
                  Compare All 3 Side-by-Side
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {/* Case 1: High-Risk Phishing */}
                <div className="p-3.5 rounded-xl bg-slate-950/90 border border-rose-900/50 hover:border-rose-500/70 transition-all flex flex-col justify-between space-y-3">
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-bold text-rose-300 flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                        1. High-Risk Phishing
                      </span>
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-rose-950 text-rose-300 border border-rose-800">
                        High Danger (~87/100)
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      Manufactures extreme panic with urgent suspension threats and a fake password verification portal link.
                    </p>
                    <div className="text-[10px] text-rose-400/90 font-mono bg-rose-950/30 p-1.5 rounded border border-rose-900/30">
                      Triggers: Urgent language, Account threat, Credential prompt, Deceptive link
                    </div>
                  </div>
                  <div className="pt-2 border-t border-slate-800/80">
                    <button
                      onClick={() => handleRunTestCase(testCases[0])}
                      disabled={isAnalyzing}
                      className="w-full py-2 px-3 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs flex items-center justify-center gap-1.5 cursor-pointer shadow-md shadow-rose-950 transition-all disabled:opacity-50"
                    >
                      <Play className="w-3 h-3" /> Run High-Risk Test
                    </button>
                  </div>
                </div>

                {/* Case 2: Medium-Risk Suspicious */}
                <div className="p-3.5 rounded-xl bg-slate-950/90 border border-amber-900/50 hover:border-amber-500/70 transition-all flex flex-col justify-between space-y-3">
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-bold text-amber-300 flex items-center gap-1.5">
                        <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
                        2. Medium-Risk Suspicious
                      </span>
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-950 text-amber-300 border border-amber-800">
                        Caution (~39/100)
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      Warns of an unfamiliar device login and urges clicking a button to review account activity.
                    </p>
                    <div className="text-[10px] text-amber-400/90 font-mono bg-amber-950/30 p-1.5 rounded border border-amber-900/30">
                      Triggers: Security review alert, Call-to-action link, Subdomain redirect
                    </div>
                  </div>
                  <div className="pt-2 border-t border-slate-800/80">
                    <button
                      onClick={() => handleRunTestCase(testCases[1])}
                      disabled={isAnalyzing}
                      className="w-full py-2 px-3 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-bold text-xs flex items-center justify-center gap-1.5 cursor-pointer shadow-md shadow-amber-950 transition-all disabled:opacity-50"
                    >
                      <Play className="w-3 h-3" /> Run Medium-Risk Test
                    </button>
                  </div>
                </div>

                {/* Case 3: Low-Risk Benign */}
                <div className="p-3.5 rounded-xl bg-slate-950/90 border border-emerald-900/50 hover:border-emerald-500/70 transition-all flex flex-col justify-between space-y-3">
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-bold text-emerald-300 flex items-center gap-1.5">
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                        3. Low-Risk / Benign Message
                      </span>
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-300 border border-emerald-800">
                        Safe (0/100)
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      Routine weekly internal engineering digest without urgency markers, threats, or password prompts.
                    </p>
                    <div className="text-[10px] text-emerald-400/90 font-mono bg-emerald-950/30 p-1.5 rounded border border-emerald-900/30">
                      Triggers: Zero red flags, No panic, No password request, Clean
                    </div>
                  </div>
                  <div className="pt-2 border-t border-slate-800/80">
                    <button
                      onClick={() => handleRunTestCase(testCases[2])}
                      disabled={isAnalyzing}
                      className="w-full py-2 px-3 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center justify-center gap-1.5 cursor-pointer shadow-md shadow-emerald-950 transition-all disabled:opacity-50"
                    >
                      <Play className="w-3 h-3" /> Run Benign Test
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Input Box */}
            <div className="rounded-xl bg-slate-900 border border-slate-800 p-5 shadow-xl space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-lg">
                    <button
                      onClick={() => setInputMode('email')}
                      className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors flex items-center gap-1.5 cursor-pointer ${
                        inputMode === 'email'
                          ? 'bg-blue-600 text-white shadow-sm'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <Mail className="w-3.5 h-3.5" />
                      Email Message
                    </button>
                    <button
                      onClick={() => setInputMode('url')}
                      className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors flex items-center gap-1.5 cursor-pointer ${
                        inputMode === 'url'
                          ? 'bg-blue-600 text-white shadow-sm'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <Globe className="w-3.5 h-3.5" />
                      Web Link (URL)
                    </button>
                  </div>
                  <span className="text-xs text-slate-500 hidden sm:inline">
                    Choose what you want to check
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handlePasteClipboard}
                    className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
                    title="Paste text from clipboard"
                  >
                    <ClipboardPaste className="w-3.5 h-3.5 text-blue-400" />
                    Paste Text
                  </button>
                  <button
                    onClick={handleClear}
                    className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors cursor-pointer"
                  >
                    Clear
                  </button>
                </div>
              </div>

              {/* Text Area */}
              <div>
                {inputMode === 'email' ? (
                  <div>
                    <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
                      <label htmlFor="userEmailInput" className="font-medium text-slate-300">
                        Paste the email text below:
                      </label>
                      <span className="text-slate-500">{emailText.length} characters</span>
                    </div>
                    <textarea
                      id="userEmailInput"
                      rows={8}
                      value={emailText}
                      onChange={(e) => setEmailText(e.target.value)}
                      placeholder="Paste the email here (for example: Dear customer, your account will be suspended today...)"
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3.5 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 leading-relaxed font-sans"
                    />
                  </div>
                ) : (
                  <div>
                    <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
                      <label htmlFor="userUrlInput" className="font-medium text-slate-300">
                        Enter the web link to check:
                      </label>
                      <span className="text-slate-500">{urlText.length} characters</span>
                    </div>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                        <Globe className="w-4 h-4 text-blue-400" />
                      </div>
                      <input
                        id="userUrlInput"
                        type="text"
                        value={urlText}
                        onChange={(e) => setUrlText(e.target.value)}
                        placeholder="https://secure-account-verification.example.com/login"
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-3 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 font-mono"
                      />
                    </div>
                  </div>
                )}
              </div>

              {/* Error Message */}
              {errorMsg && (
                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  <span>{errorMsg}</span>
                </div>
              )}

              {/* Submit Buttons */}
              <div className="pt-2 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleRunAnalysis}
                    disabled={isAnalyzing}
                    className="px-6 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-bold text-xs tracking-wider uppercase transition-all shadow-lg shadow-blue-950 flex items-center gap-2 cursor-pointer"
                  >
                    {isAnalyzing ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        Checking for Phishing...
                      </>
                    ) : (
                      <>
                        <Play className="w-3.5 h-3.5" />
                        Check for Phishing
                      </>
                    )}
                  </button>
                  <span className="text-xs text-slate-500 hidden sm:inline">
                    Tip: Press <kbd className="px-1.5 py-0.5 rounded bg-slate-800 font-mono text-[10px] text-slate-300">Ctrl</kbd> + <kbd className="px-1.5 py-0.5 rounded bg-slate-800 font-mono text-[10px] text-slate-300">Enter</kbd> to run
                  </span>
                </div>

                <div className="text-xs text-slate-400 flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-emerald-400" />
                  Safe Check: We never click or open the links you enter.
                </div>
              </div>

              {/* Disclaimer Advisory Banner */}
              <div className="p-3.5 rounded-xl bg-slate-950/90 border border-slate-800 text-xs text-slate-400 flex items-start gap-3">
                <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div className="leading-relaxed">
                  <strong className="text-slate-300">Security Advisory & Disclaimer: </strong>
                  This assessment is an automated heuristic and AI-assisted analysis provided for educational and threat-detection guidance. It is an indication and not a 100% guarantee that a message or web link is safe or malicious. Always exercise caution, verify unexpected requests through trusted out-of-band channels, and follow your organization's formal security protocols.
                </div>
              </div>
            </div>

            {/* RESULTS VIEW */}
            {analysisResult && (
              <div className="space-y-6 animate-fadeIn">
                {/* Score & Verdict Card */}
                <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 shadow-xl space-y-6">
                  {/* Top Verdict Banner */}
                  <div className={`p-4 rounded-xl border bg-gradient-to-r ${getRiskColorPalette(analysisResult.risk_level).bannerBg} ${getRiskColorPalette(analysisResult.risk_level).borderColor} flex flex-col sm:flex-row sm:items-center justify-between gap-4`}>
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 text-xs">
                        <span className={`px-2.5 py-0.5 rounded-full font-bold uppercase tracking-wider text-[11px] ${getRiskColorPalette(analysisResult.risk_level).badgeClass}`}>
                          {getFriendlyLevelName(analysisResult.risk_level)}
                        </span>
                        <span className="text-slate-500">·</span>
                        <span className="text-slate-400 font-medium">Checked as {analysisResult.input_type === 'email' ? 'Email' : 'Web Link'}</span>
                      </div>
                      <h3 className="text-xl font-bold text-white tracking-tight">
                        {getRiskColorPalette(analysisResult.risk_level).headline}
                      </h3>
                      <p className="text-xs text-slate-300 max-w-xl leading-relaxed">
                        {analysisResult.risk_score >= 50
                          ? 'This message uses pressure tactics, threats, or deceptive links to trick you into giving away your account or password.'
                          : analysisResult.risk_score >= 25
                          ? 'Some warning signs were found. We recommend double-checking the sender before clicking anything.'
                          : 'No red flags found. The message looks like a normal, legitimate communication.'}
                      </p>
                    </div>

                    {/* Big Score Box */}
                    <div className="sm:text-right pl-4 sm:border-l border-slate-800">
                      <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                        Safety Risk Score
                      </span>
                      <div className="flex items-baseline sm:justify-end gap-1 mt-0.5">
                        <span className={`text-4xl font-extrabold font-mono ${getRiskColorPalette(analysisResult.risk_level).textColor}`}>
                          {analysisResult.risk_score}
                        </span>
                        <span className="text-slate-500 text-sm font-medium">/ 100</span>
                      </div>
                      <span className="text-[10px] text-slate-400 block mt-0.5">
                        Higher score = higher danger
                      </span>
                    </div>
                  </div>

                  {/* Result Disclaimer Notice */}
                  <div className="flex items-center gap-2 text-[11px] text-slate-400 px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800">
                    <Info className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                    <span><strong>Security Notice:</strong> Automated heuristic and AI-assisted analysis for indication and guidance only — not a 100% guarantee of safety or malice. Always verify unexpected requests through trusted channels.</span>
                  </div>

                  {/* Visual Friendly Score Meter */}
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
                      <span>Safety Score Meter</span>
                      <span className={`font-bold ${getRiskColorPalette(analysisResult.risk_level).textColor}`}>
                        {analysisResult.risk_score} points ({getFriendlyLevelName(analysisResult.risk_level)})
                      </span>
                    </div>

                    <div className="relative pt-1">
                      <div className="h-3 w-full rounded-full bg-slate-800 overflow-hidden flex">
                        <div className="h-full bg-emerald-500 w-[24%]" title="Safe: 0-24" />
                        <div className="h-full bg-amber-500 w-[25%]" title="Caution: 25-49" />
                        <div className="h-full bg-orange-500 w-[25%]" title="High Risk: 50-74" />
                        <div className="h-full bg-rose-600 w-[26%]" title="Dangerous: 75-100" />
                      </div>
                      {/* Needle Position */}
                      <div
                        className="absolute top-0 transform -translate-x-1/2 transition-all duration-500"
                        style={{ left: `${Math.min(98, Math.max(2, analysisResult.risk_score))}%` }}
                      >
                        <div className="w-2 h-5 bg-white rounded-full shadow-lg border border-slate-900" />
                      </div>
                    </div>

                    <div className="flex justify-between text-[11px] text-slate-400 pt-0.5">
                      <span className="text-emerald-400">Safe (0-24)</span>
                      <span className="text-amber-400">Caution (25-49)</span>
                      <span className="text-orange-400">High Risk (50-74)</span>
                      <span className="text-rose-400">Dangerous Scam (75-100)</span>
                    </div>
                  </div>

                  {/* Friendly Result Navigation Tabs & Export Action Buttons */}
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2 flex-wrap gap-2">
                    <div className="flex items-center gap-1 text-xs">
                      <button
                        onClick={() => setResultTab('summary')}
                        className={`px-3 py-1.5 rounded-lg font-semibold transition-colors cursor-pointer ${
                          resultTab === 'summary'
                            ? 'bg-blue-600 text-white shadow-sm'
                            : 'text-slate-400 hover:text-slate-200 bg-slate-950'
                        }`}
                      >
                        Summary & Advice
                      </button>
                      <button
                        onClick={() => setResultTab('clues')}
                        className={`px-3 py-1.5 rounded-lg font-semibold transition-colors cursor-pointer ${
                          resultTab === 'clues'
                            ? 'bg-blue-600 text-white shadow-sm'
                            : 'text-slate-400 hover:text-slate-200 bg-slate-950'
                        }`}
                      >
                        Suspicious Clues Found ({analysisResult.indicators.length})
                      </button>
                      {analysisResult.url_analysis && (
                        <button
                          onClick={() => setResultTab('link_details')}
                          className={`px-3 py-1.5 rounded-lg font-semibold transition-colors cursor-pointer ${
                            resultTab === 'link_details'
                              ? 'bg-blue-600 text-white shadow-sm'
                              : 'text-slate-400 hover:text-slate-200 bg-slate-950'
                          }`}
                        >
                          Web Link Inspection
                        </button>
                      )}
                      <button
                        onClick={() => setResultTab('score_math')}
                        className={`px-3 py-1.5 rounded-lg font-semibold transition-colors cursor-pointer ${
                          resultTab === 'score_math'
                            ? 'bg-blue-600 text-white shadow-sm'
                            : 'text-slate-400 hover:text-slate-200 bg-slate-950'
                        }`}
                      >
                        Score Calculation
                      </button>
                    </div>

                    <div className="flex items-center gap-1.5 text-xs">
                      {/* DOWNLOAD AS PDF BUTTON */}
                      <button
                        onClick={handleDownloadPdf}
                        disabled={isGeneratingPdf}
                        className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white flex items-center gap-1.5 cursor-pointer font-semibold shadow-md shadow-emerald-950 transition-colors"
                        title="Download professional PDF report with ASCII data"
                      >
                        <FileDown className="w-3.5 h-3.5" />
                        {isGeneratingPdf ? 'Generating PDF...' : 'Download as PDF'}
                      </button>

                      {/* ASK GEMINI ABOUT THIS CHECK */}
                      <button
                        onClick={() => setActiveTab('chat')}
                        className="px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white flex items-center gap-1.5 cursor-pointer font-semibold shadow-md shadow-purple-950 transition-colors"
                        title="Chat with Gemini about this specific check"
                      >
                        <Bot className="w-3.5 h-3.5" />
                        Ask AI Assistant
                      </button>

                      <button
                        onClick={() => setShowFullReportModal(true)}
                        className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center gap-1 cursor-pointer font-medium"
                      >
                        <FileText className="w-3.5 h-3.5 text-blue-400" />
                        ASCII Report
                      </button>
                      <button
                        onClick={handleCopyReport}
                        className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center gap-1 cursor-pointer font-medium"
                      >
                        {copiedReport ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-blue-400" />}
                        {copiedReport ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                  </div>

                  {/* RESULT TAB 1: SUMMARY & ADVICE */}
                  {resultTab === 'summary' && (
                    <div className="space-y-4">
                      {/* AI Natural Language Summary */}
                      <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-blue-400 font-bold uppercase tracking-wider flex items-center gap-1.5">
                            <Sparkles className="w-3.5 h-3.5" />
                            Plain English Summary
                          </span>
                          <span className="text-slate-500">
                            {analysisResult.ai_explanation?.provider || 'AI Analyst'}
                          </span>
                        </div>
                        <p className="text-sm text-slate-200 leading-relaxed font-sans">
                          {analysisResult.ai_explanation?.short_explanation}
                        </p>
                      </div>

                      {/* 2 Big Action Cards: Why It's Suspicious & What You Should Do */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                          <span className="text-xs font-bold text-amber-400 flex items-center gap-1.5">
                            <AlertTriangle className="w-4 h-4 text-amber-400" />
                            Why This Looks Suspicious
                          </span>
                          <p className="text-xs text-slate-300 font-medium">
                            {analysisResult.ai_explanation?.main_suspicious_behavior}
                          </p>
                          <ul className="text-xs text-slate-400 space-y-1 list-disc list-inside pt-1">
                            {analysisResult.ai_explanation?.most_important_indicators?.map((sig, i) => (
                              <li key={i}>{sig}</li>
                            )) || <li>No dangerous signals flagged</li>}
                          </ul>
                        </div>

                        <div className="p-4 rounded-xl bg-slate-950 border border-blue-900/40 space-y-2">
                          <span className="text-xs font-bold text-blue-400 flex items-center gap-1.5">
                            <CheckCircle2 className="w-4 h-4 text-blue-400" />
                            What You Should Do (Safe Advice)
                          </span>
                          <p className="text-xs text-slate-200 leading-relaxed">
                            {analysisResult.recommendation}
                          </p>
                          <div className="p-2.5 rounded bg-blue-950/40 text-blue-300 text-[11px] leading-relaxed border border-blue-900/50 mt-2">
                            💡 <strong>Golden Rule:</strong> Never log in through a link sent in an unexpected email. Always open a fresh browser tab and visit the official website directly.
                          </div>
                        </div>
                      </div>

                      {/* WHY WAS THIS FLAGGED - 5 CORE THREAT CATEGORIES */}
                      <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 pb-2 border-b border-slate-800/80">
                          <div className="flex items-center gap-2">
                            <ShieldAlert className="w-4 h-4 text-blue-400" />
                            <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                              Why Was This Flagged? (5 Core Threat Factors)
                            </h4>
                          </div>
                          <span className="text-[11px] text-slate-400">
                            {analysisResult.indicators.length > 0
                              ? `${getThreatCategoryAnalysis(analysisResult).filter(c => c.flagged).length} of 5 threat categories triggered`
                              : 'All 5 threat categories clean'}
                          </span>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          {getThreatCategoryAnalysis(analysisResult).map((cat) => (
                            <div
                              key={cat.id}
                              className={`p-3.5 rounded-xl border transition-all flex flex-col justify-between ${
                                cat.flagged
                                  ? 'bg-rose-950/20 border-rose-900/60 ring-1 ring-rose-500/20'
                                  : 'bg-slate-900/60 border-slate-800/80'
                              }`}
                            >
                              <div>
                                <div className="flex items-start justify-between gap-2 mb-1.5">
                                  <div className="flex items-center gap-2">
                                    <span className={`p-1.5 rounded-lg shrink-0 ${cat.flagged ? 'bg-rose-950 text-rose-400 border border-rose-800' : 'bg-slate-800 text-slate-400'}`}>
                                      {cat.id === 'urgent_language' && <Clock className="w-3.5 h-3.5" />}
                                      {cat.id === 'account_threat' && <AlertTriangle className="w-3.5 h-3.5" />}
                                      {cat.id === 'login_request' && <MousePointerClick className="w-3.5 h-3.5" />}
                                      {cat.id === 'credential_request' && <KeyRound className="w-3.5 h-3.5" />}
                                      {cat.id === 'suspicious_url' && <Globe className="w-3.5 h-3.5" />}
                                    </span>
                                    <div>
                                      <h5 className="text-xs font-bold text-white">{cat.name}</h5>
                                      <span className="text-[10px] text-slate-400">{cat.categoryLabel}</span>
                                    </div>
                                  </div>
                                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full flex items-center gap-1 shrink-0 ${
                                    cat.flagged
                                      ? 'bg-rose-900/80 text-rose-200 border border-rose-700'
                                      : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                                  }`}>
                                    {cat.flagged ? (
                                      <>
                                        <AlertCircle className="w-3 h-3 text-rose-300" />
                                        FLAGGED (+{cat.points} pts)
                                      </>
                                    ) : (
                                      <>
                                        <Check className="w-3 h-3 text-emerald-400" />
                                        CLEAN (0 pts)
                                      </>
                                    )}
                                  </span>
                                </div>

                                <p className="text-[11px] text-slate-300 mt-2 leading-relaxed">
                                  {cat.details}
                                </p>

                                {/* Matched Evidence Snippets */}
                                {cat.flagged && cat.evidence.length > 0 && (
                                  <div className="mt-2 p-2 rounded bg-slate-950/80 border border-slate-800 font-mono text-[10px] text-blue-300 space-y-1">
                                    <span className="text-slate-500 font-sans font-semibold block text-[10px]">
                                      Exact text matched:
                                    </span>
                                    {cat.evidence.slice(0, 2).map((ev, i) => (
                                      <div key={i} className="truncate">"{ev}"</div>
                                    ))}
                                  </div>
                                )}
                              </div>

                              {/* Why Attackers Use This */}
                              <div className="mt-2.5 pt-2 border-t border-slate-800/80 text-[10px] text-slate-400 leading-normal">
                                <span className="font-semibold text-slate-300">Why scammers use this: </span>
                                {cat.whyAttackersUseThis}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* RESULT TAB 2: CLUES FOUND */}
                  {resultTab === 'clues' && (
                    <div className="space-y-3">
                      {analysisResult.indicators.length === 0 ? (
                        <div className="p-8 text-center rounded-xl bg-slate-950 border border-slate-800">
                          <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                          <p className="text-sm font-bold text-slate-200">No Suspicious Clues Found</p>
                          <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
                            The message does not use artificial urgency, threats of account suspension, or deceptive web links.
                          </p>
                        </div>
                      ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          {analysisResult.indicators.map((ind, idx) => (
                            <div
                              key={idx}
                              onClick={() => setSelectedClue(selectedClue === ind.indicator ? null : ind.indicator)}
                              className={`p-3.5 rounded-xl bg-slate-950 border transition-all cursor-pointer ${
                                selectedClue === ind.indicator
                                  ? 'border-blue-400 ring-1 ring-blue-400/40'
                                  : 'border-slate-800 hover:border-slate-700'
                              }`}
                            >
                              <div className="flex items-start justify-between gap-2 mb-1.5">
                                <h4 className="font-bold text-xs text-white">
                                  {ind.indicator}
                                </h4>
                                <div className="flex items-center gap-1.5 shrink-0">
                                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded capitalize ${
                                    ind.severity === 'critical' || ind.severity === 'high'
                                      ? 'bg-rose-950 text-rose-300'
                                      : ind.severity === 'medium'
                                      ? 'bg-amber-950 text-amber-300'
                                      : 'bg-slate-800 text-slate-300'
                                  }`}>
                                    {ind.severity}
                                  </span>
                                  <span className="font-mono text-xs font-bold text-blue-400">
                                    +{ind.points} pts
                                  </span>
                                </div>
                              </div>

                              <p className="text-xs text-slate-300 leading-relaxed mb-2">
                                {ind.description}
                              </p>

                              <div className="p-2 rounded bg-slate-900 border border-slate-800 font-mono text-[11px] text-blue-300 break-words">
                                <span className="text-[10px] font-sans text-slate-500 block mb-0.5 font-semibold">Found in message:</span>
                                {ind.evidence}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {/* RESULT TAB 3: LINK DETAILS */}
                  {resultTab === 'link_details' && analysisResult.url_analysis && (
                    <div className="space-y-4">
                      <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                        <span className="text-xs font-semibold text-slate-400">Website Address Checked:</span>
                        <div className="font-mono text-xs text-blue-300 break-all">{analysisResult.url_analysis.url}</div>
                      </div>

                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                        <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                          <span className="text-[11px] text-slate-400 block font-medium">Security (HTTPS)</span>
                          <span className={`text-xs font-bold block mt-0.5 ${analysisResult.url_analysis.is_https ? 'text-emerald-400' : 'text-rose-400'}`}>
                            {analysisResult.url_analysis.is_https ? 'HTTPS Encrypted' : 'Insecure (Plain HTTP)'}
                          </span>
                        </div>
                        <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                          <span className="text-[11px] text-slate-400 block font-medium">Real Website Name</span>
                          <span className={`text-xs font-bold block mt-0.5 ${analysisResult.url_analysis.has_ip_address ? 'text-rose-400' : 'text-slate-200'}`}>
                            {analysisResult.url_analysis.has_ip_address ? 'Raw IP (Dangerous)' : analysisResult.url_analysis.domain}
                          </span>
                        </div>
                        <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                          <span className="text-[11px] text-slate-400 block font-medium">Extra Subdomains</span>
                          <span className="text-xs font-bold text-slate-200 block mt-0.5">
                            {analysisResult.url_analysis.subdomain_count} ({analysisResult.url_analysis.subdomains.join('.') || 'none'})
                          </span>
                        </div>
                        <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                          <span className="text-[11px] text-slate-400 block font-medium">Hyphens & Dots</span>
                          <span className="text-xs font-bold text-slate-200 block mt-0.5">
                            {analysisResult.url_analysis.hyphen_count} hyphens · {analysisResult.url_analysis.dot_count} dots
                          </span>
                        </div>
                      </div>

                      <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                        <span className="text-xs font-semibold text-slate-400 block">Sensitive Words Found in the Link:</span>
                        <div className="flex flex-wrap gap-1.5">
                          {analysisResult.url_analysis.matched_keywords.length > 0 ? (
                            analysisResult.url_analysis.matched_keywords.map((kw, i) => (
                              <span key={i} className="px-2.5 py-0.5 rounded-full bg-slate-900 border border-slate-700 text-blue-300 text-xs font-mono">
                                {kw}
                              </span>
                            ))
                          ) : (
                            <span className="text-xs text-slate-500">None detected</span>
                          )}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* RESULT TAB 4: SCORE CALCULATION */}
                  {resultTab === 'score_math' && (
                    <div className="space-y-4">
                      {/* Mathematical Ledger Header Banner */}
                      <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-800/80">
                          <div className="flex items-center gap-2">
                            <Calculator className="w-4 h-4 text-blue-400" />
                            <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                              How the Risk Score is Calculated (Additive Mathematical Formula)
                            </h4>
                          </div>
                          <span className="text-[11px] font-mono text-slate-400">
                            Capped Maximum: 100 pts
                          </span>
                        </div>

                        {/* Interactive Formula Equation */}
                        <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 font-mono text-xs flex flex-wrap items-center gap-1.5 leading-relaxed">
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-bold">
                            Baseline: 0
                          </span>
                          {analysisResult.score_breakdown.map((item, idx) => (
                            <React.Fragment key={idx}>
                              <span className="text-slate-500 font-bold">+</span>
                              <span className="px-2 py-0.5 rounded bg-blue-950/80 text-blue-300 border border-blue-900/60 font-semibold" title={item.evidence}>
                                {item.indicator} (+{item.points})
                              </span>
                            </React.Fragment>
                          ))}
                          <span className="text-slate-500 font-bold">=</span>
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-200">
                            Subtotal: {analysisResult.score_breakdown.reduce((sum, it) => sum + it.points, 0)} pts
                          </span>
                          <span className="text-slate-500 font-bold">→</span>
                          <span className={`px-2.5 py-0.5 rounded font-bold text-white shadow-sm ${
                            analysisResult.risk_level === 'CRITICAL' ? 'bg-rose-600' :
                            analysisResult.risk_level === 'HIGH' ? 'bg-orange-600' :
                            analysisResult.risk_level === 'MEDIUM' ? 'bg-amber-600' : 'bg-emerald-600'
                          }`}>
                            Final Score: {analysisResult.risk_score} / 100 ({getFriendlyLevelName(analysisResult.risk_level)})
                          </span>
                        </div>

                        {/* Proportional Contribution Bar */}
                        {analysisResult.score_breakdown.length > 0 && (
                          <div className="space-y-1.5 pt-1">
                            <div className="flex justify-between text-[11px] text-slate-400">
                              <span>Score Contribution by Triggered Indicator:</span>
                              <span className="font-mono text-slate-300">{analysisResult.score_breakdown.length} triggered indicator(s)</span>
                            </div>
                            <div className="h-2.5 w-full rounded-full bg-slate-800 overflow-hidden flex">
                              {analysisResult.score_breakdown.map((item, idx) => {
                                const totalRaw = Math.max(1, analysisResult.score_breakdown.reduce((s, i) => s + i.points, 0));
                                const pct = (item.points / totalRaw) * 100;
                                const colors = ['bg-blue-500', 'bg-purple-500', 'bg-rose-500', 'bg-amber-500', 'bg-cyan-500', 'bg-orange-500'];
                                return (
                                  <div
                                    key={idx}
                                    style={{ width: `${pct}%` }}
                                    className={`${colors[idx % colors.length]} h-full transition-all`}
                                    title={`${item.indicator}: +${item.points} pts (${Math.round(pct)}%)`}
                                  />
                                );
                              })}
                            </div>
                          </div>
                        )}
                      </div>

                      {/* Itemized Points Ledger Table */}
                      <div className="rounded-xl bg-slate-950 border border-slate-800 overflow-hidden text-xs">
                        <div className="p-3 bg-slate-900 border-b border-slate-800 flex justify-between items-center text-slate-200 font-bold">
                          <span className="flex items-center gap-1.5">
                            <Scale className="w-3.5 h-3.5 text-blue-400" />
                            Itemized Indicator Ledger & Running Calculation
                          </span>
                          <span className="text-[11px] font-normal text-slate-400">
                            Transparent Point Additions
                          </span>
                        </div>

                        <div className="overflow-x-auto">
                          <table className="w-full text-left border-collapse">
                            <thead>
                              <tr className="bg-slate-900/60 border-b border-slate-800 text-[10px] text-slate-400 uppercase tracking-wider">
                                <th className="p-3">#</th>
                                <th className="p-3">Triggered Indicator & Category</th>
                                <th className="p-3">Severity Level</th>
                                <th className="p-3">Matched Evidence in Text</th>
                                <th className="p-3 text-right">Added Points</th>
                                <th className="p-3 text-right">Running Total</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-850">
                              <tr className="bg-slate-950/40 text-slate-400">
                                <td className="p-3 font-mono text-[11px]">0</td>
                                <td className="p-3 font-semibold text-slate-300">Baseline Starting Score</td>
                                <td className="p-3"><span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">Neutral</span></td>
                                <td className="p-3 font-mono text-[11px] text-slate-500">Unexamined input baseline</td>
                                <td className="p-3 text-right font-mono font-bold text-slate-400">0 pts</td>
                                <td className="p-3 text-right font-mono font-bold text-slate-400">0 / 100</td>
                              </tr>
                              {(() => {
                                let running = 0;
                                return analysisResult.score_breakdown.map((item, idx) => {
                                  running += item.points;
                                  const displayRunning = Math.min(100, running);
                                  return (
                                    <tr key={idx} className="hover:bg-slate-900/50 transition-colors">
                                      <td className="p-3 font-mono text-[11px] text-slate-500">{idx + 1}</td>
                                      <td className="p-3">
                                        <div className="font-semibold text-slate-200">{item.indicator}</div>
                                        <div className="text-[10px] text-slate-400 uppercase tracking-wider">{item.category}</div>
                                      </td>
                                      <td className="p-3">
                                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase ${
                                          item.severity === 'critical' ? 'bg-rose-950 text-rose-300' :
                                          item.severity === 'high' ? 'bg-orange-950 text-orange-300' :
                                          item.severity === 'medium' ? 'bg-amber-950 text-amber-300' :
                                          'bg-slate-800 text-slate-300'
                                        }`}>
                                          {item.severity}
                                        </span>
                                      </td>
                                      <td className="p-3 font-mono text-[11px] text-blue-300 max-w-xs truncate" title={item.evidence}>
                                        {item.evidence}
                                      </td>
                                      <td className="p-3 text-right font-mono font-bold text-blue-400 text-sm">
                                        +{item.points} pts
                                      </td>
                                      <td className="p-3 text-right font-mono font-bold text-slate-200">
                                        {displayRunning} / 100
                                      </td>
                                    </tr>
                                  );
                                });
                              })()}
                            </tbody>
                            <tfoot>
                              <tr className="bg-slate-900 font-bold border-t border-slate-800">
                                <td colSpan={4} className="p-3 text-white text-xs">
                                  Final Calculated Risk Score (Capped at 100)
                                </td>
                                <td className="p-3 text-right font-mono text-sm text-blue-400">
                                  +{analysisResult.score_breakdown.reduce((sum, it) => sum + it.points, 0)} pts
                                </td>
                                <td className={`p-3 text-right font-mono text-base ${getRiskColorPalette(analysisResult.risk_level).textColor}`}>
                                  {analysisResult.risk_score} / 100
                                </td>
                              </tr>
                            </tfoot>
                          </table>
                        </div>
                      </div>

                      {/* Transparent Scoring Formula Reference */}
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                        <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                          <span className="font-bold text-slate-300 block">Empirical Severity Weights</span>
                          <p className="text-[11px] text-slate-400 leading-relaxed">
                            Each indicator contributes points based on verified phishing patterns:
                          </p>
                          <ul className="text-[11px] text-slate-400 space-y-0.5 list-disc list-inside">
                            <li><strong>Critical Severity (+20 to +25 pts):</strong> Direct credential harvesting, password demands.</li>
                            <li><strong>High Severity (+14 to +18 pts):</strong> Account suspension threats, raw IP hosts.</li>
                            <li><strong>Medium Severity (+10 to +12 pts):</strong> Urgent deadlines, unfamiliar login alerts.</li>
                            <li><strong>Low Severity (+5 to +8 pts):</strong> Minor link anomalies, missing HTTPS.</li>
                          </ul>
                        </div>

                        <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                          <span className="font-bold text-slate-300 block">Risk Classification Thresholds</span>
                          <p className="text-[11px] text-slate-400 leading-relaxed">
                            The accumulated point total determines the protective guidance tier:
                          </p>
                          <ul className="text-[11px] space-y-0.5">
                            <li className="text-emerald-400"><strong>0 – 24 pts: Safe / Low Risk</strong> (Normal routine communication)</li>
                            <li className="text-amber-400"><strong>25 – 49 pts: Caution / Medium Risk</strong> (Some suspicious signals detected)</li>
                            <li className="text-orange-400"><strong>50 – 74 pts: High Risk</strong> (High probability of phishing attack)</li>
                            <li className="text-rose-400"><strong>75 – 100 pts: Dangerous Scam</strong> (Aggressive coordinated attack)</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: GEMINI CHATBOT INTERFACE */}
        {activeTab === 'chat' && (
          <div className="rounded-xl bg-slate-900 border border-slate-800 shadow-xl overflow-hidden flex flex-col h-[700px]">
            {/* Chatbot Header */}
            <div className="p-4 border-b border-slate-800 bg-slate-950 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-purple-600/20 text-purple-400 border border-purple-500/30">
                  <Bot className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-sm font-bold text-white">Gemini Cybersecurity Assistant</h2>
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-purple-950 text-purple-300 border border-purple-800 font-mono">
                      Multi-Turn Chat
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Ask questions about phishing, digital hygiene, or get personalized advice on your current check.
                  </p>
                </div>
              </div>

              {/* Model selection & Context status */}
              <div className="flex items-center gap-2 text-xs">
                {analysisResult && (
                  <span className="px-2.5 py-1 rounded-lg bg-blue-950/70 border border-blue-800/80 text-blue-300 font-medium text-[11px] flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 text-blue-400" />
                    Active Check Loaded ({analysisResult.risk_level})
                  </span>
                )}

                <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 p-0.5 rounded-lg">
                  <button
                    onClick={() => setSelectedChatModel('gemini-3.5-flash')}
                    className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                      selectedChatModel === 'gemini-3.5-flash'
                        ? 'bg-purple-600 text-white shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                    title="Gemini 3.5 Flash for general tasks"
                  >
                    Gemini 3.5 Flash (General)
                  </button>
                  <button
                    onClick={() => setSelectedChatModel('gemini-3.1-flash-lite')}
                    className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                      selectedChatModel === 'gemini-3.1-flash-lite'
                        ? 'bg-purple-600 text-white shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                    title="Gemini 3.1 Flash Lite for fast tasks"
                  >
                    <Zap className="w-3 h-3 inline mr-1" />
                    Flash Lite (Fast)
                  </button>
                </div>
              </div>
            </div>

            {/* Scrollable Message Thread */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {chatMessages.map((msg) => (
                <div
                  key={msg.id}
                  className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                >
                  {msg.role === 'model' && (
                    <div className="w-8 h-8 rounded-full bg-purple-600/20 border border-purple-500/40 text-purple-400 flex items-center justify-center shrink-0 mt-0.5">
                      <Bot className="w-4 h-4" />
                    </div>
                  )}

                  <div
                    className={`max-w-2xl rounded-2xl px-4 py-3 text-xs leading-relaxed ${
                      msg.role === 'user'
                        ? 'bg-blue-600 text-white rounded-br-none shadow-md'
                        : 'bg-slate-950 text-slate-200 border border-slate-800 rounded-bl-none'
                    }`}
                  >
                    <div className="whitespace-pre-wrap font-sans">{msg.content}</div>
                    <div
                      className={`text-[10px] mt-1.5 flex justify-end ${
                        msg.role === 'user' ? 'text-blue-200' : 'text-slate-500'
                      }`}
                    >
                      {msg.timestamp}
                    </div>
                  </div>

                  {msg.role === 'user' && (
                    <div className="w-8 h-8 rounded-full bg-blue-600 text-white flex items-center justify-center shrink-0 mt-0.5 shadow-md">
                      <User className="w-4 h-4" />
                    </div>
                  )}
                </div>
              ))}

              {isChatSending && (
                <div className="flex gap-3 justify-start items-center">
                  <div className="w-8 h-8 rounded-full bg-purple-600/20 border border-purple-500/40 text-purple-400 flex items-center justify-center shrink-0">
                    <Bot className="w-4 h-4" />
                  </div>
                  <div className="bg-slate-950 border border-slate-800 rounded-2xl px-4 py-3 text-xs text-slate-400 flex items-center gap-2">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin text-purple-400" />
                    <span>Gemini is thinking...</span>
                  </div>
                </div>
              )}

              <div ref={chatBottomRef} />
            </div>

            {/* Quick Starter Suggestion Chips */}
            <div className="p-2.5 bg-slate-950 border-t border-slate-800 flex items-center gap-2 overflow-x-auto text-xs">
              <span className="text-[11px] text-slate-500 font-medium shrink-0 flex items-center gap-1">
                <Sparkles className="w-3 h-3 text-purple-400" /> Quick Ask:
              </span>
              {analysisResult ? (
                <>
                  <button
                    onClick={() => handleSendChatMessage("Explain why this specific email was flagged.")}
                    disabled={isChatSending}
                    className="px-2.5 py-1 rounded-full bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700/80 text-[11px] whitespace-nowrap transition-colors cursor-pointer"
                  >
                    🔍 Why was my active check flagged?
                  </button>
                  <button
                    onClick={() => handleSendChatMessage("What should I do if an employee already clicked the link in this message?")}
                    disabled={isChatSending}
                    className="px-2.5 py-1 rounded-full bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700/80 text-[11px] whitespace-nowrap transition-colors cursor-pointer"
                  >
                    🚨 What if someone already clicked?
                  </button>
                </>
              ) : (
                <>
                  <button
                    onClick={() => handleSendChatMessage("What are the most common signs of a phishing email?")}
                    disabled={isChatSending}
                    className="px-2.5 py-1 rounded-full bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700/80 text-[11px] whitespace-nowrap transition-colors cursor-pointer"
                  >
                    💡 What are common phishing signs?
                  </button>
                  <button
                    onClick={() => handleSendChatMessage("How can I check if a web link is safe before clicking it?")}
                    disabled={isChatSending}
                    className="px-2.5 py-1 rounded-full bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700/80 text-[11px] whitespace-nowrap transition-colors cursor-pointer"
                  >
                    🔗 How to inspect links safely?
                  </button>
                </>
              )}
              <button
                onClick={() => handleSendChatMessage("Write a short warning email to alert our team about urgent account suspension scams.")}
                disabled={isChatSending}
                className="px-2.5 py-1 rounded-full bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700/80 text-[11px] whitespace-nowrap transition-colors cursor-pointer"
              >
                📝 Draft a team warning notice
              </button>
            </div>

            {/* Input Bar */}
            <div className="p-3 border-t border-slate-800 bg-slate-900 flex items-center gap-2">
              <input
                type="text"
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    handleSendChatMessage();
                  }
                }}
                placeholder="Ask Gemini a question about phishing or security (e.g. 'How do I report a fake bank email?')..."
                disabled={isChatSending}
                className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500/30"
              />
              <button
                onClick={() => handleSendChatMessage()}
                disabled={isChatSending || !chatInput.trim()}
                className="px-4 py-2.5 rounded-xl bg-purple-600 hover:bg-purple-500 disabled:opacity-40 text-white font-semibold text-xs flex items-center gap-1.5 transition-colors cursor-pointer shadow-md"
              >
                <Send className="w-3.5 h-3.5" />
                <span>Send</span>
              </button>
            </div>
          </div>
        )}

        {/* TAB 3: AUDIT HISTORY */}
        {activeTab === 'history' && (
          <div className="rounded-xl bg-slate-900 border border-slate-800 p-5 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <HistoryIcon className="w-4 h-4 text-blue-400" />
                  Previous Checks History
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Saved automatically in your local database (`phishing_lab.db`).
                </p>
              </div>

              <div className="flex items-center gap-2 flex-wrap">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
                  <input
                    type="text"
                    value={historySearch}
                    onChange={(e) => setHistorySearch(e.target.value)}
                    placeholder="Search previous checks..."
                    className="bg-slate-950 border border-slate-800 rounded-lg pl-7 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 w-48"
                  />
                </div>

                <select
                  value={historyRiskFilter}
                  onChange={(e) => setHistoryRiskFilter(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500 cursor-pointer"
                >
                  <option value="ALL">All Levels</option>
                  <option value="CRITICAL">Dangerous</option>
                  <option value="HIGH">High Risk</option>
                  <option value="MEDIUM">Caution</option>
                  <option value="LOW">Safe</option>
                </select>

                <button
                  onClick={fetchHistory}
                  disabled={isLoadingHistory}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isLoadingHistory ? 'animate-spin' : ''}`} />
                  Refresh
                </button>
              </div>
            </div>

            {/* Table */}
            <div className="overflow-x-auto rounded-xl border border-slate-800">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 uppercase font-semibold">
                  <tr>
                    <th className="py-3 px-4">#</th>
                    <th className="py-3 px-4">Date</th>
                    <th className="py-3 px-4">Type</th>
                    <th className="py-3 px-4">Message Preview</th>
                    <th className="py-3 px-4">Score</th>
                    <th className="py-3 px-4">Result</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 bg-slate-950/40">
                  {filteredHistory.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-slate-500">
                        {isLoadingHistory ? 'Loading history...' : 'No previous checks found.'}
                      </td>
                    </tr>
                  ) : (
                    filteredHistory.map((item) => (
                      <tr key={item.id} className="hover:bg-slate-900/60 transition-colors">
                        <td className="py-3 px-4 font-mono text-slate-400">#{item.id}</td>
                        <td className="py-3 px-4 text-slate-400 whitespace-nowrap">{item.created_at || 'Recent'}</td>
                        <td className="py-3 px-4">
                          <span className="capitalize font-semibold text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                            {item.input_type}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-slate-300 max-w-xs truncate">
                          {item.input_data}
                        </td>
                        <td className="py-3 px-4 font-bold text-slate-200 font-mono">
                          {item.risk_score} / 100
                        </td>
                        <td className="py-3 px-4">
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${getRiskColorPalette(item.risk_level).badgeClass}`}>
                            {getFriendlyLevelName(item.risk_level)}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right space-x-2 whitespace-nowrap">
                          <button
                            onClick={() => setSelectedHistoryItem(item)}
                            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-blue-300 text-xs transition-colors cursor-pointer font-medium"
                          >
                            View
                          </button>
                          <button
                            onClick={() => handleDeleteHistory(item.id)}
                            className="p-1 rounded hover:bg-rose-950 text-slate-500 hover:text-rose-300 transition-colors cursor-pointer"
                            title="Delete"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Modal for detailed inspection */}
            {selectedHistoryItem && (
              <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
                <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-2xl w-full max-h-[85vh] overflow-y-auto p-6 shadow-2xl space-y-4">
                  <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-white text-base">
                        Saved Check #{selectedHistoryItem.id}
                      </span>
                      <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${getRiskColorPalette(selectedHistoryItem.risk_level).badgeClass}`}>
                        {selectedHistoryItem.risk_score}/100 ({getFriendlyLevelName(selectedHistoryItem.risk_level)})
                      </span>
                    </div>
                    <button
                      onClick={() => setSelectedHistoryItem(null)}
                      className="text-slate-400 hover:text-white p-1 cursor-pointer"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>

                  <div className="space-y-3 text-xs">
                    <div>
                      <span className="font-semibold text-slate-400 block mb-1">Message Checked:</span>
                      <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 whitespace-pre-wrap max-h-36 overflow-y-auto font-sans leading-relaxed">
                        {selectedHistoryItem.input_data}
                      </pre>
                    </div>

                    <div>
                      <span className="font-semibold text-slate-400 block mb-1">
                        Suspicious Signs Found ({selectedHistoryItem.indicators.length}):
                      </span>
                      <div className="space-y-1.5 max-h-40 overflow-y-auto">
                        {selectedHistoryItem.indicators.map((ind, i) => (
                          <div key={i} className="p-2 rounded-lg bg-slate-950 border border-slate-800 flex justify-between items-start gap-2">
                            <div>
                              <span className="font-bold text-slate-200">{ind.indicator}</span>
                              <div className="text-blue-300 text-[11px] font-mono mt-0.5">{ind.evidence}</div>
                            </div>
                            <span className="text-blue-400 font-bold shrink-0 font-mono">+{ind.points} pts</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {selectedHistoryItem.ai_explanation?.short_explanation && (
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                        <span className="text-blue-400 font-bold">Summary:</span>
                        <p className="text-slate-300 leading-relaxed">{selectedHistoryItem.ai_explanation.short_explanation}</p>
                      </div>
                    )}
                  </div>

                  <div className="pt-3 border-t border-slate-800 flex justify-end gap-2">
                    <button
                      onClick={() => {
                        setAnalysisResult(selectedHistoryItem as any);
                        setSelectedHistoryItem(null);
                        setActiveTab('check');
                        showToast(`Loaded saved check #${selectedHistoryItem.id}`);
                      }}
                      className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs cursor-pointer"
                    >
                      Load into Checker
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 4: DETECTION TESTS */}
        {activeTab === 'tests' && (
          <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 shadow-xl space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-blue-400" />
                  Automated Detection Tests
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Runs our 18 Python unit tests to verify that phishing detection rules work properly.
                </p>
              </div>

              <button
                onClick={handleRunTests}
                disabled={isRunningTests}
                className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-bold flex items-center gap-2 transition-colors cursor-pointer"
              >
                {isRunningTests ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    Running Tests...
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5" />
                    Run All 18 Tests
                  </>
                )}
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-blue-400 font-bold block mb-1">
                  1. Message Rule Tests
                </span>
                <p className="text-slate-400">
                  Tests urgency phrases, fake suspension warnings, password requests, and verifies safe messages pass cleanly.
                </p>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-blue-400 font-bold block mb-1">
                  2. Web Link Tests
                </span>
                <p className="text-slate-400">
                  Tests raw IP addresses, fake brand subdomains, unusual characters, and clean legitimate websites.
                </p>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-blue-400 font-bold block mb-1">
                  3. Scoring Tests
                </span>
                <p className="text-slate-400">
                  Tests that risk points add up properly and stay within the 0 to 100 point scale.
                </p>
              </div>
            </div>

            {testResultOutput && (
              <div className="rounded-xl bg-slate-950 border border-slate-800 p-4 space-y-3 text-xs font-mono">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <div className="flex items-center gap-2">
                    <span className={`w-2.5 h-2.5 rounded-full ${testResultOutput.success ? 'bg-emerald-400' : 'bg-rose-400'}`} />
                    <span className="font-bold text-white">
                      {testResultOutput.success ? 'ALL 18 TESTS PASSED SUCCESSFULLY (OK)' : 'TESTS FAILED'}
                    </span>
                  </div>
                  <span className="text-slate-400">
                    Speed: {testResultOutput.duration_ms} ms
                  </span>
                </div>

                <pre className="text-slate-300 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                  {testResultOutput.stderr || testResultOutput.stdout || 'Tests completed with 0 errors.'}
                </pre>
              </div>
            )}
          </div>
        )}

        {/* TAB 5: SAFETY GUIDE */}
        {activeTab === 'guide' && (
          <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 shadow-xl space-y-4">
            <div className="border-b border-slate-800 pb-3">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-blue-400" />
                Phishing Clues Guide: How to Spot a Scam
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Learn the common tricks scammers use to steal accounts and passwords.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                <div className="flex justify-between items-center text-blue-300 font-bold">
                  <span>1. Artificial Urgency & Ticking Clocks</span>
                  <span className="text-blue-400 font-mono">+10 to +12 pts</span>
                </div>
                <p className="text-slate-300 leading-relaxed">
                  Scammers use words like "immediately", "within 24 hours", or "act today" to panic you into clicking before you stop to think.
                </p>
                <div className="text-[11px] text-slate-500 bg-slate-900 p-2 rounded">
                  Example phrases: "Verify immediately", "Act within 24 hours", "Expires today"
                </div>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                <div className="flex justify-between items-center text-blue-300 font-bold">
                  <span>2. Scaring You with Account Closure</span>
                  <span className="text-blue-400 font-mono">+12 to +18 pts</span>
                </div>
                <p className="text-slate-300 leading-relaxed">
                  They claim your account will be suspended, deleted, or blocked to make you feel like you have no choice but to follow their instructions.
                </p>
                <div className="text-[11px] text-slate-500 bg-slate-900 p-2 rounded">
                  Example phrases: "Account will be suspended", "Permanent lockout", "Unusual activity detected"
                </div>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                <div className="flex justify-between items-center text-blue-300 font-bold">
                  <span>3. Asking for Logins & Passwords</span>
                  <span className="text-blue-400 font-mono">+15 to +20 pts</span>
                </div>
                <p className="text-slate-300 leading-relaxed">
                  Real companies will never send an email asking you to verify your password or enter secret credentials through an email link.
                </p>
                <div className="text-[11px] text-slate-500 bg-slate-900 p-2 rounded">
                  Example phrases: "Verify your account", "Confirm your password", "Sign in immediately"
                </div>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                <div className="flex justify-between items-center text-blue-300 font-bold">
                  <span>4. Copied or Deceptive Web Links</span>
                  <span className="text-blue-400 font-mono">+20 to +25 pts</span>
                </div>
                <p className="text-slate-300 leading-relaxed">
                  The link might look like "paypal-security-update.com" instead of "paypal.com", or use numbers instead of a real name.
                </p>
                <div className="text-[11px] text-slate-500 bg-slate-900 p-2 rounded">
                  Example tricks: Extra hyphens, copied brand names in subdomains, raw IP numbers
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Full Report Modal */}
      {showFullReportModal && analysisResult && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto p-5 shadow-2xl space-y-3 text-xs">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <span className="font-bold text-white text-sm">
                Full Phishing Investigation Report (ASCII Format)
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleDownloadPdf}
                  className="px-2.5 py-1 rounded bg-emerald-700 hover:bg-emerald-600 text-white flex items-center gap-1 cursor-pointer font-medium"
                >
                  <FileDown className="w-3.5 h-3.5" /> Save PDF
                </button>
                <button
                  onClick={handleCopyReport}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center gap-1 cursor-pointer font-medium"
                >
                  <Copy className="w-3.5 h-3.5 text-blue-400" /> Copy
                </button>
                <button
                  onClick={() => setShowFullReportModal(false)}
                  className="text-slate-400 hover:text-white p-1 cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            <pre className="p-4 rounded-lg bg-slate-950 text-slate-300 whitespace-pre-wrap leading-relaxed border border-slate-800 max-h-[60vh] overflow-y-auto font-mono text-[11px]">
              {analysisResult.ascii_report}
            </pre>

            <div className="pt-2 flex justify-between items-center">
              <span className="text-[11px] text-slate-500 font-mono">Compatible with SIEM & IT ticketing systems</span>
              <button
                onClick={() => setShowFullReportModal(false)}
                className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-white font-bold text-xs cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Benchmark Comparison Matrix Modal */}
      {showBenchmarkComparison && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto p-5 shadow-2xl space-y-4 text-xs">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Scale className="w-4 h-4 text-blue-400" />
                <span className="font-bold text-white text-sm">
                  Side-by-Side Demonstration Comparison Matrix (3 Standard Benchmarks)
                </span>
              </div>
              <button
                onClick={() => setShowBenchmarkComparison(false)}
                className="text-slate-400 hover:text-white p-1 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-slate-300 leading-relaxed">
              This matrix demonstrates how our explainable rule engine and scoring model evaluate the three core tiers of cybersecurity email scenarios:
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {/* Benchmark Column 1: High Risk */}
              <div className="p-4 rounded-xl bg-slate-950 border border-rose-900/60 flex flex-col justify-between space-y-3">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-rose-300 text-xs flex items-center gap-1">
                      <AlertTriangle className="w-3.5 h-3.5 text-rose-400" /> 1. High-Risk Phishing
                    </span>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-rose-950 text-rose-300 border border-rose-800">
                      Score: ~87 / 100
                    </span>
                  </div>

                  <div className="p-2 rounded bg-slate-900 font-mono text-[10px] text-slate-300 border border-slate-800 space-y-1">
                    <div className="text-slate-500 font-sans font-semibold">Message Excerpt:</div>
                    <div className="italic">"Your account will be suspended today due to unusual activity. Verify your account immediately using the link below: https://secure-account-verification..."</div>
                  </div>

                  <div className="space-y-1">
                    <span className="font-semibold text-slate-200 block text-[11px]">Why It Was Flagged:</span>
                    <ul className="space-y-1 text-[11px] text-slate-300">
                      <li className="flex items-center gap-1.5 text-rose-300">
                        <Check className="w-3 h-3 text-rose-400 shrink-0" /> Urgent Language ("immediately", "today")
                      </li>
                      <li className="flex items-center gap-1.5 text-rose-300">
                        <Check className="w-3 h-3 text-rose-400 shrink-0" /> Account Threat ("will be suspended")
                      </li>
                      <li className="flex items-center gap-1.5 text-rose-300">
                        <Check className="w-3 h-3 text-rose-400 shrink-0" /> Credential Prompt ("verify account")
                      </li>
                      <li className="flex items-center gap-1.5 text-rose-300">
                        <Check className="w-3 h-3 text-rose-400 shrink-0" /> Suspicious Link (deceptive domain)
                      </li>
                    </ul>
                  </div>

                  <div className="text-[11px] text-slate-400 leading-relaxed pt-1">
                    <strong className="text-slate-300">Defensive Playbook:</strong> Do not click. Never enter credentials via unsolicited links. Flag as malicious phishing.
                  </div>
                </div>

                <button
                  onClick={() => {
                    setShowBenchmarkComparison(false);
                    handleRunTestCase(testCases[0]);
                  }}
                  className="w-full py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs flex items-center justify-center gap-1.5 cursor-pointer shadow-md shadow-rose-950 transition-colors"
                >
                  <Play className="w-3 h-3" /> Test This Case Now
                </button>
              </div>

              {/* Benchmark Column 2: Medium Risk */}
              <div className="p-4 rounded-xl bg-slate-950 border border-amber-900/60 flex flex-col justify-between space-y-3">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-amber-300 text-xs flex items-center gap-1">
                      <AlertCircle className="w-3.5 h-3.5 text-amber-400" /> 2. Medium-Risk Suspicious
                    </span>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-950 text-amber-300 border border-amber-800">
                      Score: ~39 / 100
                    </span>
                  </div>

                  <div className="p-2 rounded bg-slate-900 font-mono text-[10px] text-slate-300 border border-slate-800 space-y-1">
                    <div className="text-slate-500 font-sans font-semibold">Message Excerpt:</div>
                    <div className="italic">"We noticed a login from an unfamiliar device. Please review your account activity. Click here to update your information..."</div>
                  </div>

                  <div className="space-y-1">
                    <span className="font-semibold text-slate-200 block text-[11px]">Why It Was Flagged:</span>
                    <ul className="space-y-1 text-[11px] text-slate-300">
                      <li className="flex items-center gap-1.5 text-amber-300">
                        <Check className="w-3 h-3 text-amber-400 shrink-0" /> Security Review Alert ("unfamiliar device")
                      </li>
                      <li className="flex items-center gap-1.5 text-amber-300">
                        <Check className="w-3 h-3 text-amber-400 shrink-0" /> Call-to-Action Link ("Click here")
                      </li>
                      <li className="flex items-center gap-1.5 text-amber-300">
                        <Check className="w-3 h-3 text-amber-400 shrink-0" /> External Redirect URL
                      </li>
                      <li className="flex items-center gap-1.5 text-slate-500 line-through">
                        No direct ultimatum or countdown
                      </li>
                    </ul>
                  </div>

                  <div className="text-[11px] text-slate-400 leading-relaxed pt-1">
                    <strong className="text-slate-300">Defensive Playbook:</strong> Verify independently. Open official service app or website directly instead of clicking.
                  </div>
                </div>

                <button
                  onClick={() => {
                    setShowBenchmarkComparison(false);
                    handleRunTestCase(testCases[1]);
                  }}
                  className="w-full py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-bold text-xs flex items-center justify-center gap-1.5 cursor-pointer shadow-md shadow-amber-950 transition-colors"
                >
                  <Play className="w-3 h-3" /> Test This Case Now
                </button>
              </div>

              {/* Benchmark Column 3: Low Risk */}
              <div className="p-4 rounded-xl bg-slate-950 border border-emerald-900/60 flex flex-col justify-between space-y-3">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-emerald-300 text-xs flex items-center gap-1">
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> 3. Low-Risk / Benign
                    </span>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-300 border border-emerald-800">
                      Score: 0 / 100
                    </span>
                  </div>

                  <div className="p-2 rounded bg-slate-900 font-mono text-[10px] text-slate-300 border border-slate-800 space-y-1">
                    <div className="text-slate-500 font-sans font-semibold">Message Excerpt:</div>
                    <div className="italic">"Weekly Team Engineering Digest #42. Sprint planning begins Tuesday at 10:00 AM UTC. Please review the architectural RFC doc on our wiki..."</div>
                  </div>

                  <div className="space-y-1">
                    <span className="font-semibold text-slate-200 block text-[11px]">Why It Was Flagged:</span>
                    <ul className="space-y-1 text-[11px] text-emerald-300">
                      <li className="flex items-center gap-1.5">
                        <Check className="w-3 h-3 text-emerald-400 shrink-0" /> Zero panic or pressure tactics
                      </li>
                      <li className="flex items-center gap-1.5">
                        <Check className="w-3 h-3 text-emerald-400 shrink-0" /> Zero account threats or ultimatums
                      </li>
                      <li className="flex items-center gap-1.5">
                        <Check className="w-3 h-3 text-emerald-400 shrink-0" /> Zero credential harvesting prompts
                      </li>
                      <li className="flex items-center gap-1.5">
                        <Check className="w-3 h-3 text-emerald-400 shrink-0" /> Zero deceptive link manipulation
                      </li>
                    </ul>
                  </div>

                  <div className="text-[11px] text-slate-400 leading-relaxed pt-1">
                    <strong className="text-slate-300">Defensive Playbook:</strong> Harmless routine communication. Normal handling appropriate.
                  </div>
                </div>

                <button
                  onClick={() => {
                    setShowBenchmarkComparison(false);
                    handleRunTestCase(testCases[2]);
                  }}
                  className="w-full py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center justify-center gap-1.5 cursor-pointer shadow-md shadow-emerald-950 transition-colors"
                >
                  <Play className="w-3 h-3" /> Test This Case Now
                </button>
              </div>
            </div>

            {/* Modal Disclaimer */}
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] text-slate-400 flex items-start gap-2">
              <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
              <span>
                <strong>Disclaimer:</strong> This comparison demonstrates synthetic testing scenarios. Automated analysis provides threat-detection guidance and indication, not a 100% guarantee of safety or malice.
              </span>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setShowBenchmarkComparison(false)}
                className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-white font-bold text-xs cursor-pointer"
              >
                Close Matrix
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Friendly Footer with Security Disclaimer */}
      <footer className="border-t border-slate-800/80 py-6 text-center text-xs text-slate-500 space-y-2 px-4">
        <div>Phishing Detector & Safety Lab · Built for Educational Cybersecurity Learning & Threat Analysis</div>
        <div className="text-[11px] text-slate-500 max-w-2xl mx-auto leading-relaxed">
          ⚠️ <strong>Security Disclaimer:</strong> This application provides automated heuristic and AI-assisted indicators for educational guidance. It is an indication and not a 100% guarantee that a message or web link is safe or malicious. Always exercise caution and verify unexpected requests through trusted channels.
        </div>
      </footer>
    </div>
  );
}
