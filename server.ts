import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import { spawn } from 'child_process';
import { GoogleGenAI } from '@google/genai';
import { DatabaseSync } from 'node:sqlite';

const PORT = 3000;
const DB_PATH = path.resolve(process.cwd(), 'phishing_lab.db');

// Initialize SQLite database table
const db = new DatabaseSync(DB_PATH);
db.exec(`
  CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    input_type TEXT NOT NULL,
    input_data TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    indicators_json TEXT NOT NULL,
    score_breakdown_json TEXT NOT NULL,
    url_analysis_json TEXT,
    ai_explanation_json TEXT,
    recommendation TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at DESC);
`);

// Shared Gemini client setup
let aiClient: GoogleGenAI | null = null;
if (process.env.GEMINI_API_KEY) {
  aiClient = new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

const SYNTHETIC_TEST_CASES = [
  {
    id: "high-risk-urgent-suspension",
    title: "Test 1 — Urgent Account Suspension (High Risk)",
    type: "email",
    tag: "High Risk · Urgency + Suspension",
    description: "Fabricated suspension notice claiming unusual activity with urgency deadline and deceptive verification portal link.",
    content: `Subject: Urgent: Your Account Will Be Suspended

Dear Customer,

Your account will be suspended today due to unusual activity. Verify your account immediately using the link below:

https://secure-account-verification.example.com/login

Failure to verify will result in permanent suspension.`
  },
  {
    id: "medium-risk-activity-review",
    title: "Test 2 — Account Activity Review (Medium Risk)",
    type: "email",
    tag: "Medium Risk · Activity Alert",
    description: "Notification alleging an unrecognized login with a request to review activity and update details.",
    content: `Subject: Account Security Review Notification

Hello user,

We noticed a login from an unfamiliar device. Please review your account activity. 
Click here to update your information if this was not you:
https://portal-notice.example.com/security/review`
  },
  {
    id: "low-risk-engineering-memo",
    title: "Test 3 — Routine Internal Newsletter (Low Risk)",
    type: "email",
    tag: "Low Risk · Benign Internal Memo",
    description: "Normal organizational update without urgent pressure, credential demands, or malicious heuristics.",
    content: `Subject: Weekly Team Engineering Digest #42

Hello everyone,

Here is our weekly project digest. Sprint planning begins Tuesday at 10:00 AM UTC.
Please review the architectural RFC doc on our internal engineering wiki when you have time.

Best regards,
Engineering Operations Team`
  },
  {
    id: "url-suspicious-ip-host",
    title: "Test 4 — Raw IP + Credential Path (URL)",
    type: "url",
    tag: "High Risk · Raw IPv4 Host",
    description: "Suspicious raw IPv4 hostname targeting login and account verification paths.",
    content: "http://192.168.1.100/secure-account/verify/login.php"
  },
  {
    id: "url-brand-impersonation",
    title: "Test 5 — Brand Subdomain Impersonation (URL)",
    type: "url",
    tag: "High Risk · Impersonation",
    description: "Multi-hyphenated brand name spoofing in subdomain chain.",
    content: "https://paypal-security-account-verification.attacker-host.com/signin"
  },
  {
    id: "url-clean-official",
    title: "Test 6 — Standard Clean HTTPS (URL)",
    type: "url",
    tag: "Low Risk · Standard HTTPS",
    description: "Legitimate, clean HTTPS endpoint with normal path structure.",
    content: "https://example.com/resources/documentation"
  }
];

function runPythonCli(payload: any): Promise<any> {
  return new Promise((resolve, reject) => {
    const pyProcess = spawn('python3', ['run_cli.py'], {
      cwd: process.cwd(),
      env: process.env,
    });

    let stdoutData = '';
    let stderrData = '';

    pyProcess.stdout.on('data', (data) => {
      stdoutData += data.toString();
    });

    pyProcess.stderr.on('data', (data) => {
      stderrData += data.toString();
    });

    pyProcess.on('close', (code) => {
      if (code !== 0) {
        return reject(new Error(`Python analyzer exited with code ${code}: ${stderrData || stdoutData}`));
      }
      try {
        const parsed = JSON.parse(stdoutData.trim());
        resolve(parsed);
      } catch (err) {
        reject(new Error(`Failed to parse Python output: ${err} - Raw: ${stdoutData}`));
      }
    });

    pyProcess.stdin.write(JSON.stringify(payload));
    pyProcess.stdin.end();
  });
}

async function generateAiExplanationWithGemini(
  text: string,
  ruleIndicators: any[],
  urlAnalysis: any,
  riskScore: number,
  riskLevel: string
) {
  if (!aiClient) {
    return buildFallbackExplanation(ruleIndicators, riskScore, riskLevel);
  }

  try {
    const prompt = `
You are an expert Cybersecurity Incident Response & Threat Analyst.
Analyze the following structured phishing detection results and provide an explainable summary.

CONTEXT DATA:
- Input Risk Score: ${riskScore}/100
- Risk Level: ${riskLevel}
- Detected Rule Indicators: ${JSON.stringify(ruleIndicators, null, 2)}
- URL Analysis Heuristics: ${JSON.stringify(urlAnalysis || {}, null, 2)}
- Analyzed Raw Snippet: ${text.slice(0, 500)}

IMPORTANT GUIDELINES:
1. Do NOT recalculate or override the deterministic risk score (${riskScore}/100).
2. Clearly explain WHY these indicators together represent a threat or safe baseline.
3. Be professional, concise, and educational for a SOC analyst or employee.

Respond ONLY with a valid JSON object matching this schema:
{
  "short_explanation": "Concise 2-3 sentence overview explaining why it was classified as this risk level.",
  "main_suspicious_behavior": "Key psychological or technical deception vector (e.g. Manufactured Urgency + Account Suspension Ultimatum)",
  "most_important_indicators": [
    "Indicator 1 summary",
    "Indicator 2 summary",
    "Indicator 3 summary"
  ],
  "recommended_action": "Clear, practical instructions on what the recipient should do right now."
}
`;

    const response = await aiClient.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        temperature: 0.2,
      },
    });

    const parsed = JSON.parse(response.text || '{}');
    parsed.provider = 'Gemini 3.8 Flash (AI Analyst)';
    return parsed;
  } catch (err) {
    console.warn('Gemini API call failed, using deterministic fallback:', err);
    return buildFallbackExplanation(ruleIndicators, riskScore, riskLevel);
  }
}

function buildFallbackExplanation(ruleIndicators: any[], riskScore: number, riskLevel: string) {
  if (!ruleIndicators || ruleIndicators.length === 0) {
    return {
      short_explanation: "No suspicious phishing indicators or deceptive patterns were detected during this evaluation.",
      main_suspicious_behavior: "Benign communication baseline; normal informational message.",
      most_important_indicators: ["No urgency pressure detected", "No credential requests", "No deceptive links"],
      recommended_action: "Standard operating procedure: Keep software updated and follow routine security hygiene.",
      provider: "Rule-Based Deterministic NLP Synthesizer (AI Baseline)"
    };
  }

  const indicatorNames = ruleIndicators.map(i => i.indicator).filter(Boolean);
  const highSev = ruleIndicators.filter(i => i.severity === 'high' || i.severity === 'critical');

  const behaviors: string[] = [];
  if (ruleIndicators.some(i => i.category === 'urgency')) behaviors.push("manufactured urgency");
  if (ruleIndicators.some(i => i.category === 'threat')) behaviors.push("punitive threats (account suspension/closure)");
  if (ruleIndicators.some(i => i.category === 'credential')) behaviors.push("unsolicited credential verification demands");
  if (ruleIndicators.some(i => i.category === 'financial')) behaviors.push("financial / transaction lures");
  if (ruleIndicators.some(i => i.category === 'url_heuristic')) behaviors.push("suspicious URL domain patterns");

  const behaviorSummary = behaviors.length > 0 ? behaviors.join(' + ') : 'suspicious communication patterns';

  return {
    short_explanation: `This item was classified as ${riskLevel} (${riskScore}/100) because it exhibits ${behaviorSummary}. Threat actors rely on these psychological levers to bypass deliberation and direct targets toward credential harvesting portals.`,
    main_suspicious_behavior: `Coordinated combination of: ${indicatorNames.slice(0, 4).join(', ')}`,
    most_important_indicators: (highSev.length > 0 ? highSev : ruleIndicators).slice(0, 3).map(
      i => `${i.indicator} (+${i.points} pts): ${i.description}`
    ),
    recommended_action: riskScore >= 50
      ? "Do not click any embedded links or provide login credentials. Verify account security directly through an official browser bookmark or the organization's verified app."
      : "Inspect sender addresses carefully and verify any unexpected requests out-of-band.",
    provider: "Rule-Based Deterministic NLP Synthesizer (AI Baseline)"
  };
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  // API Routes
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'healthy',
      service: 'AI-Powered Phishing Investigation Lab',
      version: '1.0.0',
      ai_configured: Boolean(process.env.GEMINI_API_KEY),
      database: 'phishing_lab.db',
    });
  });

  app.get('/api/test-cases', (req, res) => {
    res.json(SYNTHETIC_TEST_CASES);
  });

  app.post('/api/chat', async (req, res) => {
    try {
      const { messages, currentAnalysis, model = 'gemini-3.5-flash' } = req.body;
      if (!messages || !Array.isArray(messages) || messages.length === 0) {
        return res.status(400).json({ error: 'Messages array is required.' });
      }

      if (!aiClient) {
        const lastUserMsg = messages[messages.length - 1]?.content || '';
        return res.json({
          reply: `[Offline AI Assistant] You asked: "${lastUserMsg}". In general, phishing messages create artificial urgency, threaten account closure, or impersonate brands to steal credentials. Always verify through official channels before clicking links.`,
          model: 'Deterministic Assistant (Offline)',
        });
      }

      let systemInstruction = `You are a supportive, knowledgeable Cybersecurity Assistant for the Phishing Detector & Safety Lab.
Your role is to help users understand phishing threats, investigate suspicious emails and web links, and provide practical defensive security guidance.
Keep answers clear, reassuring, accessible, and structured with bullet points where helpful. Avoid unnecessary technical jargon unless explaining a term simply.`;

      if (currentAnalysis) {
        systemInstruction += `\n\nCURRENT INVESTIGATION CONTEXT:
The user is actively inspecting an item:
- Threat Level: ${currentAnalysis.risk_level} (${currentAnalysis.risk_score}/100)
- Type: ${currentAnalysis.input_type}
- Text excerpt: ${String(currentAnalysis.input_data || '').slice(0, 300)}
- Detected clues: ${currentAnalysis.indicators?.map((i: any) => i.indicator).join(', ') || 'None'}
- Recommended Action: ${currentAnalysis.recommendation || ''}
If the user asks questions about this item (e.g., "Why was it flagged?", "What should I do?"), tailor your advice directly to this context.`;
      }

      const contents = messages.map((m: any) => ({
        role: m.role === 'model' || m.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: m.content }],
      }));

      const response = await aiClient.models.generateContent({
        model: model || 'gemini-3.5-flash',
        contents: contents,
        config: {
          systemInstruction: systemInstruction,
          temperature: 0.7,
        },
      });

      res.json({
        reply: response.text || 'I evaluated your question. Please remain cautious with unexpected links and verify requests independently.',
        model: model || 'gemini-3.5-flash',
      });
    } catch (err: any) {
      console.error('Chat API error:', err);
      res.status(500).json({ error: err.message || 'Failed to process chat message' });
    }
  });

  app.get('/api/stats', (req, res) => {
    try {
      const stmt = db.prepare(`
        SELECT 
          COUNT(*) as total,
          SUM(CASE WHEN risk_level IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END) as high_risk,
          SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium_risk,
          SUM(CASE WHEN risk_level = 'LOW' THEN 1 ELSE 0 END) as low_risk,
          AVG(risk_score) as avg_score
        FROM analyses
      `);
      const row: any = stmt.get();
      res.json({
        total: row.total || 0,
        high_risk: row.high_risk || 0,
        medium_risk: row.medium_risk || 0,
        low_risk: row.low_risk || 0,
        avg_score: row.avg_score ? Math.round(row.avg_score * 10) / 10 : 0,
      });
    } catch (err: any) {
      res.status(500).json({ error: `Failed to fetch stats: ${err.message}` });
    }
  });

  app.post('/api/analyze/email', async (req, res) => {
    try {
      const text = req.body.content || req.body.text || '';
      if (!text || !text.trim()) {
        return res.status(400).json({ error: 'Email content is required.' });
      }

      // 1. Run Python rule engine
      const pyResult = await runPythonCli({ mode: 'email', content: text.trim() });

      // 2. Enrich with AI explanation
      const aiExplanation = await generateAiExplanationWithGemini(
        text,
        pyResult.indicators,
        pyResult.url_analysis,
        pyResult.risk_score,
        pyResult.risk_level
      );

      // 3. Persist into SQLite
      const insertStmt = db.prepare(`
        INSERT INTO analyses (
          input_type, input_data, risk_score, risk_level,
          indicators_json, score_breakdown_json, url_analysis_json,
          ai_explanation_json, recommendation
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const result = insertStmt.run(
        'email',
        text.trim().slice(0, 2000),
        pyResult.risk_score,
        pyResult.risk_level,
        JSON.stringify(pyResult.indicators),
        JSON.stringify(pyResult.score_breakdown),
        pyResult.url_analysis ? JSON.stringify(pyResult.url_analysis) : null,
        JSON.stringify(aiExplanation),
        pyResult.recommendation
      );

      const savedId = Number(result.lastInsertRowid);

      res.json({
        id: savedId,
        input_type: 'email',
        input_data: text.trim(),
        risk_score: pyResult.risk_score,
        risk_level: pyResult.risk_level,
        indicators: pyResult.indicators,
        score_breakdown: pyResult.score_breakdown,
        extracted_urls: pyResult.extracted_urls || [],
        url_analysis: pyResult.url_analysis,
        ai_explanation: aiExplanation,
        recommendation: pyResult.recommendation,
        ascii_report: pyResult.ascii_report,
      });
    } catch (err: any) {
      console.error('Email analysis error:', err);
      res.status(500).json({ error: err.message || 'Analysis failed' });
    }
  });

  app.post('/api/analyze/url', async (req, res) => {
    try {
      const url = req.body.url || req.body.content || '';
      if (!url || !url.trim()) {
        return res.status(400).json({ error: 'Target URL is required.' });
      }

      // 1. Run Python URL analyzer
      const pyResult = await runPythonCli({ mode: 'url', url: url.trim() });

      // 2. Enrich with AI explanation
      const aiExplanation = await generateAiExplanationWithGemini(
        url,
        pyResult.indicators,
        pyResult.url_analysis,
        pyResult.risk_score,
        pyResult.risk_level
      );

      // 3. Persist into SQLite
      const insertStmt = db.prepare(`
        INSERT INTO analyses (
          input_type, input_data, risk_score, risk_level,
          indicators_json, score_breakdown_json, url_analysis_json,
          ai_explanation_json, recommendation
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const result = insertStmt.run(
        'url',
        url.trim().slice(0, 2000),
        pyResult.risk_score,
        pyResult.risk_level,
        JSON.stringify(pyResult.indicators),
        JSON.stringify(pyResult.score_breakdown),
        JSON.stringify(pyResult.url_analysis),
        JSON.stringify(aiExplanation),
        pyResult.recommendation
      );

      const savedId = Number(result.lastInsertRowid);

      res.json({
        id: savedId,
        input_type: 'url',
        input_data: url.trim(),
        risk_score: pyResult.risk_score,
        risk_level: pyResult.risk_level,
        indicators: pyResult.indicators,
        score_breakdown: pyResult.score_breakdown,
        url_analysis: pyResult.url_analysis,
        ai_explanation: aiExplanation,
        recommendation: pyResult.recommendation,
        ascii_report: pyResult.ascii_report,
      });
    } catch (err: any) {
      console.error('URL analysis error:', err);
      res.status(500).json({ error: err.message || 'URL analysis failed' });
    }
  });

  app.get('/api/history', (req, res) => {
    try {
      const limit = Math.min(parseInt((req.query.limit as string) || '50', 10), 100);
      const offset = Math.max(parseInt((req.query.offset as string) || '0', 10), 0);

      const stmt = db.prepare(`
        SELECT id, input_type, input_data, risk_score, risk_level,
               indicators_json, score_breakdown_json, url_analysis_json,
               ai_explanation_json, recommendation, created_at
        FROM analyses
        ORDER BY id DESC
        LIMIT ? OFFSET ?
      `);
      const rows = stmt.all(limit, offset) as any[];

      const records = rows.map((r) => ({
        id: r.id,
        input_type: r.input_type,
        input_data: r.input_data,
        risk_score: r.risk_score,
        risk_level: r.risk_level,
        indicators: r.indicators_json ? JSON.parse(r.indicators_json) : [],
        score_breakdown: r.score_breakdown_json ? JSON.parse(r.score_breakdown_json) : [],
        url_analysis: r.url_analysis_json ? JSON.parse(r.url_analysis_json) : null,
        ai_explanation: r.ai_explanation_json ? JSON.parse(r.ai_explanation_json) : {},
        recommendation: r.recommendation,
        created_at: r.created_at,
      }));

      res.json(records);
    } catch (err: any) {
      res.status(500).json({ error: `Failed to fetch history: ${err.message}` });
    }
  });

  app.get('/api/history/:id', (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const stmt = db.prepare(`
        SELECT id, input_type, input_data, risk_score, risk_level,
               indicators_json, score_breakdown_json, url_analysis_json,
               ai_explanation_json, recommendation, created_at
        FROM analyses
        WHERE id = ?
      `);
      const r: any = stmt.get(id);
      if (!r) {
        return res.status(400).json({ error: `Investigation #${id} not found.` });
      }

      res.json({
        id: r.id,
        input_type: r.input_type,
        input_data: r.input_data,
        risk_score: r.risk_score,
        risk_level: r.risk_level,
        indicators: r.indicators_json ? JSON.parse(r.indicators_json) : [],
        score_breakdown: r.score_breakdown_json ? JSON.parse(r.score_breakdown_json) : [],
        url_analysis: r.url_analysis_json ? JSON.parse(r.url_analysis_json) : null,
        ai_explanation: r.ai_explanation_json ? JSON.parse(r.ai_explanation_json) : {},
        recommendation: r.recommendation,
        created_at: r.created_at,
      });
    } catch (err: any) {
      res.status(500).json({ error: `Failed to fetch record: ${err.message}` });
    }
  });

  app.delete('/api/history/:id', (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const stmt = db.prepare('DELETE FROM analyses WHERE id = ?');
      stmt.run(id);
      res.json({ success: true, message: `Investigation #${id} deleted.` });
    } catch (err: any) {
      res.status(500).json({ error: `Failed to delete record: ${err.message}` });
    }
  });

  app.post('/api/run-tests', (req, res) => {
    const startTime = Date.now();
    const testProc = spawn('python3', ['-m', 'unittest', 'discover', 'tests'], {
      cwd: process.cwd(),
      env: process.env,
    });

    let stdout = '';
    let stderr = '';

    testProc.stdout.on('data', (d) => { stdout += d.toString(); });
    testProc.stderr.on('data', (d) => { stderr += d.toString(); });

    testProc.on('close', (code) => {
      const duration = Date.now() - startTime;
      res.json({
        success: code === 0,
        exit_code: code,
        stdout,
        stderr,
        duration_ms: duration,
      });
    });
  });

  // Mount Vite development middlewares
  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (req, res) => {
        res.sendFile(path.resolve(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`AI-Powered Phishing Investigation Lab server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
