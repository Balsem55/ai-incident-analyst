import { useState } from "react";
import axios from "axios";
const N8N_BASE = "http://localhost:5678/webhook";
const severityColor = {

  critical: "#ff2d55",
  high: "#ff6b35",
  medium: "#ffd60a",
  low: "#30d158",
  unknown: "#636366",
};
const severityBg = {
   critical: "rgba(255,45,85,0.12)",
  high: "rgba(255,107,53,0.12)",
  medium: "rgba(255,214,10,0.12)",
  low: "rgba(48,209,88,0.12)",
  unknown: "rgba(99,99,102,0.12)",
};
export default function App (){
  const [activeTab , setActiveTab] = useState("logs");
  const [results , setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [logInput, setLogInput] = useState("");
  const [logSource, setLogSource] = useState("firewall");
  const [urlInput, setUrlInput] = useState("");
  const [ipInput, setIpInput] = useState("");
  const [nucleiInput, setNucleiInput] = useState("");
const stats = {
  total : results.length,
  incidents : results.filter((r)=> r.is_malicious || r.incident).length,
  safe : results.filter((r)=> !r.is_malicious && !r.incident).length,
  critical : results.filter((r)=> r.severity==="critical").length,
};
const analyzeLog = async()=> {
  if (! logInput.trim()) return;
  setLoading(true);
  try{
  const res = await axios.post(`${N8N_BASE}/logs`, {
  source: logSource,
  log: logInput,
});

const d = res.data;
  setResults((prev)=>[
    {
      id: Date.now(),
      type: "LOG",
      target : logInput.slice(0, 60) + "...",
      status:d.status,
severity: d.severity || "unknown",
timestamp: d.timestamp || new Date().toISOString(),   
  
 is_malicious : d.status?.includes("INCIDENT"),
      incident: d.status?.includes("INCIDENT"),
    },
      ...prev,
  ]);
    setLogInput("");
  }catch(e){
    alert("Erreur :" +e.message);
  }
    setLoading(false);
};

const scanUrl = async () => {
    if(!urlInput.trim() ) return;
  setLoading(true);
  try{
    const res= await axios.post(`${N8N_BASE}/scan-url`, { url : urlInput});
    const d = res.data;
    setResults((prev)=>[{
      id: Date.now(),
      type: "URL" ,
       target : urlInput,
       status : d.status,
       severity : d.severity || "low",
       explanation : `VirusTotal : ${d.virustotal?.malicious || 0} malicious engines `,
      timestamp : d.timestamp || new Date().toISOString(),
      is_malicious: d.status?.includes("MALICIOUS"),
      incident : d.status?.includes("MALICIOUS"),
      },
      ...prev ,
  ]);
}catch (e) {
      alert("Erreur: " + e.message);
    }
    setLoading(false);
};

const scanIp= async()=> {
  if (!ipInput.trim()) return ;
  setLoading(true);
  try{
    const res = await axios.post(`${N8N_BASE}/scan-ip`, {ip:ipInput});
    const d=res.data;
    setResults((prev)=>[{
      id:Date.now(),
      type:"IP",
      target : ipInput,
      status:d.status,
      severity : d.severity || "low" ,
        explanation: `Abuse Score: ${d.abuseipdb?.abuse_score || 0}% | Country: ${d.abuseipdb?.country || "N/A"} | Reports: ${d.abuseipdb?.total_reports || 0}`,
          timestamp: d.timestamp || new Date().toISOString(),
          is_malicious: d.status?.includes("MALICIOUS"),
          incident: d.status?.includes("MALICIOUS"),
    },
  ...prev,
]);
setIpInput("");
  }catch (e) {
      alert("Erreur: " + e.message);
    }
    setLoading(false);
  };
  const scanNuclei = async () => {
  if (!nucleiInput.trim()) return;
  setLoading(true);
  try {
    // Lance le scan Nuclei
    await fetch(`http://localhost:5678/webhook/scan-nuclei`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: nucleiInput })
    });

    // Attend 30 secondes que Nuclei finisse
    await new Promise(resolve => setTimeout(resolve, 30000));

    // Lit les résultats
    const res = await axios.post(`${N8N_BASE}/scan-nuclei`, {
      target: nucleiInput
    });
    const d = res.data;
    setResults((prev) => [
      {
        id: Date.now(),
        type: "NUCLEI",
        target: nucleiInput,
        status: d.ai_analysis?.risk_level === 'critical' || d.ai_analysis?.risk_level === 'high'
          ? ' VULNERABILITIES FOUND'
          : ' No Critical Issues',
        severity: d.ai_analysis?.risk_level || "low",
        explanation: `Total: ${d.scan_summary?.total || 0} | Critical: ${d.scan_summary?.critical || 0} | High: ${d.scan_summary?.high || 0} | Medium: ${d.scan_summary?.medium || 0} | ${d.ai_analysis?.recommendation || ''}`,
        timestamp: d.timestamp || new Date().toISOString(),
        is_malicious: d.scan_summary?.total > 0,
        incident: d.scan_summary?.total > 0,
      },
      ...prev,
    ]);
    setNucleiInput("");
  } catch (e) {
    alert("Erreur: " + e.message);
  }
  setLoading(false);
};
return (
    <div style={styles.root}>

      {/* Header */}
      <header style={styles.header}>
        <div style={styles.headerLeft}>
          <span style={styles.shield}>🛡️</span>
          <div>
            <div style={styles.headerTitle}>DevSecOps Platform</div>
            <div style={styles.headerSub}>AI-Powered Security Analysis</div>
          </div>
        </div>
        <div style={styles.headerRight}>
          <div style={styles.liveChip}>
            <span style={styles.liveDot} />
            LIVE
          </div>
        </div>
      </header>
       <div style={styles.statsRow}>
        {[
          { label: "Total Scans", value: stats.total, color: "#636366" },
          { label: "Incidents", value: stats.incidents, color: "#ff6b35" },
          { label: "Safe", value: stats.safe, color: "#30d158" },
          { label: "Critical", value: stats.critical, color: "#ff2d55" },
        ].map((s) => (
          <div key={s.label} style={styles.statCard}>
            <div style={{ ...styles.statValue, color: s.color }}>{s.value}</div>
            <div style={styles.statLabel}>{s.label}</div>
          </div>
        ))}
        </div>
        {/* Tabs */}
      <div style={styles.tabs}>
        {[
          { id: "logs", label: " Log Analyzer" },
          { id: "url", label: " URL Scanner" },
          { id: "ip", label: " IP Scanner" },
          { id: "nuclei", label: " Nuclei Scanner" },
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            style={{
              ...styles.tab,
              ...(activeTab === t.id ? styles.tabActive : {}),
            }}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div style={styles.inputPanel}>
        {activeTab === "logs" && (
          <div style={styles.inputGroup}>
            <select
              value={logSource}
              onChange={(e) => setLogSource(e.target.value)}
              style={styles.select}
            >
              <option value="firewall">Firewall</option>
              <option value="webserver">Web Server</option>
              <option value="system">System</option>
              <option value="database">Database</option>
            </select>
            <input
              style={styles.input}
              placeholder="Paste a log line to analyze..."
              value={logInput}
              onChange={(e) => setLogInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && analyzeLog()}
            />
            <button
              onClick={analyzeLog}
              disabled={loading}
              style={styles.btnAnalyze}
            >
              {loading ? "..." : "Analyze"}
            </button>
          </div>
        )}

        {activeTab === "url" && (
          <div style={styles.inputGroup}>
            <input
              style={styles.input}
              placeholder="Enter URL to scan (e.g. https://example.com)"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && scanUrl()}
            />
            <button
              onClick={scanUrl}
              disabled={loading}
              style={styles.btnAnalyze}
            >
              {loading ? "..." : "Scan URL"}
            </button>
          </div>
        )}

        {activeTab === "ip" && (
          <div style={styles.inputGroup}>
            <input
              style={styles.input}
              placeholder="Enter IP address to scan (e.g. 192.168.1.1)"
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && scanIp()}
            />
            <button
              onClick={scanIp}
              disabled={loading}
              style={styles.btnAnalyze}
            >
              {loading ? "..." : "Scan IP"}
            </button>
          </div>
        )}
{activeTab === "nuclei" && (
          <div style={styles.inputGroup}>
            <input
              style={styles.input}
              placeholder="Enter target URL (e.g. http://192.168.56.1:8080)"
              value={nucleiInput}
              onChange={(e) => setNucleiInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && scanNuclei()}
            />
            <button
              onClick={scanNuclei}
              disabled={loading}
              style={styles.btnAnalyze}
            >
              {loading ? "Scanning..." : "Scan"}
            </button>
          </div>
        )}
        <div style={styles.quickTests}>
          <span style={styles.quickLabel}>Quick test:</span>
          {activeTab === "logs" && (
            <>
              <button style={styles.quickBtn} onClick={() => setLogInput("Failed login attempt from IP 192.168.1.105 - 5 attempts in 10 seconds")}>Brute Force</button>
              <button style={styles.quickBtn} onClick={() => setLogInput("GET /login?id=1 OR 1=1; DROP TABLE users;--")}>SQL Injection</button>
              <button style={styles.quickBtn} onClick={() => setLogInput("User admin logged in successfully from IP 192.168.1.1")}>Normal Login</button>
            </>
          )}
          {activeTab === "url" && (
            <>
              <button style={styles.quickBtn} onClick={() => setUrlInput("https://google.com")}>google.com</button>
              <button style={styles.quickBtn} onClick={() => setUrlInput("http://malware-test.com")}>malware-test.com</button>
            </>
          )}
          {activeTab === "ip" && (
            <>
              <button style={styles.quickBtn} onClick={() => setIpInput("118.25.6.39")}>118.25.6.39</button>
              <button style={styles.quickBtn} onClick={() => setIpInput("185.220.101.1")}>185.220.101.1</button>
            </>
          )}
          {activeTab === "nuclei" && (
  <>
    <button style={styles.quickBtn} onClick={() => setNucleiInput("http://ai-incident-analyst-dvwa-1:80")}>DVWA</button>
    <button style={styles.quickBtn} onClick={() => setNucleiInput("http://192.168.56.1:8080")}>Local DVWA</button>
  </>
)}
        </div>
      </div>
      <div style={styles.resultsSection}>
        <div style={styles.resultsHeader}>
          <span style={styles.resultsTitle}>Results</span>
          {results.length > 0 && (
            <button onClick={() => setResults([])} style={styles.clearBtn}>Clear all</button>
          )}
        </div>

        {results.length === 0 ? (
          <div style={styles.emptyState}>
            <div style={styles.emptyIcon}>🔎</div>
            <div style={styles.emptyText}>No scans yet — run your first analysis above.</div>
          </div>
        ) : (
          <div style={styles.resultsList}>
            {results.map((r) => (
              <div key={r.id} style={{ ...styles.resultCard, borderLeft: `3px solid ${severityColor[r.severity] || "#636366"}`, background: severityBg[r.severity] || "rgba(99,99,102,0.08)" }}>
                <div style={styles.resultTop}>
                  <div style={styles.resultLeft}>
                    <span style={styles.resultType}>{r.type}</span>
                    <span style={{ ...styles.resultStatus, color: r.is_malicious ? "#ff6b35" : "#30d158" }}>
                      {r.status}
                    </span>
                  </div>
                  <div style={{ ...styles.severityBadge, background: severityColor[r.severity] || "#636366" }}>
                    {r.severity?.toUpperCase()}
                  </div>
                </div>
                <div style={styles.resultTarget}>{r.target}</div>
                <div style={styles.resultExplanation}>{r.explanation}</div>
                <div style={styles.resultTime}>{new Date(r.timestamp).toLocaleString()}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
const styles = {
  root: { minHeight: "100vh", background: "#0a0a0f", color: "#e5e5ea", fontFamily: "'Inter', 'SF Pro Display', system-ui, sans-serif", padding: "0 0 40px" },
  header: { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "24px 32px", borderBottom: "1px solid #1c1c2e", background: "#0d0d1a" },
  headerLeft: { display: "flex", alignItems: "center", gap: 14 },
  shield: { fontSize: 32 },
  headerTitle: { fontSize: 20, fontWeight: 700, color: "#fff", letterSpacing: "-0.3px" },
  headerSub: { fontSize: 12, color: "#636366", marginTop: 2 },
  headerRight: { display: "flex", alignItems: "center", gap: 12 },
  liveChip: { display: "flex", alignItems: "center", gap: 6, background: "rgba(48,209,88,0.12)", border: "1px solid rgba(48,209,88,0.3)", borderRadius: 20, padding: "4px 12px", fontSize: 11, fontWeight: 700, color: "#30d158", letterSpacing: 1 },
  liveDot: { width: 6, height: 6, borderRadius: "50%", background: "#30d158", display: "inline-block" },
  statsRow: { display: "flex", gap: 16, padding: "24px 32px" },
  statCard: { flex: 1, background: "#13131f", border: "1px solid #1c1c2e", borderRadius: 12, padding: "18px 20px" },
  statValue: { fontSize: 32, fontWeight: 800, lineHeight: 1 },
  statLabel: { fontSize: 12, color: "#636366", marginTop: 6, fontWeight: 500 },
  tabs: { display: "flex", gap: 4, padding: "0 32px", marginBottom: 0 },
  tab: { padding: "10px 20px", border: "1px solid #1c1c2e", borderBottom: "none", borderRadius: "10px 10px 0 0", background: "#13131f", color: "#636366", cursor: "pointer", fontSize: 13, fontWeight: 600 },
  tabActive: { background: "#1c1c2e", color: "#fff", borderColor: "#2c2c3e" },
  inputPanel: { background: "#13131f", border: "1px solid #1c1c2e", borderRadius: "0 12px 12px 12px", margin: "0 32px", padding: "20px" },
  inputGroup: { display: "flex", gap: 10 },
  select: { background: "#0a0a0f", border: "1px solid #2c2c3e", borderRadius: 8, color: "#e5e5ea", padding: "10px 12px", fontSize: 13, outline: "none" },
  input: { flex: 1, background: "#0a0a0f", border: "1px solid #2c2c3e", borderRadius: 8, color: "#e5e5ea", padding: "10px 14px", fontSize: 13, outline: "none" },
  btnAnalyze: { background: "linear-gradient(135deg, #5e5ce6, #bf5af2)", border: "none", borderRadius: 8, color: "#fff", padding: "10px 24px", fontSize: 13, fontWeight: 700, cursor: "pointer" },
  quickTests: { display: "flex", alignItems: "center", gap: 8, marginTop: 12 },
  quickLabel: { fontSize: 11, color: "#636366", fontWeight: 600 },
  quickBtn: { background: "#1c1c2e", border: "1px solid #2c2c3e", borderRadius: 6, color: "#a0a0b0", padding: "4px 10px", fontSize: 11, cursor: "pointer" },
  resultsSection: { margin: "24px 32px 0" },
  resultsHeader: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 },
  resultsTitle: { fontSize: 14, fontWeight: 700, color: "#a0a0b0", letterSpacing: 0.5 },
  clearBtn: { background: "none", border: "1px solid #2c2c3e", borderRadius: 6, color: "#636366", padding: "4px 12px", fontSize: 11, cursor: "pointer" },
  emptyState: { textAlign: "center", padding: "60px 0", color: "#636366" },
  emptyIcon: { fontSize: 40, marginBottom: 12 },
  emptyText: { fontSize: 14 },
  resultsList: { display: "flex", flexDirection: "column", gap: 10 },
  resultCard: { borderRadius: 10, padding: "14px 16px", border: "1px solid #1c1c2e" },
  resultTop: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 },
  resultLeft: { display: "flex", alignItems: "center", gap: 10 },
  resultType: { fontSize: 10, fontWeight: 800, color: "#636366", background: "#1c1c2e", padding: "2px 8px", borderRadius: 4, letterSpacing: 1 },
  resultStatus: { fontSize: 13, fontWeight: 700 },
  severityBadge: { fontSize: 10, fontWeight: 800, color: "#fff", padding: "2px 10px", borderRadius: 20, letterSpacing: 0.5 },
  resultTarget: { fontSize: 13, color: "#a0a0b0", marginBottom: 4, fontFamily: "monospace" },
  resultExplanation: { fontSize: 12, color: "#636366", lineHeight: 1.5 },
  resultTime: { fontSize: 11, color: "#48484a", marginTop: 8 },
};