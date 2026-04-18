import React, { useMemo, useState } from "react";
import "./SoarDashboard.css";

function nowTime() {
  return new Date().toLocaleTimeString();
}

function nowStamp() {
  return new Date().toLocaleString();
}

function randomIp() {
  const p = () => Math.floor(Math.random() * 254) + 1;
  return `${p()}.${p()}.${p()}.${p()}`;
}

function randomUrl() {
  const domains = ["secure-update-login.com", "bank-alert-verify.net", "mail-check-auth.org"];
  return `https://${domains[Math.floor(Math.random() * domains.length)]}`;
}

// Mock decision logic to simulate SOAR behavior in UI.
function enrichAndDecide(type, value, frequencyMap) {
  const currentCount = (frequencyMap[value] || 0) + 1;

  let threatScore = 0;
  let reasons = [];

  if (type === "ip") {
    threatScore = Math.floor(Math.random() * 91) + 10; // 10-100
    reasons.push(
      threatScore >= 75 ? "High threat score from intelligence feed." : "Threat score from intelligence feed is not high."
    );
  } else {
    const isMalicious = Math.random() < 0.33;
    threatScore = isMalicious
      ? Math.floor(Math.random() * 31) + 70 // 70-100
      : Math.floor(Math.random() * 36) + 5; // 5-40
    reasons.push(isMalicious ? "URL is flagged as suspicious." : "URL reputation is not critical.");
  }

  const frequencyBoost = Math.min(currentCount * 8, 30);
  const riskScore = Math.min(threatScore + frequencyBoost, 100);

  reasons.push(
    currentCount >= 3
      ? "Multiple attempts detected."
      : currentCount === 2
      ? "Repeated attempt detected."
      : "First attempt observed."
  );

  let action = "ignore";
  let risk = "LOW";
  let status = "Closed";
  if (riskScore > 80) {
    action = "block";
    risk = "HIGH";
    status = "Escalated";
    reasons.push("Risk is high, so entity is blocked.");
  } else if (riskScore >= 50) {
    action = "monitor";
    risk = "MEDIUM";
    status = "Under Review";
    reasons.push("Risk is medium, so monitoring is enabled.");
  } else {
    reasons.push("Risk is low, so alert is ignored.");
  }

  return {
    currentCount,
    score: riskScore,
    risk,
    action,
    status,
    reason: reasons.slice(0, 3),
  };
}

export default function SoarDashboard({ adminUser, onLogout }) {
  const [activeSection, setActiveSection] = useState("dashboard");
  const [alertType, setAlertType] = useState("ip");
  const [alertValue, setAlertValue] = useState("");
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [riskFilter, setRiskFilter] = useState("ALL");
  const [alerts, setAlerts] = useState([]);
  const [blockedIps, setBlockedIps] = useState([]);
  const [flaggedUrls, setFlaggedUrls] = useState([]);
  const [logs, setLogs] = useState([]);
  const [frequencyMap, setFrequencyMap] = useState({});

  const selectedAlert = useMemo(
    () => alerts.find((item) => item.id === selectedAlertId) || null,
    [alerts, selectedAlertId]
  );

  const filteredAlerts = useMemo(() => {
    if (riskFilter === "ALL") return alerts;
    return alerts.filter((item) => item.risk === riskFilter);
  }, [alerts, riskFilter]);

  const highRiskCount = useMemo(
    () => alerts.filter((item) => item.risk === "HIGH").length,
    [alerts]
  );

  const mediumRiskCount = useMemo(
    () => alerts.filter((item) => item.risk === "MEDIUM").length,
    [alerts]
  );

  const lowRiskCount = useMemo(
    () => alerts.filter((item) => item.risk === "LOW").length,
    [alerts]
  );

  const addLog = (message) => {
    setLogs((prev) => [{ id: crypto.randomUUID(), time: nowTime(), message }, ...prev].slice(0, 30));
  };

  const createAlert = (type, value) => {
    const decision = enrichAndDecide(type, value, frequencyMap);
    setFrequencyMap((prev) => ({ ...prev, [value]: decision.currentCount }));

    const alert = {
      id: crypto.randomUUID(),
      type,
      value,
      timestamp: nowStamp(),
      status: decision.status,
      risk: decision.risk,
      action: decision.action,
      reason: decision.reason,
      score: decision.score,
    };

    setAlerts((prev) => [alert, ...prev]);
    setSelectedAlertId(alert.id);

    if (decision.action === "block" && type === "ip") {
      setBlockedIps((prev) => (prev.some((item) => item.value === value) ? prev : [{ value, timestamp: nowStamp(), reason: alert.reason[0] }, ...prev]));
      addLog(`Blocked IP ${value}`);
    } else if (type === "url" && decision.risk !== "LOW") {
      setFlaggedUrls((prev) =>
        prev.some((item) => item.value === value) ? prev : [{ value, timestamp: nowStamp(), reason: alert.reason[0] }, ...prev]
      );
      addLog(`Flagged URL ${value}`);
    } else {
      addLog(`Processed ${type.toUpperCase()} ${value} with action ${decision.action}`);
    }
  };

  const handleTriggerAlert = () => {
    const value = alertValue.trim();
    if (!value) return;
    createAlert(alertType, value);
    setAlertValue("");
    setActiveSection("alerts");
  };

  const simulateIpAttack = () => createAlert("ip", randomIp());
  const simulatePhishing = () => createAlert("url", randomUrl());

  const riskClass = (risk) => {
    if (risk === "HIGH") return "risk-high";
    if (risk === "MEDIUM") return "risk-medium";
    return "risk-low";
  };

  const renderDashboard = () => (
    <div className="panel-grid">
      <div className="card metric-card">
        <p className="muted">Total Alerts</p>
        <h3>{alerts.length}</h3>
      </div>
      <div className="card metric-card">
        <p className="muted">High Risk Alerts</p>
        <h3>{highRiskCount}</h3>
      </div>
      <div className="card metric-card">
        <p className="muted">Blocked IPs</p>
        <h3>{blockedIps.length}</h3>
      </div>
      <div className="card metric-card">
        <p className="muted">Recent Actions</p>
        <h3>{logs.length}</h3>
      </div>

      <div className="card">
        <h3>Simulation</h3>
        <div className="btn-row">
          <button onClick={simulateIpAttack}>Simulate IP Attack</button>
          <button className="secondary-btn" onClick={simulatePhishing}>
            Simulate Phishing Email
          </button>
        </div>
      </div>

      <div className="card">
        <h3>Risk Distribution</h3>
        <div className="chart-row">
          <span>High</span>
          <div className="chart-bar"><div style={{ width: `${Math.min(highRiskCount * 20, 100)}%` }} /></div>
          <strong>{highRiskCount}</strong>
        </div>
        <div className="chart-row">
          <span>Medium</span>
          <div className="chart-bar"><div style={{ width: `${Math.min(mediumRiskCount * 20, 100)}%` }} /></div>
          <strong>{mediumRiskCount}</strong>
        </div>
        <div className="chart-row">
          <span>Low</span>
          <div className="chart-bar"><div style={{ width: `${Math.min(lowRiskCount * 20, 100)}%` }} /></div>
          <strong>{lowRiskCount}</strong>
        </div>
      </div>

      <div className="card">
        <h3>Recent Actions</h3>
        {logs.length === 0 ? (
          <p className="muted">No activity yet.</p>
        ) : (
          <ul>
            {logs.slice(0, 5).map((entry) => (
              <li key={entry.id}>[{entry.time}] {entry.message}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );

  const renderAlerts = () => (
    <div className="card">
      <h3>Alerts</h3>
      <div className="toolbar">
        <select value={riskFilter} onChange={(e) => setRiskFilter(e.target.value)}>
          <option value="ALL">All Risks</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
      </div>
      {filteredAlerts.length === 0 ? (
        <p className="muted">No alerts available for this filter.</p>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Type</th>
              <th>Value</th>
              <th>Timestamp</th>
              <th>Status</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {filteredAlerts.map((item) => (
              <tr key={item.id} onClick={() => { setSelectedAlertId(item.id); setActiveSection("analysis"); }}>
                <td>{item.type.toUpperCase()}</td>
                <td>{item.value}</td>
                <td>{item.timestamp}</td>
                <td>{item.status}</td>
                <td><span className={`risk-pill ${riskClass(item.risk)}`}>{item.risk}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );

  const renderAnalysis = () => (
    <div className="card">
      <h3>Incident Details / Analysis</h3>
      {!selectedAlert ? (
        <p className="muted">Select an alert from Alerts to see details.</p>
      ) : (
        <>
          <p><strong>Indicator:</strong> {selectedAlert.type.toUpperCase()} - {selectedAlert.value}</p>
          <p><strong>Risk:</strong> <span className={`risk-pill ${riskClass(selectedAlert.risk)}`}>{selectedAlert.risk}</span></p>
          <p><strong>Action:</strong> {selectedAlert.action}</p>
          <p><strong>Score:</strong> {selectedAlert.score}</p>
          <div>
            <strong>Reason:</strong>
            <ul>
              {selectedAlert.reason.map((item, idx) => (
                <li key={`${item}-${idx}`}>{item}</li>
              ))}
            </ul>
          </div>
        </>
      )}
    </div>
  );

  const renderBlocked = () => (
    <div className="panel-grid">
      <div className="card">
        <h3>Blocked IPs</h3>
        {blockedIps.length === 0 ? <p className="muted">No blocked IPs yet.</p> : (
          <ul>
            {blockedIps.map((item) => (
              <li key={item.value}>{item.value} - {item.timestamp} ({item.reason})</li>
            ))}
          </ul>
        )}
      </div>
      <div className="card">
        <h3>Flagged URLs</h3>
        {flaggedUrls.length === 0 ? <p className="muted">No flagged URLs yet.</p> : (
          <ul>
            {flaggedUrls.map((item) => (
              <li key={item.value}>{item.value} - {item.timestamp} ({item.reason})</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );

  const renderLogs = () => (
    <div className="card">
      <h3>Activity Logs</h3>
      {logs.length === 0 ? (
        <p className="muted">No actions logged yet.</p>
      ) : (
        <ul>
          {logs.map((entry) => (
            <li key={entry.id}>[{entry.time}] {entry.message}</li>
          ))}
        </ul>
      )}
    </div>
  );

  const renderPlaybook = () => (
    <div className="panel-grid">
      <div className="card">
        <h3>Playbook: Decision Rules</h3>
        <ul className="rule-list">
          <li>
            <strong>Rule 1:</strong> If risk score is above <strong>80</strong>, action is <strong>Block</strong>.
          </li>
          <li>
            <strong>Rule 2:</strong> If risk score is between <strong>50 and 80</strong>, action is <strong>Monitor</strong>.
          </li>
          <li>
            <strong>Rule 3:</strong> If risk score is below <strong>50</strong>, action is <strong>Ignore</strong>.
          </li>
        </ul>
      </div>
      <div className="card">
        <h3>How Risk is Calculated</h3>
        <ul className="rule-list">
          <li>Threat score comes from IP/URL enrichment.</li>
          <li>Repeated activity adds a frequency boost.</li>
          <li>Final score = threat score + frequency impact (capped).</li>
          <li>Explanations are generated with simple human-readable reasons.</li>
        </ul>
      </div>
      <div className="card">
        <h3>Response Workflow</h3>
        <p className="muted">
          Ingest Alert → Enrichment → Decision Engine → Action Engine → Activity Log
        </p>
        <div className="workflow-row">
          <span>Ingest</span>
          <span>Enrich</span>
          <span>Decide</span>
          <span>Respond</span>
        </div>
      </div>
    </div>
  );

  const renderContent = () => {
    if (activeSection === "dashboard") return renderDashboard();
    if (activeSection === "alerts") return renderAlerts();
    if (activeSection === "analysis") return renderAnalysis();
    if (activeSection === "blocked") return renderBlocked();
    if (activeSection === "playbook") return renderPlaybook();
    return renderLogs();
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <h2>SOAR</h2>
        <p className="sidebar-subtitle">Security Orchestration Console</p>
        <button className={activeSection === "dashboard" ? "nav-btn active" : "nav-btn"} onClick={() => setActiveSection("dashboard")}>Dashboard</button>
        <button className={activeSection === "alerts" ? "nav-btn active" : "nav-btn"} onClick={() => setActiveSection("alerts")}>Alerts</button>
        <button className={activeSection === "analysis" ? "nav-btn active" : "nav-btn"} onClick={() => setActiveSection("analysis")}>Analysis</button>
        <button className={activeSection === "blocked" ? "nav-btn active" : "nav-btn"} onClick={() => setActiveSection("blocked")}>Blocked</button>
        <button className={activeSection === "playbook" ? "nav-btn active" : "nav-btn"} onClick={() => setActiveSection("playbook")}>Playbook</button>
        <button className={activeSection === "logs" ? "nav-btn active" : "nav-btn"} onClick={() => setActiveSection("logs")}>Logs</button>
      </aside>

      <main className="main-content">
        <div className="topbar">
          <div>
            <strong>System Status:</strong> <span className="status-pill">Active</span>
          </div>
          <div className="dashboard-meta">
            <span className="muted">Admin: {adminUser?.username}</span>
            <button className="secondary-btn" onClick={onLogout}>
              Logout
            </button>
          </div>
        </div>

        <div className="card">
          <h3>Quick Alert Simulation</h3>
          <div className="form-grid">
            <div className="form-row">
              <label htmlFor="alertType">Type</label>
              <select
                id="alertType"
                value={alertType}
                onChange={(e) => setAlertType(e.target.value)}
              >
                <option value="ip">IP</option>
                <option value="url">URL</option>
              </select>
            </div>

            <div className="form-row">
              <label htmlFor="alertValue">Value</label>
              <input
                id="alertValue"
                type="text"
                placeholder={alertType === "ip" ? "e.g. 1.2.3.4" : "e.g. https://bad.site"}
                value={alertValue}
                onChange={(e) => setAlertValue(e.target.value)}
              />
            </div>
          </div>
          <button onClick={handleTriggerAlert}>Trigger Alert</button>
        </div>

        {renderContent()}
      </main>
    </div>
  );
}
