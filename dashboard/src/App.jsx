import { useMemo, useRef, useState } from "react";

export default function AISecurityDashboard() {
  const [authFile, setAuthFile] = useState(null);
  const [cloudFile, setCloudFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const authInputRef = useRef(null);
  const cloudInputRef = useRef(null);
  const resultsRef = useRef(null);
  
  const API_BASE_URL = "http://127.0.0.1:8000";

  const handleAnalyze = async () => {
  if (!authFile || !cloudFile) {
    setError("請先選擇 auth_file 和 cloud_file");
    return;
  }

  setLoading(true);
  setError("");

  try {
    const formData = new FormData();
    formData.append("auth_file", authFile);
    formData.append("cloud_file", cloudFile);

    const response = await fetch(`${API_BASE_URL}/analyze/unified`, {
      method: "POST",
      body: formData,
    });

    if (!response.ok) {
      throw new Error("分析失敗");
    }

    const data = await response.json();
    setResult(data);

    setTimeout(() => {
      resultsRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }, 100);
  } catch (err) {
    setError(err.message || "發生錯誤");
  } finally {
    setLoading(false);
  }
};

  const handleDownloadReport = () => {
    if (!result) return;

    const blob = new Blob([JSON.stringify(result, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "unified_report.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadHtmlReport = () => {
    if (!result) return;

    const incidentsHtml = (result.incidents || [])
      .map((item) => {
        const evidenceHtml = (item.evidence || [])
          .map(
            (ev) =>
              `<li style="margin:6px 0;padding:8px 10px;background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;">${escapeHtml(
                ev
              )}</li>`
          )
          .join("");

        return `
          <div style="border:1px solid #e2e8f0;border-radius:16px;padding:18px;margin-bottom:16px;background:#ffffff;">
            <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;">
              <div>
                <h3 style="margin:0;font-size:22px;">${escapeHtml(
                  item.type || "Unknown Incident"
                )}</h3>
                <p style="margin:8px 0 0 0;color:#64748b;">Source: ${escapeHtml(
                  item.source || "-"
                )}</p>
              </div>
              <span style="padding:6px 10px;border-radius:999px;font-size:12px;font-weight:700;${badgeInlineStyle(
                item.severity || item.risk || "Unknown"
              )}">
                ${escapeHtml(item.severity || item.risk || "Unknown")}
              </span>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-top:16px;">
              <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:12px;">
                <div style="font-size:12px;color:#64748b;">IP</div>
                <div style="font-weight:700;margin-top:6px;">${escapeHtml(
                  item.ip || "-"
                )}</div>
              </div>
              <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:12px;">
                <div style="font-size:12px;color:#64748b;">Count</div>
                <div style="font-weight:700;margin-top:6px;">${escapeHtml(
                  String(item.count ?? "-")
                )}</div>
              </div>
              <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:12px;">
                <div style="font-size:12px;color:#64748b;">Risk Score</div>
                <div style="font-weight:700;margin-top:6px;">${escapeHtml(
                  String(item.risk_score ?? "-")
                )}</div>
              </div>
            </div>

            <div style="margin-top:12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:12px;">
              <div style="font-size:12px;color:#64748b;">Window</div>
              <div style="margin-top:6px;font-weight:600;">${escapeHtml(
                item.window || "-"
              )}</div>
            </div>

            ${
              evidenceHtml
                ? `
              <div style="margin-top:14px;">
                <div style="font-weight:700;color:#9a3412;margin-bottom:8px;">Evidence</div>
                <ul style="padding-left:18px;margin:0;">${evidenceHtml}</ul>
              </div>
            `
                : ""
            }
          </div>
        `;
      })
      .join("");

    const timelineRows = (result.incidents || [])
      .map(
        (item) => `
        <tr>
          <td style="padding:12px;border-top:1px solid #e2e8f0;">${escapeHtml(
            item.start_time || "-"
          )}</td>
          <td style="padding:12px;border-top:1px solid #e2e8f0;font-weight:700;">${escapeHtml(
            item.type || "-"
          )}</td>
          <td style="padding:12px;border-top:1px solid #e2e8f0;">${escapeHtml(
            item.ip || "-"
          )}</td>
          <td style="padding:12px;border-top:1px solid #e2e8f0;">
            <span style="padding:6px 10px;border-radius:999px;font-size:12px;font-weight:700;${badgeInlineStyle(
              item.severity || item.risk || "Unknown"
            )}">
              ${escapeHtml(item.severity || item.risk || "Unknown")}
            </span>
          </td>
        </tr>
      `
      )
      .join("");

    const highestRiskScore =
      result.incidents?.length > 0
        ? Math.max(...result.incidents.map((i) => i.risk_score || 0))
        : 0;

    const criticalCount = (result.incidents || []).filter(
      (i) => String(i.severity || i.risk || "").toUpperCase() === "CRITICAL"
    ).length;

    const topIp =
      Array.isArray(result?.top_ips) && result.top_ips.length > 0
        ? result.top_ips[0][0]
        : result.incidents?.[0]?.ip || "-";

    const topIpCount =
      Array.isArray(result?.top_ips) && result.top_ips.length > 0
        ? result.top_ips[0][1]
        : (result.incidents || []).filter((i) => i.ip && i.ip === topIp).length;

    const html = `
<!DOCTYPE html>
<html lang="zh-Hant">
<head>
  <meta charset="UTF-8" />
  <title>Unified Threat Report</title>
  <style>
    body {
      margin: 0;
      font-family: Inter, Arial, sans-serif;
      background: #f8fafc;
      color: #0f172a;
    }
    .hero {
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: white;
      padding: 36px 24px;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
    }
    .pill {
      display: inline-block;
      padding: 6px 12px;
      border-radius: 999px;
      background: rgba(255,255,255,0.12);
      font-size: 13px;
      margin-bottom: 14px;
    }
    .title {
      font-size: 48px;
      font-weight: 800;
      margin: 0;
      letter-spacing: -1px;
    }
    .subtitle {
      color: #cbd5e1;
      font-size: 18px;
      margin-top: 14px;
      max-width: 760px;
    }
    .content {
      max-width: 1200px;
      margin: 0 auto;
      padding: 24px;
    }
    .grid {
      display: grid;
      gap: 24px;
    }
    .grid-2 {
      grid-template-columns: 2fr 1fr;
    }
    .grid-3 {
      grid-template-columns: 1fr 1fr 1fr;
    }
    .panel {
      background: white;
      border: 1px solid #e2e8f0;
      border-radius: 20px;
      box-shadow: 0 8px 24px rgba(15, 23, 42, 0.04);
      padding: 24px;
    }
    .summary-box {
      padding: 18px;
      border-radius: 18px;
      background: #0f172a;
      color: white;
    }
    .summary-box .big {
      font-size: 42px;
      font-weight: 800;
      margin-top: 6px;
    }
    .mini-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-top: 12px;
    }
    .mini-card {
      padding: 16px;
      border-radius: 16px;
    }
    .mini-card .label {
      font-size: 13px;
      color: #64748b;
    }
    .mini-card .value {
      font-size: 30px;
      font-weight: 800;
      margin-top: 6px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      background: white;
    }
    thead {
      background: #f8fafc;
    }
    th {
      text-align: left;
      padding: 14px;
      font-size: 13px;
      color: #64748b;
    }
    .section-title {
      font-size: 32px;
      margin: 0 0 14px 0;
    }
    @media print {
      body {
        background: white;
      }
      .panel {
        box-shadow: none;
      }
    }
  </style>
</head>
<body>
  <div class="hero">
    <div class="container">
      <div class="pill">AI Security SaaS</div>
      <h1 class="title">Unified Threat Report</h1>
      <p class="subtitle">
        Generated from auth logs and cloud trail data correlation.
      </p>
    </div>
  </div>

  <div class="content">
    <div class="grid grid-2">
      <div class="panel">
        <h2 class="section-title">Executive Summary</h2>
        <div class="summary-box">
          <div style="opacity:.8;font-size:14px;">Highest Risk Score</div>
          <div class="big">${highestRiskScore}</div>
        </div>

        <div class="mini-grid">
          <div class="mini-card" style="background:#fff1f2;border:1px solid #ffe4e6;">
            <div class="label">Critical Incidents</div>
            <div class="value" style="color:#be123c;">${criticalCount}</div>
          </div>
          <div class="mini-card" style="background:#eff6ff;border:1px solid #dbeafe;">
            <div class="label">Top IP</div>
            <div class="value" style="font-size:22px;color:#1d4ed8;">${escapeHtml(
              topIp
            )}</div>
          </div>
        </div>
      </div>

      <div class="panel">
        <h2 class="section-title">Overview</h2>
        <div class="grid grid-3" style="grid-template-columns:1fr;gap:12px;">
          <div style="padding:16px;border-radius:16px;border:1px solid #e2e8f0;background:#f8fafc;">
            <div style="font-size:14px;color:#64748b;">Incidents</div>
            <div style="font-size:36px;font-weight:800;margin-top:8px;">${escapeHtml(
              String(result.incidents?.length || 0)
            )}</div>
          </div>
          <div style="padding:16px;border-radius:16px;border:1px solid #e2e8f0;background:#f8fafc;">
            <div style="font-size:14px;color:#64748b;">Top IP Count</div>
            <div style="font-size:36px;font-weight:800;margin-top:8px;">${escapeHtml(
              String(topIpCount)
            )}</div>
          </div>
          <div style="padding:16px;border-radius:16px;border:1px solid #e2e8f0;background:#f8fafc;">
            <div style="font-size:14px;color:#64748b;">Status</div>
            <div style="font-size:30px;font-weight:800;margin-top:8px;color:#15803d;">Analyzed</div>
          </div>
        </div>
      </div>
    </div>

    <div class="grid" style="grid-template-columns:1.1fr 1fr;margin-top:24px;">
      <div class="panel">
        <h2 class="section-title">Incidents</h2>
        ${incidentsHtml || `<div style="color:#64748b;">尚未有分析結果</div>`}
      </div>

      <div class="panel">
        <h2 class="section-title">Timeline</h2>
        ${
          timelineRows
            ? `
          <div style="overflow:hidden;border-radius:18px;border:1px solid #e2e8f0;">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Event</th>
                  <th>IP</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                ${timelineRows}
              </tbody>
            </table>
          </div>
        `
            : `<div style="color:#64748b;">尚未有 timeline 資料</div>`
        }
      </div>
    </div>
  </div>
</body>
</html>
    `;

    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "unified_report.html";
    a.click();
    URL.revokeObjectURL(url);
  };

const handleReset = () => {
  setAuthFile(null);
  setCloudFile(null);
  setResult(null);
  setError("");
  setLoading(false);

  if (authInputRef.current) {
    authInputRef.current.value = "";
  }
  if (cloudInputRef.current) {
    cloudInputRef.current.value = "";
  }
};

  const incidents = result?.incidents || [];

  const highestRiskScore = incidents.length
    ? Math.max(...incidents.map((i) => i.risk_score || 0))
    : 0;

  const criticalCount = incidents.filter(
    (i) => (i.severity || i.risk || "").toUpperCase() === "CRITICAL"
  ).length;

  const topIp =
    Array.isArray(result?.top_ips) && result.top_ips.length > 0
      ? result.top_ips[0][0]
      : incidents[0]?.ip || "-";

  const topIpCount =
    Array.isArray(result?.top_ips) && result.top_ips.length > 0
      ? result.top_ips[0][1]
      : incidents.filter((i) => i.ip && i.ip === topIp).length;

  const timeline = useMemo(() => {
    return incidents.map((item, idx) => ({
      id: idx,
      time: item.start_time || "-",
      event: item.type || "-",
      severity: item.severity || item.risk || "-",
      ip: item.ip || "-",
    }));
  }, [incidents]);

  const getBadgeStyle = (level) => {
    const value = String(level || "").toUpperCase();

    if (value === "CRITICAL") {
      return {
        background: "#fee2e2",
        color: "#b91c1c",
        border: "1px solid #fecaca",
      };
    }
    if (value === "HIGH") {
      return {
        background: "#fff7ed",
        color: "#c2410c",
        border: "1px solid #fed7aa",
      };
    }
    if (value === "MEDIUM") {
      return {
        background: "#fef9c3",
        color: "#a16207",
        border: "1px solid #fde68a",
      };
    }
    if (value === "LOW") {
      return {
        background: "#dcfce7",
        color: "#166534",
        border: "1px solid #bbf7d0",
      };
    }

    return {
      background: "#e2e8f0",
      color: "#334155",
      border: "1px solid #cbd5e1",
    };
  };

  const cardStyle = {
    background: "white",
    border: "1px solid #e2e8f0",
    borderRadius: "20px",
    boxShadow: "0 8px 24px rgba(15, 23, 42, 0.04)",
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#f8fafc",
        color: "#0f172a",
        fontFamily:
          'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
      }}
    >
      <div
        style={{
          background: "linear-gradient(135deg, #0f172a 0%, #1e293b 100%)",
          color: "white",
          padding: "36px 24px",
        }}
      >
        <div style={{ maxWidth: "1200px", margin: "0 auto" }}>
          <div
            style={{
              display: "inline-block",
              padding: "6px 12px",
              borderRadius: "999px",
              background: "rgba(255,255,255,0.12)",
              fontSize: "13px",
              marginBottom: "14px",
            }}
          >
            AI Security SaaS
          </div>

          <h1
            style={{
              margin: 0,
              fontSize: "52px",
              lineHeight: 1.05,
              fontWeight: 800,
              letterSpacing: "-1px",
            }}
          >
            Unified Threat Analysis Dashboard
          </h1>

          <p
            style={{
              marginTop: "14px",
              marginBottom: 0,
              color: "#cbd5e1",
              fontSize: "18px",
              maxWidth: "760px",
            }}
          >
            Upload auth logs and cloud trail data, correlate suspicious behavior,
            and review high-risk incidents in one security dashboard.
          </p>
        </div>
      </div>

      <div style={{ maxWidth: "1200px", margin: "0 auto", padding: "24px" }}>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "2fr 1fr",
            gap: "24px",
            marginTop: "-28px",
          }}
        >
          <div style={{ ...cardStyle, padding: "24px" }}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "start",
                gap: "16px",
              }}
            >
              <div>
                <h2 style={{ margin: 0, fontSize: "32px" }}>Upload Files</h2>
                <p style={{ color: "#475569", marginTop: "10px" }}>
                  需要同時上傳 auth_file 與 cloud_file
                </p>
              </div>

              <div
                style={{
                  padding: "8px 12px",
                  borderRadius: "999px",
                  background: "#eef2ff",
                  color: "#4338ca",
                  fontSize: "13px",
                  fontWeight: 600,
                }}
              >
                Unified Analysis
              </div>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "16px",
                marginTop: "20px",
              }}
            >
              <div
                style={{
                  border: "1px dashed #cbd5e1",
                  borderRadius: "16px",
                  padding: "18px",
                  background: "#f8fafc",
                }}
              >
                <label
                  style={{
                    display: "block",
                    fontWeight: 700,
                    marginBottom: "10px",
                  }}
                >
                  auth_file
                </label>
                <input
  ref={authInputRef}
  type="file"
  onChange={(e) => setAuthFile(e.target.files?.[0] || null)}
  style={{ display: "block", width: "100%" }}
/>
                <p
                  style={{
                    marginTop: "10px",
                    color: "#475569",
                    minHeight: "24px",
                  }}
                >
                  {authFile ? authFile.name : "尚未選擇檔案"}
                </p>
              </div>

              <div
                style={{
                  border: "1px dashed #cbd5e1",
                  borderRadius: "16px",
                  padding: "18px",
                  background: "#f8fafc",
                }}
              >
                <label
                  style={{
                    display: "block",
                    fontWeight: 700,
                    marginBottom: "10px",
                  }}
                >
                  cloud_file
                </label>
                <input
  ref={cloudInputRef}
  type="file"
  onChange={(e) => setCloudFile(e.target.files?.[0] || null)}
  style={{ display: "block", width: "100%" }}
/>
                <p
                  style={{
                    marginTop: "10px",
                    color: "#475569",
                    minHeight: "24px",
                  }}
                >
                  {cloudFile ? cloudFile.name : "尚未選擇檔案"}
                </p>
              </div>
            </div>

            <div
              style={{
                marginTop: "18px",
                display: "flex",
                alignItems: "center",
                gap: "14px",
                flexWrap: "wrap",
              }}
            >
              <button
                onClick={handleAnalyze}
                disabled={loading}
                style={{
                  padding: "14px 22px",
                  background: loading ? "#334155" : "#0f172a",
                  color: "white",
                  border: "none",
                  borderRadius: "14px",
                  cursor: "pointer",
                  fontWeight: 700,
                  fontSize: "15px",
                  boxShadow: "0 8px 20px rgba(15,23,42,0.15)",
                }}
              >
                {loading ? "Analyzing..." : "Run Unified Analysis"}
              </button>

              <button
                onClick={handleDownloadReport}
                disabled={!result}
                style={{
                  padding: "14px 22px",
                  background: result ? "#ffffff" : "#e2e8f0",
                  color: result ? "#0f172a" : "#64748b",
                  border: "1px solid #cbd5e1",
                  borderRadius: "14px",
                  cursor: result ? "pointer" : "not-allowed",
                  fontWeight: 700,
                  fontSize: "15px",
                }}
              >
                Download JSON Report
              </button>

              <button
                onClick={handleDownloadHtmlReport}
                disabled={!result}
                style={{
                  padding: "14px 22px",
                  background: result ? "#0f172a" : "#e2e8f0",
                  color: result ? "#ffffff" : "#64748b",
                  border: "1px solid #cbd5e1",
                  borderRadius: "14px",
                  cursor: result ? "pointer" : "not-allowed",
                  fontWeight: 700,
                  fontSize: "15px",
                }}
              >
                Download HTML Report
                <button
  onClick={handleReset}
  style={{
    padding: "14px 22px",
    background: "#ffffff",
    color: "#0f172a",
    border: "1px solid #cbd5e1",
    borderRadius: "14px",
    cursor: "pointer",
    fontWeight: 700,
    fontSize: "15px",
  }}
>
  Reset
</button>
              </button>

              <span style={{ color: "#64748b", fontSize: "14px" }}>
                {result ? "最近一次分析已完成" : "等待上傳與分析"}
              </span>
            </div>

            {error && (
              <div
                style={{
                  marginTop: "16px",
                  padding: "12px 14px",
                  borderRadius: "12px",
                  background: "#fee2e2",
                  color: "#b91c1c",
                  border: "1px solid #fecaca",
                }}
              >
                {error}
              </div>
            )}
          </div>

          <div style={{ ...cardStyle, padding: "24px" }}>
            <h2 style={{ margin: 0, fontSize: "32px" }}>Executive Summary</h2>

            <div style={{ marginTop: "20px", display: "grid", gap: "14px" }}>
              <div
                style={{
                  padding: "18px",
                  borderRadius: "18px",
                  background: "#0f172a",
                  color: "white",
                }}
              >
                <div style={{ opacity: 0.8, fontSize: "14px" }}>
                  Highest Risk Score
                </div>
                <div
                  style={{
                    fontSize: "42px",
                    fontWeight: 800,
                    marginTop: "6px",
                  }}
                >
                  {highestRiskScore}
                </div>
              </div>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  gap: "12px",
                }}
              >
                <div
                  style={{
                    padding: "16px",
                    borderRadius: "16px",
                    background: "#fff1f2",
                    border: "1px solid #ffe4e6",
                  }}
                >
                  <div style={{ color: "#64748b", fontSize: "13px" }}>
                    Critical Incidents
                  </div>
                  <div
                    style={{
                      fontSize: "30px",
                      fontWeight: 800,
                      color: "#be123c",
                      marginTop: "6px",
                    }}
                  >
                    {criticalCount}
                  </div>
                </div>

                <div
                  style={{
                    padding: "16px",
                    borderRadius: "16px",
                    background: "#eff6ff",
                    border: "1px solid #dbeafe",
                  }}
                >
                  <div style={{ color: "#64748b", fontSize: "13px" }}>Top IP</div>
                  <div
                    style={{
                      fontSize: "22px",
                      fontWeight: 800,
                      color: "#1d4ed8",
                      marginTop: "8px",
                      wordBreak: "break-all",
                    }}
                  >
                    {topIp}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div ref={resultsRef}>
  <div
    style={{
      display: "grid",
      gridTemplateColumns: "1fr 1fr 1fr",
      gap: "16px",
      marginTop: "22px",
    }}
  >
    </div>

          <div style={{ ...cardStyle, padding: "20px" }}>
            <div style={{ color: "#64748b", fontSize: "14px" }}>Incidents</div>
            <div style={{ fontSize: "40px", fontWeight: 800, marginTop: "10px" }}>
              {incidents.length}
            </div>
          </div>

          <div style={{ ...cardStyle, padding: "20px" }}>
            <div style={{ color: "#64748b", fontSize: "14px" }}>Top IP Count</div>
            <div style={{ fontSize: "40px", fontWeight: 800, marginTop: "10px" }}>
              {topIpCount}
            </div>
          </div>

          <div style={{ ...cardStyle, padding: "20px" }}>
            <div style={{ color: "#64748b", fontSize: "14px" }}>Status</div>
            <div
              style={{
                fontSize: "30px",
                fontWeight: 800,
                marginTop: "10px",
                color: result ? "#15803d" : "#475569",
              }}
            >
              {result ? "Analyzed" : "Waiting"}
            </div>
          </div>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1.1fr 1fr",
            gap: "24px",
            marginTop: "24px",
            alignItems: "start",
          }}
        >
          <div style={{ ...cardStyle, padding: "24px" }}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "12px",
              }}
            >
              <h2 style={{ margin: 0, fontSize: "32px" }}>Incidents</h2>
              <span
                style={{
                  padding: "8px 12px",
                  borderRadius: "999px",
                  background: "#f1f5f9",
                  color: "#334155",
                  fontSize: "13px",
                  fontWeight: 600,
                }}
              >
                {incidents.length} detected
              </span>
            </div>

            {incidents.length === 0 ? (
              <div
                style={{
                  border: "1px dashed #cbd5e1",
                  borderRadius: "16px",
                  padding: "24px",
                  color: "#64748b",
                  background: "#f8fafc",
                }}
              >
                尚未有分析結果
              </div>
            ) : (
              incidents.map((item, index) => {
                const severity = item.severity || item.risk || "Unknown";

                return (
                  <div
                    key={index}
                    style={{
                      border: "1px solid #e2e8f0",
                      borderRadius: "18px",
                      padding: "18px",
                      marginTop: "14px",
                      background: "#ffffff",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        gap: "12px",
                        alignItems: "start",
                      }}
                    >
                      <div>
                        <h3 style={{ margin: 0, fontSize: "26px" }}>
                          {item.type || "Unknown Incident"}
                        </h3>
                        <p style={{ margin: "8px 0 0 0", color: "#64748b" }}>
                          Source: {item.source || "-"}
                        </p>
                      </div>

                      <span
                        style={{
                          ...getBadgeStyle(severity),
                          padding: "8px 12px",
                          borderRadius: "999px",
                          fontSize: "12px",
                          fontWeight: 700,
                          whiteSpace: "nowrap",
                        }}
                      >
                        {severity}
                      </span>
                    </div>

                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "1fr 1fr 1fr",
                        gap: "12px",
                        marginTop: "16px",
                      }}
                    >
                      <div
                        style={{
                          background: "#f8fafc",
                          borderRadius: "14px",
                          padding: "12px",
                          border: "1px solid #e2e8f0",
                        }}
                      >
                        <div style={{ fontSize: "12px", color: "#64748b" }}>IP</div>
                        <div style={{ fontWeight: 700, marginTop: "6px" }}>
                          {item.ip || "-"}
                        </div>
                      </div>

                      <div
                        style={{
                          background: "#f8fafc",
                          borderRadius: "14px",
                          padding: "12px",
                          border: "1px solid #e2e8f0",
                        }}
                      >
                        <div style={{ fontSize: "12px", color: "#64748b" }}>Count</div>
                        <div style={{ fontWeight: 700, marginTop: "6px" }}>
                          {item.count ?? "-"}
                        </div>
                      </div>

                      <div
                        style={{
                          background: "#f8fafc",
                          borderRadius: "14px",
                          padding: "12px",
                          border: "1px solid #e2e8f0",
                        }}
                      >
                        <div style={{ fontSize: "12px", color: "#64748b" }}>
                          Risk Score
                        </div>
                        <div style={{ fontWeight: 700, marginTop: "6px" }}>
                          {item.risk_score ?? "-"}
                        </div>
                      </div>
                    </div>

                    <div
                      style={{
                        marginTop: "14px",
                        padding: "12px 14px",
                        background: "#f8fafc",
                        border: "1px solid #e2e8f0",
                        borderRadius: "14px",
                      }}
                    >
                      <div style={{ fontSize: "12px", color: "#64748b" }}>
                        Window
                      </div>
                      <div style={{ marginTop: "6px", fontWeight: 600 }}>
                        {item.window || "-"}
                      </div>
                    </div>

                    {item.evidence?.length > 0 && (
                      <div
                        style={{
                          marginTop: "14px",
                          padding: "14px",
                          borderRadius: "14px",
                          background: "#fff7ed",
                          border: "1px solid #fed7aa",
                        }}
                      >
                        <div
                          style={{
                            fontWeight: 700,
                            color: "#9a3412",
                            marginBottom: "8px",
                          }}
                        >
                          Evidence
                        </div>

                        <div style={{ display: "grid", gap: "8px" }}>
                          {item.evidence.map((ev, i) => (
                            <div
                              key={i}
                              style={{
                                background: "white",
                                border: "1px solid #fdba74",
                                borderRadius: "12px",
                                padding: "10px 12px",
                                color: "#7c2d12",
                                fontSize: "14px",
                              }}
                            >
                              {ev}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>

          <div style={{ ...cardStyle, padding: "24px" }}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "12px",
              }}
            >
              <h2 style={{ margin: 0, fontSize: "32px" }}>Timeline</h2>
              <span
                style={{
                  padding: "8px 12px",
                  borderRadius: "999px",
                  background: "#f1f5f9",
                  color: "#334155",
                  fontSize: "13px",
                  fontWeight: 600,
                }}
              >
                {timeline.length} events
              </span>
            </div>

            {timeline.length === 0 ? (
              <div
                style={{
                  border: "1px dashed #cbd5e1",
                  borderRadius: "16px",
                  padding: "24px",
                  color: "#64748b",
                  background: "#f8fafc",
                }}
              >
                尚未有 timeline 資料
              </div>
            ) : (
              <div
                style={{
                  overflow: "hidden",
                  borderRadius: "18px",
                  border: "1px solid #e2e8f0",
                }}
              >
                <table
                  style={{
                    width: "100%",
                    borderCollapse: "collapse",
                    background: "white",
                  }}
                >
                  <thead style={{ background: "#f8fafc" }}>
                    <tr>
                      <th
                        style={{
                          textAlign: "left",
                          padding: "14px",
                          fontSize: "13px",
                          color: "#64748b",
                        }}
                      >
                        Time
                      </th>
                      <th
                        style={{
                          textAlign: "left",
                          padding: "14px",
                          fontSize: "13px",
                          color: "#64748b",
                        }}
                      >
                        Event
                      </th>
                      <th
                        style={{
                          textAlign: "left",
                          padding: "14px",
                          fontSize: "13px",
                          color: "#64748b",
                        }}
                      >
                        IP
                      </th>
                      <th
                        style={{
                          textAlign: "left",
                          padding: "14px",
                          fontSize: "13px",
                          color: "#64748b",
                        }}
                      >
                        Severity
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {timeline.map((row) => (
                      <tr key={row.id}>
                        <td
                          style={{
                            padding: "12px 14px",
                            borderTop: "1px solid #e2e8f0",
                            color: "#334155",
                          }}
                        >
                          {row.time}
                        </td>
                        <td
                          style={{
                            padding: "12px 14px",
                            borderTop: "1px solid #e2e8f0",
                            fontWeight: 700,
                          }}
                        >
                          {row.event}
                        </td>
                        <td
                          style={{
                            padding: "12px 14px",
                            borderTop: "1px solid #e2e8f0",
                            color: "#334155",
                          }}
                        >
                          {row.ip}
                        </td>
                        <td
                          style={{
                            padding: "12px 14px",
                            borderTop: "1px solid #e2e8f0",
                          }}
                        >
                          <span
                            style={{
                              ...getBadgeStyle(row.severity),
                              padding: "6px 10px",
                              borderRadius: "999px",
                              fontSize: "12px",
                              fontWeight: 700,
                            }}
                          >
                            {row.severity}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function badgeInlineStyle(level) {
  const value = String(level || "").toUpperCase();

  if (value === "CRITICAL") {
    return "background:#fee2e2;color:#b91c1c;border:1px solid #fecaca;";
  }
  if (value === "HIGH") {
    return "background:#fff7ed;color:#c2410c;border:1px solid #fed7aa;";
  }
  if (value === "MEDIUM") {
    return "background:#fef9c3;color:#a16207;border:1px solid #fde68a;";
  }
  if (value === "LOW") {
    return "background:#dcfce7;color:#166534;border:1px solid #bbf7d0;";
  }
  return "background:#e2e8f0;color:#334155;border:1px solid #cbd5e1;";
}