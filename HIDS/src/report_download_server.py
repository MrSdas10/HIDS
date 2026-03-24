"""
report_download_server.py - Downloadable HIDS PDF report service

Starts a lightweight Flask server so users can download a generated
HIDS incident report from the browser.

Usage:
    python3 src/report_download_server.py

Then open:
    http://127.0.0.1:5001/
"""

import argparse
import os
from datetime import datetime

from flask import Flask, jsonify, render_template_string, request, send_file

from report_generator import build_summary, generate_hids_report, parse_events, read_alert_lines
from simulation import simulate_event
from utils import ALERT_LOG


INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>HIDS Dashboard</title>
    <style>
        :root {
            --bg: #f1f6fb;
            --card: #ffffff;
            --primary: #102a43;
            --accent: #0b7285;
            --text: #1f2937;
            --muted: #5f6b7a;
            --border: #d8e0ea;
            --high: #b42318;
            --medium: #b54708;
            --low: #027a48;
        }

        body {
            margin: 0;
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(160deg, #f8fbff 0%, #eef4fb 50%, #e6f0f9 100%);
            color: var(--text);
            padding: 28px;
        }

        .container {
            width: min(1100px, 100%);
            margin: 0 auto;
        }

        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 20px;
            box-shadow: 0 12px 30px rgba(23, 50, 79, 0.12);
        }

        .header {
            display: flex;
            justify-content: space-between;
            gap: 16px;
            align-items: center;
            margin-bottom: 18px;
        }

        h1 {
            margin: 0;
            color: var(--primary);
            font-size: 1.5rem;
        }

        p {
            margin: 6px 0 0;
            color: var(--muted);
            line-height: 1.5;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin: 14px 0 18px;
        }

        .stat {
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 12px;
            background: #fbfdff;
        }

        .stat .label {
            font-size: 0.86rem;
            color: var(--muted);
        }

        .stat .value {
            margin-top: 4px;
            font-size: 1.35rem;
            font-weight: 700;
            color: var(--primary);
        }

        .btn {
            appearance: none;
            border: none;
            border-radius: 10px;
            background: var(--accent);
            color: #fff;
            font-weight: 600;
            font-size: 0.98rem;
            padding: 12px 18px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }

        .btn:hover {
            filter: brightness(0.95);
        }

        .btn-row {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 0 0 14px;
        }

        .btn-secondary {
            background: #2f6f3e;
        }

        .btn-tertiary {
            background: #7a4a0f;
        }

        .btn-danger {
            background: #a61b1b;
        }

        .status {
            margin: 0 0 14px;
            font-size: 0.92rem;
            color: #1f2937;
            min-height: 1.2rem;
        }

        .table-wrap {
            overflow-x: auto;
            border: 1px solid var(--border);
            border-radius: 10px;
            background: #fff;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 760px;
        }

        th, td {
            padding: 10px 12px;
            border-bottom: 1px solid #e8edf3;
            text-align: left;
            font-size: 0.92rem;
        }

        th {
            background: #f3f8fd;
            color: #26415d;
            font-weight: 700;
        }

        tr:hover {
            background: #f8fbff;
        }

        .risk-high { color: var(--high); font-weight: 700; }
        .risk-medium { color: var(--medium); font-weight: 700; }
        .risk-low { color: var(--low); font-weight: 700; }

        .hint {
            margin-top: 10px;
            font-size: 0.9rem;
            color: var(--muted);
        }

        @media (max-width: 700px) {
            body {
                padding: 14px;
            }

            .header {
                flex-direction: column;
                align-items: flex-start;
            }
        }
    </style>
</head>
<body>
    <main class="container card">
        <section class="header">
            <div>
                <h1>HIDS Monitoring Dashboard</h1>
                <p>Live alerts with automatic refresh and one-click PDF export.</p>
            </div>
            <a class="btn" href="/download-report">Download PDF Report</a>
        </section>

        <section class="btn-row">
            <button class="btn btn-secondary" type="button" onclick="triggerSimulation('ssh_bruteforce')">Simulate SSH Brute Force</button>
            <button class="btn btn-tertiary" type="button" onclick="triggerSimulation('file_modification')">Simulate File Modification</button>
            <button class="btn btn-danger" type="button" onclick="triggerSimulation('full_attack_chain')">Simulate Full Attack Chain</button>
        </section>
        <div class="status" id="simulate-status">Simulation controls write test events into real monitor sources.</div>

        <section class="summary-grid">
            <div class="stat"><div class="label">Total Alerts</div><div class="value" id="total-alerts">0</div></div>
            <div class="stat"><div class="label">High Risk</div><div class="value" id="high-risk">0</div></div>
            <div class="stat"><div class="label">Medium Risk</div><div class="value" id="medium-risk">0</div></div>
            <div class="stat"><div class="label">Low Risk</div><div class="value" id="low-risk">0</div></div>
        </section>

        <section class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Type</th>
                        <th>IP</th>
                        <th>Risk</th>
                        <th>Message</th>
                    </tr>
                </thead>
                <tbody id="alerts-body">
                    <tr><td colspan="5">Loading alerts...</td></tr>
                </tbody>
            </table>
        </section>
        <div class="hint">Auto-refresh interval: 5 seconds</div>
    </main>

    <script>
        const REFRESH_MS = 5000;

        function riskClass(risk) {
            const normalized = (risk || "low").toLowerCase();
            if (normalized === "high") return "risk-high";
            if (normalized === "medium") return "risk-medium";
            return "risk-low";
        }

        function titleCase(text) {
            return (text || "unknown")
                .replace(/_/g, " ")
                .replace(/\b\w/g, ch => ch.toUpperCase());
        }

        function renderSummary(summary) {
            document.getElementById("total-alerts").textContent = summary.total_alerts;
            document.getElementById("high-risk").textContent = summary.risk_breakdown.High;
            document.getElementById("medium-risk").textContent = summary.risk_breakdown.Medium;
            document.getElementById("low-risk").textContent = summary.risk_breakdown.Low;
        }

        function renderAlerts(alerts) {
            const tbody = document.getElementById("alerts-body");

            if (!alerts.length) {
                tbody.innerHTML = '<tr><td colspan="5">No alerts yet.</td></tr>';
                return;
            }

            tbody.innerHTML = "";
            alerts.forEach(alert => {
                const row = document.createElement("tr");

                const timeCell = document.createElement("td");
                timeCell.textContent = alert.time || "";

                const typeCell = document.createElement("td");
                typeCell.textContent = titleCase(alert.type);

                const ipCell = document.createElement("td");
                ipCell.textContent = alert.ip || "N/A";

                const riskCell = document.createElement("td");
                riskCell.className = riskClass(alert.risk_level);
                riskCell.textContent = alert.risk_level || "Low";

                const msgCell = document.createElement("td");
                msgCell.textContent = alert.message || "";

                row.appendChild(timeCell);
                row.appendChild(typeCell);
                row.appendChild(ipCell);
                row.appendChild(riskCell);
                row.appendChild(msgCell);
                tbody.appendChild(row);
            });
        }

        async function refreshAlerts() {
            try {
                const response = await fetch('/api/alerts', { cache: 'no-store' });
                const data = await response.json();
                renderSummary(data.summary);
                renderAlerts(data.alerts);
            } catch (error) {
                const tbody = document.getElementById("alerts-body");
                tbody.innerHTML = '<tr><td colspan="5">Failed to load alerts.</td></tr>';
            }
        }

        async function triggerSimulation(eventType) {
            const status = document.getElementById("simulate-status");
            status.textContent = "Running simulation...";

            try {
                const response = await fetch('/api/simulate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ event_type: eventType }),
                });

                const data = await response.json();
                status.textContent = data.message || 'Simulation completed.';
                await refreshAlerts();
            } catch (error) {
                status.textContent = 'Simulation failed. Check server logs.';
            }
        }

        refreshAlerts();
        setInterval(refreshAlerts, REFRESH_MS);
    </script>
</body>
</html>
"""


def create_report_download_app(alert_log_path=ALERT_LOG, output_dir=None, allow_remote=False):
    """Create a Flask app with live alerts dashboard + downloadable reports."""
    app = Flask(__name__)

    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")

    os.makedirs(output_dir, exist_ok=True)

    def _is_local_request():
        if allow_remote:
            return True
        remote = (request.remote_addr or "").strip()
        return remote in {"127.0.0.1", "::1", "::ffff:127.0.0.1"}

    @app.get("/")
    def index():
        if not _is_local_request():
            return jsonify({"error": "Dashboard is localhost-only."}), 403
        return render_template_string(INDEX_HTML)

    @app.get("/api/alerts")
    def list_alerts():
        try:
            if not _is_local_request():
                return jsonify({"error": "Alerts API is localhost-only."}), 403

            lines = read_alert_lines(alert_log_path)
            incidents, _actions = parse_events(lines)
            incidents = sorted(incidents, key=lambda x: x.get("time", ""), reverse=True)
            summary = build_summary(incidents)
            return jsonify({"alerts": incidents[:100], "summary": summary})
        except Exception as e:
            return jsonify({"error": f"Failed to load alerts: {e}"}), 500

    @app.post("/api/simulate")
    def run_simulation():
        try:
            if not _is_local_request():
                return jsonify({"ok": False, "message": "Simulation endpoint is localhost-only."}), 403

            payload = request.get_json(silent=True) or {}
            event_type = payload.get("event_type", "")
            result = simulate_event(event_type)
            status_code = 200 if result.get("ok") else 400
            return jsonify(result), status_code
        except Exception as e:
            return jsonify({"ok": False, "message": f"Simulation failed: {e}"}), 500

    @app.get("/download-report")
    def download_report():
        try:
            if not _is_local_request():
                return jsonify({"error": "Report download is localhost-only."}), 403

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"hids_report_{timestamp}.pdf"
            report_path = os.path.join(output_dir, filename)

            generated_path = generate_hids_report(
                alert_log_path=alert_log_path,
                output_path=report_path,
            )

            return send_file(
                generated_path,
                as_attachment=True,
                download_name=filename,
                mimetype="application/pdf",
            )
        except Exception as e:
            return jsonify({"error": f"Failed to generate/download report: {e}"}), 500

    return app


def main():
    parser = argparse.ArgumentParser(description="Serve downloadable HIDS PDF reports via Flask.")
    parser.add_argument("--input", default=ALERT_LOG, help="Path to alerts.log")
    parser.add_argument("--host", default="127.0.0.1", help="Flask host")
    parser.add_argument("--port", type=int, default=5001, help="Flask port")
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Allow dashboard and APIs from non-localhost clients.",
    )
    args = parser.parse_args()

    app = create_report_download_app(
        alert_log_path=args.input,
        allow_remote=args.allow_remote,
    )
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
