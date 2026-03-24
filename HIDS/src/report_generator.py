"""
report_generator.py - HIDS PDF Report Generator

Generates a professional PDF report from alerts.log with:
1) Summary (total alerts + risk breakdown)
2) Incident details (time, IP, type)
3) Explanation for each attack
4) Actions taken (e.g., IP blocked)

Usage:
    python3 src/report_generator.py
    python3 src/report_generator.py --input /path/to/alerts.log --output hids_report.pdf
"""

import argparse
import os
import re
from collections import Counter
from datetime import datetime

from fpdf import FPDF

from utils import ALERT_LOG, describe_alert

DEFAULT_REPORT_NAME = "hids_report.pdf"

TIMESTAMP_REGEX = re.compile(r"^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+(?P<msg>.+)$")
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def read_alert_lines(alert_log_path):
    """Read alert lines from a log file safely."""
    if not os.path.exists(alert_log_path):
        return []

    try:
        with open(alert_log_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except (IOError, OSError):
        return []


def parse_log_line(line):
    """Parse a log line into timestamp + message."""
    match = TIMESTAMP_REGEX.match(line)
    if not match:
        return None

    return {
        "timestamp": match.group("ts"),
        "message": match.group("msg"),
    }


def extract_ip(message):
    """Extract first IPv4 from message, if present."""
    match = IP_REGEX.search(message)
    return match.group(0) if match else "N/A"


def classify_alert_type(message):
    """Map raw alert messages to normalized alert types."""
    text = message.lower()

    if "ssh_brute_force" in text:
        return "brute_force"
    if "ssh_success_after_failures" in text:
        return "brute_force"
    if "file modified" in text or "file deleted" in text or "new file detected" in text:
        return "file_change"
    if "suspicious root process" in text or "privileged" in text:
        return "privilege_escalation"
    return "unknown"


def is_action_line(message):
    """Check whether a line is an action event."""
    return "[action]" in message.lower()


def infer_risk_level(normalized_type):
    """Get risk from shared helper for consistency."""
    details = describe_alert(normalized_type)
    return details.get("risk_level", "Low")


def parse_events(lines):
    """Build structured incident/action events from raw lines."""
    incidents = []
    actions = []

    for raw_line in lines:
        parsed = parse_log_line(raw_line)
        if not parsed:
            continue

        message = parsed["message"]
        event = {
            "time": parsed["timestamp"],
            "ip": extract_ip(message),
            "type": classify_alert_type(message),
            "message": message,
        }

        if is_action_line(message):
            actions.append(event)
        elif "[alert]" in message.lower() or "[warning]" in message.lower() or "[error]" in message.lower():
            event["risk_level"] = infer_risk_level(event["type"])
            incidents.append(event)

    return incidents, actions


def build_summary(incidents):
    """Create summary data used in the PDF header section."""
    risk_counter = Counter(incident.get("risk_level", "Low") for incident in incidents)
    return {
        "total_alerts": len(incidents),
        "risk_breakdown": {
            "High": risk_counter.get("High", 0),
            "Medium": risk_counter.get("Medium", 0),
            "Low": risk_counter.get("Low", 0),
        },
    }


class HIDSReportPDF(FPDF):
    """Custom PDF class for report styling."""

    def header(self):
        self.set_fill_color(18, 42, 66)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 16)
        self.cell(0, 12, "HIDS Security Incident Report", ln=True, fill=True)
        self.ln(2)

    def section_title(self, title):
        self.set_text_color(23, 37, 84)
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 8, title, ln=True)
        self.set_text_color(0, 0, 0)


def add_summary_section(pdf, summary):
    """Render summary block."""
    pdf.section_title("1. Summary")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, f"Total Alerts: {summary['total_alerts']}", ln=True)
    pdf.cell(0, 7, f"High Risk: {summary['risk_breakdown']['High']}", ln=True)
    pdf.cell(0, 7, f"Medium Risk: {summary['risk_breakdown']['Medium']}", ln=True)
    pdf.cell(0, 7, f"Low Risk: {summary['risk_breakdown']['Low']}", ln=True)
    pdf.ln(2)


def add_incident_details_section(pdf, incidents):
    """Render incident details table-like list."""
    pdf.section_title("2. Incident Details")
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(230, 236, 245)

    pdf.cell(44, 8, "Time", border=1, fill=True)
    pdf.cell(38, 8, "IP", border=1, fill=True)
    pdf.cell(46, 8, "Type", border=1, fill=True)
    pdf.cell(28, 8, "Risk", border=1, fill=True)
    pdf.cell(0, 8, "Status", border=1, ln=True, fill=True)

    pdf.set_font("Helvetica", "", 9)

    if not incidents:
        pdf.cell(0, 8, "No incidents found.", border=1, ln=True)
        pdf.ln(2)
        return

    for incident in incidents:
        incident_type = incident["type"].replace("_", " ").title()
        status = "Observed"

        pdf.cell(44, 8, incident["time"], border=1)
        pdf.cell(38, 8, incident["ip"], border=1)
        pdf.cell(46, 8, incident_type, border=1)
        pdf.cell(28, 8, incident.get("risk_level", "Low"), border=1)
        pdf.cell(0, 8, status, border=1, ln=True)

    pdf.ln(2)


def add_explanations_section(pdf, incidents):
    """Render explanation + mitigation per incident type."""
    pdf.section_title("3. Explanation By Attack Type")

    unique_types = sorted({incident["type"] for incident in incidents if incident["type"] != "unknown"})
    if not unique_types:
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 6, "No known attack types found in current incidents.")
        pdf.ln(2)
        return

    for attack_type in unique_types:
        details = describe_alert(attack_type)

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(30, 64, 96)
        pdf.cell(0, 7, attack_type.replace("_", " ").title(), ln=True)

        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 6, f"What happened: {details['explanation']}")
        pdf.multi_cell(0, 6, f"Risk level: {details['risk_level']}")
        pdf.multi_cell(0, 6, f"Suggested mitigation: {details['suggested_mitigation']}")
        pdf.ln(1)


def add_actions_section(pdf, actions):
    """Render actions taken from [ACTION] lines."""
    pdf.section_title("4. Actions Taken")
    pdf.set_font("Helvetica", "", 10)

    if not actions:
        pdf.multi_cell(0, 6, "No actions were recorded.")
        return

    for action in actions:
        line = f"{action['time']} | IP: {action['ip']} | {action['message']}"
        pdf.multi_cell(0, 6, line)


def generate_hids_report(alert_log_path=ALERT_LOG, output_path=DEFAULT_REPORT_NAME):
    """Generate PDF report from alerts log."""
    lines = read_alert_lines(alert_log_path)
    incidents, actions = parse_events(lines)
    summary = build_summary(incidents)

    pdf = HIDSReportPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    generated_on = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 7, f"Generated on: {generated_on}", ln=True)
    pdf.ln(2)

    add_summary_section(pdf, summary)
    add_incident_details_section(pdf, incidents)
    add_explanations_section(pdf, incidents)
    add_actions_section(pdf, actions)

    pdf.output(output_path)
    return output_path


def main():
    parser = argparse.ArgumentParser(description="Generate a HIDS PDF report from alerts log.")
    parser.add_argument("--input", default=ALERT_LOG, help="Path to alerts.log")
    parser.add_argument("--output", default=DEFAULT_REPORT_NAME, help="Output PDF file path")
    args = parser.parse_args()

    report_path = generate_hids_report(alert_log_path=args.input, output_path=args.output)
    print(f"[INFO] Report generated: {report_path}")


if __name__ == "__main__":
    main()
