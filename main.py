import json
import sys


def calculate_risk(alert):
    score = 0
    reasons = []

    if alert.get("process", "").lower() == "powershell.exe":
        score += 15

        if "-encodedcommand" in alert.get("command_line", "").lower():
            score += 30
            reasons.append("Encoded PowerShell detected")

    if alert.get("parent_process", "").lower() in ["winword.exe", "excel.exe"]:
        score += 20
        reasons.append("Office spawning PowerShell")

    if alert.get("external_network_connection"):
        score += 20
        reasons.append("External network connection observed")

    if alert.get("is_admin"):
        score += 10
        reasons.append("Executed with administrative privileges")

    if not alert.get("signed_binary", True):
        score += 15
        reasons.append("Unsigned binary execution")

    return min(score, 100), reasons


def determine_severity(score):
    if score >= 75:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def recommended_action(severity):
    if severity == "HIGH":
        return [
            "Isolate host",
            "Acquire memory capture",
            "Escalate to Tier 2 IR",
            "Review related authentication logs"
        ]
    elif severity == "MEDIUM":
        return [
            "Investigate parent process",
            "Check user history",
            "Monitor host for additional activity"
        ]
    else:
        return [
            "Document alert",
            "Continue monitoring"
        ]


def main():
    if len(sys.argv) != 2:
        print("Usage: python triage.py <alert.json>")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        alert = json.load(f)

    score, reasons = calculate_risk(alert)
    severity = determine_severity(score)
    actions = recommended_action(severity)

    print("\n=== ALERT TRIAGE REPORT ===")
    print(f"Alert Type: {alert.get('alert_type')}")
    print(f"Host: {alert.get('host')}")
    print(f"User: {alert.get('user')}\n")

    print(f"Risk Score: {score}/100")
    print(f"Severity: {severity}\n")

    print("Reasons:")
    for r in reasons:
        print(f"- {r}")

    print("\nRecommended Action:")
    for a in actions:
        print(f"- {a}")


if __name__ == "__main__":
    main()
