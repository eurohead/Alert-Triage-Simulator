# SOC Alert Triage Simulator

## Overview

A lightweight CLI tool that simulates SOC alert triage.
It ingests structured JSON alerts, applies rule-based risk scoring, and outputs:

* Risk score (0–100)
* Severity classification
* Investigation reasoning
* Recommended response actions

Built to model real-world analyst decision-making and escalation logic.

---

## Example

**Input (JSON alert):**

```json
{
  "alert_type": "PROCESS_CREATION",
  "process": "powershell.exe",
  "command_line": "powershell.exe -EncodedCommand ...",
  "parent_process": "winword.exe",
  "external_network_connection": true
}
```

**Output:**

```
Risk Score: 78/100
Severity: HIGH

Reasons:
- Encoded PowerShell detected
- Office spawning PowerShell
- External network activity

Recommended Action:
- Isolate host
- Escalate to Tier 2
```

---

## Design

* Transparent, rule-based scoring
* Severity tiers: LOW / MEDIUM / HIGH
* Easily extendable detection logic
* Focused on operational clarity over complexity

---

## Run

```bash
python triage.py alert.json
```
