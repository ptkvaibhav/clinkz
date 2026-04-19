---
name: review-findings
description: "Review latest engagement findings for accuracy, false positives, and evidence quality"
---
Apply phase-work rules unless overridden by this skill.

Read the latest engagement output (check outputs/ directory for the most recent
JSON report, or query the engagement state DB).

For each finding, evaluate:
1. CVSS score appropriateness for the severity and impact
2. PoC quality: does the request+response pair actually demonstrate the vuln?
3. False positive risk: could the response be a generic error or WAF block?
4. Reproduction clarity: could a developer verify this from the steps given?

Summarize: total findings by severity, any flagged as likely false positives,
any with insufficient evidence.
