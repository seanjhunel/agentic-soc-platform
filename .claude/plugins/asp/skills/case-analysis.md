---
name: case-analysis
description: Analyze security cases and provide detailed investigation reports
---

# Security Case Analysis Skill

This skill provides comprehensive analysis of security cases from the ASP platform.

## Usage

When invoked, this skill will:

1. **Retrieve Case Information**
   - Use MCP tools to fetch complete case details
   - Load associated alerts, artifacts, and enrichments
   - Gather timeline and status information

2. **Perform Analysis**
   - Identify attack patterns and techniques
   - Correlate indicators across alerts
   - Map to MITRE ATT&CK framework
   - Assess severity and impact

3. **Generate Report**
   - Executive summary
   - Detailed findings
   - Attack timeline reconstruction
   - Affected assets and scope
   - Remediation recommendations

## Example

```
User: Analyze case C-2024-001
```

The skill will:
1. Call `get_case_by_case_id("C-2024-001")`
2. Extract and analyze all related data
3. Generate a structured analysis report
4. Provide actionable recommendations

## Output Structure

```
# Case Analysis Report: [Case Title]

## Executive Summary
[Brief overview of the incident]

## Case Details
- Case ID: [ID]
- Severity: [Level]
- Status: [Current Status]
- Created: [Timestamp]

## Key Findings
- [Finding 1]
- [Finding 2]
- [Finding 3]

## Attack Timeline
[Chronological sequence of events]

## Indicators of Compromise (IOCs)
- IPs: [List]
- Domains: [List]
- File Hashes: [List]
- User Accounts: [List]

## MITRE ATT&CK Mapping
- Tactics: [List]
- Techniques: [List]

## Impact Assessment
[Affected systems, data, and business impact]

## Recommendations
1. [Immediate actions]
2. [Short-term remediation]
3. [Long-term prevention]

## Next Steps
[Further investigation or monitoring needed]
```
