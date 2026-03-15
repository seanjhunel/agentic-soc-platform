---
name: asp-case-update
description: Update an existing security case
argument-hint: "<case_id> [severity=<severity>] [status=<status>] [verdict=<verdict>] [severity_ai=<severity_ai>] [confidence_ai=<confidence_ai>] [comment_ai=<markdown>] [summary_ai=<markdown>]"
allowed-tools: [ "*" ]
---

Update case {{case_id}} with the following changes:

- Severity: {{severity}}
- Status: {{status}}
- Verdict: {{verdict}}
- AI Severity: {{severity_ai}}
- AI Confidence: {{confidence_ai}}
- Comment AI: {{comment_ai}}
- Summary AI: {{summary_ai}}

**Valid values:**

- Severity: Informational, Low, Medium, High, Critical, Fatal, Unknown, Other
- Status: New, In Progress, On Hold, Resolved, Closed
- Verdict: Unknown, False Positive, True Positive, Disregard, Suspicious, Benign, Test, Insufficient Data, Security Risk, Managed Externally, Duplicate, Other
- AI Confidence: Unknown, Low, Medium, High, Other

`comment_ai` and `summary_ai` are fully replaced by the provided content.

`comment_ai` and `summary_ai` support Markdown. For readability, avoid `#`, `##`, `###` headings and use `####` as the top-level heading.

Use the MCP tool `update_case` with the case ID and any provided update fields.

The tool returns the updated case row ID, or `None` if the case does not exist.

If the tool returns `None`, clearly state that the case was not found.

After successful update, display:

**Case Updated Successfully**

Show the fields that were requested to change, then display:

- Rowid
- Case ID
- Severity
- Status
- Verdict
- AI Severity
- AI Confidence
- Comment AI content
- Summary AI content

If full updated details are needed, call `get_case` after the update and present the latest case data.
