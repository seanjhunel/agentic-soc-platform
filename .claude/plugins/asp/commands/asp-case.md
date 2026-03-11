---
name: asp-case
description: Query security case details by case ID or rowid
args:
  - name: id
    description: Case ID or rowid to query
    required: true
---

Query case: {{id}}

Please use the MCP tool `get_case_by_case_id` or `get_case_by_rowid` to retrieve the case details and format the output with:

- Case ID and Title
- Severity and Status
- Description
- Associated Alerts (count and summary)
- Associated Artifacts (count and key entities)
- Timeline information
- Any AI analysis results
