---
name: asp-case-list
description: List security cases with optional filters
args:
  - name: status
    description: Filter by case status
    required: false
  - name: severity
    description: Filter by severity level
    required: false
  - name: limit
    description: Maximum number of results
    required: false
---

List cases with filters:
- Status: {{status}}
- Severity: {{severity}}
- Limit: {{limit}}

Please use the MCP tool `list_cases` to retrieve cases and display them in a table format with:
- Case ID
- Title
- Severity
- Status
- Created Time
