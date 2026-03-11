---
name: asp-case-update
description: Update an existing security case
args:
  - name: case_id
    description: Case ID to update
    required: true
  - name: title
    description: New title
    required: false
  - name: severity
    description: New severity level
    required: false
  - name: status
    description: New status
    required: false
  - name: description
    description: New description
    required: false
---

Update case {{case_id}} with:
- Title: {{title}}
- Severity: {{severity}}
- Status: {{status}}
- Description: {{description}}

Please use the MCP tool `update_case` to update the case and display the updated case details.
