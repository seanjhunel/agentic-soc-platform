---
name: asp-case-create
description: Create a new security case
args:
  - name: title
    description: Case title
    required: true
  - name: severity
    description: Severity level (Critical, High, Medium, Low, Info)
    required: true
  - name: description
    description: Case description
    required: false
  - name: status
    description: Initial status (default New)
    required: false
---

Create a new case:
- Title: {{title}}
- Severity: {{severity}}
- Description: {{description}}
- Status: {{status}}

Please use the MCP tool `create_case` to create the case and display the created case details including the assigned case ID and rowid.
