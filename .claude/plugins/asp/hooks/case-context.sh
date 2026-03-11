#!/bin/bash

# PreToolUse Hook: Auto-load case context when case ID is detected

# Check if user input contains a case ID pattern (e.g., C-2024-001 or similar)
if echo "$CLAUDE_USER_INPUT" | grep -qE '(C|CASE)-[0-9]{4}-[0-9]{3,}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'; then
    # Extract the case ID
    CASE_ID=$(echo "$CLAUDE_USER_INPUT" | grep -oE '(C|CASE)-[0-9]{4}-[0-9]{3,}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}' | head -1)

    # Inject a system message to load case context
    echo "Detected case ID: $CASE_ID. Loading case context..."
    echo "CLAUDE_INJECT_CONTEXT: Please use get_case_by_case_id('$CASE_ID') to load case context before responding."
fi
