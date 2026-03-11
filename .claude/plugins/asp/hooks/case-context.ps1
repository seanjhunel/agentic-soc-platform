# PreToolUse Hook: Auto-load case context when case ID is detected

$userInput = $env:CLAUDE_USER_INPUT

# Check if user input contains a case ID pattern
if ($userInput -match '(C|CASE)-[0-9]{4}-[0-9]{3,}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}') {
    $caseId = $matches[0]

    Write-Host "Detected case ID: $caseId. Loading case context..."
    Write-Host "CLAUDE_INJECT_CONTEXT: Please use get_case_by_case_id('$caseId') to load case context before responding."
}
