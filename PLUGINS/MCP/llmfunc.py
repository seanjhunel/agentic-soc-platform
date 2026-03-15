from typing import Annotated, Optional

from PLUGINS.SIRP.nocolymodel import Group, Condition, Operator
from PLUGINS.SIRP.sirpapi import Case
from PLUGINS.SIRP.sirpmodel import CaseModel, Severity, CaseStatus, CaseVerdict, Confidence


def get_case(
        case_id: Annotated[str, "Case ID, for example case_000005"]
) -> Annotated[Optional[str], "AI-friendly JSON string of the case, or None if the case does not exist"]:
    """Retrieve a security case by case ID."""
    model = Case.get_by_id(case_id)
    if not model:
        return None
    result = model.model_dump_json_for_ai()
    return result


def list_cases(
        status: Annotated[Optional[list[CaseStatus]], "Filter by case status or a list of case statuses"] = None,
        severity: Annotated[Optional[list[Severity]], "Filter by severity level or a list of severity levels"] = None,
        limit: Annotated[int, "Maximum number of results to return"] = 10
) -> Annotated[list[str], "Security cases matching the filters"]:
    """List security cases with optional filters."""
    conditions = []

    if status:
        conditions.append(Condition(field="status", operator=Operator.IN, value=status))

    if severity:
        conditions.append(Condition(field="severity", operator=Operator.IN, value=severity))

    filter_model = Group(logic="AND", children=conditions) if conditions else Group(logic="AND", children=[])

    models = Case.list(filter_model)
    result = []
    for model in models[:limit]:
        result.append(model.model_dump_json_for_ai())
    return result


def create_case(
        title: Annotated[str, "Case title"],
        severity: Annotated[str, "Severity level: Critical, High, Medium, Low, Info"],
        description: Annotated[str, "Case description"] = "",
        status: Annotated[str, "Case status"] = "New"
) -> Annotated[str, "Row ID of the created case"]:
    """Create a new security case."""
    case_model = CaseModel(
        title=title,
        severity=Severity(severity),
        description=description,
        status=CaseStatus(status)
    )
    return Case.create(case_model)


def update_case(
        case_id: Annotated[str, "Case ID to update"],
        severity: Annotated[Optional[str], "New severity"] = None,
        status: Annotated[Optional[str], "New status"] = None,
        verdict: Annotated[Optional[str], "New verdict"] = None,
        severity_ai: Annotated[Optional[str], "New AI-assessed severity"] = None,
        confidence_ai: Annotated[Optional[str], "New AI-assessed confidence"] = None,
        comment_ai: Annotated[Optional[
            str], "Append content to comment_ai. Supports Markdown format. For readability, avoid #, ##, ### headings and use #### as the top-level heading."] = None,
        summary_ai: Annotated[Optional[
            str], "Append content to summary_ai. Supports Markdown format. For readability, avoid #, ##, ### headings and use #### as the top-level heading."] = None
) -> Annotated[Optional[str], "Row ID of the updated case_old, or None if the case_old does not exist"]:
    """Update an existing security case_old."""
    case_old = Case.get_by_id(case_id, lazy_load=True)
    if not case_old:
        return None

    def append_text(existing: Optional[str], new_content: str) -> str:
        if existing:
            return f"{existing.rstrip()}\n\n{new_content.lstrip()}"
        return new_content

    case_new = CaseModel()
    case_new.rowid = case_old.rowid
    if severity:
        case_new.severity = Severity(severity)
    if status:
        case_new.status = CaseStatus(status)
    if verdict:
        case_new.verdict = CaseVerdict(verdict)
    if severity_ai:
        case_new.severity_ai = Severity(severity_ai)
    if confidence_ai:
        case_new.confidence_ai = Confidence(confidence_ai)

    if comment_ai:
        case_new.comment_ai = append_text(case_old.comment_ai, comment_ai)
    if summary_ai:
        case_new.summary_ai = append_text(case_old.summary_ai, summary_ai)

    return Case.update(case_new)


if __name__ == "__main__":
    import os

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    import django

    django.setup()
    cases = list_cases(limit=1)
    print(cases)
    if cases:
        case = Case.list(Group(logic="AND", children=[]), lazy_load=True)[0]
        result = update_case(
            case_id=case.id,
            status=CaseStatus.IN_PROGRESS,
            verdict=CaseVerdict.SUSPICIOUS,
            severity_ai=Severity.HIGH,
            confidence_ai=Confidence.MEDIUM,
            comment_ai="#### AI Comment\n\nAdditional investigation notes.",
            summary_ai="#### AI Summary\n\nUpdated case summary."
        )
    else:
        result = None
    print(result)
