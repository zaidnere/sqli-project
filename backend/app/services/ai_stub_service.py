from app.schemas.scan import AIStubRequest, AIStubResponse, ScanIssue


async def scan_with_ai_stub(payload: AIStubRequest) -> AIStubResponse:
    joined = " ".join(payload.sequence).lower()

    suspicious = any(keyword in joined for keyword in [
        "sql_select",
        "sql_union",
        "sql_drop",
        "sql_insert",
        "sql_update",
        "sql_delete",
    ])

    concatenation = "+" in payload.sequence or "." in payload.sequence

    if suspicious and concatenation:
        return AIStubResponse(
            riskScore=0.82,
            label="SQL Injection Risk",
            issues=[
                ScanIssue(
                    line=1,
                    description="Possible SQL injection pattern detected from SQL tokens combined with string concatenation.",
                    severity="high",
                )
            ],
            summary="Potential vulnerability detected.",
            recommendations="Use parameterized queries / prepared statements and avoid dynamic query concatenation.",
        )

    if suspicious:
        return AIStubResponse(
            riskScore=0.46,
            label="Potential Risk",
            issues=[
                ScanIssue(
                    line=1,
                    description="SQL-related pattern detected. Manual review recommended.",
                    severity="medium",
                )
            ],
            summary="Suspicious SQL usage found.",
            recommendations="Review how user input reaches the query and prefer bound parameters.",
        )

    return AIStubResponse(
        riskScore=0.08,
        label="Low Risk",
        issues=[],
        summary="No obvious SQL injection pattern detected by the stub.",
        recommendations="Continue using parameterized queries and validate input paths.",
    )