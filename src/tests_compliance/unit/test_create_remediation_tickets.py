"""Unit tests for create_remediation_tickets node."""


def test_create_remediation_tickets_no_itsm_returns_empty(empty_state):
    from compliance_audit_agent.nodes.create_remediation_tickets import create_remediation_tickets
    result = create_remediation_tickets(empty_state)
    assert result["remediation_tickets"] == []


def test_create_remediation_tickets_no_gaps_returns_empty(empty_state):
    from compliance_audit_agent.nodes.create_remediation_tickets import create_remediation_tickets
    import os
    os.environ["COMPLIANCE_ITSM_API_URL"] = "http://itsm.test"
    result = create_remediation_tickets(empty_state)
    assert result["remediation_tickets"] == []
    os.environ["COMPLIANCE_ITSM_API_URL"] = ""


def test_create_remediation_tickets_creates_tickets_for_gaps():
    from compliance_audit_agent.nodes.create_remediation_tickets import create_remediation_tickets
    from compliance_audit_agent.config import get_settings
    import os
    os.environ["COMPLIANCE_ITSM_API_URL"] = "http://itsm.test"
    get_settings.cache_clear()
    state = {
        "evidence_items": [], "control_mappings": [], "effectiveness_scores": {},
        "gaps": [
            {"gap_id": "g1", "control_id": "A.9.1.1", "framework": "ISO27001",
             "description": "Test gap", "severity": "critical",
             "remediation_guidance": "Review access controls", "identified_at": "2026-01-01T00:00:00"},
        ],
        "framework_scores": {}, "audit_packs": [],
        "drift_alerts": [], "remediation_tickets": [], "processing_errors": [],
    }
    result = create_remediation_tickets(state)
    assert len(result["remediation_tickets"]) == 1
    os.environ["COMPLIANCE_ITSM_API_URL"] = ""
    get_settings.cache_clear()


def test_create_remediation_tickets_maps_severity_to_priority():
    from compliance_audit_agent.nodes.create_remediation_tickets import create_remediation_tickets
    from compliance_audit_agent.config import get_settings
    import os
    os.environ["COMPLIANCE_ITSM_API_URL"] = "http://itsm.test"
    get_settings.cache_clear()
    state = {
        "evidence_items": [], "control_mappings": [], "effectiveness_scores": {},
        "gaps": [
            {"gap_id": "g1", "control_id": "A.9.1.1", "framework": "ISO27001",
             "description": "Gap", "severity": "critical",
             "remediation_guidance": "Fix", "identified_at": "2026-01-01T00:00:00"},
        ],
        "framework_scores": {}, "audit_packs": [],
        "drift_alerts": [], "remediation_tickets": [], "processing_errors": [],
    }
    result = create_remediation_tickets(state)
    assert result["remediation_tickets"][0]["priority"] == "P1"
    os.environ["COMPLIANCE_ITSM_API_URL"] = ""
    get_settings.cache_clear()


def test_create_remediation_tickets_returns_list(empty_state):
    from compliance_audit_agent.nodes.create_remediation_tickets import create_remediation_tickets
    result = create_remediation_tickets(empty_state)
    assert isinstance(result["remediation_tickets"], list)
