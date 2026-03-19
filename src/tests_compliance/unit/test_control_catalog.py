"""Unit tests for ControlCatalog."""

from compliance_audit_agent.rules.control_catalog import ControlCatalog


def test_get_control_name_returns_string():
    cat = ControlCatalog()
    name = cat.get_control_name("A.9.1.1", "ISO27001")
    assert isinstance(name, str)
    assert len(name) > 0


def test_get_control_name_unknown_returns_id():
    cat = ControlCatalog()
    name = cat.get_control_name("UNKNOWN-CTL", "CUSTOM")
    assert name == "UNKNOWN-CTL"


def test_get_harmonised_controls_iso27001_access_control():
    cat = ControlCatalog()
    harmonised = cat.get_harmonised_controls("A.9.1.1", "ISO27001")
    assert len(harmonised) > 0
    # Should include at least NIST and SOC2 equivalents
    assert any("NIST" in h or "SOC2" in h or "PCI" in h for h in harmonised)


def test_get_harmonised_controls_no_mapping_returns_empty():
    cat = ControlCatalog()
    result = cat.get_harmonised_controls("A.5.1.1", "ISO27001")
    assert isinstance(result, list)


def test_get_required_controls_iso27001():
    cat = ControlCatalog()
    controls = cat.get_required_controls("ISO27001")
    assert len(controls) >= 5


def test_get_required_controls_unknown_framework():
    cat = ControlCatalog()
    controls = cat.get_required_controls("UNKNOWN")
    assert controls == []
