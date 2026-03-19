"""Unit tests for EffectivenessEngine."""

from compliance_audit_agent.rules.effectiveness_engine import EffectivenessEngine


def test_fully_effective_with_high_weight_evidence():
    eng = EffectivenessEngine()
    evidence = [{"source_type": "audit_trail"}, {"source_type": "audit_trail"}]
    rating, score = eng.evaluate("A.9.1.1", "ISO27001", evidence)
    assert rating == "fully_effective"
    assert score >= 85.0


def test_ineffective_with_no_evidence():
    eng = EffectivenessEngine()
    rating, score = eng.evaluate("A.9.1.1", "ISO27001", [])
    assert rating == "not_assessed"
    assert score == 0.0


def test_partially_effective_with_single_policy_doc():
    eng = EffectivenessEngine()
    evidence = [{"source_type": "policy_doc"}]
    rating, score = eng.evaluate("A.9.1.1", "ISO27001", evidence)
    # policy_doc = 0.7 = 70%, which is >= 60% (partial) but < 85% (full)
    assert rating == "partially_effective"
    assert 60.0 <= score < 85.0


def test_score_within_0_100():
    eng = EffectivenessEngine()
    for stype in ["log_summary", "access_report", "config_snapshot", "scan_result", "policy_doc"]:
        _, score = eng.evaluate("ctrl", "FW", [{"source_type": stype}])
        assert 0.0 <= score <= 100.0


def test_multiple_corroboration_boosts_score():
    eng = EffectivenessEngine()
    single_rating, single_score = eng.evaluate("ctrl", "FW", [{"source_type": "access_report"}])
    multi_rating, multi_score = eng.evaluate("ctrl", "FW", [{"source_type": "access_report"}] * 5)
    assert multi_score > single_score


def test_unknown_source_type_uses_default():
    eng = EffectivenessEngine()
    rating, score = eng.evaluate("ctrl", "FW", [{"source_type": "unknown_xyz"}])
    assert rating in ("ineffective", "partially_effective")
