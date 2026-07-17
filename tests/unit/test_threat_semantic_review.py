from __future__ import annotations

from ai4sec_platform.pipelines.steps.threat_risk import _normalize_semantic_review, _semantic_review_payload, _semantic_review_prompt


def test_threat_semantic_review_payload_contains_agent_judgement_inputs() -> None:
    target = {
        "id": 1,
        "title": "openharmony/kernel_linux_4.19",
        "summary": "kernel CVE security patches",
        "score": 92,
        "status": "高风险待研判",
        "source_url": "https://gitcode.com/openharmony/kernel_linux_4.19",
        "payload": {
            "attack_surface": {"grade": "A", "breakdown": {"historical_cve": 15}},
            "scoring": {"score": 92},
            "vulnerability_signals": {"cve_count": 6, "sample_security_items": [{"description": "RCE parser crash"}]},
            "cves": [{"cve_id": "CVE-2024-12345", "severity": "critical"}],
            "sa_items": [{"sa_id": "OpenHarmony-SA-2024-0001", "severity": "high"}],
            "broad_sec_items": [{"description": "possible injection", "source_type": "project_issue"}],
            "raw": {"description": "kernel parser security boundary"},
        },
    }
    prompt = _semantic_review_prompt()
    payload = _semantic_review_payload(target)
    assert "broad_sec_items" in prompt
    assert "attack_surface" in prompt
    assert payload["attack_surface"]["grade"] == "A"
    assert payload["cves"][0]["cve_id"] == "CVE-2024-12345"
    assert payload["broad_sec_items"][0]["description"] == "possible injection"


def test_normalize_semantic_review_schema() -> None:
    review = _normalize_semantic_review(
        {
            "summary": "高风险内核攻击面",
            "is_real_security_target": True,
            "valid_security_findings": ["critical CVE"],
            "false_positive_risks": "普通 bug 混入",
            "attack_surface_summary": "kernel/parser",
            "vulnerability_hypotheses": ["解析器内存破坏"],
            "recommended_tracking_level": "高风险跟踪",
            "recommended_actions": ["核验修复版本"],
            "confidence": 0.86,
        }
    )
    assert review["summary"] == "高风险内核攻击面"
    assert review["recommended_tracking_level"] == "高风险跟踪"
    assert review["false_positive_risks"] == ["普通 bug 混入"]
    assert review["confidence"] == 0.86
