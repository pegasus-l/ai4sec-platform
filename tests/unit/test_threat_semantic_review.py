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
    # 提示词 2026-10 重写过: 现在只要模型做三件事 —— 攻击面校准 / CVE 优先级 / 挖洞假设。
    # `broad_sec_items` 仍然随 payload 发出去(下面有断言), 只是提示词不再点名它,
    # 所以"prompt 里必须有 broad_sec_items"这条旧断言已经不成立。
    assert "attack_surface" in prompt
    assert "cve_priority" in prompt
    assert "hypotheses" in prompt
    assert payload["attack_surface"]["grade"] == "A"
    assert payload["cves"][0]["cve_id"] == "CVE-2024-12345"
    assert payload["broad_sec_items"][0]["description"] == "possible injection"


def test_normalize_semantic_review_schema() -> None:
    # 清洗函数跟着提示词一起改过: 输出契约变成"攻击面校准 + CVE 优先级 + 挖洞假设",
    # 旧的 `recommended_tracking_level` / `recommended_actions` / `false_positive_risks`
    # 这套字段已经不再产出(旧用例按旧契约断言, 一直在 KeyError)。
    review = _normalize_semantic_review(
        {
            "summary": "高风险内核攻击面",
            "calibrated_surface": "kernel",
            "calibrated_score": 82,
            "attack_surface_calibration": "规则说 parser/codec, 实际是 kernel",
            "rule_score_assessment": "规则评分偏低",
            "cve_priority": [{"cve_id": "CVE-2024-12345", "value": "high", "reason": "解析器可达"}],
            "false_positives": "普通 bug 混入",
            "hypotheses": ["解析器内存破坏"],
            "confidence": 0.86,
        }
    )
    assert review["summary"] == "高风险内核攻击面"
    assert review["calibrated_surface"] == "kernel"
    assert review["calibrated_score"] == 82
    assert review["cve_priority"][0]["value"] == "high"
    # 单值会包成列表(`_as_list`), 老模型回 "普通 bug 混入" 这种字符串也不能让下游炸
    assert review["false_positives"] == ["普通 bug 混入"]
    assert review["hypotheses"] == ["解析器内存破坏"]
    assert review["confidence"] == 0.86
    # 旧字段不许"复活": 复活意味着有人在没改提示词的情况下又写回旧契约
    assert "recommended_tracking_level" not in review
