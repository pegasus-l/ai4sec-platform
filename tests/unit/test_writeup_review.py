"""T4.2 独立复核: 只降不升、必须有引文、失败不改判。"""
from __future__ import annotations

import pytest

from ai4sec_platform.domains.capabilities.writeup_repro import review


def _evidence() -> dict:
    return {
        "probe": {"cmd": "curl -s http://127.0.0.1:8080/admin", "matched": True,
                  "stdout_tail": "HTTP/1.1 200 OK\n<h1>Login</h1>", "exit_code": 0},
        "commands": [
            {"cmd": "curl -s http://127.0.0.1:8080/admin", "exit_code": 0,
             "stdout_tail": "HTTP/1.1 200 OK\n<h1>Login</h1>"},
        ],
        "guard": {"allowed": True}, "egress": {"review_required": False},
    }


class _Provider:
    def __init__(self, result: dict) -> None:
        self.result = result

    def complete_json(self, *, prompt: str, payload: dict) -> dict:  # noqa: ARG002
        return {"result": self.result}


def _run(monkeypatch: pytest.MonkeyPatch, result: dict) -> dict:
    monkeypatch.setattr(review.LLMRouter, "provider_for", lambda self, profile: _Provider(result))
    return review.review(_evidence(), {"probe": {"success_signal": "stdout 包含 HTTP/1.1 200"}}, {})


def test_a_rejection_with_a_real_quote_is_recorded(monkeypatch: pytest.MonkeyPatch) -> None:
    out = _run(monkeypatch, {"review_verdict": "rejected", "quote": "<h1>Login</h1>",
                             "reason": "命中的是登录页, 漏洞没触发"})
    assert out["review_verdict"] == "rejected"
    assert out["quote_verified"] is True


def test_a_rejection_without_a_real_quote_is_downgraded(monkeypatch: pytest.MonkeyPatch) -> None:
    out = _run(monkeypatch, {"review_verdict": "rejected", "quote": "看起来像登录页"})
    assert out["review_verdict"] == "insufficient"
    assert out["quote_verified"] is False


def test_supported_needs_no_quote(monkeypatch: pytest.MonkeyPatch) -> None:
    out = _run(monkeypatch, {"review_verdict": "supported", "reason": "响应里带管理接口数据"})
    assert out["review_verdict"] == "supported"


def test_an_unparseable_verdict_is_an_error_not_a_rejection(monkeypatch: pytest.MonkeyPatch) -> None:
    out = _run(monkeypatch, {"review_verdict": "looks fine"})
    assert out["status"] == "error"


def test_conflict_downgrades_success_to_partial() -> None:
    verdict, reason, notes = review.apply(
        "success", "", [], {"status": "ok", "review_verdict": "rejected",
                            "quote_verified": True, "reason": "命中的是登录页", "quote": "<h1>Login</h1>"})
    assert verdict == "partial" and reason == "review_conflict"
    assert any("独立复核不认可" in note for note in notes)


def test_apply_never_upgrades_a_partial() -> None:
    verdict, reason, _ = review.apply(
        "partial", "probe_not_matched", [], {"status": "ok", "review_verdict": "supported"})
    assert verdict == "partial" and reason == "probe_not_matched"


def test_an_unsupported_review_changes_nothing() -> None:
    verdict, reason, _ = review.apply(
        "success", "", [], {"status": "ok", "review_verdict": "insufficient"})
    assert verdict == "success" and reason == ""


def test_failed_reviews_write_no_fields() -> None:
    assert review.fields({"status": "error"}) == {"review_verdict": "", "review_reason": ""}
    assert review.fields({"status": "ok", "review_verdict": "rejected", "reason": "x"})["review_verdict"] == "rejected"


def test_the_reviewer_can_be_switched_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WRITEUP_REVIEWER", "0")
    assert review.enabled() is False
    assert review.review(_evidence(), {}, {})["status"] == "disabled"
