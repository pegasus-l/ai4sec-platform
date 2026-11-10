"""T1.2 预筛模型层:模型只指、规则来对(2026-11-10)。

这一层的失败模式有两种, 都不报错:

- 模型**编**一段 PoC —— 拿去复现, 跑不通, 而且看不出是文章的问题还是我们的问题;
- 模型把**别处**的仓库/版本填进来(它很懂这个漏洞, 只是原文没写) —— 复现的是另一个东西。

所以这里的用例几乎全在测"什么时候**不**认", 而不是测"什么时候认"。
"""
from __future__ import annotations

import pytest

from ai4sec_platform.domains.capabilities.writeup_repro import screener
from ai4sec_platform.domains.capabilities.writeup_repro.screener_rules import screen_rules

TEXT = """# foo 堆溢出

foo 2.3.1 的 parse() 有堆溢出, 作者给了完整 PoC。

```bash
git clone https://github.com/acme/foo
cd foo && git checkout 2.3.1
make
```

```c
int main(void) {
  char *p = malloc(8);
  memcpy(p, buf, 4096);
  return 0;
}
```

影响 foo <= 2.3.1。
"""

POC_C = "int main(void) {\n  char *p = malloc(8);\n  memcpy(p, buf, 4096);\n  return 0;\n}"

RESULT_OK = {
    "is_writeup": True,
    "has_poc": True,
    "poc_lang": "c",
    "poc_code": POC_C,
    "target_kind": "oss_repo",
    "target_repo": "https://github.com/acme/foo",
    "target_version": "2.3.1",
    "env_hint": "linux x86_64",
    "claimed_effect": "parse() 堆溢出, 可崩溃",
    "evidence_quote": "foo 2.3.1 的 parse() 有堆溢出, 作者给了完整 PoC。",
    "confidence": 0.92,
}


def _rule():
    return screen_rules(TEXT, title="foo 堆溢出")


def _outcome(result: dict | None = None, text: str = TEXT) -> dict:
    return {"rule": _rule(), "result": dict(result or RESULT_OK), "text": text}


# ---------------------------------------------------------------- PoC 校验

def test_poc_verbatim_from_article_is_accepted() -> None:
    ok, reason = screener.verify_poc(POC_C, TEXT, [])
    assert ok, reason


def test_poc_with_one_invented_line_is_rejected() -> None:
    """模型多写一行"帮你补全"的代码 —— 整段就不算原文了, 并要说清是几行对不上。"""
    code = POC_C.replace("  return 0;", "  return 0;\n  setuid(0);")
    ok, reason = screener.verify_poc(code, TEXT, [POC_C])
    assert not ok
    assert "1/6" in reason


def test_poc_whitespace_differences_are_tolerated() -> None:
    """换缩进/多空行不该被判成编造 —— 判据是内容不是排版。"""
    ok, _ = screener.verify_poc("  int main(void) {  \n\n char *p = malloc(8);", TEXT, [])
    assert ok


def test_empty_poc_is_not_verified() -> None:
    ok, reason = screener.verify_poc("", TEXT, [])
    assert not ok and "没给出" in reason


def test_poc_can_be_found_in_block_body_only() -> None:
    """正文被截断时, 块内容本身也是合法来源。"""
    body = "line_a\nline_b_is_long_enough_to_matter"
    ok, _ = screener.verify_poc("line_b_is_long_enough_to_matter", "无关正文", [body])
    assert ok


# ---------------------------------------------------------------- 仓库校验

def test_repo_normalizes_and_must_appear_in_text() -> None:
    repo, reason = screener.verify_repo("https://github.com/acme/foo.git", TEXT)
    assert repo == "github:acme/foo" and not reason


def test_repo_not_mentioned_in_article_is_rejected() -> None:
    """能归一 ≠ 可信: 模型凭常识填了另一个仓, 复现的就不是这篇文章的洞。"""
    repo, reason = screener.verify_repo("https://github.com/acme/bar", TEXT)
    assert repo == ""
    assert "在原文里找不到" in reason


def test_repo_that_cannot_be_normalized_is_rejected() -> None:
    repo, reason = screener.verify_repo("https://blog.example.com/post/1", TEXT)
    assert repo == "" and "归一不成仓库" in reason


# ---------------------------------------------------------------- 版本校验

def test_version_present_in_article_is_kept() -> None:
    assert screener.verify_version("2.3.1", TEXT) == ("2.3.1", "")


def test_version_absent_from_article_is_dropped() -> None:
    version, reason = screener.verify_version("9.9.9", TEXT)
    assert version == "" and "找不到" in reason


def test_empty_version_is_not_an_error() -> None:
    assert screener.verify_version("", TEXT) == ("", "")


# ---------------------------------------------------------------- 判定表

def test_app_menu_without_poc_is_no_poc() -> None:
    result = {**RESULT_OK, "has_poc": False, "poc_code": ""}
    assert screener.decide(_rule(), result, poc_ok=False, repo="", version="") == (False, "no_poc")


def test_listing_page_is_not_writeup() -> None:
    result = {**RESULT_OK, "is_writeup": False}
    assert screener.decide(_rule(), result, poc_ok=True, repo="", version="") == (False, "not_writeup")


def test_claimed_poc_that_cannot_be_found_is_its_own_bucket() -> None:
    """模型说有 PoC 但原文找不到 → poc_unverified, 不是 no_poc(后者会把模型缺陷记成文章问题)。"""
    result = {**RESULT_OK, "poc_code": "完全不存在的一段代码"}
    assert screener.decide(_rule(), result, poc_ok=False, repo="", version="") == (False, "poc_unverified")


def test_online_service_is_rejected_even_with_poc() -> None:
    result = {**RESULT_OK, "target_kind": "online_service"}
    assert screener.decide(_rule(), result, poc_ok=True, repo="", version="") == (False, "online_service")


SOLIDITY = """```c
#include <stdio.h>
int main(void) { return 0; }
```
"""


def test_self_contained_target_passes_without_any_repo() -> None:
    """原文自带完整漏洞目标(示例合约 / 靶场), 没有仓库也可以复现 —— 而且最省事。"""
    rule = screen_rules(SOLIDITY)
    assert rule.has_source and not rule.cve_ids and not rule.versions and not rule.target_repo
    result = {**RESULT_OK, "target_kind": "self_contained", "target_repo": "", "target_version": ""}
    assert screener.decide(rule, result, poc_ok=True, repo="", version="") == (True, "")


def test_self_contained_without_any_source_block_is_not_trusted() -> None:
    """只凭模型一句 self_contained 就放行 = 给这一档开无门槛后门, 必须有源码块才认。"""
    rule = screen_rules("```\njust some text\n```\n")
    assert not rule.has_source
    result = {**RESULT_OK, "target_kind": "self_contained", "target_repo": "", "target_version": ""}
    assert screener.decide(rule, result, poc_ok=True, repo="", version="") == (False, "target_unknown")


def test_no_target_clue_at_all_is_target_unknown() -> None:
    result = {**RESULT_OK, "target_kind": "unknown"}
    rule = screen_rules("```c\nint x;\n```\n", title="t")
    assert screener.decide(rule, result, poc_ok=True, repo="", version="") == (False, "target_unknown")


# ---------------------------------------------------------------- 落库行

def test_candidate_row_carries_verified_fields() -> None:
    row = screener.build_candidate(42, "2026-11-10T12:00:00Z", _outcome())
    assert row["material_id"] == 42
    assert row["screenable"] == 1 and row["reject_reason"] == ""
    assert row["target_repo"] == "github:acme/foo"
    assert row["target_version"] == "2.3.1"
    assert row["poc_verified"] == 1 and row["has_poc"] == 1
    assert row["rule_version"] == "rules-v2"
    assert '"confidence": 0.92' in row["screen_json"]


def test_candidate_row_never_touches_priority_columns() -> None:
    """优先级是后续步骤的结论, 重筛不许顺手清零(否则页面上成了"算过又没算过")。"""
    row = screener.build_candidate(42, "2026-11-10T12:00:00Z", _outcome())
    for column in ("priority", "asset_hit", "asset_ids", "asset_confidence", "priority_reason"):
        assert column not in row


def test_candidate_row_keeps_reject_reason_for_rejected_items() -> None:
    row = screener.build_candidate(7, "2026-11-10T12:00:00Z", _outcome({**RESULT_OK, "has_poc": False}))
    assert row["screenable"] == 0 and row["reject_reason"] == "no_poc"


def test_unknown_target_kind_falls_back_to_unknown() -> None:
    row = screener.build_candidate(1, "t", _outcome({**RESULT_OK, "target_kind": "whatever"}))
    assert row["target_kind"] == "unknown"


def test_contradictory_poc_is_recorded_in_notes() -> None:
    """摘出了原文里的代码却说没 PoC —— 按无 PoC 处理, 但要留痕, 别混进"文章没料"的桶。"""
    row = screener.build_candidate(1, "t", _outcome({**RESULT_OK, "has_poc": False}))
    assert row["screenable"] == 0 and row["reject_reason"] == "no_poc"
    assert "自相矛盾" in row["screen_json"]


def test_rule_only_row_marks_it_did_not_see_the_model() -> None:
    """规则层就拒的也留证, 但要标清没经过模型 —— 统计"模型编了多少"时不能算进分母。"""
    rule = screen_rules("这是一篇新闻, 没有代码。", title="新闻")
    row = screener.build_rule_only_candidate(5, "t", rule)
    assert row["screenable"] == 0 and row["reject_reason"] == "not_writeup"
    assert row["screened_by"] == "rules" and row["model_profile"] == ""
    assert row["rule_version"] == "rules-v2"


# ---------------------------------------------------------------- 送模型的内容

def test_payload_keeps_code_blocks_that_sit_beyond_the_excerpt() -> None:
    """长文的 PoC 常在几千字之后: 只发正文节选会让模型诚实地回一句"没有 PoC"。"""
    filler = "无关段落。" * 2000
    text = filler + "\n```bash\nmsfconsole -r exploit.rc\n```\n"
    rule = screen_rules(text)
    payload = screener.build_payload("t", "u", text, rule)
    assert len(payload["text_excerpt"]) < len(text)
    assert any("msfconsole" in block["code"] for block in payload["code_blocks"])


def test_payload_caps_the_number_of_blocks() -> None:
    text = "".join(f"```bash\ncurl http://x/{i}\n```\n" for i in range(20))
    payload = screener.build_payload("t", "u", text, screen_rules(text))
    assert len(payload["code_blocks"]) == screener.MAX_BLOCKS


def test_payload_includes_config_and_data_blocks_but_orders_commands_first() -> None:
    """规则层的分类只决定**顺序**, 不决定**能不能被看见** —— 见下面的回归用例。"""
    text = "```yaml\nkey: value\n```\n\n```bash\ncurl -s http://x\n```\n"
    payload = screener.build_payload("t", "u", text, screen_rules(text))
    assert len(payload["code_blocks"]) == 2
    assert "curl" in payload["code_blocks"][0]["code"]
    assert "kind" not in payload["code_blocks"][0]


def test_exploit_block_starting_with_comment_still_reaches_the_model() -> None:
    """GHSL/Quarkus 公告的真实形状(2026-11-10 踩到)。

    exploit 块以 ``#`` 注释开头, 规则层会把它判成 ``data``; 早先按 kind 过滤送模型,
    这一块就整块消失, 模型于是如实回答"没有 PoC" —— 而原文里那是完整可跑的两条 curl。
    """
    text = """CVE-2026-39852 的 PoC 如下:

```
# Normal request (blocked - requires authentication)
curl -i 'http://127.0.0.1:8080/api/admin'
# Response: 401 Unauthorized

# Bypass request
curl -i 'http://127.0.0.1:8080/api/admin;bypass'
# Response: 200 OK
```
"""
    rule = screen_rules(text)
    assert [b.kind for b in rule.blocks] == ["command"]
    assert rule.screenable
    payload = screener.build_payload("t", "u", text, rule)
    assert any("bypass" in block["code"] for block in payload["code_blocks"])


# ---------------------------------------------------------------- 模型调用

class _Provider:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    def complete_json(self, *, prompt, payload):
        self.calls.append(payload)
        if self.error:
            raise self.error
        return {"provider": "fake", "model": "fake-1", "result": self.result}


class _Router:
    def __init__(self, provider):
        self.provider = provider

    def provider_for(self, profile):
        assert profile == screener.MODEL_PROFILE
        return self.provider


def test_screen_material_success_shape(monkeypatch) -> None:
    provider = _Provider(RESULT_OK)
    monkeypatch.setattr(screener, "LLMRouter", lambda: _Router(provider))
    outcome = screener.screen_material({"id": 1, "title": "foo", "url": "", "cleaned_text": TEXT})
    assert outcome["status"] == "success"
    assert outcome["result"]["target_version"] == "2.3.1"
    assert provider.calls and "code_blocks" in provider.calls[0]


def test_screen_material_error_returns_no_conclusion(monkeypatch) -> None:
    """模型报错时 result 必须为空 —— 调用方据此跳过落库, 下一轮重试。"""
    provider = _Provider(error=RuntimeError("HTTP 403"))
    monkeypatch.setattr(screener, "LLMRouter", lambda: _Router(provider))
    outcome = screener.screen_material({"id": 1, "title": "foo", "url": "", "cleaned_text": TEXT})
    assert outcome["status"] == "error"
    assert outcome["result"] == {}
    assert "403" in outcome["reason"]


def test_screen_material_error_is_not_a_rejection(monkeypatch) -> None:
    """把报错记成 no_poc 是最难发现的一类谎 —— 这里锁住"它根本没走到判定"。"""
    provider = _Provider(error=RuntimeError("timeout"))
    monkeypatch.setattr(screener, "LLMRouter", lambda: _Router(provider))
    outcome = screener.screen_material({"id": 1, "title": "foo", "url": "", "cleaned_text": TEXT})
    assert "screenable" not in outcome and "reject_reason" not in outcome


def test_screen_material_rejects_non_dict_result(monkeypatch) -> None:
    class _Bad(_Provider):
        def complete_json(self, *, prompt, payload):
            return {"provider": "fake", "model": "m", "result": None}

    monkeypatch.setattr(screener, "LLMRouter", lambda: _Router(_Bad()))
    outcome = screener.screen_material({"id": 1, "title": "foo", "url": "", "cleaned_text": TEXT})
    assert outcome["status"] == "error"


def test_screen_material_rejects_result_missing_verdict_keys(monkeypatch) -> None:
    """缺 is_writeup/has_poc 时不能算 success —— 否则默认值会把它读成"没 PoC"。"""
    provider = _Provider({"target_repo": "https://github.com/acme/foo"})
    monkeypatch.setattr(screener, "LLMRouter", lambda: _Router(provider))
    outcome = screener.screen_material({"id": 1, "title": "foo", "url": "", "cleaned_text": TEXT})
    assert outcome["status"] == "error"
    assert "缺字段" in outcome["reason"]


@pytest.mark.parametrize("kind", screener.TARGET_KINDS)
def test_target_kinds_are_a_closed_set(kind: str) -> None:
    row = screener.build_candidate(1, "t", _outcome({**RESULT_OK, "target_kind": kind}))
    assert row["target_kind"] == kind
