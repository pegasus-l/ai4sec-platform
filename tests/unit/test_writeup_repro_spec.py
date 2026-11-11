"""T2.2:``verification_spec`` 的校验。

判据只有一句: **spec 里每一句"文章这么说"都要能在原文里找到**。找不到的时候,
结论是 ``cannot_repro + article_incomplete``(原文没写清), 而不是我们自己补一步跑给他看 ——
补出来的步骤跑通, 证明的是我们的想象力。
"""
from __future__ import annotations

from ai4sec_platform.domains.capabilities.writeup_repro import spec as spec_module

ARTICLE = """# foo 管理接口越权

foo 1.2.3 的 /admin 没有鉴权, 任何人可读配置。

```bash
git clone https://github.com/acme/foo && cd foo && make
```

启动服务:

```bash
./foo --port 8080
```

然后请求管理接口:

```bash
curl -s http://127.0.0.1:8080/admin
```

返回 200 和配置内容, 即可复现。
"""

CLAIM_QUOTE = "foo 1.2.3 的 /admin 没有鉴权, 任何人可读配置。"
CLONE_QUOTE = "git clone https://github.com/acme/foo && cd foo && make"
START_QUOTE = "./foo --port 8080"
CURL_QUOTE = "curl -s http://127.0.0.1:8080/admin"


def _spec(**overrides):
    spec = {
        "sufficient": True,
        "claim": "未鉴权的用户可以读取配置",
        "claim_quote": CLAIM_QUOTE,
        "target": {"kind": "oss_repo", "repo": "https://github.com/acme/foo", "ref": "1.2.3", "setup": []},
        "steps": [
            {"run": "git clone https://github.com/acme/foo && cd foo && make", "expect": "编译完成", "source_quote": CLONE_QUOTE},
            {"run": "./foo --port 8080", "expect": "服务监听 8080", "source_quote": START_QUOTE},
            {"run": "curl -s http://127.0.0.1:8080/admin", "expect": "返回配置", "source_quote": CURL_QUOTE},
        ],
        "probe": {"type": "http_status", "cmd": "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/admin",
                  "success_signal": "stdout 等于 200"},
        "evidence": ["admin 响应正文"],
        "known_pitfalls": [],
    }
    spec.update(overrides)
    return spec


CANDIDATE = {"target_repo": "github:acme/foo", "target_version": "1.2.3", "url": "http://blog/1"}


# ---------------------------------------------------------------- 三条硬规则

def test_valid_spec_passes() -> None:
    check = spec_module.verify_spec(_spec(), ARTICLE, title="foo 管理接口越权", candidate=CANDIDATE)
    assert check.ok, check.reason
    assert [step["index"] for step in check.spec["steps"]] == [1, 2, 3]
    assert check.spec["target"]["repo"] == "github:acme/foo"


def test_claim_quote_that_is_not_in_the_article_is_not_a_verdict() -> None:
    """引用对不上 ⇒ spec 不成形(重试), **不是**"原文不可复现"。

    冒烟实测(84535): 同一素材同一 prompt, 第一次模型把第五步命令抄漏一截、第二次一字不差。
    单次对不上分不清谁的问题, 而 article_incomplete 是写进统计、记在作者头上的结论。
    """
    check = spec_module.verify_spec(_spec(claim_quote="作者说这里有个严重越权"), ARTICLE)
    assert check.verdict == "invalid"
    assert "claim_quote" in check.reason and "重试" in check.reason


def test_step_without_source_quote_is_rejected() -> None:
    """原文没写这一步 → 我们不替作者补; 但判"没写"要模型自己认(sufficient=false)。"""
    steps = list(_spec()["steps"])
    steps[1] = {"run": "docker run -p 8080:8080 acme/foo", "expect": "服务起来", "source_quote": ""}
    check = spec_module.verify_spec(_spec(steps=steps), ARTICLE)
    assert check.verdict == "invalid"
    assert "不替作者补" in check.reason


def test_step_quote_that_is_not_in_the_article_is_rejected() -> None:
    steps = list(_spec()["steps"])
    steps[1] = {**steps[1], "source_quote": "用 make install 安装到 /usr/local"}
    check = spec_module.verify_spec(_spec(steps=steps), ARTICLE)
    assert check.verdict == "invalid"
    assert "第 2 步" in check.reason


def test_placeholder_command_is_not_a_probe() -> None:
    check = spec_module.verify_spec(_spec(probe={"cmd": "...", "success_signal": "exit_code == 0"}), ARTICLE)
    assert check.verdict == "invalid"


def test_prose_success_signal_is_not_machine_checkable() -> None:
    """“服务正常启动了”这种句子既不能自动判, 也不能被第二个人复核。"""
    check = spec_module.verify_spec(_spec(probe={"cmd": "curl -s http://127.0.0.1:8080/admin",
                                                 "success_signal": "服务正常启动了"}), ARTICLE)
    assert check.verdict == "invalid"
    assert "机器判定" in check.reason


def test_insufficient_spec_becomes_article_incomplete() -> None:
    check = spec_module.verify_spec({"sufficient": False, "insufficient_reason": "没写怎么编译"}, ARTICLE)
    assert check.verdict == "article_incomplete" and check.reason == "没写怎么编译"


def test_empty_steps_is_invalid() -> None:
    check = spec_module.verify_spec(_spec(steps=[]), ARTICLE)
    assert check.verdict == "invalid"


def test_steps_are_capped() -> None:
    steps = [{"run": f"echo {i}", "expect": "", "source_quote": ""} for i in range(spec_module.MAX_STEPS + 5)]
    steps[0]["source_quote"] = CURL_QUOTE
    check = spec_module.verify_spec(_spec(steps=steps), ARTICLE, strict=False)
    assert len(check.spec["steps"]) == spec_module.MAX_STEPS
    assert any("步骤过多" in note for note in check.notes)


# ---------------------------------------------------------------- root_cause(§13.4)

def test_root_cause_pointing_at_a_real_line_is_fact() -> None:
    root = {"location": {"file": "/admin", "function": "", "lines": ""},
            "invariant": "读取配置前没有校验身份",
            "code_quote": CURL_QUOTE}
    check = spec_module.verify_spec(_spec(root_cause=root), ARTICLE)
    assert check.ok
    assert check.spec["root_cause"]["provenance"] == "llm_extracted"


def test_hallucinated_root_cause_is_downgraded_not_dropped() -> None:
    """位置对不上时保留答案但标成“没核对过” —— 行还有用, 但不能当事实展示。"""
    root = {"location": {"file": "src/auth.go", "function": "checkAdmin", "lines": "42-44"},
            "invariant": "读取配置前没有校验身份"}
    check = spec_module.verify_spec(_spec(root_cause=root), ARTICLE)
    assert check.ok
    assert check.spec["root_cause"]["provenance"] == "llm_extracted_unverified"
    assert check.spec["root_cause"]["caveats"]


# ---------------------------------------------------------------- 目标与人工编辑

def test_target_repo_must_be_supported_by_the_article() -> None:
    spec = _spec(target={"kind": "oss_repo", "repo": "https://github.com/acme/other", "ref": ""})
    check = spec_module.verify_spec(spec, ARTICLE, candidate=CANDIDATE)
    assert check.ok
    assert check.spec["target"]["repo"] == "github:acme/foo", "原文没写的仓库要退回预筛结论"
    assert any("目标仓库不可信" in note for note in check.notes)


def test_human_edit_is_not_vetoed_by_a_substring_check() -> None:
    """人工 spec 判定时优先(§5.3): 引用对不上只记 note, 不判 article_incomplete。"""
    spec = _spec(claim_quote="人肉整理的一句话")
    check = spec_module.verify_spec(spec, ARTICLE, strict=False)
    assert check.ok
    assert any("claim_quote" in note for note in check.notes)
    assert check.spec["verification"]["strict"] is False


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
        assert profile == spec_module.MODEL_PROFILE
        return self.provider


def _material():
    return {"id": 1, "title": "foo 管理接口越权", "url": "http://blog/1", "cleaned_text": ARTICLE}


def test_generate_spec_success_shape(monkeypatch) -> None:
    provider = _Provider(_spec())
    monkeypatch.setattr(spec_module, "LLMRouter", lambda: _Router(provider))
    outcome = spec_module.generate_spec(_material(), CANDIDATE)
    assert outcome["status"] == "success"
    assert outcome["spec"]["claim_quote"] == CLAIM_QUOTE
    assert provider.calls[0]["screener"]["target_repo"] == "github:acme/foo"


def test_generate_spec_error_is_not_a_conclusion(monkeypatch) -> None:
    monkeypatch.setattr(spec_module, "LLMRouter", lambda: _Router(_Provider(error=RuntimeError("HTTP 403"))))
    outcome = spec_module.generate_spec(_material(), CANDIDATE)
    assert outcome["status"] == "error" and outcome["spec"] == {}
    assert "403" in outcome["reason"]


def test_generate_spec_requires_explicit_sufficient(monkeypatch) -> None:
    """缺 sufficient 时不能默认成 True —— 那会把“没写清”读成“写得很清楚”。"""
    result = {key: value for key, value in _spec().items() if key != "sufficient"}
    monkeypatch.setattr(spec_module, "LLMRouter", lambda: _Router(_Provider(result)))
    outcome = spec_module.generate_spec(_material(), CANDIDATE)
    assert outcome["status"] == "error" and "sufficient" in outcome["reason"]


def test_generate_spec_rejects_non_dict(monkeypatch) -> None:
    monkeypatch.setattr(spec_module, "LLMRouter", lambda: _Router(_Provider(None)))
    outcome = spec_module.generate_spec(_material(), CANDIDATE)
    assert outcome["status"] == "error" and outcome["spec"] == {}
