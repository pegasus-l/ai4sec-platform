"""页面自检: 平台侧确定性检查(2026-10-29)。

背景: 复现 agent 只要 curl 到 200 就报 web_started=true, 实际两个任务分别是
「入口 js 全 404, 页面停在 Loading」和「REST 401, 页面报错连不上」。这里用无浏览器的
静态校验兜住: 首页 200 + 每个入口 js/css 资源 200 且 MIME 匹配 + 有可见正文或可执行脚本。
"""
from __future__ import annotations

import io

import pytest

from ai4sec_platform.pipelines.steps import repro


class _FakeResp:
    def __init__(self, body: str = "", status: int = 200, content_type: str = "text/html"):
        self._body = body.encode("utf-8")
        self.status = status
        self.headers = {"content-type": content_type}

    def read(self, _n: int = -1) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _fake_urlopen(mapping):
    def _open(url, timeout=None):  # noqa: ARG001
        for key, resp in mapping.items():
            if url.endswith(key):
                if isinstance(resp, Exception):
                    raise resp
                return resp
        raise AssertionError(f"unexpected url {url}")
    return _open


def test_html_visible_text_strips_script_style_and_tags():
    html = '<html><head><style>.a{}</style><script>var x=1</script></head><body><h1>你好</h1><p>世界</p></body></html>'
    assert repro._html_visible_text(html) == "你好 世界"


def test_page_refs_finds_scripts_and_stylesheets_only():
    html = (
        '<link rel="icon" href="/favicon.ico">'
        '<link href="css/app.css" rel="stylesheet">'
        '<script src="_framework/blazor.webassembly.js"></script>'
        '<script src="https://cdn.example.com/x.js"></script>'
    )
    assert repro._page_refs(html) == [("_framework/blazor.webassembly.js", "js"),
                                      ("https://cdn.example.com/x.js", "js"),
                                      ("css/app.css", "css")]


def test_strip_task_prefix_normalizes_user_facing_prefix():
    assert repro._strip_task_prefix("/insights/repro-web/task/7/assets/a.js", 7) == "/task/7/assets/a.js"
    assert repro._strip_task_prefix("/task/7/a.js", 7) == "/task/7/a.js"
    assert repro._strip_task_prefix("/assets/a.js", 7) == "/assets/a.js"


def _entry_html(refs: str, body: str = "") -> str:
    return f'<html><head><base href="/insights/repro-web/task/7/">{refs}</head><body>{body}</body></html>'


def test_check_web_page_reports_asset_served_as_html(monkeypatch):
    """入口 js 被 SPA 兜底成 text/html —— 就是 1025 那个「一直 Loading」的样子。"""
    html = _entry_html('<script src="_framework/blazor.webassembly.js"></script>', body="")
    monkeypatch.setattr(repro.urllib.request, "urlopen", _fake_urlopen({
        "/task/7/": _FakeResp(html),
        "/task/7/_framework/blazor.webassembly.js": _FakeResp(html, 200, "text/html; charset=utf-8"),
    }))
    check = repro._check_web_page("http://repro:4096", 7)
    assert check["ok"] is False
    assert check["resources_checked"] == 1
    assert any("text/html" in f for f in check["failed"])
    assert any("入口资源" in i for i in check["issues"])


def test_check_web_page_passes_when_assets_and_content_ok(monkeypatch):
    html = _entry_html('<script src="assets/app.js"></script><link rel="stylesheet" href="assets/app.css">',
                       body="<div id=root>欢迎使用控制台, 这里是首页正文</div>")
    monkeypatch.setattr(repro.urllib.request, "urlopen", _fake_urlopen({
        "/task/7/": _FakeResp(html),
        "/task/7/assets/app.js": _FakeResp("var a=1", 200, "text/javascript; charset=utf-8"),
        "/task/7/assets/app.css": _FakeResp("body{}", 200, "text/css; charset=utf-8"),
    }))
    check = repro._check_web_page("http://repro:4096", 7)
    assert check["ok"] is True
    assert check["resources_checked"] == 2
    assert check["visible_chars"] > 0


def test_check_web_page_flags_spa_shell_without_working_script(monkeypatch):
    """空壳首页 + 脚本 404: 没有可见正文, 也没有能跑起来的入口脚本。"""
    html = _entry_html('<script src="/assets/app.js"></script>', body="")
    monkeypatch.setattr(repro.urllib.request, "urlopen", _fake_urlopen({
        "/task/7/": _FakeResp(html),
        "/task/7/assets/app.js": OSError("boom"),
    }))
    check = repro._check_web_page("http://repro:4096", 7)
    assert check["ok"] is False
    assert any("请求失败" in f for f in check["failed"])
    assert any("没有可见正文" in i for i in check["issues"])


def test_check_web_page_handles_unreachable_entry(monkeypatch):
    monkeypatch.setattr(repro.urllib.request, "urlopen", _fake_urlopen({"/task/7/": OSError("refused")}))
    check = repro._check_web_page("http://repro:4096", 7)
    assert check["ok"] is False
    assert any("首页打不开" in i for i in check["issues"])


def test_apply_page_check_downgrades_success(monkeypatch):
    logs: list[str] = []
    monkeypatch.setattr(repro, "_append_log", lambda task_id, line: logs.append(line))
    monkeypatch.setattr(repro, "_check_web_page", lambda url, tid: {
        "ok": False, "method": "http-static-check", "visible_chars": 0,
        "resources_checked": 1, "failed": ["x → 404 text/html"], "issues": ["入口资源 1 个加载失败"],
    })
    report = {"status": "success", "web_started": True, "blockers": []}
    assert repro._apply_page_check(report, "success", "http://repro:4096", 7) == "partial"
    assert report["status"] == "partial"
    assert report["page_check"]["ok"] is False
    assert any("入口资源" in i for i in report["acceptance_issues"])
    assert any(b.startswith("页面自检:") for b in report["blockers"])
    assert logs


def test_apply_page_check_keeps_verdict_when_not_web_started(monkeypatch):
    monkeypatch.setattr(repro, "_check_web_page", lambda url, tid: pytest.fail("不该跑自检"))
    report = {"status": "failed", "web_started": False}
    assert repro._apply_page_check(report, "success", "http://repro:4096", 7) == "success"


def test_apply_page_check_never_breaks_task_on_self_error(monkeypatch):
    logs: list[str] = []
    monkeypatch.setattr(repro, "_append_log", lambda task_id, line: logs.append(line))

    def _boom(url, tid):
        raise RuntimeError("network down")

    monkeypatch.setattr(repro, "_check_web_page", _boom)
    report = {"status": "success", "web_started": True}
    assert repro._apply_page_check(report, "success", "http://repro:4096", 7) == "success"
    assert report["page_check"]["ok"] is None
    assert report["status"] == "success"


def test_report_tests_text_prefers_structured_report():
    text = repro._report_tests_text({"tests": {"framework": "pytest", "result": "pass"}}, "noise")
    assert '"framework": "pytest"' in text
    assert repro._report_tests_text({}, "pytest: 3 passed") != ""


def test_web_prompt_requires_render_and_tests():
    prompt = repro._build_repro_prompt("https://github.com/a/b", 7)
    assert "页面必须真的渲染出来" in prompt
    assert "scripts.test" in prompt
    # 浏览器是预装的: 提示词必须指向现成脚本, 且不能留"自己联网装"的老指令
    assert "node /workspace/.repro-web/render-check.js" in prompt
    assert "不要联网重装" in prompt
    assert "npx --yes playwright" not in prompt
    assert '"page_check"' in prompt and '"tests"' in prompt
    assert "/insights/repro-web/task/7/" in prompt


def test_web_prompt_carries_e0_evidence_requirements():
    """E0 证据链: 提示词必须要求可复核证据, 且由平台定级、agent 不自评。"""
    prompt = repro._build_repro_prompt("https://github.com/a/b", 7)
    assert "平台按证据算等级, 你不需要自己评级" in prompt
    # L1 构建 / L4 核心工作流: 要命令、退出码、真实响应片段
    assert chr(34) + "build" + chr(34) in prompt
    assert chr(34) + "exit_code" + chr(34) in prompt and chr(34) + "artifact" + chr(34) in prompt
    assert "core_workflow.evidence" in prompt
    assert "禁止只写" in prompt
    # L3 冒烟: 测试从「顺便跑」变成必跑
    assert "必须跑一套" in prompt and "平台按没跑处理" in prompt
    # partial 必须说清哪一部分坏了
    assert chr(34) + "partial_reason" + chr(34) in prompt and "哪一部分有问题" in prompt
    # 旧口径废止: 用 mock 不再自动降级, "未执行核心业务链不得报 success" 已删除
    assert "只能报 partial" not in prompt
    assert "未执行核心业务链不得报 success" not in prompt
