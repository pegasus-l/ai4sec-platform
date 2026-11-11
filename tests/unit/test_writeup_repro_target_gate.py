"""T1.4 两刀(``rules-v3``,2026-11-11):无目标的稿子不再放行,但带编号的真产品洞不能一起丢。

背景:全量 1229 条素材跑完,102 条"可复现"里有 47 条既没有仓库也没有版本 ——
其中 16 条是纯教程(堆溢出入门 / chroot 逃逸 / ret2plt,该拒),6 条是真产品洞
(标题里就写着 CVE 号,只是抽取器没落字段),25 条只是正文顺带提到编号。

这一层要守住的四件事,每一件错了都**不会报错**:

- 教程类("文章自带完整示例")再也不能凭 ``self_contained`` 过关;
- "正文里出现过某个 CVE"不等于有目标 —— 编号必须能反查成产品/版本;
- 模型编出来的编号必须被原文校验挡住,否则会去复现另一个洞;
- **查不到 ≠ 查崩了**:OSV/NVD 挂掉时一个字都不许落库,下一轮重挑。
"""
from __future__ import annotations

import json
import sqlite3

from ai4sec_platform.core.config import load_settings
from ai4sec_platform.db.models import init_db
from ai4sec_platform.domains.capabilities.writeup_repro import (
    cve_targets,
    screener,
    screener_rules,
    store,
)
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.steps import writeup_repro as step_module
from ai4sec_platform.pipelines.steps.writeup_repro import ScreenWriteupMaterialsStep

#: 一篇典型的 F1 教程:有源码块、能照着做,但目标是文章自己写的演示程序,没有编号。
TUTORIAL = """# 堆溢出入门

覆盖相邻堆块里的函数指针,让 winner() 代替 nowinner()。

```c
int main(void) {
  char *p = malloc(8);
  memcpy(p, buf, 4096);
  return 0;
}
```

编译后运行, 打印 level passed。
"""
POC_C = "int main(void) {\n  char *p = malloc(8);\n  memcpy(p, buf, 4096);\n  return 0;\n}"

#: 模型自己读出了仓库的情况 —— 仓库必须真的在原文里(``verify_repo`` 会查)。
REPO_TEXT = TUTORIAL + "\n源码: https://github.com/acme/foo\n"

#: 一篇真有目标 CVE 的稿子:正文里没有仓库 URL、没有版本号,只有编号。
CVE_TEXT = """# FOO 符号链接陷阱

攻击者赢得符号链接竞态, 以 root 身份 chown /etc。

```bash
ln -sf /etc /tmp/x && ./trigger
```

影响 CVE-2026-31979。
"""

RESULT_TUTORIAL = {
    "is_writeup": True,
    "has_poc": True,
    "poc_lang": "c",
    "poc_code": POC_C,
    "target_kind": "self_contained",
    "target_repo": "",
    "target_version": "",
    "target_cve": "",
    "env_hint": "linux",
    "claimed_effect": "打印 level passed",
    "evidence_quote": "编译后运行, 打印 level passed。",
    "confidence": 0.9,
}


def _result(**overrides):
    row = dict(RESULT_TUTORIAL)
    row.update(overrides)
    return row


#: CVE_TEXT 里的 PoC 是那条 bash —— 摘录必须在原文里逐行找得到, 否则先挂在 poc_unverified,
#: 根本走不到目标判断。
CVE_POC = "ln -sf /etc /tmp/x && ./trigger"


def _cve_result(**overrides):
    row = _result(poc_lang="shell", poc_code=CVE_POC)
    row.update(overrides)
    return row


class _Provider:
    def __init__(self, result=None) -> None:
        self.result = result or RESULT_TUTORIAL
        self.calls = 0

    def complete_json(self, *, prompt, payload):
        self.calls += 1
        return {"provider": "fake", "model": "fake-1", "result": self.result}


class _Router:
    def __init__(self, provider) -> None:
        self.provider = provider

    def provider_for(self, profile):
        return self.provider


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


def _material(conn, item_id: int, text: str, title: str = "t") -> None:
    conn.execute(
        "INSERT INTO domain_items (id, domain, item_type, title, status, source, source_url, primary_date, payload_json, created_at, updated_at) "
        "VALUES (?, 'vulnerabilities', 'material', ?, 'active', 'src', 'http://x', '2026-11-01', ?, 'now', 'now')",
        (item_id, title, json.dumps({"cleaned_text": text})),
    )
    conn.commit()


def _ctx(conn, **params) -> PipelineContext:
    return PipelineContext(
        run_id="run_v3", pipeline_name="capabilities.writeup_repro_prescreen",
        domain="capabilities", settings=load_settings(), conn=conn,
        artifact_store=object(), params=params,
    )


def _patch_model(monkeypatch, provider) -> None:
    monkeypatch.setattr(screener, "LLMRouter", lambda: _Router(provider))


def _patch_resolver(monkeypatch, resolver) -> None:
    """把步骤里构造的 resolver 换掉 —— 单测不许碰网络。"""
    monkeypatch.setattr(step_module, "CaseTargetResolver", lambda conn, **kw: resolver)


# ---------------------------------------------------------------- 第一刀:不再放行

def test_self_contained_tutorial_is_rejected(monkeypatch) -> None:
    """F1 教程: 有源码块、模型说 self_contained, 但没有任何目标 —— 拒。"""
    conn = _conn()
    _material(conn, 1, TUTORIAL)
    _patch_model(monkeypatch, _Provider())

    ScreenWriteupMaterialsStep().run(_ctx(conn))

    row = store.get_candidate(conn, 1)
    assert row["screenable"] == 0
    assert row["reject_reason"] == "target_unknown"
    assert row["target_source"] == ""


def test_cve_mentioned_in_body_is_not_a_target(monkeypatch) -> None:
    """正文里出现过编号不再自动放行: 编号只是线索, 要能反查成产品才算目标。

    而且**只有正文提到、模型没指认、标题里也没有**的编号, 连查都不该去查 ——
    T1.4 实测这种有 25 条, 编号全是文章举的例子(CSP 手册提到 CVE-2020-6519)。
    """
    conn = _conn()
    _material(conn, 2, CVE_TEXT)
    _patch_model(monkeypatch, _Provider(_cve_result(target_kind="unknown")))
    _patch_resolver(monkeypatch, lambda cve: (_ for _ in ()).throw(AssertionError("不该拿正文顺带提到的编号去查")))

    metrics = ScreenWriteupMaterialsStep().run(_ctx(conn)).metrics

    row = store.get_candidate(conn, 2)
    assert row["screenable"] == 0
    assert row["reject_reason"] == "target_unknown"
    assert row["target_cve"] == ""
    assert metrics["cve_unresolved"] == 0
    # 编号本身仍留在 rule_json 里, 事后复查"它当时提到过哪些编号"不用重跑
    assert "CVE-2026-31979" in row["rule_json"]["cve_ids"]


# ---------------------------------------------------------------- 第二刀:查到就留下

def test_resolved_cve_fills_the_target(monkeypatch) -> None:
    """F2: 模型给不出仓库/版本, 但编号查到了产品 —— 放行, 并记清是谁给的。"""
    conn = _conn()
    _material(conn, 3, CVE_TEXT)
    _patch_model(monkeypatch, _Provider(_cve_result(target_kind="unknown", target_cve="CVE-2026-31979")))
    _patch_resolver(monkeypatch, lambda cve: cve_targets.ResolvedTarget(
        repo="github:acme/foo", version="< 1.4.2", source="osv", cve=cve,
    ))

    metrics = ScreenWriteupMaterialsStep().run(_ctx(conn)).metrics

    row = store.get_candidate(conn, 3)
    assert row["screenable"] == 1
    assert row["target_repo"] == "github:acme/foo"
    assert row["target_version"] == "< 1.4.2"
    assert row["target_source"] == "osv"
    assert row["target_cve"] == "CVE-2026-31979"
    assert metrics["cve_resolved"] == 1


def test_resolved_target_corrects_self_contained_kind(monkeypatch) -> None:
    """模型把它当"文章自带的样例", 反查却查到了真实仓库 —— 分类必须纠正。

    否则下游按 ``self_contained`` 准备环境, 复现的是文章里那个演示程序, 而不是真产品。
    """
    conn = _conn()
    _material(conn, 9, CVE_TEXT)
    _patch_model(monkeypatch, _Provider(_cve_result(
        target_kind="self_contained", target_cve="CVE-2026-31979",
    )))
    _patch_resolver(monkeypatch, lambda cve: cve_targets.ResolvedTarget(
        repo="github:acme/foo", source="osv", cve=cve,
    ))

    ScreenWriteupMaterialsStep().run(_ctx(conn))

    row = store.get_candidate(conn, 9)
    assert row["screenable"] == 1
    assert row["target_kind"] == "oss_repo"


def test_model_supplied_repo_is_marked_as_model(monkeypatch) -> None:
    """模型自己读出来的仓库不该被算成"反查救回来的"。"""
    conn = _conn()
    _material(conn, 4, REPO_TEXT)
    _patch_model(monkeypatch, _Provider(_result(
        target_kind="oss_repo", target_repo="https://github.com/acme/foo", target_version="",
    )))
    _patch_resolver(monkeypatch, lambda cve: (_ for _ in ()).throw(AssertionError("不该查")))

    ScreenWriteupMaterialsStep().run(_ctx(conn))

    row = store.get_candidate(conn, 4)
    assert row["screenable"] == 1
    assert row["target_repo"] == "github:acme/foo"
    assert row["target_source"] == "model"


def test_hallucinated_target_cve_is_not_used(monkeypatch) -> None:
    """模型编了个原文里没有的编号 —— 不许拿去查, 否则复现的是另一个洞。"""
    conn = _conn()
    _material(conn, 5, TUTORIAL)
    _patch_model(monkeypatch, _Provider(_result(target_cve="CVE-2024-99999")))
    _patch_resolver(monkeypatch, lambda cve: (_ for _ in ()).throw(AssertionError("编的编号不该去查")))

    ScreenWriteupMaterialsStep().run(_ctx(conn))

    row = store.get_candidate(conn, 5)
    assert row["target_cve"] == "", "原文里找不到的编号必须丢弃"
    assert row["screenable"] == 0


def test_title_cve_is_used_when_model_gives_none(monkeypatch) -> None:
    """实测有文章的编号只写在标题里; 标题是确定性的, 模型漏了也能救。"""
    conn = _conn()
    _material(conn, 6, TUTORIAL, title="CVE-2025-30208: Vite @fs 路径遍历")
    _patch_model(monkeypatch, _Provider())
    calls = []

    def _resolver(cve):
        calls.append(cve)
        return cve_targets.ResolvedTarget(repo="github:vitejs/vite", source="osv", cve=cve)

    _patch_resolver(monkeypatch, _resolver)
    ScreenWriteupMaterialsStep().run(_ctx(conn))

    assert calls == ["CVE-2025-30208"]
    assert store.get_candidate(conn, 6)["screenable"] == 1


# ---------------------------------------------------------------- 查崩了不是结论

def test_lookup_unavailable_is_not_persisted(monkeypatch) -> None:
    conn = _conn()
    _material(conn, 7, CVE_TEXT)
    _patch_model(monkeypatch, _Provider(_cve_result(target_kind="unknown", target_cve="CVE-2026-31979")))

    def _boom(cve):
        raise cve_targets.TargetLookupUnavailable("osv 502; nvd 502")

    _patch_resolver(monkeypatch, _boom)
    metrics = ScreenWriteupMaterialsStep().run(_ctx(conn)).metrics

    assert store.get_candidate(conn, 7) is None, "外部源挂了不许落成 target_unknown"
    assert metrics["lookup_unavailable"] == 1
    assert metrics["written"] == 0


def test_deferred_lookup_is_not_persisted_and_comes_back(monkeypatch) -> None:
    conn = _conn()
    _material(conn, 8, CVE_TEXT)
    _patch_model(monkeypatch, _Provider(_cve_result(target_kind="unknown", target_cve="CVE-2026-31979")))

    def _defer(cve):
        raise cve_targets.LookupDeferred("预算用完")

    _patch_resolver(monkeypatch, _defer)
    first = ScreenWriteupMaterialsStep().run(_ctx(conn)).metrics

    assert store.get_candidate(conn, 8) is None
    assert first["lookup_deferred"] == 1

    _patch_resolver(monkeypatch, lambda cve: cve_targets.ResolvedTarget(product="linux:linux_kernel", source="nvd", cve=cve))
    second = ScreenWriteupMaterialsStep().run(_ctx(conn)).metrics

    assert second["pending"] == 1, "上一轮没查成的素材必须被重新挑出来"
    assert store.get_candidate(conn, 8)["target_product"] == "linux:linux_kernel"


# ---------------------------------------------------------------- resolver 本体

class _FakeOsv:
    def __init__(self, payload=None, error: Exception | None = None) -> None:
        self.payload = payload
        self.error = error
        self.calls = 0

    def lookup(self, cve: str):
        self.calls += 1
        if self.error:
            raise self.error
        return self.payload


class _FakeNvd:
    def __init__(self, item=None, error: Exception | None = None) -> None:
        self.item = item
        self.error = error
        self.calls = 0

    def fetch_by_id(self, cve: str):
        self.calls += 1
        if self.error:
            raise self.error
        return self.item


def _case(conn, cve: str, *, products=(), ranges=(), refs=()) -> None:
    conn.execute(
        "INSERT INTO vulnerability_cases (canonical_id, affected_products_json, affected_ranges_json, "
        "references_json, created_at, updated_at) VALUES (?, ?, ?, ?, 'now', 'now')",
        (cve, json.dumps(list(products)), json.dumps(list(ranges)), json.dumps(list(refs))),
    )
    conn.commit()


def test_resolver_reads_the_case_library_first() -> None:
    """案例库是零成本的, 有答案时连连接器都不该碰。"""
    conn = _conn()
    _case(conn, "CVE-2021-44228", products=["Maven:org.apache.logging.log4j:log4j-core"],
          ranges=["ECOSYSTEM: introduced 0; fixed 2.15.0"],
          refs=["https://github.com/apache/logging-log4j2/commit/abc"])
    osv, nvd = _FakeOsv(), _FakeNvd()
    resolved = cve_targets.CaseTargetResolver(conn, osv=osv, nvd=nvd)("CVE-2021-44228")

    assert resolved.repo == "github:apache/logging-log4j2"
    assert resolved.version == "< 2.15.0"
    assert resolved.source == "db"
    assert (osv.calls, nvd.calls) == (0, 0)


def test_resolver_skips_cve_record_mirror_repos() -> None:
    """``CVEProject/cvelistV5`` 这类镜像仓不是代码所在 —— 认成目标等于复现别人的仓库。"""
    assert cve_targets.repo_from_urls([
        "https://github.com/CVEProject/cvelistV5/tree/main/cves/2025/30xxx/CVE-2025-30208.json",
        "https://github.com/vitejs/vite/security/advisories/GHSA-x574-m823-4x7w",
    ]) == "github:vitejs/vite"


def test_resolver_uses_osv_affected_range_and_references() -> None:
    conn = _conn()
    osv = _FakeOsv({
        "id": "GHSA-x574-m823-4x7w",
        "aliases": ["CVE-2025-30208"],
        "affected": [{
            "package": {"ecosystem": "npm", "name": "vite"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "5.4.15"}]}],
        }],
        "references": [{"type": "FIX", "url": "https://github.com/vitejs/vite/commit/315695e"}],
    })
    resolved = cve_targets.CaseTargetResolver(conn, osv=osv, nvd=_FakeNvd())("CVE-2025-30208")

    assert resolved.repo == "github:vitejs/vite"
    assert resolved.version == "< 5.4.15"
    assert resolved.product == "npm:vite"
    assert resolved.source == "osv"


def test_resolver_falls_back_to_nvd_cpe() -> None:
    """OSV 没有的洞(厂商私有 CVE / 小众项目)只剩 NVD 的 CPE 可用。"""
    conn = _conn()
    nvd = _FakeNvd({"cve": {
        "id": "CVE-2016-0040",
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True,
            "criteria": "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "10.0.14393",
        }]}]}],
        "references": [],
    }})
    resolved = cve_targets.CaseTargetResolver(conn, osv=_FakeOsv(), nvd=nvd)("CVE-2016-0040")

    assert resolved.product == "microsoft:windows_10"
    assert resolved.version == "< 10.0.14393"
    assert resolved.source == "nvd"


def test_resolver_returns_empty_when_both_sources_answer_not_found() -> None:
    """404 是结论(查过、没有), 不是异常 —— 调用方按 target_unknown 拒。"""
    resolved = cve_targets.CaseTargetResolver(_conn(), osv=_FakeOsv(None), nvd=_FakeNvd(None))("CVE-2024-99999")
    assert not resolved.usable


def test_resolver_raises_when_every_source_fails() -> None:
    resolver = cve_targets.CaseTargetResolver(
        _conn(),
        osv=_FakeOsv(error=RuntimeError("502")),
        nvd=_FakeNvd(error=RuntimeError("timeout")),
    )
    try:
        resolver("CVE-2024-99999")
    except cve_targets.TargetLookupUnavailable:
        return
    raise AssertionError("两个源都挂了必须抛 TargetLookupUnavailable, 不能当成'查不到'")


def test_resolver_budget_defers_instead_of_rejecting() -> None:
    resolver = cve_targets.CaseTargetResolver(_conn(), osv=_FakeOsv(None), nvd=_FakeNvd(None), max_lookups=1)
    resolver("CVE-2024-0001")          # 用掉唯一一次预算(两个源都回答"没有")
    try:
        resolver("CVE-2024-0002")
    except cve_targets.LookupDeferred:
        return
    raise AssertionError("预算用完必须抛 LookupDeferred —— 用'没查'冒充'没有'会把好稿子判死")


def test_version_from_ranges_ignores_git_commits() -> None:
    assert cve_targets.version_from_ranges(["GIT: introduced 0, fixed dec3693cbb151b46"]) == ""
    assert cve_targets.version_from_ranges(["SEMVER: introduced 0; fixed 1.2.3"]) == "< 1.2.3"
    assert cve_targets.version_from_ranges([]) == ""


def test_rule_version_is_bumped() -> None:
    assert screener_rules.SCREENER_VERSION == "rules-v3"
