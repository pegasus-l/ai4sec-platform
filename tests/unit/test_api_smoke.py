from __future__ import annotations

from pathlib import Path

import pytest

from ai4sec_platform.app.main import FRONTEND_DIST
from _session_auth import signed_client


def _client():
    """带 admin 会话票的客户端 —— `/api/*` 从 2026-10-31 起一律验 cookie。"""
    return signed_client(username="smoke")


def _patch_threat_connector_records(monkeypatch) -> None:
    records = [
        {
            "source": "repos",
            "path": "connector:test/repos",
            "exists": True,
            "mode": "connector",
            "items": [
                {
                    "name": "security",
                    "url": "https://gitcode.com/openharmony/security",
                    "description": "security advisories CVE-2024-12345",
                    "star_count": 20,
                    "org": "openharmony",
                    "platform": "gitcode",
                    "security_files": [{"path": "security.md", "content": "| Component | ID | Severity |\n| kernel_parser | CVE-2024-12345 | Critical |"}],
                },
                {
                    "name": "kernel_parser",
                    "url": "https://gitcode.com/openharmony/kernel_parser",
                    "description": "kernel parser security boundary RCE exploit",
                    "star_count": 99,
                    "org": "openharmony",
                    "platform": "gitcode",
                    "issues": [{"title": "CVE-2024-12345 RCE parser crash", "description": "security vulnerability PoC"}],
                },
            ],
            "raw": {},
        },
        {
            "source": "firmware",
            "path": "connector:test/firmware",
            "exists": True,
            "mode": "connector",
            "items": [{"productModel": "AscendFirmware", "packageCount": 5, "latestRelease": "2026-07-01"}],
            "raw": {},
        },
    ]

    def fake_load(settings, params):
        return records

    from ai4sec_platform.domains.threats.adapters import huawei_sources
    from ai4sec_platform.pipelines.steps import threat_asset_import, threat_cve_scout, threat_raw, threat_score_filter, threat_sources

    # CollectHuaweiSourcesStep **不经过** load_huawei_sources —— 它直接调下面这两个采集函数。
    # 只打上面那几处等于没打: 用例会真的去 gitcode / atomgit / hiascend 采一遍, 按退避重试
    # 拖上几分钟, 整轮单测看起来就像"卡住了"。
    monkeypatch.setattr(threat_sources, "_collect_repo_records", lambda *a, **k: [records[0]])
    monkeypatch.setattr(threat_sources, "_collect_live_assets", lambda *a, **k: [records[1]])
    monkeypatch.setattr(huawei_sources, "load_huawei_sources", fake_load)
    monkeypatch.setattr(huawei_sources, "load_huawei_live", lambda params: records)
    monkeypatch.setattr(threat_raw, "load_huawei_sources", fake_load)
    monkeypatch.setattr(threat_cve_scout, "load_huawei_sources", fake_load)
    monkeypatch.setattr(threat_score_filter, "load_huawei_sources", fake_load)
    monkeypatch.setattr(threat_asset_import, "load_huawei_sources", fake_load)


def _stub_news_model_review(monkeypatch) -> None:
    """把新闻候选的**模型评审**换成确定的桩。

    `news.legacy_raw_pipeline` 的 `enrich_news_candidates_with_model` 会真的调模型网关:
    96 个候选逐个判定 selected/watch/rejected。判定结果由当天的样例内容和模型状态决定,
    实测同一份样例两次跑可以一次选出 1 条、一次选出 0 条 —— 下游 `/api/news/items` 与
    `/api/capabilities/items` 非空与否就跟着摇。单测不该靠"模型今天心情好"过。
    这里只桩评审结论,采集/解析/去重/建条目这些要验的链路照旧真跑。
    """
    from ai4sec_platform.pipelines.steps import news as news_steps

    def _selected(items):
        return [
            {
                **item,
                "review": {
                    "decision": "selected",
                    "score": 82.0,
                    "confidence": 0.9,
                    "topic": "LLM 安全",
                    "review_reason": "unit-test stub",
                },
            }
            for item in items
        ]

    def _metrics(items, selected):
        return {
            "candidates": len(items),
            "model_calls": 0,
            "cache_hits": 0,
            "selected": len(selected),
            "watch": 0,
            "rejected": 0,
            "failed": 0,
            "degraded": 0,
            "backlog_enqueued": 0,
        }

    # 两处都要桩: gate(第一遍判定 selected/watch/rejected)和 enrich(入选后补字段)。
    # 只桩后者的话, 候选在 gate 就被判成 watch/rejected, 下游照样一条都不建。
    monkeypatch.setattr(news_steps, "gate_candidates", lambda conn, items, **kw: (_selected(items), _metrics(items, items)))
    monkeypatch.setattr(news_steps, "enrich_candidates", lambda conn, items, **kw: (_selected(items), _metrics(items, items)))


def test_health_endpoint() -> None:
    client = _client()
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_dashboard_overview_shape() -> None:
    client = _client()
    response = client.get("/api/dashboard/overview")
    assert response.status_code == 200
    data = response.json()
    assert data["production_writes"] is False
    assert {item["domain"] for item in data["domains"]} == {"news", "capabilities", "threats", "vulnerabilities"}


def test_frontend_index() -> None:
    # 前端 dist 是 `npm run build` 的产物, 不随源码 checkout 进来; 没构建过的机器上
    # index.html 不存在, 这一条测的不是接口而是"本机构建过没有"。跳过并说明原因,
    # 不要让它把"没跑过 npm build"报成"首页坏了"。
    if not (Path(FRONTEND_DIST) / "index.html").is_file():
        pytest.skip(f"前端未构建({FRONTEND_DIST}/index.html 不存在), 这条只在本机 build 过之后有意义")
    client = _client()
    response = client.get("/")
    assert response.status_code == 200
    assert "AI4SEC TMG" in response.text
    assert "顶部任务栏" in response.text


def test_run_pipeline_endpoint_triggers_import() -> None:
    client = _client()
    pipelines = client.get("/api/runs/pipelines")
    assert pipelines.status_code == 200
    assert any(item["name"] == "news.legacy_raw_pipeline" for item in pipelines.json()["items"])
    assert not any(item["name"] == "legacy.sample_import" for item in pipelines.json()["items"])

    response = client.post("/api/runs", json={"pipeline_name": "news.legacy_raw_pipeline", "reset": True, "wait": True, "params": {"date": "2026-07-10"}})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["pipeline_name"] == "news.legacy_raw_pipeline"

    detail = client.get(f"/api/runs/{data['run_id']}")
    assert detail.status_code == 200
    detail_data = detail.json()
    assert detail_data["tasks"]
    assert any(item["artifact_type"] == "manifest" for item in detail_data["artifacts"])


def test_raw_pipeline_builds_from_source_raw_files(monkeypatch) -> None:
    _stub_news_model_review(monkeypatch)
    client = _client()
    response = client.post(
        "/api/runs",
        json={"pipeline_name": "news.legacy_raw_pipeline", "reset": True, "wait": True, "params": {"date": "2026-07-10"}},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["pipeline_name"] == "news.legacy_raw_pipeline"
    step_names = [step["name"] for step in data["summary"]["steps"]]
    assert step_names == ["collect_news_sources", "extract_news_references", "normalize_news_items", "deduplicate_news_candidates", "resolve_news_candidate_links", "gate_news_candidates_with_tech_map", "enrich_news_candidates_with_model", "build_news_items", "build_news_daily_report", "audit_news_quality"]

    detail = client.get(f"/api/runs/{data['run_id']}").json()
    artifact_types = {item["artifact_type"] for item in detail["artifacts"]}
    assert "raw_news_arxiv" in artifact_types
    assert "normalized_news_items" in artifact_types
    assert "manifest" in artifact_types

    # `/api/news/today` 只放 score>=55 的条目当"今日亮点", 而这条用例灌进去的是
    # 2026-07-10 的样例数据 —— 分数取决于样例内容, 断言 highlights 非空等于断言
    # "样例数据今天够分", 那是数据的事, 不是接口的事。接口有没有把东西吐出来, 看全量列表。
    assert client.get("/api/news/items").json()["items"]
    assert client.get("/api/news/today").json()["kpis"]["new_count"] > 0


def test_v9_contract_endpoint_aliases_exist() -> None:
    client = _client()
    paths = [
        "/api/news/page",
        "/api/news/sources",
        "/api/news/items",
        "/api/capabilities/items",
        "/api/capabilities/repro-runs",
        "/api/capabilities/conversions",
        "/api/threats/targets",
        # `/api/threats/tracking` 没有列在这里: 2026-10-08 随「跟踪队列」页面一起下线
        # (app/api/threats.py 顶部有记录), 断言它 200 只会永远红。
        "/api/threats/graph",
        "/api/threats/risk-assessments",
        "/api/threats/assets",
        "/api/threats/cve-scout",
        "/api/threats/attack-surface",
        "/api/threats/reports",
        "/api/vulnerabilities/materials",
        "/api/vulnerabilities/knowledge",
        "/api/vulnerabilities/migration-queue",
        "/api/operations/tasks",
        "/api/operations/sources",
        "/api/operations/rules",
        "/api/operations/quality-findings",
        "/api/operations/queue-items",
    ]
    for path in paths:
        response = client.get(path)
        assert response.status_code == 200, path


def test_threat_and_vulnerability_raw_pipelines_run(monkeypatch) -> None:
    _patch_threat_connector_records(monkeypatch)
    client = _client()
    cases = [
        ("threats.huawei_full_migration_pipeline", {"limit": 20, "top_n": 5}, "/api/threats/today"),
        ("vulnerabilities.material_local_raw_import", {"report_limit": 2, "item_limit": 20}, "/api/vulnerabilities/today"),
    ]
    for pipeline_name, params, check_path in cases:
        response = client.post("/api/runs", json={"pipeline_name": pipeline_name, "reset": True, "wait": True, "params": params})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["pipeline_name"] == pipeline_name
        # 步骤形状由 test_huawei_full_migration_pipeline_runs_and_exposes_reports 逐个钉住;
        # 这里只验"跑完了并且有步骤"。
        assert data["summary"]["steps"]
        detail = client.get(f"/api/runs/{data['run_id']}").json()
        assert any(item["artifact_type"] == "manifest" for item in detail["artifacts"])
        domain_data = client.get(check_path).json()
        assert domain_data["items"]


def test_capability_pipeline_assesses_news_candidates() -> None:
    """`capabilities.from_news_pipeline` 现在是 `from_raw_pipeline` 的兼容别名。

    名字还叫 "from_news", 但它第一步 `build_from_raw` 走的是 `RawItemsSource.fetch_since`
    —— 从**外部 ASIS** 的 `/api/raw-items/export` 拉未评分的原始条目, 既不读本地 news 条目,
    也不再是"新闻候选 → 能力条目"。所以这条用例能验的只剩: 管线还注册着、步骤形状没变、
    上游拿不到数据时安静跑完且**不凭空造条目**。"选出来的新闻真的变成能力条目"需要 ASIS 上游
    加模型网关, 那不属于单测范围(硬要验就会变成断言"模型今天选了没有")。
    """
    client = _client()
    response = client.post("/api/runs", json={"pipeline_name": "capabilities.from_news_pipeline", "wait": True, "params": {"limit": 10}})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert [step["name"] for step in data["summary"]["steps"]] == [
        "build_from_raw",
        "code_link_dedup",
        "rule_filter",
        "fetch_readme",
        "llm_review",
        "retry_degraded_reviews",
        "store_capabilities",
        "select_unclassified_web",
        "classify_web_capability",
        "redemote_drifted_non_web",
    ]
    # 上游返回 0 条(单测里 ASIS 域名解析不了)⇒ 落库 0 条, 不许拿历史或样例凑数
    assert client.get("/api/capabilities/items").json()["items"] == []


def test_vulnerability_knowledge_pipeline_extracts_candidates() -> None:
    client = _client()
    raw_run = client.post(
        "/api/runs",
        json={"pipeline_name": "vulnerabilities.material_local_raw_import", "reset": True, "wait": True, "params": {"report_limit": 2, "item_limit": 20}},
    )
    assert raw_run.status_code == 200
    response = client.post("/api/runs", json={"pipeline_name": "vulnerabilities.knowledge_extraction_pipeline", "wait": True, "params": {"limit": 5}})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["summary"]["steps"][1]["metrics"]["extracted"] > 0
    knowledge = client.get("/api/vulnerabilities/knowledge").json()
    assert knowledge["items"]
    assert knowledge["items"][0]["source_material_id"]
    queue = client.get("/api/vulnerabilities/migration-queue").json()
    assert queue["items"]


def test_threat_risk_pipeline_reasons_targets(monkeypatch) -> None:
    _patch_threat_connector_records(monkeypatch)
    client = _client()
    raw_run = client.post("/api/runs", json={"pipeline_name": "threats.huawei_full_migration_pipeline", "reset": True, "wait": True, "params": {"limit": 30, "top_n": 8}})
    assert raw_run.status_code == 200
    response = client.post("/api/runs", json={"pipeline_name": "threats.risk_reasoning_pipeline", "wait": True, "params": {"limit": 8}})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["summary"]["steps"][1]["metrics"]["reasoned"] > 0
    assessments = client.get("/api/threats/risk-assessments").json()
    assert assessments["items"]
    calls = client.get("/api/operations/model-calls?domain=threats").json()
    assert calls["items"]


def test_huawei_full_migration_pipeline_runs_and_exposes_reports(monkeypatch) -> None:
    _patch_threat_connector_records(monkeypatch)
    client = _client()
    response = client.post("/api/runs", json={"pipeline_name": "threats.huawei_full_migration_pipeline", "reset": True, "wait": True, "params": {"limit": 5, "top_n": 5}})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    step_names = [step["name"] for step in data["summary"]["steps"]]
    assert "huawei_cve_scout" in step_names
    assert "huawei_attack_surface_score" in step_names
    assert "build_huawei_threat_report" in step_names
    assert client.get("/api/threats/cve-scout").json()["status"] == "ok"
    assert client.get("/api/threats/cve-compare").status_code == 404
    assert client.get("/api/threats/attack-surface").json()["status"] == "ok"
    assert client.get("/api/threats/attack-surface-compare").status_code == 404
    assert client.get("/api/threats/reports").json()["status"] == "ok"


# 2026-11-02: 删掉两条 `/api/frontend/v9` 的用例。
# 那套 v9 契约接口在「重建前端为 React 威胁工作台」之后就没了(线上 119 与本地都是 404,
# 各业务域已各自提供 /api/{domain}/*), 留着等于永久红。它们覆盖的"四个域的数据都能读出来"
# 由上方各域的 endpoint 用例与本文件里的 domain 断言分别兜着。
