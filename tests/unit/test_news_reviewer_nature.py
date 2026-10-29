"""能力库评审的「项目性质 / 推荐分」天花板(2026-10-29)。

背景: 方向(map_relevance)在加权分里只占 25%, 一个工程漂亮但方向不对的项目靠其余六维照样能到 75+。
实测 item#24574(nightglass, 海事 SAR 情报分析)81.25、item#114569(learn-claude-code, 78K stars
教学仓库, 模型自己在摘要里写「教学向」)80.9, 两条都进了「待复现验证」。
提示词里本来就有排除规则(教学类 ≤3、map_relevance 只有核心命中才给 70+), 但代码没有兜底。
这里锁住: 垂直应用 ≤65、教学演示 ≤60、资源合集 ≤45; recommended_score 反过来也是加权分上限。
"""
from __future__ import annotations

from ai4sec_platform.domains.news.reviewer import (
    _NATURE_CAPS,
    _RECOMMENDED_CEILING,
    _keyword_nature,
    _normalize_review,
    _project_nature,
    _recommended_score,
)
from ai4sec_platform.domains.news.tech_map import AgentTechMap

TECH_MAP = AgentTechMap({
    "version": "test",
    "dimensions": [
        {"name": "工具调用", "categories": [{"name": "工具集成总线", "points": ["MCP 协议"]}]},
        {"name": "记忆与上下文管理", "categories": [{"name": "长期记忆", "points": ["RAG / 混合检索"]}]},
    ],
})

PATHS = [{"dimension": "工具调用", "category": "工具集成总线", "point": "MCP 协议"}]
FRAMEWORK_SUMMARY = "一个可部署的 Agent 框架，提供工具编排、上下文管理与企业级接入。"
FRAMEWORK_REASON = "工程完整、有真实代码与评测，可直接集成到现有系统。"
HIGH_BREAKDOWN = {
    "map_relevance": 85, "novelty": 80, "technical_depth": 85,
    "engineering_value": 90, "reproducibility": 80, "influence": 95, "freshness": 90,
}


def _review(**overrides):
    result = {
        "score_breakdown": dict(HIGH_BREAKDOWN),
        "tech_paths": PATHS,
        "project_nature": "能力框架",
        "theme_descriptor": "可部署的 Agent 工具编排框架",
        "summary_zh": FRAMEWORK_SUMMARY,
        "score_reason": FRAMEWORK_REASON,
        "recommended_score": 5,
    }
    result.update(overrides)
    return _normalize_review(result, {"source_type": "project"}, TECH_MAP)


# ── 天花板本身 ──

def test_nature_caps_are_ordered() -> None:
    assert _NATURE_CAPS["能力框架"] == (100.0, 5)
    assert _NATURE_CAPS["垂直应用"][0] <= _NATURE_CAPS["能力框架"][0]
    assert _NATURE_CAPS["教学演示"][0] < _NATURE_CAPS["垂直应用"][0]
    assert _NATURE_CAPS["资源合集"][0] < _NATURE_CAPS["教学演示"][0]


def test_capability_framework_is_not_capped() -> None:
    """正经的能力框架不能因为加了这个闸门被误伤。"""
    review = _review()
    assert review["project_nature"] == "能力框架"
    assert review["score"] > 70
    assert review["decision"] == "selected"
    assert review["recommended_score"] == 5


# ── 垂直应用(海事 SAR 那类) ──

def test_vertical_application_is_capped() -> None:
    review = _review(
        project_nature="垂直应用",
        theme_descriptor="面向海事 SAR 图像与 AIS 关联的情报分析系统",
        summary_zh="把 Agent 技术用在海事遥感情报分析上的垂直应用，技术本身没有新贡献。",
        score_reason="工程成熟、七个可验证目标，但核心价值在行业场景而非 Agent 能力。",
        recommended_score=5,
    )
    assert review["project_nature"] == "垂直应用"
    assert review["score"] <= 65
    assert review["recommended_score"] == 3          # 性质把推荐分压到 ≤3, 不进「待复现验证」
    assert review["decision"] == "watch"


# ── 教学 / 资源合集 ──

def test_teaching_repo_is_capped_by_its_own_text() -> None:
    """模型一边写「教学向」一边给 4 分时, 以文本为准(learn-claude-code 实测就是这个形状)。"""
    review = _review(
        project_nature="能力框架",                   # 模型填错也拦得住
        theme_descriptor="教学演示 Agent 从 0 到 1 的工程抽象",
        summary_zh="项目定位为教学向的教学型代码仓库，覆盖从零构建的完整教程。",
        score_reason="教学价值突出，78K stars。",
        recommended_score=4,
    )
    assert review["project_nature"] == "教学演示"
    assert review["score"] <= 60
    assert review["recommended_score"] == 3
    assert review["decision"] == "watch"


def test_awesome_list_is_capped_lowest() -> None:
    review = _review(
        project_nature="资源合集",
        theme_descriptor="awesome 清单：Agent 工具合集",
        summary_zh="一个资源合集。",
        score_reason="收集了大量链接。",
        recommended_score=4,
    )
    assert review["project_nature"] == "资源合集"
    assert review["score"] <= 45
    assert review["recommended_score"] == 2
    assert review["decision"] == "rejected"


def test_single_weak_keyword_does_not_trigger() -> None:
    """正文只出现一个「教程」不判教学 —— 正经工具的介绍里写「附快速教程」很常见。"""
    review = _review(summary_zh="一个 Agent 框架，附快速教程。", score_reason="工程完整。")
    assert review["project_nature"] == "能力框架"
    assert review["score"] > 70


# ── recommended_score 反向兜住加权分 ──

def test_recommended_score_caps_weighted_score() -> None:
    review = _review(recommended_score=3)
    assert review["score"] <= _RECOMMENDED_CEILING[3]
    assert review["decision"] == "watch"


def test_missing_recommended_score_treated_as_three() -> None:
    review = _review(recommended_score=None)
    assert review["recommended_score"] == 3
    assert review["score"] <= _RECOMMENDED_CEILING[3]


def test_helpers_normalize_inputs() -> None:
    assert _recommended_score(None) == 3
    assert _recommended_score("") == 3
    assert _recommended_score(0) == 3
    assert _recommended_score("4") == 4
    assert _recommended_score(9) == 5
    assert _project_nature("垂直应用", "系统", "", "") == "垂直应用"
    assert _project_nature("乱写的性质", "系统", FRAMEWORK_SUMMARY, FRAMEWORK_REASON) == "能力框架"
    assert _keyword_nature("教学演示 Agent", "", "") == "教学演示"
    assert _keyword_nature("", "教学向的教学型仓库，附完整教程", "") == "教学演示"
