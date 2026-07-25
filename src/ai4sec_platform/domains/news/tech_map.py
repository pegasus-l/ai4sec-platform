from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class TechPath:
    dimension: str
    category: str
    point: str

    def as_payload(self) -> dict[str, str]:
        return {"dimension": self.dimension, "category": self.category, "point": self.point}


class AgentTechMap:
    def __init__(self, data: dict[str, Any]) -> None:
        self.version = str(data.get("version") or "unknown")
        self.name = str(data.get("name") or "AI Agent 技术地图")
        self.paths = [
            TechPath(str(dimension["name"]), str(category["name"]), str(point))
            for dimension in data.get("dimensions") or []
            for category in dimension.get("categories") or []
            for point in category.get("points") or []
        ]
        self._path_set = {(path.dimension, path.category, path.point) for path in self.paths}

    @classmethod
    def load(cls, project_root: Path) -> "AgentTechMap":
        path = project_root / "configs" / "agent_tech_map.yaml"
        return cls(yaml.safe_load(path.read_text(encoding="utf-8")) or {})

    def catalog(self) -> list[dict[str, str]]:
        return [path.as_payload() for path in self.paths]

    def validate_paths(self, values: Any, *, limit: int = 72) -> list[dict[str, str]]:
        if not isinstance(values, list):
            return []
        result: list[dict[str, str]] = []
        for value in values:
            if not isinstance(value, dict):
                continue
            key = (str(value.get("dimension") or ""), str(value.get("category") or ""), str(value.get("point") or ""))
            if key in self._path_set and key not in {(item["dimension"], item["category"], item["point"]) for item in result}:
                result.append({"dimension": key[0], "category": key[1], "point": key[2]})
            if len(result) >= limit:
                break
        return result

    def fallback_paths(self, item: dict[str, Any]) -> list[dict[str, str]]:
        text = " ".join(str(item.get(key) or "") for key in ["title", "summary", "topics", "code_url"]).lower()
        rules = [
            (["mcp", "function call", "tool use", "tool calling"], "工具调用", "工具集成总线", "MCP 协议"),
            (["multi-agent", "multi agent", "agent collaboration"], "多Agent协作", "调度与执行", "Manager 进程调度"),
            (["memory", "rag", "knowledge graph"], "记忆与上下文管理", "长期记忆", "RAG / 混合检索"),
            (["reflection", "reflexion", "self-correct"], "推理与规划", "反思与纠正", "Reflexion 自评分"),
            (["evaluation", "benchmark", "verify", "validation", "test"], "验证与评估", "自验证", "自动测试生成"),
            (["prompt optimization", "dspy", "textgrad"], "自进化", "Prompt 自动优化", "Prompt 自动改写"),
            (["skill", "experience distillation"], "技能管理", "技能库构建", "经验自提炼"),
            (["agent", "planning", "reasoning"], "推理与规划", "规划与意图", "任务分解与编排"),
        ]
        for terms, dimension, category, point in rules:
            if any(term in text for term in terms):
                return [{"dimension": dimension, "category": category, "point": point}]
        return []
