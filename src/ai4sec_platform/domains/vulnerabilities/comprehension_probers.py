from __future__ import annotations

import hashlib
import re
from typing import Any

from ai4sec_platform.models.local_rules import LocalRuleProvider
from ai4sec_platform.models.router import LLMRouter

COMPREHENSION_FIELDS = ("root_cause", "trigger_condition", "exploit_primitives", "mitigation")
DIM_LABELS = {
    "root_cause": "根因",
    "trigger_condition": "触发条件",
    "exploit_primitives": "利用分析",
    "mitigation": "修复",
}
SCORE_WEIGHTS = {"root_cause": 0.30, "trigger_condition": 0.25, "exploit_primitives": 0.25, "mitigation": 0.20}
VERDICT_THRESHOLD = 0.7
WEAK_FIELD_THRESHOLD = 0.5

COMPREHENSION_ANSWER_PROMPT = """你是漏洞理解性测试模型。你将看到一篇漏洞资料原文。请仔细阅读，然后用你自己的话（不要照抄原文句子）回答以下理解性问题，证明你真正理解了这则漏洞的前因后果：

1. root_cause: 这个漏洞的根因是什么？为什么会在这类系统里普遍出现？
2. trigger_condition: 触发该漏洞需要什么前置条件/输入/状态？
3. exploit_primitives: 攻击者可以利用哪些原语/能力做什么？列出具体条目。
4. mitigation: 如何修复或缓解这类漏洞？

请以 JSON 返回：
{
  "root_cause": "…",
  "trigger_condition": "…",
  "exploit_primitives": ["…"],
  "mitigation": "…"
}
如果资料中没有覆盖某个问题，该字段明确写“资料未覆盖”，不要编造。"""

JUDGE_PROMPT = """你是答案一致性判分模型。已知某漏洞知识库条目对漏洞的标准理解（ground_truth），另一个模型只读过该漏洞的原始资料后给出的理解（answer）。请判断 answer 与 ground_truth 是否表达相同含义。

判分规则：
- 允许同义改写、允许详略差异，只要关键信息一致就算一致。
- 相悖、含糊不清、遗漏关键信息、或直接写“资料未覆盖”但 ground_truth 有内容的，不得分。
- exploit_primitives 是列表：按条目重合度打分。

请逐字段比较，以 JSON 返回：
{
  "scores": {"root_cause": 0-1, "trigger_condition": 0-1, "exploit_primitives": 0-1, "mitigation": 0-1},
  "reason": "整体说明，指出哪些字段一致、哪些不一致、以及不一致的要点"
}"""


def probe_knowledge(knowledge_item: dict[str, Any], material_text: str, *, use_model: bool = True) -> dict[str, Any]:
    """知识重建一致度测试：新 LLM 只读素材作答，judge LLM 与知识条目标准字段比对判分。

    - use_model=True: 走真实 LLM（作答 + 判分两次调用），失败回退本地规则
    - use_model=False: 本地规则兜底（素材对知识字段的关键词覆盖粗打分）
    """
    ground_truth = _ground_truth_fields(knowledge_item)
    if use_model:
        try:
            provider = LLMRouter().provider_for("vulnerability_comprehension_prober")
            if not isinstance(provider, LocalRuleProvider):
                answer_response = provider.complete_json(prompt=COMPREHENSION_ANSWER_PROMPT, payload={"material": material_text})
                answer = answer_response.get("result") or answer_response.get("parsed") or {}
                if isinstance(answer, dict) and answer:
                    judge_response = provider.complete_json(
                        prompt=JUDGE_PROMPT,
                        payload={"ground_truth": ground_truth, "answer": answer},
                    )
                    judge = judge_response.get("result") or judge_response.get("parsed") or {}
                    if isinstance(judge, dict) and judge:
                        result = _finalize_probe(ground_truth, answer, judge)
                        result["model_used"] = True
                        result["model"] = answer_response.get("model")
                        result["provider"] = answer_response.get("provider")
                        return {"provider": answer_response.get("provider"), "status": "success", "model": answer_response.get("model"), "result": result}
        except Exception as exc:  # pragma: no cover - external model dependent
            result = _rule_probe(ground_truth, material_text)
            result["model_used"] = False
            result["llm_error"] = str(exc)[:300]
            return {"provider": "local_rules", "status": "fallback", "result": result}
    result = _rule_probe(ground_truth, material_text)
    result["model_used"] = False
    return {"provider": "local_rules", "status": "fallback", "result": result}


def _ground_truth_fields(knowledge_item: dict[str, Any]) -> dict[str, Any]:
    payload = knowledge_item.get("payload") or {}
    return {
        "root_cause": str(payload.get("root_cause_pattern") or "").strip(),
        "trigger_condition": str(payload.get("trigger_condition") or "").strip(),
        "exploit_primitives": [str(x) for x in (payload.get("exploit_primitives") or []) if str(x).strip()],
        "mitigation": str(payload.get("mitigation_or_fix") or "").strip(),
    }


def _finalize_probe(ground_truth: dict[str, Any], answer: dict[str, Any], judge: dict[str, Any]) -> dict[str, Any]:
    raw_scores = judge.get("scores") or {}
    per_field = {}
    for field in COMPREHENSION_FIELDS:
        value = raw_scores.get(field)
        if isinstance(value, (int, float)):
            per_field[field] = round(min(max(float(value), 0.0), 1.0), 2)
        else:
            per_field[field] = 0.0
    overall = round(sum(per_field[f] * SCORE_WEIGHTS[f] for f in COMPREHENSION_FIELDS), 2)
    weak = [f for f in COMPREHENSION_FIELDS if per_field[f] < WEAK_FIELD_THRESHOLD]
    return {
        "per_field_scores": per_field,
        "overall_score": overall,
        "weak_fields": weak,
        "verdict": "pass" if overall >= VERDICT_THRESHOLD else "fail",
        "judge_reason": str(judge.get("reason") or ""),
        "answers": answer,
        "ground_truth": ground_truth,
    }


def _rule_probe(ground_truth: dict[str, Any], material_text: str) -> dict[str, Any]:
    """无 LLM 兜底：素材文本对知识字段关键信息的关键词覆盖粗打分（代理“素材自包含度”）。"""
    blob = material_text.lower()

    def _ratio(field_text: str) -> float:
        if not field_text:
            return 0.0
        terms = [t for t in re.split(r"[，。；、,.!?;:/\s]+", field_text.lower()) if len(t) >= 2]
        if not terms:
            return 0.0
        return round(sum(1 for t in terms if t in blob) / len(terms), 2)

    per_field = {
        "root_cause": _ratio(ground_truth.get("root_cause") or ""),
        "trigger_condition": _ratio(ground_truth.get("trigger_condition") or ""),
        "mitigation": _ratio(ground_truth.get("mitigation") or ""),
    }
    prims = [str(p) for p in (ground_truth.get("exploit_primitives") or [])]
    per_field["exploit_primitives"] = round(sum(1 for p in prims if p.lower() in blob) / max(len(prims), 1), 2) if prims else 0.0
    overall = round(sum(per_field[f] * SCORE_WEIGHTS[f] for f in COMPREHENSION_FIELDS), 2)
    weak = [f for f in COMPREHENSION_FIELDS if per_field[f] < WEAK_FIELD_THRESHOLD]
    return {
        "per_field_scores": per_field,
        "overall_score": overall,
        "weak_fields": weak,
        "verdict": "pass" if overall >= VERDICT_THRESHOLD else "fail",
        "judge_reason": "本地规则兜底：基于素材对知识字段关键信息的关键词覆盖粗打分（代理自包含度）。",
        "answers": {},
        "ground_truth": ground_truth,
    }


def build_probe_payload(knowledge_item: dict[str, Any], material_text: str, output: dict[str, Any]) -> dict[str, Any]:
    """probe item payload：双模型对拍的完整记录。"""
    result = output.get("result") if isinstance(output.get("result"), dict) else output
    payload = knowledge_item.get("payload") or {}
    return {
        "probe_id": f"cmp-{knowledge_item.get('id')}",
        "knowledge_id": knowledge_item.get("id"),
        "material_id": payload.get("source_material_id"),
        "knowledge_title": knowledge_item.get("title"),
        "material_text_hash": _sha256(material_text)[:16],
        "answers": result.get("answers") or {},
        "ground_truth": result.get("ground_truth") or {},
        "per_field_scores": result.get("per_field_scores") or {},
        "overall_score": _safe_float(result.get("overall_score"), 0.0),
        "weak_fields": list(result.get("weak_fields") or []),
        "verdict": result.get("verdict") or "fail",
        "judge_reason": str(result.get("judge_reason") or ""),
        "model_used": bool(result.get("model_used", False)),
        "model_output": output,
    }


def aggregate_feedback(probes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """回灌建议：按理解维度聚合平均分/弱条目数，映射到评审标准维度，产出“标准收紧建议”。"""
    review_dim_map = {
        "root_cause": "完整性与教学性",
        "trigger_condition": "完整性与教学性",
        "exploit_primitives": "利用分析",
        "mitigation": "技术深度",
    }
    aggregated: list[dict[str, Any]] = []
    for dim in COMPREHENSION_FIELDS:
        values = [
            p.get("per_field_scores", {}).get(dim)
            for p in probes
            if isinstance(p.get("per_field_scores"), dict)
        ]
        numeric = [v for v in values if isinstance(v, (int, float))]
        if not numeric:
            continue
        avg = round(sum(numeric) / len(numeric), 2)
        weak_n = sum(1 for v in numeric if v < WEAK_FIELD_THRESHOLD)
        review_dim = review_dim_map[dim]
        suggestion = (
            f"「{review_dim}」评审维度建议收紧：{weak_n}/{len(numeric)} 条素材的{DIM_LABELS[dim]}理解重建低于 {WEAK_FIELD_THRESHOLD}，"
            f"说明素材对{DIM_LABELS[dim]}的讲解不够自包含/清晰，评审标准可要求更明确的前因后果交代。"
            if weak_n else ""
        )
        aggregated.append({
            "dimension": dim,
            "label": DIM_LABELS[dim],
            "avg_score": avg,
            "weak_count": weak_n,
            "total_count": len(numeric),
            "review_dimension": review_dim,
            "suggestion": suggestion,
        })
    return aggregated


def render_probe_markdown(item: dict[str, Any]) -> str:
    """把可理解性验证条目渲染成可下载 markdown。"""
    payload = item.get("payload") or {}
    scores = payload.get("per_field_scores") or {}
    verdict = payload.get("verdict")
    lines = [
        f"# 可理解性验证：{payload.get('knowledge_title') or item.get('title') or '未命名'}",
        "",
        f"> probe ID：{payload.get('probe_id')} · 知识条目 #{payload.get('knowledge_id')} · 素材 #{payload.get('material_id') or '-'}",
        "",
        "## 总体结果",
        "",
        f"- 整体可理解性得分：{_percent(payload.get('overall_score'))}",
        f"- 结论：{'通过' if verdict == 'pass' else '未通过'}（阈值 {VERDICT_THRESHOLD}）",
        f"- 弱维度：{', '.join(payload.get('weak_fields') or []) or '无'}",
        f"- 生成方式：{'双模型对拍（新 LLM 读素材作答 + judge 判分）' if payload.get('model_used') else '本地规则兜底'}",
        "",
        "## 逐维度得分",
        "",
    ]
    for dim in COMPREHENSION_FIELDS:
        lines.append(f"- {DIM_LABELS[dim]}：{_percent(scores.get(dim))}")
    lines.extend(["", "## 判分说明", "", payload.get("judge_reason") or "无", "", "## 新 LLM 的理解作答", ""])
    answers = payload.get("answers") or {}
    if answers:
        lines.append(f"- 根因：{answers.get('root_cause') or '—'}")
        lines.append(f"- 触发条件：{answers.get('trigger_condition') or '—'}")
        prims = answers.get("exploit_primitives") or []
        lines.append(f"- 利用原语：{'; '.join(str(x) for x in prims) or '—'}")
        lines.append(f"- 修复：{answers.get('mitigation') or '—'}")
    else:
        lines.append("- 本地规则兜底，无新 LLM 作答。")
    lines.extend(["", "## 知识库标准理解（ground truth）", ""])
    gt = payload.get("ground_truth") or {}
    lines.append(f"- 根因：{gt.get('root_cause') or '—'}")
    lines.append(f"- 触发条件：{gt.get('trigger_condition') or '—'}")
    prims = gt.get("exploit_primitives") or []
    lines.append(f"- 利用原语：{'; '.join(str(x) for x in prims) or '—'}")
    lines.append(f"- 修复：{gt.get('mitigation') or '—'}")
    return "\n".join(lines)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _safe_float(value: Any, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback


def _percent(value: Any) -> str:
    try:
        return f"{float(value) * 100:.0f}%"
    except (TypeError, ValueError):
        return "-"
