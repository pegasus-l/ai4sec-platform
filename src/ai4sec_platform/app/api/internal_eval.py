"""容器间内部接口: 评测执行位(与 repro 的 /repro-gc 同一套反向轮询模型)。

为什么是反向轮询: 平台容器里没有 docker CLI/套接字, 它**没法**去启动或探活评测容器;
评测容器也没有平台的数据库。所以由评测容器主动来「领活 → 交卷 → 收尾」,
平台只负责记账与判分。

鉴权: 平台 env `EVAL_TOKEN`(没配才退回 `REPRO_PASSWORD`), 评测容器 env `EVAL_TOKEN`。
分开是刻意的 —— 评测容器里跑第三方工具, 是这套系统里最该假定"会被攻破"的一段, 不该
和 repro 共用那条能调 `/internal/repro-gc` 的令牌。
`/api/internal/` 前缀在 middleware 里不做 cookie 校验, 由本模块自己比对。

**这一层不许把真值发出去**: 领活只给题面(`sample_prompts`), 真值留在平台侧给判分脚本读。
被测工具/适配 agent 能看到真值的那一刻, 这个评测就没有意义了(契约 §7 第 2 条)。
"""
from __future__ import annotations

import hmac
import json
import os
import re
import sqlite3
import time
import uuid
from typing import Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.capabilities.eval import llm_tokens, store
# 仓库地址的解析规则只留一份: 复现选候选时怎么认 code_url, 适配时就得怎么认 ——
# 两处各写一套的话, "能复现的工具适配不到" 会变成一类查不出原因的失败。
from ai4sec_platform.domains.capabilities.selectors import _resolve_repo_url
from ai4sec_platform.models.router import LLMRouter

router = APIRouter(prefix="/internal/eval", tags=["internal-eval"])

# 领活后多久没交卷算"卡住了"。超过这个时间仍 running 的 run 由 G3 回收, 不在这里删。
STALE_SECONDS = int(os.environ.get("EVAL_STALE_SECONDS", "3600"))


def _require_token(token: str) -> None:
    """共享令牌。优先用**评测专用**的 `EVAL_TOKEN`; 没配才退回 `REPRO_PASSWORD`。

    为什么要分开: 评测容器里跑的是第三方工具, 是这个系统里最该假定"会被攻破"的那一段。
    跟 repro 共用一条令牌, 意味着它一旦被攻破就能去调 `/internal/repro-gc` 清掉复现工作区。
    """
    expected = os.environ.get("EVAL_TOKEN") or os.environ.get("REPRO_PASSWORD", "")
    if not expected:
        raise HTTPException(status_code=503, detail="EVAL_TOKEN not configured")
    if not hmac.compare_digest(token or "", expected):
        raise HTTPException(status_code=401, detail="bad token")


class AnswersPayload(BaseModel):
    # 每项是字符串(工具直出契约格式)或 {"raw": 原生输出, "answer": 翻译结果} 的对象。
    # 用 Any 是**故意**的: 答案格式归判分管, 这一层拒绝会让"工具不合规"看起来像接口坏了。
    answers: dict[str, list[Any]] = Field(default_factory=dict)


class FinishPayload(BaseModel):
    status: str = Field("success")
    failure_reason: str = ""
    cost: dict[str, Any] = Field(default_factory=dict)
    work_dir: str = ""
    score: bool = True


# 评测用的模型 profile 只能落在这个命名空间里。不限制的话, 评测容器就能借平台的身份
# 调任意 profile —— 那等于把"平台内部的所有模型配置"开成一个公开接口。
EVAL_PROFILE = re.compile(r"^capability_eval_[a-z0-9_]{1,40}$")
MAX_LLM_PAYLOAD_BYTES = 256_000


class LlmPayload(BaseModel):
    profile: str = Field("capability_eval_adapter", max_length=64)
    prompt: str = Field(..., max_length=40_000)
    payload: dict[str, Any] = Field(default_factory=dict)


class RecipePayload(BaseModel):
    item_id: int
    category: str = store.CATEGORY_CLASS1
    tool_version: str
    recipe: dict[str, Any]
    exploit_note: str = ""


@router.post("/llm")
def llm(
    payload: LlmPayload,
    x_repro_token: str = Header(""),
) -> dict[str, Any]:
    """模型代理: 评测容器里**没有**任何模型密钥, 要模型能力就到这里来要。

    为什么值得多这一跳: 适配 agent 与翻译节点跑在"装着第三方工具"的容器里, 把 key
    放进去等于把 key 交给被测工具。这里由平台带着自己的降级链去调, 容器只看到结果。

    没配模型时**明确回 503**, 不退回本地规则引擎 —— 后者会返回一段像模像样的摘要,
    被当成"翻译结果"写进答卷, 那比失败难查得多。
    """
    _require_token(x_repro_token)
    if not EVAL_PROFILE.fullmatch(payload.profile):
        raise HTTPException(status_code=400,
                            detail=f"profile 必须是 capability_eval_*: {payload.profile!r}")
    if len(json.dumps(payload.payload, ensure_ascii=False)) > MAX_LLM_PAYLOAD_BYTES:
        raise HTTPException(status_code=413, detail="payload 太大")

    router_llm = LLMRouter()
    config = router_llm.active_config(payload.profile)
    # local_rules 是"没配模型时"的兜底规则引擎, 它会返回一段像模像样的摘要。
    # 那不是翻译结果 —— 落到答卷里就是一条编出来的结论。所以这里明确拒绝。
    if config.get("provider") == "local_rules" or not config.get("configured"):
        raise HTTPException(status_code=503, detail="平台未配置模型, 评测不能借本地规则冒充")
    try:
        result = router_llm.complete_json(profile=payload.profile,
                                          prompt=payload.prompt, payload=payload.payload)
    except Exception as exc:  # noqa: BLE001 —— 模型侧的错要原样带回去, 由调用方决定重试还是放弃
        raise HTTPException(status_code=502, detail=f"模型调用失败: {str(exc)[:300]}") from exc
    parsed = result.get("parsed")
    if not isinstance(parsed, dict):
        parsed = result.get("result") if isinstance(result.get("result"), dict) else None
    # `model` 是这次**请求**的模型(网关里是个组别名), `serving` 是**实际服务方**。
    # 评测报告要记后者: 组里挂着多把 key 与一个备用厂商, 只有网关响应头能说清谁答的。
    # 读不到头时 `serving.upstream_model` 是 `unknown`, 平台不替它猜。
    return {"parsed": parsed, "model": result.get("model", ""),
            "provider": result.get("provider", ""),
            "serving": result.get("serving") or {},
            "usage": result.get("usage") or {}}


# ── L5: 被测工具的模型入口(OpenAI 兼容) ─────────────────────────────────────
#
# 为什么要有这一层: 有一类被测工具(OpenAnt 就是)**自己**调模型 —— 它不接受"你把结论
# 算好给我", 它要一个 `base_url` + `api_key`。而这个容器里跑的是第三方代码, 是整套系统里
# 最该假定"会被攻破"的一段。
#
# 所以发给它的不是网关的 key, 而是一个**只能调回这里**的一次性令牌: 网关地址它根本不知道,
# 令牌只认这一轮、只认这个 profile、次数与 token 数都有上限, 收尾即吊销。
# 代价是: 工具只能拿到"我们愿意转一次"的能力(不支持 stream / tool-calls), 见下面的拒法。

TOOL_PROFILE = "capability_eval_tool"


def _openai_error(status: int, message: str, code: str) -> JSONResponse:
    """按 OpenAI 的错误形状回, 否则各家 SDK 只会给一句 "Unexpected response"。

    错误信息里**不带令牌**: 错误体常常被工具原样打印进日志, 令牌不能跟着走。
    """
    return JSONResponse(
        status_code=status,
        content={"error": {"message": message, "type": "invalid_request_error", "code": code}})


def _bearer(authorization: str) -> str:
    parts = (authorization or "").split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return ""


def _flatten_content(content: Any) -> str | None:
    """OpenAI 的 `content` 既可以是字符串, 也可以是 `[{"type":"text","text":...}]`。

    只认文本: 图片/音频这类模态我们转不过去, 悄悄丢掉它们等于让工具以为看过了。
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if not isinstance(item, dict) or item.get("type") != "text":
                return None
            parts.append(str(item.get("text") or ""))
        return "".join(parts)
    if content is None:
        return ""
    return None


@router.get("/v1/models")
def list_tool_models(authorization: str = Header(""), x_repro_token: str = Header(""),
                     conn: sqlite3.Connection = Depends(get_db)) -> Any:
    """有些 SDK/工具启动时会先探一下模型列表。不实现它, 工具会在第一步就报 404,
    而我们看到的只是"适配失败" —— 那会把人引到错误的地方去查。"""
    token = _bearer(authorization) or x_repro_token
    try:
        llm_tokens.verify(conn, token)
    except llm_tokens.LlmTokenError as exc:
        return _openai_error(exc.status, exc.detail, "token")
    router_llm = LLMRouter()
    config = router_llm.active_config(TOOL_PROFILE)
    model = str(config.get("model") or "")
    return {"object": "list",
            "data": [{"id": model, "object": "model", "owned_by": "ai4sec-platform"}]}


@router.post("/v1/chat/completions")
def chat_completions(body: dict[str, Any] = Body(...),
                     authorization: str = Header(""), x_repro_token: str = Header(""),
                     conn: sqlite3.Connection = Depends(get_db)) -> Any:
    """把被测工具的一次 Chat Completions 请求转给平台自己的模型链。

    鉴权用的是**这一轮的一次性令牌**, 不是 `EVAL_TOKEN`: 令牌只能证明"我是某一轮", 不能
    证明"我是平台内部调用方"。所以它换不来 `/claim`、换不来判分接口, 也换不来别的轮次。
    """
    token = _bearer(authorization) or x_repro_token
    try:
        row = llm_tokens.verify(conn, token)
    except llm_tokens.LlmTokenError as exc:
        return _openai_error(exc.status, exc.detail, "token")

    if body.get("stream"):
        # 不支持就明确拒。假装支持再一次性吐完, SDK 会按 SSE 解析失败, 报出来的错
        # 跟真正的原因(不支持流式)完全无关。
        return _openai_error(400, "stream=true 不支持: 这一层只做非流式转发", "stream_not_supported")

    # function calling 是**透传**, 不是自己实现: tools/tool_choice/response_format 原样
    # 交给模型, tool_calls 原样带回去。被测工具用 `with_structured_output` 拿结构化答案,
    # 这一层要是把它们吃掉, 工具就只能自我降级成"让模型输出 JSON 再正则" ——
    # 那已经不是同一个工具了(2026-11-03 multi-agent-code-review 就是死在这)。
    tools = body.get("tools")
    if tools is not None and (not isinstance(tools, list) or any(not isinstance(t, dict) for t in tools)):
        return _openai_error(400, "tools 必须是对象数组", "bad_messages")
    if body.get("functions") or body.get("function_call"):
        # 2023 年的老写法。**不**替调用方翻译成 tools: 翻错了对方拿到的是它没要的形状,
        # 报出来的错跟真正原因无关。新版 SDK 一律走 tools, 让他改一行就好。
        return _openai_error(400, "functions/function_call 已废弃, 请改用 tools/tool_choice",
                             "legacy_function_call")
    tool_choice = body.get("tool_choice")
    if tool_choice is not None and not isinstance(tool_choice, (str, dict)):
        return _openai_error(400, "tool_choice 只能是字符串或对象", "bad_messages")
    response_format = body.get("response_format")
    if response_format is not None and not isinstance(response_format, dict):
        return _openai_error(400, "response_format 必须是对象", "bad_messages")

    raw_messages = body.get("messages")
    if not isinstance(raw_messages, list) or not raw_messages:
        return _openai_error(400, "messages 必须是非空数组", "bad_messages")
    messages: list[dict[str, Any]] = []
    for item in raw_messages:
        if not isinstance(item, dict):
            return _openai_error(400, "messages 的每一项必须是对象", "bad_messages")
        role = str(item.get("role") or "")
        # 新 SDK 把 system 叫 developer(OpenAI 明确说这两个等价)。个别上游不认这个名字,
        # 这里翻成 system 就行 —— 翻的是**协议字段**, 不是工具的提示词。
        if role == "developer":
            role = "system"
        if role not in {"system", "user", "assistant", "tool"}:
            return _openai_error(400, f"不支持的角色: {role or '(空)'}", "bad_messages")
        content = _flatten_content(item.get("content"))
        if content is None:
            return _openai_error(400, "content 只支持纯文本", "bad_messages")
        message: dict[str, Any] = {"role": role, "content": content}
        if role == "assistant":
            tool_calls = item.get("tool_calls")
            if tool_calls is not None:
                if not isinstance(tool_calls, list) or any(not isinstance(c, dict) for c in tool_calls):
                    return _openai_error(400, "assistant.tool_calls 必须是对象数组", "bad_messages")
            if tool_calls:
                message["tool_calls"] = tool_calls
                if content == "":
                    # 带 tool_calls 的 assistant 回合, content 本来就该是 null。留空串的话,
                    # 有的上游会把它当成"这一轮又有话说", 判成非法请求。
                    message["content"] = None
        elif role == "tool":
            tool_call_id = str(item.get("tool_call_id") or "")
            if not tool_call_id:
                # 漏了 id 时上游会拒, 而且拒得很含糊。这里是调用方没按协议给, 直接说清。
                return _openai_error(400, "tool 角色的消息必须带 tool_call_id", "bad_messages")
            message["tool_call_id"] = tool_call_id
        messages.append(message)

    router_llm = LLMRouter()
    config = router_llm.active_config(TOOL_PROFILE)
    # 与 `/llm` 同一条硬规则: 没配模型时**不许**退回本地规则引擎 —— 它会返回一段像模像样的
    # 文本, 工具会把它当成模型的判断写进答卷。
    if config.get("provider") == "local_rules" or not config.get("configured"):
        return _openai_error(503, "平台未配置模型, 不能借本地规则冒充", "model_unconfigured")

    hard_cap = int(config.get("max_output_tokens") or 4096)
    requested_max = body.get("max_tokens")
    max_tokens = min(int(requested_max), hard_cap) if isinstance(requested_max, int) and requested_max > 0 \
        else hard_cap
    temperature = body.get("temperature") if isinstance(body.get("temperature"), (int, float)) else None

    try:
        result = router_llm.chat_completion(profile=TOOL_PROFILE, messages=messages,
                                            max_tokens=max_tokens, temperature=temperature,
                                            tools=tools or None, tool_choice=tool_choice,
                                            response_format=response_format)
    except Exception as exc:  # noqa: BLE001 —— 模型侧的错原样带回去, 由工具自己决定怎么办
        return _openai_error(502, f"模型调用失败: {str(exc)[:300]}", "model_error")

    usage = llm_tokens.charge(conn, row["token_hash"], result.get("usage"))
    requested_model = str(body.get("model") or "") or str(config.get("model") or "")
    reply: dict[str, Any] = {"role": "assistant", "content": result.get("content") or ""}
    tool_calls = result.get("tool_calls") or []
    if tool_calls:
        # tool_calls 原样回给工具(它的 id 要与下一轮 tool 消息的 tool_call_id 对上)。
        # 这一回合按 OpenAI 的约定 content 是 null, 不是空串。
        reply["tool_calls"] = tool_calls
        reply["content"] = result.get("content") or None
    return {
        "id": f"chatcmpl-eval-{uuid.uuid4().hex[:24]}",
        "object": "chat.completion",
        "created": int(time.time()),
        # 回给工具的是**它请求的名字**(它的日志/断言按这个走); 真正是谁答的看 `serving`。
        "model": requested_model,
        "choices": [{"index": 0,
                     "message": reply,
                     "finish_reason": result.get("finish_reason") or "stop"}],
        "usage": usage,
        # 非标准字段, 但不藏着: 网关降级时这一轮和别轮不可比, 账要能对上。
        "serving": result.get("serving") or {},
    }


@router.post("/recipes")
def post_recipe(
    payload: RecipePayload,
    x_repro_token: str = Header(""),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    """冻结适配 agent 探出来的 recipe(D2)。旧版本不删, 靠 `superseded_by` 串起来。"""
    _require_token(x_repro_token)
    try:
        return store.save_recipe(conn, item_id=payload.item_id, category=payload.category,
                                 tool_version=payload.tool_version, recipe=payload.recipe,
                                 exploit_note=payload.exploit_note)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _tool_ref(conn: sqlite3.Connection, item_id: int) -> dict[str, Any]:
    """被测工具的来源。执行位靠它在工具目录里 clone 一次源码来做适配(D4)。

    查不到条目、或者条目压根没有仓库地址时**发空对象** —— 执行位会落成 `repo_unavailable`
    终态。这里不猜地址: 拿一个猜的 URL 去 clone, 装出来的东西可能根本不是这个工具,
    而分数会照样记在它头上。
    """
    item = repo.get_domain_item(conn, "capabilities", int(item_id))
    if not item:
        return {}
    payload = item.get("payload") or {}
    return {
        "item_id": int(item_id),
        "name": str(item.get("title") or payload.get("name") or "")[:200],
        "repo_url": _resolve_repo_url(item),
        "git_ref": str(payload.get("git_ref") or payload.get("default_branch") or "")[:200],
    }


@router.post("/claim")
def claim(
    x_repro_token: str = Header(""),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    """领一轮还没交卷的评测。

    重复领到同一轮是**故意**的: agent 崩了重来时就该接着上一轮做, 而不是开新的 run
    (开新的会把失败计到工具头上)。有答卷的行会带 `has_answers`, 用来判断是重跑还是续跑。
    """
    _require_token(x_repro_token)
    row = conn.execute(
        "SELECT id FROM capability_eval_runs WHERE status='running'"
        " ORDER BY started_at ASC, id ASC LIMIT 1",
    ).fetchone()
    if row is None:
        return {"run": None}

    run_id = int(row["id"])
    run = store.get_run(conn, run_id)
    if run is None:
        return {"run": None}
    answered = conn.execute(
        "SELECT COUNT(*) FROM capability_eval_answers WHERE run_id=?", (run_id,)).fetchone()[0]
    try:
        packets = store.sample_packets(conn, run["category"])
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    recipe = store.latest_recipe(conn, run["item_id"], run["category"])
    budget = run["budget_json"] if isinstance(run["budget_json"], dict) else {}
    # 每轮一个模型令牌(L5)。**默认给**: 被测工具要不要模型, 往往要等适配 agent 探过才知道,
    # 而适配发生在这一轮之内 —— 那时再去要令牌, 这一轮就白开了。令牌本身不是权限:
    # 它只认这一轮、只能在 `capability_eval_tool` 这个 profile 上转普通对话, 有次数与
    # token 上限, 收尾即吊销。真的不想给模型能力, 在 `budget` 里写 `allow_llm: false`。
    llm = None
    if budget.get("allow_llm", True):
        minted = llm_tokens.mint(
            conn, run_id,
            max_calls=int(budget.get("llm_max_calls") or llm_tokens.DEFAULT_MAX_CALLS),
            max_tokens=int(budget.get("llm_max_tokens") or llm_tokens.DEFAULT_MAX_TOKENS),
            ttl_seconds=int(budget.get("llm_ttl_seconds") or llm_tokens.DEFAULT_TTL_SECONDS),
        )
        # 只回令牌本身; 能不能连、连到哪, 由执行位按它自己到平台的地址拼
        # (平台不知道容器眼里的自己叫什么)。模型名要发: 工具得把它写进配置,
        # 而"到底用哪个模型"必须由平台说, 不能让工具自己猜。
        llm = {**minted, "model": str(LLMRouter().active_config(TOOL_PROFILE).get("model") or "")}
    return {
        "run": {
            "run_id": run_id, "category": run["category"], "item_id": run["item_id"],
            "tool_version": run["tool_version"], "repeats": run["repeats"],
            "budget": run["budget_json"], "started_at": run["started_at"],
            "has_answers": answered > 0,
        },
        # 令牌明文**只在这里**出现一次: 不落库(库里是 sha256)、不进日志、不进 cost_json。
        "llm": llm,
        # recipe 为 null = 这个工具还没被适配过。执行位应当以 failed/agent_gave_up 收尾,
        # **不要**凭默认参数瞎跑 —— 没 recipe 就跑出来的数不代表任何东西。
        "recipe": recipe,
        "tool": _tool_ref(conn, run["item_id"]),
        "samples": packets,
    }


@router.post("/runs/{run_id}/answers")
def post_answers(
    run_id: int,
    payload: AnswersPayload,
    x_repro_token: str = Header(""),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    _require_token(x_repro_token)
    try:
        return store.save_answers(conn, run_id, payload.answers)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/runs/{run_id}/finish")
def finish(
    run_id: int,
    payload: FinishPayload,
    x_repro_token: str = Header(""),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    """收尾并按需判分。

    `status` 只能是终态: 工具装不上是 `failed` + failure_reason(R9 终态), 超预算是
    `budget_exceeded`。两种都不会自动重试。
    """
    _require_token(x_repro_token)
    # 先吊销令牌再写账: 中途出错也不能把一条还能用的凭证留在外面。
    llm_usage = llm_tokens.summary(conn, run_id)
    llm_tokens.revoke(conn, run_id)
    cost = dict(payload.cost or {})
    if llm_usage.get("calls"):
        # 模型这一侧的用量以**平台自己记的**为准: 执行位只看得见它自己的 agent 调用,
        # 看不见被测工具绕过它去调的那部分。
        cost["llm_key"] = llm_usage
        if llm_usage.get("budget_exceeded"):
            # 令牌侧超预算是硬事实: 这一轮跑出来的数不代表工具的能力, 记成成功会误导。
            payload.status = "budget_exceeded"
            payload.failure_reason = payload.failure_reason or "model_budget_exceeded"
    if payload.status == "success":
        answered = conn.execute(
            "SELECT COUNT(*) FROM capability_eval_answers WHERE run_id=?", (run_id,)).fetchone()[0]
        if not answered:
            raise HTTPException(status_code=409, detail="没有答卷, 不能收尾为 success")
        store.finish_run(conn, run_id, "success", cost=cost, work_dir=payload.work_dir)
        report = store.score_run(conn, run_id) if payload.score else None
        return {"status": "success", "scored": report is not None,
                "n_samples": (report or {}).get("n_samples"),
                # 执行位在日志里要把这个数打出来: "交了 20 条"和"20 条进了分母"不是一回事
                "n_excluded": (report or {}).get("n_excluded")}

    try:
        store.finish_run(conn, run_id, payload.status,
                         failure_reason=payload.failure_reason,
                         cost=cost, work_dir=payload.work_dir)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": payload.status, "scored": False, "n_samples": None}
