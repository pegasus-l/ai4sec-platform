"""一 run 一个受限模型令牌(L5)。

**为什么不发 litellm 虚拟 key**(2026-11-02 实测改的口径):

  · 119 的网关没有接数据库 —— `POST /key/generate`、`GET /key/info` 都返回
    `500 Database not connected`,虚拟 key 根本发不出来;
  · 就算发得出来也没用:模型不在 litellm 价目表里,每次调用计费 `$0.0`(L6 已知缺口),
    按美元设 `max_budget` 等于不限额 —— 那是一个看起来有预算、实际没有的配置。

所以令牌与预算都放在平台侧:令牌只能调我们自己的 OpenAI 兼容入口
(`/api/internal/eval/v1/chat/completions`),预算记在**真实数字**上 —— 调用次数与 token 数。

三条硬规则:

  · 库里只存 sha256;明文只在 claim 的响应里出现一次,不进日志、不进 `cost_json`、
    不进 recipe(适配 agent 把令牌抄进配置会被当面拒掉, 见 `contains_secret`)。
  · 过期 / 吊销 / 超预算一律 401 / 429。**不许**在拿不准的时候放行 ——
    放行的代价是账外成本,拦错的代价只是这一轮跑不完,而跑不完是看得见的。
  · 收尾就吊销。令牌活过 run 结束是纯粹的账外成本,也没有任何排障价值。
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

# 前缀不是装饰: 出事时能在日志/配置里一眼认出"这是评测令牌", 而不是平台的真 key。
TOKEN_PREFIX = "caev1_"

# 默认额度按 D4 的实测口径估: OpenAnt 一次 scan 的 7 个 phase 加上验证, 十几个样本
# 也就是百来次调用。给 3~4 倍余量, 超了说明工具在空转, 该停下来看, 而不是继续烧。
DEFAULT_MAX_CALLS = 400
DEFAULT_MAX_TOKENS = 400_000
DEFAULT_TTL_SECONDS = 2 * 3600


class LlmTokenError(RuntimeError):
    """令牌不可用。`status` 直接当作 HTTP 状态码用: 401=令牌问题, 429=预算问题。"""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash(token: str) -> str:
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def _reset_expired(conn: sqlite3.Connection) -> None:
    """过期就作废。

    留着过期行没用: 认不认它在 `verify` 里都要再判一次时间, 而库里堆一批"看起来还有效"
    的行只会让人怀疑校验是不是漏了。这里只置 `revoked_at`, 不删 —— 花了多少 token 的
    台账要留着, 那是这一轮成本的一部分。
    """
    conn.execute(
        "UPDATE capability_eval_llm_tokens SET revoked_at=?"
        " WHERE revoked_at IS NULL AND expires_at <= ?",
        (_now().isoformat(), _now().isoformat()),
    )
    conn.commit()


def mint(conn: sqlite3.Connection, run_id: int, *,
         max_calls: int = DEFAULT_MAX_CALLS,
         max_tokens: int = DEFAULT_MAX_TOKENS,
         ttl_seconds: int = DEFAULT_TTL_SECONDS) -> dict[str, Any]:
    """给这一轮发一个令牌。同一个 run 再发一次会换新的, 旧的当场吊销。

    为什么要换: claim 是重入的(agent 崩了重来会再领一次)。让两个令牌同时有效,
    "这一轮到底用了哪个"就说不清了。
    """
    _reset_expired(conn)
    revoke(conn, run_id)
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    now = _now()
    conn.execute(
        "INSERT INTO capability_eval_llm_tokens"
        " (token_hash, run_id, created_at, expires_at, max_calls, max_tokens,"
        "  calls, prompt_tokens, completion_tokens, revoked_at)"
        " VALUES (?,?,?,?,?,?,0,0,0,NULL)",
        (_hash(token), int(run_id), now.isoformat(),
         (now + timedelta(seconds=max(int(ttl_seconds), 60))).isoformat(),
         max(int(max_calls), 0), max(int(max_tokens), 0)),
    )
    conn.commit()
    # 明文只在这里出现一次。调用方拿到后应立即放进本次 claim 的响应里, 不要落库、不要打日志。
    return {"token": token, "expires_at": (now + timedelta(seconds=int(ttl_seconds))).isoformat(),
            "max_calls": int(max_calls), "max_tokens": int(max_tokens)}


def revoke(conn: sqlite3.Connection, run_id: int) -> int:
    cur = conn.execute(
        "UPDATE capability_eval_llm_tokens SET revoked_at=?"
        " WHERE run_id=? AND revoked_at IS NULL", (_now().isoformat(), int(run_id)))
    conn.commit()
    return int(cur.rowcount or 0)


def _row(conn: sqlite3.Connection, token: str) -> Mapping[str, Any] | None:
    return conn.execute(
        "SELECT * FROM capability_eval_llm_tokens WHERE token_hash=?",
        (_hash(token),)).fetchone()


def _check(row: Mapping[str, Any]) -> None:
    """一条令牌行还能不能用。`verify`(拿着明文)与 `verify_run`(按 run 查)共用这套判据 ——
    两条路各写一遍, 迟早会有一边少一条规则, 而少的那条正好是"预算已经用尽"。
    """
    if row["revoked_at"]:
        raise LlmTokenError(401, "revoked")
    if datetime.fromisoformat(row["expires_at"]) <= _now():
        raise LlmTokenError(401, "expired")
    if row["max_calls"] and row["calls"] >= row["max_calls"]:
        raise LlmTokenError(429, f"调用次数已用尽 ({row['calls']}/{row['max_calls']})")
    used = row["prompt_tokens"] + row["completion_tokens"]
    if row["max_tokens"] and used >= row["max_tokens"]:
        raise LlmTokenError(429, f"token 预算已用尽 ({used}/{row['max_tokens']})")


def verify(conn: sqlite3.Connection, token: str) -> dict[str, Any]:
    """校验并返回这一轮的令牌行。不通过就抛 —— 没有"降级放行"这一档。"""
    if not (token or "").startswith(TOKEN_PREFIX):
        raise LlmTokenError(401, "invalid_token")
    row = _row(conn, token)
    if row is None:
        raise LlmTokenError(401, "invalid_token")
    _check(row)
    return dict(row)


def verify_run(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    """按 run 取这一轮**最新**的令牌行并校验。

    给适配 agent 的模型入口(`/api/internal/eval/llm`)用。那条入口认的是平台自己的
    `EVAL_TOKEN`, 它只能证明"我是执行位", 说不出"我是哪一轮" —— 于是适配阶段的模型调用
    **一分钱都没记进这一轮的预算**(2026-11-03 run 6 实测: 适配侧 1,122,409 tokens 全部账外)。
    调用方在请求体里带上 `run_id`, 这里就能把它记到同一本账上。

    没有令牌行就**直接拒**(401): 放行等于又回到账外, 而且会让人以为预算被管住了。
    """
    row = conn.execute(
        "SELECT * FROM capability_eval_llm_tokens WHERE run_id=?"
        " ORDER BY created_at DESC, rowid DESC LIMIT 1", (int(run_id),)).fetchone()
    if row is None:
        raise LlmTokenError(401, f"这一轮(run {run_id})没有可用的模型令牌")
    _check(row)
    return dict(row)


def charge(conn: sqlite3.Connection, token_hash: str,
           usage: Mapping[str, Any] | None) -> dict[str, Any]:
    """记一笔真实用量。`usage` 缺失时只记次数 —— 不拿请求里的 max_tokens 去估。

    估出来的数是假的: 它既不是花的钱, 也不是模型真吐的 token, 只是把"我们不知道"
    写成了一行看起来很确定的记录。
    """
    usage = usage or {}
    prompt = usage.get("prompt_tokens") if isinstance(usage.get("prompt_tokens"), int) else 0
    completion = usage.get("completion_tokens") if isinstance(usage.get("completion_tokens"), int) else 0
    conn.execute(
        "UPDATE capability_eval_llm_tokens SET calls=calls+1,"
        " prompt_tokens=prompt_tokens+?, completion_tokens=completion_tokens+?"
        " WHERE token_hash=?", (prompt, completion, token_hash))
    conn.commit()
    return {"prompt_tokens": prompt, "completion_tokens": completion}


def summary(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    """这一轮模型侧的实际用量, 收尾时写进 `cost_json.llm`。

    注意 `spend_usd` **不存在**: 网关对未登记价目表的模型一律记 $0.0, 我们不替它编价。
    要金额, 得先在网关上把单价配上(见 TASKS.md L6)。
    """
    row = conn.execute(
        "SELECT calls, prompt_tokens, completion_tokens, max_calls, max_tokens"
        " FROM capability_eval_llm_tokens WHERE run_id=? ORDER BY created_at DESC, rowid DESC"
        " LIMIT 1", (int(run_id),)).fetchone()
    if row is None:
        return {"calls": 0}
    used = row["prompt_tokens"] + row["completion_tokens"]
    return {
        "calls": int(row["calls"]),
        "prompt_tokens": int(row["prompt_tokens"]),
        "completion_tokens": int(row["completion_tokens"]),
        "total_tokens": used,
        # 超没超是"这一轮的结果", 不是"用了多少": 两者都要留下, 否则没法解释一条
        # budget_exceeded 到底是额度太小还是工具在空转。
        "max_calls": int(row["max_calls"]),
        "max_tokens": int(row["max_tokens"]),
        "budget_exceeded": bool(
            (row["max_calls"] and row["calls"] >= row["max_calls"])
            or (row["max_tokens"] and used >= row["max_tokens"])),
    }


def contains_secret(value: Any, token: str) -> bool:
    """令牌是不是被抄进了 recipe / 命令行里。

    recipe 会被冻结、复用、在页面上展示 —— 令牌一旦进去, 下一轮跑的就是"上一轮的凭证",
    而且它会跟着配置一起被看见。渲染占位符的路径(`{llm_api_key}`)只在内存里替换,
    不会经过这里。
    """
    if not token:
        return False
    try:
        return token in str(value)
    except Exception:  # noqa: BLE001 —— 序列化不了的怪对象不该把校验带崩
        return False
