"""复现模块——cap-pipeline 评估完成后，调 opencode serve 做项目复现（clone+build+test）。
流程: 创建session → 发消息(让AI clone+build+test) → 轮询结果 → 写回DB
"""
from __future__ import annotations

import json, os, time, urllib.request, urllib.error
from dataclasses import dataclass
from typing import Any

from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult
from ai4sec_platform.db import repositories as repo


def _env(key: str, default: str = "") -> str:
    return os.getenv(key, default)


@dataclass
class TriggerReproStep:
    """评估完成后，对"待复现验证"的条目触发 opencode serve 复现。"""
    name: str = "trigger_repro"
    step_type: str = "repro"

    def run(self, context: PipelineContext) -> StepResult:
        repro_url = _env("REPRO_API_URL", "http://repro:4096")
        repro_password = _env("REPRO_PASSWORD", "")
        timeout = int(context.params.get("repro_timeout_seconds", 300))

        limit = int(context.params.get("repro_limit", 1))
        target_id = context.params.get("repro_item_id")

        # 直接扫库取候选:待复现验证 + 有 code_url + 尚未复现过
        # (不依赖当次 run 的 capability_ids——repro_pipeline 独立跑时 outputs 是空的)
        if target_id:
            row = repo.get_domain_item(context.conn, "capabilities", int(target_id))
            candidates = [row] if row else []
        else:
            items = repo.list_domain_items(context.conn, "capabilities", item_type="capability", status="待复现验证", limit=10000)
            candidates = [
                it for it in items
                if (it.get("payload") or {}).get("code_url")
                and (it.get("payload") or {}).get("repro_status") not in ("succeeded", "failed", "error")
            ][:limit]
        triggered = 0
        succeeded = 0
        failed = 0

        for item in candidates:
            payload = item.get("payload") or {}
            review = payload.get("review") or {}
            code_url = payload.get("code_url") or ""
            status = item.get("status") or ""
            item_id = item.get("id")

            # 只对"待复现验证"且有 code_url 的触发
            if status != "待复现验证" or not code_url:
                continue

            try:
                result = _trigger_repro(repro_url, repro_password, code_url, item.get("title", ""), timeout)
                # 写回复现结果
                payload["repro_result"] = result
                payload["repro_status"] = "succeeded" if result.get("build_success") else "failed"
                repo.update_domain_item(context.conn, item_id=item_id, status="已复现" if result.get("build_success") else "复现失败", payload=payload)
                triggered += 1
                if result.get("build_success"):
                    succeeded += 1
                else:
                    failed += 1
            except Exception as e:
                payload["repro_result"] = {"error": str(e)}
                payload["repro_status"] = "error"
                repo.update_domain_item(context.conn, item_id=item_id, status="复现失败", payload=payload)
                failed += 1

        return StepResult(metrics={"triggered": triggered, "succeeded": succeeded, "failed": failed})


def _trigger_repro(base_url: str, password: str, code_url: str, title: str, timeout: int) -> dict[str, Any]:
    """调 opencode serve: 创建 session → 发消息 → 轮询结果。"""
    headers = {"Content-Type": "application/json"}
    if password:
        import base64
        cred = base64.b64encode(f"opencode:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {cred}"

    # 1. 创建 session
    req = urllib.request.Request(f"{base_url}/session", method="POST", headers=headers,
                                 data=json.dumps({"title": f"repro: {title}"}).encode())
    with urllib.request.urlopen(req, timeout=30) as resp:
        session = json.loads(resp.read())
        session_id = session.get("id") or session.get("ID")
        if not session_id:
            raise RuntimeError("opencode serve: no session ID returned")

    # 2. 发消息：让 AI clone + build + test
    prompt = (
        f"Please clone the repository at {code_url}, read the README, "
        f"install dependencies, run the build, and execute tests. "
        f"Report: 1) build success/failure 2) test results 3) key issues or caveats. "
        f"Be concise.\n"
        f"At the very end output exactly one line: FINAL_VERDICT: SUCCESS, PARTIAL, or FAILURE. "
        f"(SUCCESS = clean build and tests pass; PARTIAL = builds/tests only after manual fixes "
        f"like creating missing stub files; FAILURE = cannot build or run.)"
    )
    req = urllib.request.Request(
        f"{base_url}/session/{session_id}/message", method="POST", headers=headers,
        data=json.dumps({"messageID": f"msg-{int(time.time())}", "parts": [{"type": "text", "text": prompt}]}).encode(),
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        msg_data = json.loads(resp.read())

    # 3. 解析结果
    parts = msg_data.get("parts") or []
    text_parts = [p.get("text", "") for p in parts if isinstance(p, dict) and p.get("type") == "text"]
    full_response = "\n".join(text_parts)

    return {
        "session_id": session_id,
        "build_success": _detect_build_success(full_response),
        "test_results": _extract_test_results(full_response),
        "summary": full_response[:2000],
        "raw": msg_data,
    }


def _detect_build_success(text: str) -> bool:
    text_lower = text.lower()
    # 结构化判定优先:agent 按要求输出 FINAL_VERDICT 行(SUCCESS/PARTIAL/FAILURE)
    for line in text_lower.splitlines():
        if "final_verdict" not in line:
            continue
        if "partial" in line:
            return False  # 需人工补文件才能跑,按未成功处理(原因保留在 summary)
        if "failure" in line:
            return False
        if "success" in line:
            return True
    # 关键词兜底(旧报告/agent 未遵循格式时)
    success_markers = ["build succeeded", "build successful", "build complete", "build success", "successfully built", "build passed", "✓ build", "✓ all tests"]
    failure_markers = ["build failed", "build error", "compilation failed", "build failure", "❌", "error: build"]
    has_success = any(m in text_lower for m in success_markers)
    has_failure = any(m in text_lower for m in failure_markers)
    if has_success and not has_failure:
        return True
    if has_failure:
        return False
    return has_success


def _extract_test_results(text: str) -> str:
    lines = text.split("\n")
    test_lines = [l for l in lines if any(k in l.lower() for k in ["test", "pass", "fail", "skip", "coverage"])]
    return "\n".join(test_lines[:20]) if test_lines else "No test results found in response"
