"""能力评估模块 - Web 项目预分类 + 能力评估。

迁移自旧 v1 web_classifier.py（486 行），适配点：
  1. 去硬编码 GITHUB_TOKEN/DASHSCOPE_API_KEY → 从 .env 读
  2. LLM 调用从 GLM-5.1 → DeepSeek（通过 LLMRouter，profile="deepseek"）
  3. db.update_item_web_class → repo.update_domain_item（写 payload）
  4. classify_batch 接收 conn + items，不直接读 DB
"""
from __future__ import annotations

import base64
import json
import os
import re
import time
from datetime import datetime
from typing import Any

import requests

from ai4sec_platform.core.env import load_env_file
from ai4sec_platform.domains.capabilities.scorers import score_capability_candidate
from ai4sec_platform.models.router import LLMRouter

# ============================================================================
# 配置（从 .env 读，去硬编码）
# ============================================================================
load_env_file()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "Authorization": f"Bearer {GITHUB_TOKEN}" if GITHUB_TOKEN else "",
}


# ============================================================================
# 常量（迁自旧 web_classifier.py 第 41/121/130 行）
# ============================================================================
WEB_FRAMEWORKS = {
    "streamlit", "gradio", "flask", "fastapi", "django",
    "uvicorn", "gunicorn", "tornado",
    "next", "nuxt", "vite", "react", "vue", "angular", "svelte",
    "express", "koa", "nest",
}

WEB_FILE_PATTERNS = [
    r"app\.py$", r"server\.py$",
    r"pages/", r"src/components/", r"src/app/",
    r"index\.html$", r"index\.tsx?$", r"App\.tsx?$",
    r"package\.json$", r"next\.config\.", r"vite\.config\.",
    r"streamlit_app\.py$", r"gradio_app\.py$",
]

WEB_README_KEYWORDS = [
    "localhost", "127.0.0.1", "streamlit run", "gradio",
    "npm run dev", "npm start", "yarn dev",
    "web ui", "web interface", "dashboard",
    "open your browser", "visit http",
    "uvicorn", "flask run", "fastapi",
]


# ============================================================================
# 工具函数（迁自旧 web_classifier.py）
# ============================================================================
def parse_github_url(url: str) -> tuple[str | None, str | None]:
    """从 GitHub URL 提取 owner/repo（迁自旧第 142 行）"""
    if not url:
        return None, None
    url = url.rstrip(".,;:!?")
    m = re.search(r"github\.com/([^/]+)/([^/\s#?]+)", url)
    if not m:
        return None, None
    name = m.group(2).rstrip(".")
    if name.endswith(".git"):
        name = name[:-4]
    return m.group(1), name


def extract_demo_urls(readme: str) -> list[str]:
    """从 README 提取 demo/在线体验链接（迁自旧第 50 行）"""
    demo_urls: list[str] = []
    patterns = [
        r'(?:demo|live demo|try it|在线体验|online demo|playground)[:\s]*\n?\s*(https?://[^\s\)>\]]+)',
        r'\[(?:demo|live demo|try[^\]]*|在线[^\]]*|playground[^\]]*)\]\((https?://[^\)]+)\)',
        r'(https?://(?:[\w-]+\.)?(?:hf\.space|gradio\.app|streamlit\.app|vercel\.app|netlify\.app|herokuapp\.com|railway\.app|render\.com)[/\w.-]*)',
        # 独立域名 demo（app/live/try/visit 关键词附近，排除 github/docs/arxiv）
        r'(?:app|live at|try (?:it|here|now)|visit|在线体验|playground)[:\s]*(https?://(?!github\.com|raw\.githubusercontent|api\.|docs\.|arxiv)[^\s\)>\]]+)',
    ]
    blacklist = [
        '/datasets/', '/docs/', '/wiki/', '/blob/', '/tree/',
        'arxiv.org', 'paper', 'install', 'setup', 'tutorial',
        'huggingface.co/docs', 'huggingface.co/datasets',
        'github.io',
        '.md', '.pdf', '.txt', 'badge', 'shield',
    ]
    for pat in patterns:
        for m in re.finditer(pat, readme, re.IGNORECASE):
            url = m.group(1) if m.lastindex else m.group(0)
            url = url.rstrip('.,;:!?')
            url_lower = url.lower()
            if any(b in url_lower for b in blacklist):
                continue
            if url not in demo_urls and len(url) < 200:
                demo_urls.append(url)
    return demo_urls[:5]


def verify_demo_url(url: str, timeout: int = 8) -> bool:
    """验证 URL 是否可交互在线 demo（迁自旧第 78 行）"""
    if not url:
        return False
    url_lower = url.lower()
    url_blacklist = [
        '/docs', '/doc/', '-docs.', 'documentation',
        'huggingface.co/',
        'github.io',
        '/wiki', '/about', '/pricing', '/blog',
    ]
    if any(b in url_lower for b in url_blacklist):
        return False
    try:
        resp = requests.head(url, timeout=timeout, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code >= 500 or resp.status_code == 404:
            return False
        if resp.status_code in (403, 429):
            resp = requests.get(url, timeout=timeout, allow_redirects=True,
                               headers={"User-Agent": "Mozilla/5.0"}, stream=True)
            resp.close()
            if resp.status_code >= 400:
                return False
        ct = resp.headers.get("content-type", "").lower()
        if "text/html" in ct or "application/xhtml" in ct:
            return True
        if not ct:
            resp2 = requests.get(url, timeout=timeout, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0"}, stream=True)
            chunk = resp2.raw.read(1024).decode("utf-8", errors="ignore")
            resp2.close()
            if resp2.status_code < 400 and ("<html" in chunk.lower() or "<!doctype" in chunk.lower()):
                return True
        return False
    except Exception:
        return False


# ============================================================================
# GitHub API（迁自旧第 156-212 行，GITHUB_TOKEN 从 .env 读）
# ============================================================================
def fetch_repo_info(owner: str, repo: str) -> dict:
    r = requests.get(f"https://api.github.com/repos/{owner}/{repo}",
                     headers=GITHUB_HEADERS, timeout=10)
    if r.status_code != 200:
        return {}
    return r.json()


def fetch_file_tree(owner: str, repo: str, max_items: int = 500) -> list[str]:
    r = requests.get(
        f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1",
        headers=GITHUB_HEADERS, timeout=15)
    if r.status_code != 200:
        return []
    tree = r.json().get("tree", [])
    paths = [item["path"] for item in tree if item["type"] == "blob"]
    return paths[:max_items]


def fetch_languages(owner: str, repo: str) -> dict:
    r = requests.get(f"https://api.github.com/repos/{owner}/{repo}/languages",
                     headers=GITHUB_HEADERS, timeout=10)
    if r.status_code != 200:
        return {}
    return r.json()


def fetch_readme(owner: str, repo: str, max_chars: int = 8000) -> str:
    r = requests.get(f"https://api.github.com/repos/{owner}/{repo}/readme",
                     headers=GITHUB_HEADERS, timeout=10)
    if r.status_code != 200:
        return ""
    data = r.json()
    content = data.get("content", "")
    encoding = data.get("encoding", "")
    if encoding == "base64":
        try:
            text = base64.b64decode(content).decode("utf-8", errors="replace")
        except Exception:
            return ""
    else:
        text = content
    return text[:max_chars]


def fetch_dep_file(owner: str, repo: str, path: str) -> str:
    r = requests.get(
        f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
        headers=GITHUB_HEADERS, timeout=10)
    if r.status_code != 200:
        return ""
    content = r.json().get("content", "")
    try:
        return base64.b64decode(content).decode("utf-8", errors="replace")
    except Exception:
        return ""


# ============================================================================
# 规则预筛（迁自旧第 218 行）
# ============================================================================
def rule_based_classify(file_tree: list[str], readme: str, dep_content: str, languages: dict | None = None) -> dict:
    """基于规则的预筛。返回 {score, signals}。

    评分规则：
      dep 命中 web framework → +3
      file tree 命中 web file pattern → +1
      README 命中 web keyword → +2
      语言 web 前端比例 > 10% → +3
      top lang JS/TS → +2
    """
    signals: list[str] = []
    score = 0

    dep_lower = dep_content.lower()
    for fw in WEB_FRAMEWORKS:
        if fw in dep_lower:
            signals.append("dep:" + fw)
            score += 3

    for path in file_tree:
        for pattern in WEB_FILE_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                signals.append("file:" + path)
                score += 1
                break

    readme_lower = readme.lower()
    for kw in WEB_README_KEYWORDS:
        if kw.lower() in readme_lower:
            signals.append("readme:" + kw)
            score += 2

    if languages:
        total_bytes = sum(languages.values()) or 1
        web_langs = {"JavaScript", "TypeScript", "CSS", "HTML", "SCSS", "Less", "Vue", "Svelte"}
        web_bytes = sum(v for k, v in languages.items() if k in web_langs)
        web_pct = web_bytes / total_bytes
        if web_pct > 0.10:
            signals.append(f"lang:web_frontend({web_pct:.0%})")
            score += 3
        top_lang = max(languages, key=languages.get) if languages else ""
        if top_lang in ("JavaScript", "TypeScript"):
            signals.append("lang:js_primary")
            score += 2

    return {"score": score, "signals": signals[:15]}


# ============================================================================
# LLM Web 分类（迁自旧第 263 行，GLM → DeepSeek via LLMRouter）
# ============================================================================
def llm_classify_web(
    repo_name: str,
    description: str,
    language: str,
    topics: list[str],
    file_tree: list[str],
    readme: str,
    rule_result: dict,
    languages: dict | None = None,
    *,
    router: LLMRouter | None = None,
) -> dict:
    """调用 DeepSeek 判断是否 Web 项目（迁自旧 llm_classify，改用 LLMRouter）。

    输出 schema: {is_web, framework, confidence, reason, demo_url}
    """
    file_tree_str = "\n".join(file_tree[:80])
    readme_short = readme[:4000]
    if rule_result["signals"]:
        rule_hint = "规则预筛得分: {} (信号: {})".format(
            rule_result["score"], ", ".join(rule_result["signals"][:8]))
    else:
        rule_hint = "规则预筛: 无 Web 信号"

    lang_info = ""
    if languages:
        total = sum(languages.values()) or 1
        top5 = sorted(languages.items(), key=lambda x: -x[1])[:5]
        lang_info = "- 语言统计: " + ", ".join(f"{k}({v / total:.1%})" for k, v in top5)

    prompt = f"""你是一个项目分类助手。根据以下 GitHub 项目信息，判断该项目是否**自带**可运行的 Web 界面/服务。

注意：
- "自带 Web" 指项目本身就是一个 Web 应用（有前端页面或可通过浏览器访问的界面/dashboard）
- 纯数据集、prompt 合集 → 不算 Web
- 如果项目有 Web 界面/dashboard/前端页面，即使也提供 CLI 或 API 库，也算 Web
- 浏览器扩展/插件、IDE 插件 → 不算 Web
- 宁可漏判不要多判：只有明确自带可运行 Web 界面/服务（README 有部署/访问方式、项目内含前端页面或 dashboard）才算 Web；仅凭迹象、拿不准、或项目本体不含可访问前端界面的一律判非 Web

项目信息：
- 名称: {repo_name}
- 描述: {description or "(无)"}
- 主语言: {language or "(未知)"}
- Topics: {", ".join(topics) if topics else "(无)"}
{lang_info}
- 文件树:
{file_tree_str}
- README 摘要:
{readme_short}
- {rule_hint}

只回答 JSON（不要其他文字）：
{{"is_web": true/false, "framework": "具体框架名或空字符串", "confidence": 0.0-1.0, "reason": "一句话理由", "demo_url": "项目部署的可交互在线实例,没有则空字符串"}}"""

    payload = {
        "repo_name": repo_name,
        "description": description,
        "language": language,
        "topics": topics,
        "file_tree_count": len(file_tree),
        "rule_score": rule_result["score"],
    }

    try:
        r = router or LLMRouter()
        output = r.complete_json(profile="deepseek", prompt=prompt, payload=payload)
        # LLMRouter.complete_json 返回 dict，可能含 result/parsed/或直接是 JSON
        result = output.get("result") or output.get("parsed") or output
        if isinstance(result, str):
            result = json.loads(result)
        # 验证 schema
        if "is_web" in result:
            return result
        return {"error": f"LLM 输出缺 is_web 字段: {str(result)[:200]}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# 完整编排（迁自旧第 337/385/411 行）
# ============================================================================
def classify_repo_internal(owner: str, repo: str, *, router: LLMRouter | None = None) -> dict:
    """对单个 GitHub 仓库做完整 Web 分类（迁自旧 classify_repo_internal）"""
    info = fetch_repo_info(owner, repo)
    if not info:
        return {"error": "无法获取仓库信息（可能不存在或私有）"}

    description = info.get("description", "")
    language = info.get("language", "")
    topics = info.get("topics", [])

    file_tree = fetch_file_tree(owner, repo)
    readme = fetch_readme(owner, repo)
    languages = fetch_languages(owner, repo)

    dep_content = ""
    dep_files = ["requirements.txt", "setup.py", "pyproject.toml", "package.json",
                 "Pipfile", "Cargo.toml", "go.mod"]
    for df in dep_files:
        if df in file_tree or any(p.endswith(df) for p in file_tree):
            content = fetch_dep_file(owner, repo, df)
            if content:
                dep_content += f"\n--- {df} ---\n{content[:1500]}\n"

    rule_result = rule_based_classify(file_tree, readme, dep_content, languages)
    llm_result = llm_classify_web(
        repo_name=f"{owner}/{repo}",
        description=description,
        language=language,
        topics=topics,
        file_tree=file_tree,
        readme=readme,
        rule_result=rule_result,
        languages=languages,
        router=router,
    )
    demo_urls = extract_demo_urls(readme)

    return {
        "repo": f"{owner}/{repo}",
        "rule_score": rule_result["score"],
        "rule_signals": rule_result["signals"],
        "llm": llm_result,
        "demo_urls": demo_urls,
    }


def classify_single_item(item: dict, *, router: LLMRouter | None = None) -> dict:
    """对单个 capability item 做 Web 分类（迁自旧 classify_single_item）"""
    url = ""
    if item.get('source_type') == 'github' and item.get('source_url'):
        url = item['source_url']
    elif item.get('code_url'):
        url = item['code_url']
        if not url.startswith("http"):
            url = "https://github.com/" + url
    elif item.get('source_url') and "github.com" in (item.get('source_url') or ""):
        url = item['source_url']

    owner, repo = parse_github_url(url)
    if not owner:
        return {"item_id": item.get('id'), "error": f"无法解析 GitHub URL: {url}"}

    result = classify_repo_internal(owner, repo, router=router)
    result["item_id"] = item.get('id')
    result["url"] = url
    return result


def classify_batch(
    conn,
    items: list[dict],
    *,
    limit: int = 50,
    router: LLMRouter | None = None,
) -> dict:
    """批量 Web 分类，写回 domain_items payload（迁自旧 classify_batch，改用新平台 repo）。

    适配点：
      - db.update_item_web_class → repo.update_domain_item（写 payload.is_web/web_framework/demo_url/classify_ts）
      - items 从外部传入，不直接读 DB
    """
    from ai4sec_platform.db import repositories as repo

    results: list[dict] = []
    demoted = 0  # web 把关:非 web 无 demo / 不可分类 而降级的条数
    for item in items[:limit]:
        item_id = item.get('id')
        try:
            result = classify_single_item(item, router=router)
        except Exception as e:
            result = {"item_id": item_id, "error": str(e)}
        results.append(result)

        if "error" not in result:
            llm = result.get("llm", {})
            if "error" not in llm:
                # === 规则/demo 兜底覆盖（宁误不漏）===
                rule_score = result.get("rule_score", 0)
                rule_signals = result.get("rule_signals", [])
                has_dep_signal = any(s.startswith("dep:") for s in rule_signals)

                # 快速路径 1: demo URL 验证通过 → 强制 is_web=True + 标记已复现
                demo_urls_found = result.get("demo_urls", [])
                verified_demo = ""
                for u in demo_urls_found:
                    if verify_demo_url(u):
                        verified_demo = u
                        break

                # 快速路径 2: rule_score >= 6 且有 dep 框架命中 → 强制 is_web=True
                rule_high = rule_score >= 6 and has_dep_signal

                # 最终决策：LLM 说了算，但 demo/rule 可覆盖
                final_is_web = bool(llm.get("is_web"))
                final_framework = llm.get("framework", "") or ""
                repro_status = ""

                if verified_demo:
                    final_is_web = True
                    repro_status = "demo_verified"
                    if not final_framework:
                        final_framework = "demo-detected"
                elif rule_high:
                    final_is_web = True
                    if not final_framework:
                        dep_signals = [s for s in rule_signals if s.startswith("dep:")]
                        if dep_signals:
                            final_framework = dep_signals[0].replace("dep:", "")

                # 低置信 Web 兜底:LLM 判 web 但无任何佐证(无验证通过的 demo、无框架名、无规则信号)
                # → 不视为 Web。修复 misevolve 类误判:LLM 按旧"宁可多判"口径把无 Web 界面的
                #   纯 CLI/评测基准项目误判成 web。现口径已改"宁可漏判", 此覆盖兜底低置信判 web。
                #   此覆盖不算真非 web, 保留原状态走 CLI 复现, 不降级。
                low_conf_web = (
                    final_is_web
                    and not verified_demo
                    and not final_framework
                    and rule_score < 6
                )
                if low_conf_web:
                    final_is_web = False
                    final_framework = "LOWCONF"

                is_web = 1 if final_is_web else 0
                framework = final_framework
                classify_ts = datetime.now().isoformat()
                demo_url = verified_demo or (llm.get("demo_url", "") or "")
                if not demo_url and result.get("demo_urls"):
                    demo_url = result["demo_urls"][0]
                if demo_url and not verify_demo_url(demo_url):
                    demo_url = ""

                # 写回 domain_items payload
                # repro_status 只在 demo_verified 时才写，避免覆盖 Store 步骤设的 "candidate"
                web_payload = {
                    "is_web": bool(is_web),
                    "web_framework": framework,
                    "web_classify_ts": classify_ts,
                    "demo_url": demo_url,
                }
                if repro_status:
                    web_payload["repro_status"] = repro_status
                # web/demo 把关:LLM 判非 web 且无 demo 兜底 → 降为已淘汰,不进复现队列
                # (低置信覆盖 not final_is_web 但 low_conf_web 为真, 不降级)
                if not final_is_web and not low_conf_web:
                    demoted += 1
                    repo.update_domain_item(
                        conn,
                        item_id=item_id,
                        payload=web_payload,
                        status="已淘汰",
                        metrics={"web_classify_score": rule_score},
                    )
                else:
                    repo.update_domain_item(
                        conn,
                        item_id=item_id,
                        payload=web_payload,
                        metrics={"web_classify_score": rule_score},
                    )
            else:
                # LLM error: 标记避免重复重试;分类未定 → 降到待资料补齐(不进复现队列、不判死)
                repo.update_domain_item(
                    conn, item_id=item_id,
                    payload={"is_web": False, "web_framework": "ERROR", "web_classify_ts": datetime.now().isoformat()},
                    status="待资料补齐",
                )
        else:
            # 无有效 repo: 标记为不可分类;无 web 依据 → 降为已淘汰,不进复现队列
            demoted += 1
            repo.update_domain_item(
                conn, item_id=item_id,
                payload={"is_web": False, "web_framework": "SKIP", "web_classify_ts": datetime.now().isoformat()},
                status="已淘汰",
            )

        time.sleep(1)  # GitHub API 限流

    classified = sum(1 for r in results if "error" not in r and "error" not in r.get("llm", {}))
    failed = len(results) - classified
    return {"classified": classified, "failed": failed, "demoted": demoted, "results": results}


# ============================================================================
# 规则评估（保留现有 + 扩展完整评估）
# ============================================================================
def rule_based_assessment(item: dict) -> dict:
    """本地规则评估（保留现有接口）"""
    has_code = bool(item.get("code_url") or item.get("source_url") or item.get("repo_url"))
    scoring = score_capability_candidate(item)
    return {
        "status": "待复现验证" if has_code else "待资料补齐",
        "reason": "基于代码链接、论文线索、安全主题和可复现性进行本地规则评估。",
        "score": scoring.score,
        "scoring": scoring.as_payload(),
        "input": item,
    }


def assess_capability(item: dict, *, router: LLMRouter | None = None) -> dict:
    """完整能力评估：多维度评分 + Web 分类（如果 item 有 GitHub repo）。

    返回: {score, breakdown, is_web, web_framework, demo_url, ...}
    """
    scoring = score_capability_candidate(item)
    result: dict[str, Any] = {
        "score": scoring.score,
        "breakdown": scoring.breakdown,
        "priority": scoring.priority,
        "reasons": scoring.reasons,
        "signals": scoring.signals,
    }

    # 如果有 GitHub repo，做 Web 分类
    code_url = item.get("code_url") or ""
    source_url = item.get("source_url") or ""
    github_url = code_url if code_url else (source_url if "github.com" in source_url else "")

    if github_url:
        owner, repo_name = parse_github_url(github_url)
        if owner:
            web_result = classify_repo_internal(owner, repo_name, router=router)
            llm = web_result.get("llm", {})
            if "error" not in llm:
                result["is_web"] = bool(llm.get("is_web"))
                result["web_framework"] = llm.get("framework", "")
                result["web_confidence"] = llm.get("confidence", 0)
                result["demo_url"] = llm.get("demo_url", "")
                if not result["demo_url"] and web_result.get("demo_urls"):
                    candidate_url = web_result["demo_urls"][0]
                    if verify_demo_url(candidate_url):
                        result["demo_url"] = candidate_url
            result["web_classify"] = web_result

    return result
