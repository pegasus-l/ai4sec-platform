"""人工投喂 URL / 文章(2026-10-10)。

**为什么要这个模块**:漏洞域此前没有任何"我把这篇文章喂给它"的入口。crawl4ai 只按搜索关键词
自己找,用户看到一篇好 writeup,只能等它被搜到 —— 而且很可能永远等不到(`skip_existing_urls`
会去重、时间范围只覆盖最近 30 天、排序靠前的永远是热词)。这里给出那条人工通道。

**与自动采集的关系**:`crawl_extract_review` 走的是**与自动采集完全相同**的
抓取 → 正文抽取 → 评审链路(同一个 crawl4ai 连接器、同一个 `extract_page_content`、
同一个 `review_crawled_material`),所以人工素材的字段结构、证据抽取、溯源口径与自动素材
完全一致,不会在下游(知识抽取、事件聚合、模式合成)里变成第二种物种。

**与链接钻取的关系**:`DrillDownAcceptedMaterialsStep` 里的 `_drill_one` 本来就是这套闭环
(它给子文章独立建素材)。`crawl_extract_review` 是把它原样提取出来的公共实现,`_drill_one`
改为调用本函数 —— 一条代码路径两处复用,行为逐字不变,自动钻取的产出不受本次改动影响。

**容错约定**:`crawl_extract_review` 整体 try/except,任何异常(连接器抛错、模型超时、
URL 解析失败)都收敛成 `{"url": ..., "success": False, "error": ...}`,由调用方按条计入
失败,绝不中断整批 —— 人工投喂是"用户盯着看"的操作,一条坏 URL 不该让另外九条也白喂。
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from ai4sec_platform.core.time import utc_now
from ai4sec_platform.domains.vulnerabilities.content_extractors import extract_page_content
from ai4sec_platform.domains.vulnerabilities.material_reviewers import review_crawled_material
from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.connectors.vulnerabilities.crawl4ai import Crawl4aiConnector

# 允许投喂的最长 URL(防脏行撑爆 payload)
MAX_URL_LENGTH = 2_000
# 用户直接贴正文时的最短长度。低于这个数"不是素材而是误操作"(贴了个标题、粘了半句话),
# 在 API 层就 400 掉,给出即时反馈,而不是让用户等一次跑批才发现失败。
MIN_PROVIDED_BODY_CHARS = 200
# **强制入库也守的硬底线**:正文短于这个数,说明压根没抓到内容(或者抓到的是导航页)。
# 注意这与"模型说这文章不够格"是两回事 —— 用户的决定是"忽略模型的质量判断",不是
# "把空页面也塞进知识库"。
MIN_MATERIAL_CHARS = 200

DEFAULT_REQUIREMENTS = "高质量漏洞技术分析、PoC、公告、补丁或可沉淀知识的漏洞情报"


def fallback_title(review: dict[str, Any], url: str) -> str:
    """标题兜底:短标题多为站点名(Blogger 等 `<title>`=站点),不予采信;
    依次用 URL slug 反解 / 正文首段可读行推导,避免裸 URL 或站点名当素材标题。

    2026-10-10 从 pipelines/steps/vulnerability_discovery.py 的 `_drill_title` 原样挪来
    (人工投喂也要用同一份兜底,否则同一篇文章走人工和走钻取会得到两个标题)。逻辑逐字未改。
    """
    title = str(review.get("title") or "").strip()
    if title and title != url and title != "未命名抓取页" and len(title) >= 18:
        return title
    slug = _url_slug_title(url)
    if slug:
        return slug
    cleaned = str(review.get("cleaned_text") or "").strip()
    for line in cleaned.splitlines()[:8]:
        text = line.strip().lstrip("#").strip()
        if 8 <= len(text) <= 120 and not text.lower().startswith(("http://", "https://", "search", "home", "about", "tags")):
            return text
    return title or url


def _url_slug_title(url: str) -> str:
    """URL 路径段反解标题:从最后一个可读 path segment 推导
    (如 .../reviving-exploits-against-cred-struct.html → 'Reviving Exploits Against Cred Struct')。"""
    path = (urlparse(url).path or "").rstrip("/")
    if not path:
        return ""
    segment = path.rsplit("/", 1)[-1]
    segment = re.sub(r"\.(html?|php|aspx?|jsp)$", "", segment, flags=re.IGNORECASE)
    words = [w for w in re.split(r"[-_+]+", segment) if w.strip()]
    if len(words) < 3:
        return ""
    return " ".join(w.capitalize() for w in words)


def validate_url(url: str) -> str:
    """校验人工投喂的 URL 并归一(去首尾空白)。必填,且必须是 http/https 且有主机名。

    必填的理由:素材按 `source_url` 去重(domains/vulnerabilities/builders.py),不给 URL
    的"裸正文"每次投喂都会新建一条重复素材,越喂越脏。正文可以不给(平台自己去抓),
    URL 不能不给。
    """
    clean = str(url or "").strip()
    if not clean:
        raise ValueError("请填写原文 URL")
    if len(clean) > MAX_URL_LENGTH:
        raise ValueError("URL 过长")
    parsed = urlparse(clean)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("请填完整 URL(含 http/https)")
    return clean


def crawl_extract_review(
    url: str,
    *,
    requirements: str = DEFAULT_REQUIREMENTS,
    confidence_threshold: float = 0.55,
    timeout_seconds: int = 30,
    use_model: bool = True,
    title: str = "",
    body: str = "",
) -> dict[str, Any]:
    """URL → 抓取 → 正文抽取 → 评审。失败收敛成 success=False,不抛异常。

    给了 `body`(用户直接贴了正文)就**跳过抓取**直接进同一条抽取+评审链 —— 省一次外网
    请求,也让需要登录/已经下线的页面能被喂进来。此时 URL 只作为溯源标识,不校验可达性。
    """
    try:
        page = _load_page(url, title=title, body=body, timeout_seconds=timeout_seconds)
        if not page.get("success"):
            return {"url": url, "success": False, "error": str(page.get("error") or "no_result")[:300]}
        extracted = extract_page_content(page, use_model=use_model)
        return review_crawled_material(
            extracted,
            requirements=requirements,
            confidence_threshold=confidence_threshold,
            use_model=use_model,
        )
    except Exception as exc:  # noqa: BLE001 - 外部抓取/模型调用,任何异常都不该中断调用方
        return {"url": url, "success": False, "error": str(exc)[:300]}


def cleaned_text_of(review: dict[str, Any]) -> str:
    """取评审结果里的正文(供长度底线判断)。"""
    return str(review.get("cleaned_text") or review.get("markdown") or "").strip()


def manual_override_block(
    review: dict[str, Any],
    *,
    created_by: str,
    label: str = "",
    note: str = "",
) -> dict[str, Any]:
    """强制入库时保留的"模型原本怎么判"的元数据。

    用户 2026-10-10 拍板:人工喂的必须进库,模型结论只作为元数据留着 —— 既能事后回溯
    "有多少人工素材是模型不认可的"(这是评估模型质量门的现成样本),也不至于让"强制入库"
    变成一个查不出原因的空白决定。
    """
    meta = review.get("review") if isinstance(review.get("review"), dict) else {}
    return {
        "by": str(created_by or ""),
        "label": str(label or ""),
        "note": str(note or ""),
        "at": utc_now(),
        "original_decision": str(review.get("decision") or ""),
        "original_confidence": review.get("confidence"),
        "original_reason": str(review.get("reason") or "")[:500],
        "original_reviewer": str(meta.get("reviewer") or ""),
    }


def _load_page(url: str, *, title: str, body: str, timeout_seconds: int) -> dict[str, Any]:
    """取页面。用户贴了正文就手工构造 page dict,否则走 crawl4ai。"""
    text = str(body or "").strip()
    if text:
        return {
            "success": True,
            "url": url,
            "title": str(title or "").strip(),
            "markdown": text,
            "cleaned_text": text,
            "crawl_info": {"mode": "manual_body", "success": True, "markdown_length": len(text)},
        }
    result = Crawl4aiConnector().fetch(
        SourceFetchRequest(
            source_name="crawl4ai",
            params={"urls": [url], "prefer_url_fetch": True, "max_items": 1, "timeout_seconds": int(timeout_seconds)},
            config={},
        )
    )
    pages = result.items or []
    if not pages:
        return {"success": False, "url": url, "error": "no_result"}
    page = pages[0]
    if str(title or "").strip():
        # 用户显式填了标题就用它 —— 人工输入优先,所见即所得(不然用户填了却不生效最费解)。
        page = {**page, "title": str(title).strip()}
    return page
