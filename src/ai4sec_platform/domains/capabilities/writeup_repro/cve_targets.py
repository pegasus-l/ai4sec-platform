"""刀二:把模型指认的 CVE 编号落成**能执行**的复现目标(仓库 / 产品 / 版本)。

为什么需要这一步
================

T1.4 基线(2026-11-11,全量 1229 条素材)发现:102 条"可复现"里有 **47 条既没有仓库
也没有版本**。逐条读完再分,这 47 条不是一类东西:

- **16 条纯教程**(堆溢出入门、chroot 逃逸、ret2plt、PATH 提权):该拒,跑通只证明我们会编译;
- **6 条是真产品洞**,标题里就写着 CVE 号(Vite CVE-2025-30208、Himmelblau CVE-2026-31979、
  Kubernetes CVE-2020-8562 ……):**不该拒**,它们的目标其实是明确的,只是 T1.2 的抽取器
  没能把 ``target_repo`` / ``target_version`` 落下来;
- 25 条只是在正文里顺带提到编号:按教程处理。

所以"收紧 self_contained"一刀切是错的,会把那 6 条真产品洞一起丢掉。这里做第二刀:
**带着编号去查**。查到了就补字段放行,查不到才按 ``target_unknown`` 拒。

查的顺序 = 从便宜到贵,前一步能解决就不走下一步
=============================================

1. 站内案例库 ``vulnerability_cases``:零成本、零网络。但只有被回溯富化过的行才有 products ——
   896 条历史迁移行是空的(2026-11-11 实测),所以它现在基本查不出东西,留着是为了以后。
2. OSV 按 id:免 key,给受影响的包 + 版本区间,references 里常有修复 commit(能反推仓库)。
3. NVD 按 id:OSV 没收录的洞(厂商私有 CVE、小众项目),只有 CPE 产品名与版本区间。

三条纪律
========

- **"查不到"和"查崩了"是两件事。** 404 / 没有记录是结论(返回空目标,按 ``target_unknown`` 拒);
  网络错误 / 5xx / 超时是**没拿到答案** —— 抛 ``TargetLookupUnavailable``,调用方一个字都不许
  落库,下一轮重挑。与"模型报错不落库"同一条纪律: 把"没查成"写成"查过、没有"是最难发现的谎。
- **不猜仓库。** references 里没有 github/gitlab 链接就是没有,绝不拿产品名去拼 ``vendor/product``。
  猜错等于让人去复现另一个项目,而且每一步都看起来是对的。
- **版本必须是别人写的数。** 区间取 "fixed" 的事件写成 ``< 1.2.3``;拿不到就留空 ——
  "有仓库无版本"(C 档)是一个合理状态,不是失败,靠人补或靠 T2 的 spec 再定。
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from ai4sec_platform.domains.capabilities.writeup_repro.screener_rules import normalize_repo

#: 一篇文章最多让外部源查几条 —— 只是防止参数写错时把整批素材都变成"每条一次网络往返",
#: 正常每晚几十条以内。用完之后抛 ``LookupDeferred``,这一条不落库,下一轮再来。
DEFAULT_MAX_LOOKUPS = 25

#: 这些仓库里出现的洞**不是**本文的目标: 它们是漏洞记录的镜像仓 / 公告库。
#: 实测 OSV 的 references 第一条经常就是 ``github.com/CVEProject/cvelistV5/...`` ——
#: 不排掉的话每条都能"反查到仓库",而且都是同一个仓。
_REFERENCE_NOISE_REPOS = frozenset({
    "cveproject/cvelistv5",
    "github/advisory-database",
    "nvd-nist/nvd",
})


class TargetLookupUnavailable(RuntimeError):
    """外部源全线不可用 —— 这不是结论,调用方不能落库。"""


class LookupDeferred(RuntimeError):
    """本轮查询预算用完了 —— 同上,这一条留给下一轮。"""


@dataclass(frozen=True)
class ResolvedTarget:
    """从 CVE 反查出来的目标。三者全空 = 查过、没有。"""

    repo: str = ""
    version: str = ""
    product: str = ""
    source: str = ""            # db | osv | nvd
    cve: str = ""

    @property
    def usable(self) -> bool:
        return bool(self.repo or self.version or self.product)


def _json_list(raw: Any) -> list[str]:
    try:
        value = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item or "").strip()]


def repo_from_urls(urls: list[str]) -> str:
    """从一堆 URL 里认出一个仓库地址;认不出返回空串。

    只认 ``normalize_repo`` 认得的平台(仓库 URL 本身),并且排掉漏洞记录镜像仓 ——
    那些链接只能证明"这个洞被记录过",不能证明"代码在这里"。
    """
    for raw in urls:
        repo = normalize_repo(str(raw or ""))
        if not repo:
            continue
        if repo.split(":", 1)[1] in _REFERENCE_NOISE_REPOS:
            continue
        return repo
    return ""


def version_from_ranges(ranges: list[str]) -> str:
    """OSV / 案例库的受影响区间 → 一个能拿去装环境的版本约束。

    只认 OSV 归一过的那种文本(``SEMVER: introduced 0; fixed 1.2.3``)。GIT 区间是 commit
    不是版本,跳过 —— 拿 commit 当版本去 checkout 是另一回事(T2 的 spec 再处理)。
    """
    for text in ranges:
        text = str(text or "")
        if text.strip().upper().startswith("GIT:"):
            continue
        match = re.search(r"fixed\s+([0-9][\w.\-+]*)", text)
        if match:
            return f"< {match.group(1)}"
        match = re.search(r"introduced\s+([0-9][\w.\-+]*)", text)
        if match and match.group(1) not in ("0", "0.0", "0.0.0"):
            return f">= {match.group(1)}"
    return ""


def _nvd_cpe_target(configurations: list[Any]) -> tuple[str, str]:
    """NVD 的 ``configurations`` → (产品, 版本约束)。NVD 只有 CPE,没有仓库。"""
    for config in configurations:
        if not isinstance(config, dict):
            continue
        for node in config.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch") or []:
                if not isinstance(match, dict) or not match.get("vulnerable", True):
                    continue
                parts = str(match.get("criteria") or "").split(":")
                if len(parts) < 5:
                    continue
                vendor, name = parts[3], parts[4]
                if not name or name in ("*", "-"):
                    continue
                product = f"{vendor}:{name}" if vendor and vendor != "*" else name
                version = ""
                if match.get("versionEndExcluding"):
                    version = f"< {match['versionEndExcluding']}"
                elif match.get("versionEndIncluding"):
                    version = f"<= {match['versionEndIncluding']}"
                elif match.get("versionStartIncluding"):
                    version = f">= {match['versionStartIncluding']}"
                elif parts[5] not in ("*", "-", ""):
                    version = str(parts[5])
                return product, version
    return "", ""


class CaseTargetResolver:
    """按 CVE 反查目标。实例**带预算**,一次预筛跑批共用一个。

    ``osv`` / ``nvd`` 传 None 时按需构造(只有真的走到网络那一步才导入连接器) ——
    单测和"这批没有一条需要反查"的跑批都不会因此拉起 HTTP 栈。
    """

    def __init__(
        self,
        conn: sqlite3.Connection | None,
        *,
        osv: Any = None,
        nvd: Any = None,
        max_lookups: int = DEFAULT_MAX_LOOKUPS,
    ) -> None:
        self._conn = conn
        self._osv = osv
        self._nvd = nvd
        self._budget = max(0, int(max_lookups))
        self._cache: dict[str, ResolvedTarget] = {}

    # ── 对外 ────────────────────────────────────────────────────────────────

    def __call__(self, cve_id: str) -> ResolvedTarget:
        cve = str(cve_id or "").strip().upper()
        if not cve:
            return ResolvedTarget()
        if cve in self._cache:
            return self._cache[cve]

        target = self._from_case_library(cve)
        if target.usable:
            self._cache[cve] = target
            return target

        if self._budget <= 0:
            # 不缓存、也不给结论: 这一条留到下一轮。用"查不起"冒充"查不到"会把好稿子判死。
            raise LookupDeferred(f"本轮 CVE 反查预算已用完({cve} 未查)")

        self._budget -= 1
        answered = False          # 至少有一个源明确回答过(包括"没有这条")
        errors: list[str] = []

        try:
            target = self._from_osv(cve)
            answered = True
            if target.usable:
                self._cache[cve] = target
                return target
        except Exception as exc:  # noqa: BLE001 - 单源失败换下一个源,两个都挂才抛
            errors.append(f"osv: {type(exc).__name__}: {exc}")

        try:
            target = self._from_nvd(cve)
            answered = True
            if target.usable:
                self._cache[cve] = target
                return target
        except Exception as exc:  # noqa: BLE001
            errors.append(f"nvd: {type(exc).__name__}: {exc}")

        if not answered:
            raise TargetLookupUnavailable("; ".join(errors)[:300])

        empty = ResolvedTarget(cve=cve)
        self._cache[cve] = empty
        return empty

    # ── 三个来源 ────────────────────────────────────────────────────────────

    def _from_case_library(self, cve: str) -> ResolvedTarget:
        """站内案例库。零成本、零网络,但只有被回溯富化过的行才有 products。"""
        if self._conn is None:
            return ResolvedTarget(cve=cve)
        try:
            row = self._conn.execute(
                "SELECT affected_products_json, affected_ranges_json, references_json "
                "  FROM vulnerability_cases WHERE canonical_id = ?",
                (cve,),
            ).fetchone()
        except sqlite3.Error:
            return ResolvedTarget(cve=cve)
        if row is None:
            return ResolvedTarget(cve=cve)
        products = _json_list(row[0])
        ranges = _json_list(row[1])
        target = ResolvedTarget(
            repo=repo_from_urls(_json_list(row[2])),
            version=version_from_ranges(ranges),
            product=products[0] if products else "",
            source="db",
            cve=cve,
        )
        return target if target.usable else ResolvedTarget(cve=cve)

    def _from_osv(self, cve: str) -> ResolvedTarget:
        from ai4sec_platform.domains.vulnerabilities.case_sources import osv_fields

        payload = self._osv_connector().lookup(cve)   # 404 → None
        if not payload:
            return ResolvedTarget(cve=cve)
        fields = osv_fields(payload)
        products = list(fields.get("affected_products") or [])
        target = ResolvedTarget(
            repo=repo_from_urls(list(fields.get("references") or [])),
            version=version_from_ranges(list(fields.get("affected_ranges") or [])),
            product=products[0] if products else "",
            source="osv",
            cve=cve,
        )
        return target if target.usable else ResolvedTarget(cve=cve)

    def _from_nvd(self, cve: str) -> ResolvedTarget:
        item = self._nvd_connector().fetch_by_id(cve)   # 没有这条 → None
        if not isinstance(item, dict):
            return ResolvedTarget(cve=cve)
        cve_obj = item.get("cve") or {}
        refs = [str((ref or {}).get("url") or "") for ref in (cve_obj.get("references") or [])]
        product, version = _nvd_cpe_target(list(cve_obj.get("configurations") or []))
        target = ResolvedTarget(
            repo=repo_from_urls(refs),
            version=version,
            product=product,
            source="nvd",
            cve=cve,
        )
        return target if target.usable else ResolvedTarget(cve=cve)

    # ── 连接器 ──────────────────────────────────────────────────────────────

    def _osv_connector(self) -> Any:
        if self._osv is None:
            from ai4sec_platform.sources.connectors.vulnerabilities.osv import OsvConnector

            self._osv = OsvConnector()
        return self._osv

    def _nvd_connector(self) -> Any:
        if self._nvd is None:
            from ai4sec_platform.sources.connectors.vulnerabilities.nvd import NvdConnector

            self._nvd = NvdConnector()
        return self._nvd
