"""修复前源码与仓库归档的抓取(P4b)。

**为什么不用 GitHub API 拿父提交:** `api.github.com` 未鉴权只有 60 次/小时,而每晚要处理
几十个洞;实测共享出口 IP 的那点额度经常只剩个位数。改成"抓**修复后**的文件 + 用补丁
反向回滚"——补丁本身就在库里(`patch_diff.content`),`git apply -R` 的语义用纯 Python
实现即可(见 `dataflow_extractor.reverse_apply`),不消耗任何 API 配额,也不依赖 git
(容器里没有 git,只有 tar)。

三个端点:
- `raw.githubusercontent.com/{repo}/{ref}/{path}` —— 单文件(修复后状态,由调用方回滚)
- `codeload.github.com/{repo}/tar.gz/{ref}` —— 整仓归档,只在找 1 跳调用者时用,有体积上限
- `github.com/{repo}/releases.atom` —— 发布说明(P5b 自有源),同样不吃 api.github.com 配额
- GitLab 的 `/-/raw/` 单文件(不拉归档:GitLab 归档 URL 形态与体积都更难控)
"""

from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.result import SourceFetchResult

USER_AGENT = "ai4sec-platform/0.1 (+vulnerability-case-context)"

# 单文件上限:源码文件正常在几十 KB;超过 2 MB 的多半是压缩包/生成物,送进模型没有意义
FILE_MAX_BYTES = 2_000_000
# 整仓归档上限(压缩后)。linux 这类超大仓会超限 —— 那是**跳过找调用者**,不是失败:
# 漏洞点文件本身仍然抓得到,数据流仍可从该文件内推断。
ARCHIVE_MAX_BYTES = 25 * 1024 * 1024

# GitHub 提交 RSS/Atom 流里的 commit 形如 `<id>tag:github.com,2008:Grit::Commit/<40hex></id>`。
# 用 atom 而不是 api.github.com/commits:后者未鉴权 60 次/小时,和 P4b 避开的是同一份额度。
_ATOM_COMMIT_RE = re.compile(r"Grit::Commit/([0-9a-f]{40})")


_ATOM_NS = "{http://www.w3.org/2005/Atom}"


def parse_release_atom(text: str, *, limit: int = 5) -> list[dict[str, str]]:
    """Atom → [{entry_id, title, updated, content}](新到旧)。**纯解析**,单测直接喂 XML。

    解析失败返回空列表而不是抛:一个项目的 feed 坏了不该让整晚同步停下。
    """
    try:
        root = ET.fromstring(str(text or "").strip())
    except ET.ParseError:
        return []
    prefix = _ATOM_NS if root.tag.startswith(_ATOM_NS) else ""
    out: list[dict[str, str]] = []
    for entry in root.findall(f"{prefix}entry"):
        def field(tag: str) -> str:
            node = entry.find(f"{prefix}{tag}")
            return (node.text or "").strip() if node is not None else ""
        content = field("content") or field("summary")
        out.append({
            "entry_id": field("id"),
            "title": field("title"),
            "updated": field("updated") or field("published"),
            "content": content,
        })
        if len(out) >= max(1, int(limit)):
            break
    return out


class GithubSourceConnector:
    connector_name = "github_source"
    source_type = "github_source"

    def health_check(self, config: dict) -> SourceHealth:
        return SourceHealth(status="ok", message="raw.githubusercontent.com / codeload.github.com(免 key)")

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        """供连接器注册表调用的最小实现:`{repo, ref, path}` → 单个文件。"""
        repo = str(request.params.get("repo") or "")
        ref = str(request.params.get("ref") or "")
        path = str(request.params.get("path") or "")
        if not repo or not ref or not path:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, errors=["missing_repo_ref_path"])
        try:
            text = self.fetch_file(repo, ref, path)
        except Exception as exc:  # noqa: BLE001
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, errors=[str(exc)[:300]])
        if text is None:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, errors=["not_found"])
        return SourceFetchResult(
            source_name=request.source_name,
            connector_name=self.connector_name,
            items=[{"repo": repo, "ref": ref, "path": path, "content": text}],
            metadata={"bytes": len(text)},
        )

    # ── 单文件 ────────────────────────────────────────────────────────────────

    def fetch_file(self, repo: str, ref: str, path: str, *, timeout: int = 45) -> str | None:
        """GitHub 单文件。**404 返回 None**(文件在这个 ref 下不存在),其余错误照常抛。"""
        url = f"https://raw.githubusercontent.com/{urllib.parse.quote(repo, safe='/')}/{urllib.parse.quote(ref, safe='')}/{urllib.parse.quote(path, safe='/')}"
        return self._get_text(url, timeout=timeout, max_bytes=FILE_MAX_BYTES)

    def fetch_gitlab_file(self, project: str, ref: str, path: str, *, timeout: int = 45) -> str | None:
        url = f"https://gitlab.com/{urllib.parse.quote(project, safe='/')}/-/raw/{urllib.parse.quote(ref, safe='')}/{urllib.parse.quote(path, safe='/')}"
        return self._get_text(url, timeout=timeout, max_bytes=FILE_MAX_BYTES)

    # ── 最近提交(默认分支) ───────────────────────────────────────────────────

    def recent_commit_shas(self, repo: str, *, limit: int = 5, timeout: int = 45) -> list[str]:
        """默认分支最近 N 个 commit 的 sha(从 atom 流读,不消耗 API 配额)。

        仓不存在 / 私有仓返回 404 → 空列表(调用方记"没有提交",不当异常)。
        """
        url = f"https://github.com/{urllib.parse.quote(repo, safe='/')}/commits.atom"
        text = self._get_text(url, timeout=timeout, max_bytes=512_000)
        if text is None:
            return []
        out: list[str] = []
        for sha in _ATOM_COMMIT_RE.findall(text):
            if sha not in out:
                out.append(sha)
            if len(out) >= max(1, int(limit)):
                break
        return out

    # ── 发布说明(P5b 自有源) ──────────────────────────────────────────────────

    def recent_releases(self, repo: str, *, limit: int = 5, timeout: int = 45) -> list[dict[str, str]]:
        """默认分支最近的 release 条目(新到旧)。仓没有 release / 404 → 空列表。

        `releases.atom` 与 `commits.atom` 是同一套免 token 通道:内容里就是发布说明正文
        (HTML),漏洞编号(CVE/GHSA)常常直接写在里面。**不解析 HTML**,交给
        `project_sources.extract_ids` 做正则 —— 发布说明的结构千奇百怪,挑一种解析器
        去认另一种格式只会静默漏数据。
        """
        url = f"https://github.com/{urllib.parse.quote(repo, safe='/')}/releases.atom"
        text = self._get_text(url, timeout=timeout, max_bytes=1_000_000)
        if text is None:
            return []
        return parse_release_atom(text, limit=limit)

    # ── 整仓归档 ──────────────────────────────────────────────────────────────

    def fetch_archive(self, repo: str, ref: str, *, max_bytes: int = ARCHIVE_MAX_BYTES, timeout: int = 120) -> tuple[bytes | None, str]:
        """取 GitHub 仓库在某个 commit 上的 tar.gz。返回 (内容, 跳过原因)。

        超限返回 `(None, "archive_too_large")` 而不是抛错 —— 找 1 跳调用者是**尽力而为**,
        不能因为仓库大就让整条数据流失败。
        """
        url = f"https://codeload.github.com/{urllib.parse.quote(repo, safe='/')}/tar.gz/{urllib.parse.quote(ref, safe='')}"
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/x-gzip,*/*"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - 只拼 codeload.github.com
                payload = response.read(max_bytes + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None, "archive_not_found"
            raise
        if len(payload) > max_bytes:
            return None, "archive_too_large"
        return payload, ""

    # ── 内部 ──────────────────────────────────────────────────────────────────

    def _get_text(self, url: str, *, timeout: int, max_bytes: int) -> str | None:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/plain,*/*"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - 只拼 github/gitlab 域名
                raw = response.read(max_bytes + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise
        if len(raw) > max_bytes:
            return None
        return raw.decode("utf-8", errors="replace")
