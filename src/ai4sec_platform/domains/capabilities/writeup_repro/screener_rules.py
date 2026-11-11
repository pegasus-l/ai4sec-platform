"""T1.1:writeup 可复现性预筛的**规则层**(L0/L1),不调模型、不碰数据库。

设计口径
========

三道闸门,一道比一道严,但**全部是结构判断**,没有任何"看起来像"的模糊判断:

1. **L0-a 没有代码块** → ``not_writeup``。清单页、新闻体、纯评论到此为止。
2. **L0-b 有代码块但没有一块是命令或源码** → ``no_poc``。实测这类最多的是
   程序菜单、路径串、十六进制 dump、配置片段 —— 它们长得像代码,但跑不出东西。
3. **L1 有命令或源码,但定不下目标** → ``target_unknown``。目标只能来自三种**硬证据**:
   仓库 URL、CVE 编号、三段式版本号。定不下来就不进队列,因为"复现谁"都不知道。

> **``rules-v3``(2026-11-11,T1.4 两刀)**:L1 过线只代表"值得送去模型看",不再代表可复现。
> T1.4 基线发现 102 条"可复现"里 47 条既无仓库也无版本 —— 其中"正文里出现过某个 CVE"
> 这条最松的口子放了 25 条教程进来(编号只是文章举的例子)。所以现在 **CVE 只是线索,
> 要能反查成产品/版本才算目标**:模型层指认 CVE → ``cve_targets`` 去查 → 查到才放行。
> 规则层这里放宽不放宽都不影响最终结论,留着它的唯一理由是"没有仓库也没有编号的稿子
> 连模型都不用调"。

通过 L1 的素材才允许进 L2(模型抽取 target/spec)。

两条刻意的克制
--------------

- **不在规则层判 ``online_service``。** "目标是线上服务"要看语境(打的是自己的靶场
  还是别人的生产站),正则判不准;这条留给 L2 的模型 + T3.4 的执行边界双保险。
  规则层宁可放过去,也不赌。
- **版本号只认三段式(或带 v 前缀的两段式)。** 正文里 ``1.2`` 这种东西到处都是,
  拿它当"定得下版本"等于没定。

``#`` 开头的行不一律当 shell 提示符:实测输出/地图 dump 里的 ``#  ├── center: ...``
会被误判成命令。只有 ``#`` 后面紧跟已知命令时才算(root 权限示例的常见写法)。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SCREENER_VERSION = "rules-v3"

#: 拒绝桶。固定枚举 —— 新值要改代码,不允许管道里随手回传自由文本。
REJECT_REASONS: tuple[str, ...] = (
    "not_writeup",       # 没有代码块:清单页 / 新闻体 / 纯评论
    "no_poc",            # 有代码块,但没有一块是命令或源码
    "target_unknown",    # 有 PoC,但定不下仓库 / CVE / 版本
    "article_incomplete",  # 留给 L2:原文讲了一半
    "online_service",      # 留给 L2:目标是线上服务,只读不打
    # 留给 L2:模型说有 PoC,但摘出来的那段代码在原文里找不到(编的)。与 no_poc 是两件事 ——
    # 混在一起统计, 会把"模型瞎编"读成"文章没料", 而前者是我们要盯的模型缺陷。
    "poc_unverified",
)

#: 代码块分类。
BLOCK_KINDS: tuple[str, ...] = ("command", "source", "config", "data", "empty")

#: 显式标注了语言、且该语言本身就是"能跑的东西"。``bash`` 一类另走命令判定。
SOURCE_LANGS: frozenset[str] = frozenset({
    "python", "py", "c", "cpp", "c++", "h", "hh", "java", "js", "javascript",
    "ts", "typescript", "go", "golang", "php", "ruby", "rb", "rust", "rs",
    "solidity", "sol", "csharp", "cs", "kotlin", "kt", "swift", "scala",
    "perl", "pl", "lua", "asm", "nasm", "powershell", "ps1", "sql",
})

#: 无语言标注时,靠这些行首特征认源码。
_SOURCE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(re.compile(p, re.M) for p in (
    r"^\s*#include\s*[<\"]",
    r"^\s*import\s+[\w.*]+",
    r"^\s*from\s+\w[\w.]*\s+import\b",
    r"^\s*def\s+\w+\s*\(",
    r"^\s*class\s+\w+",
    r"^\s*public\s+(?:static\s+)?(?:final\s+)?(?:class|interface|void|int|String)\b",
    r"^\s*package\s+main\b",
    r"^\s*<\?php",
    r"^\s*func\s+\w+\s*\(",
    r"^\s*fn\s+\w+\s*[<(]",
    r"^\s*pragma\s+solidity\b",
    r"^\s*using\s+System\b",
    r"^\s*int\s+main\s*\(",
    r"^\s*void\s+main\s*\(",
))

#: 出现在行首即可判定"这是条命令"的常见可执行文件。宁可宽一点:这里误收的代价
#: 只是多送 L2,漏收的代价是一篇真 writeup 被永久判死。
COMMAND_TOKENS: frozenset[str] = frozenset({
    "curl", "wget", "python", "python2", "python3", "pip", "pip3", "pipx", "uv",
    "npm", "npx", "yarn", "pnpm", "node", "deno", "bun",
    "go", "cargo", "rustc", "gcc", "g++", "clang", "cc", "make", "cmake", "ninja",
    "docker", "docker-compose", "podman", "git", "svn",
    "bash", "sh", "zsh", "fish", "source", "export", "chmod", "chown", "sudo",
    "apt", "apt-get", "yum", "dnf", "apk", "pacman", "brew", "snap",
    "echo", "cat", "ls", "cd", "cp", "mv", "rm", "mkdir", "touch", "tar", "unzip",
    "grep", "awk", "sed", "head", "tail", "find", "xargs", "tee", "chmod",
    "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "rsync",
    "nmap", "masscan", "sqlmap", "msfconsole", "msfvenom", "searchsploit",
    "gdb", "objdump", "readelf", "r2", "radare2", "ltrace", "strace", "gcore",
    "java", "javac", "mvn", "gradle", "ant", "kotlin", "kotlinc",
    "composer", "php", "ruby", "gem", "bundle", "rails", "perl", "lua",
    "openssl", "certutil", "openssl", "keytool", "jarsigner",
    "pytest", "tox", "forge", "cast", "anvil", "hardhat", "truffle",
    "kubectl", "helm", "terraform", "ansible", "vagrant",
    "tcpdump", "iptables", "modprobe", "insmod", "rmmod", "dmesg", "sysctl",
    "busybox", "adb", "aapt", "jadx", "apktool", "frida", "objection",
    "wireshark", "tshark", "mitmproxy", "burpsuite", "mimikatz",
})

#: 明确当命令看的语言标注(内容里混着输出也行)。
_COMMAND_LANGS: frozenset[str] = frozenset({"sh", "shell", "bash", "console", "zsh", "terminal", "cmd", "bat"})

_PROMPT_PREFIXES: tuple[str, ...] = ("$ ", "PS> ", "PS C:\\", "# ")

_FENCE_RE = re.compile(r"```([^\n]*)\n(.*?)```", re.S)

#: 只认这些域名当"仓库"。博客域名、论坛域名一律不是仓库。
_REPO_RE = re.compile(
    r"https?://(github\.com|gitlab\.com|gitee\.com|gitcode\.com|atomgit\.com|bitbucket\.org)"
    r"/([\w.\-]+)/([\w.\-]+)",
    re.I,
)
_REPO_HOST_MAP = {
    "github.com": "github",
    "gitlab.com": "gitlab",
    "gitee.com": "gitee",
    "gitcode.com": "gitcode",
    "atomgit.com": "atomgit",
    "bitbucket.org": "bitbucket",
}
#: 仓库 URL 后面跟的这些段不是仓库名的一部分。
_NON_REPO_SEGMENTS = frozenset({
    "issues", "issue", "pull", "pulls", "blob", "tree", "commit", "commits",
    "releases", "actions", "wiki", "raw", "security", "advisories", "-",
})

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
#: 三段式(1.2.3)或带 v 的两段式(v1.2)。``1.2`` 单看不认。
_VERSION_RE = re.compile(r"(?<![\w.])(?:v\d+\.\d+(?:\.\d+)?|\d+\.\d+\.\d+)(?![\w.])", re.I)


def find_cves(*texts: str) -> tuple[str, ...]:
    """从若干段文本里抽出 CVE 编号(统一大写、去重、排序)。

    单独暴露出来是因为 T1.4 之后有两处要用同一个口径: 规则层判"有没有目标线索",
    以及模型层核对"模型指的那个 CVE 是不是真的在原文里"(2026-11-11)。
    """
    found: set[str] = set()
    for text in texts:
        for match in _CVE_RE.finditer(str(text or "")):
            found.add(match.group(0).upper())
    return tuple(sorted(found))


@dataclass(frozen=True)
class Block:
    """一个 fenced 代码块。``index`` 是它在原文里的序号,便于回查。"""

    index: int
    lang: str
    kind: str
    line_count: int
    head: str


@dataclass(frozen=True)
class RuleScreen:
    """规则层结论。一旦 ``screenable=False``,``reject_reason`` 必有值且只有一个。"""

    screenable: bool
    reject_reason: str
    has_command: bool
    has_source: bool
    target_repo: str
    cve_ids: tuple[str, ...]
    versions: tuple[str, ...]
    blocks: tuple[Block, ...] = field(default_factory=tuple)
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def block_kinds(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for b in self.blocks:
            counts[b.kind] = counts.get(b.kind, 0) + 1
        return counts


def _base_token(token: str) -> str:
    return token.strip("'\"`").rsplit("/", 1)[-1].lower()


def is_command_line(line: str) -> bool:
    """这一行像不像在终端里敲的命令。

    ``#`` 单独出现不算 —— 输出/列表里的注释行会因此被判成命令(实测踩过)。
    """
    s = line.strip()
    if not s:
        return False
    if s.startswith("$ ") or s.startswith("PS> ") or s.startswith("PS C:\\"):
        return True
    if s.startswith("# "):
        rest = s[2:].strip()
        if not rest:
            return False
        return _base_token(rest.split()[0]) in COMMAND_TOKENS
    token = s.split()[0]
    if _base_token(token) in COMMAND_TOKENS:
        return True
    return token.startswith("./")


def _is_comment(line: str) -> bool:
    s = line.strip()
    return s.startswith("#") or s.startswith("//")


def classify_block(lang: str, body: str) -> str:
    """把一个代码块归到 ``command`` / ``source`` / ``config`` / ``data`` / ``empty``。

    判定顺序很重要:先认命令(显式 shell 标注 → 命令行占多数 → 短块含一行命令),
    再认源码(语言标注 → 行首特征),最后才退到 config/data。
    """
    lines = [ln for ln in body.splitlines() if ln.strip()]
    if not lines:
        return "empty"

    tag = lang.strip().lower().split()[0] if lang.strip() else ""
    n = len(lines)
    cmd_lines = sum(1 for ln in lines if is_command_line(ln))
    # 注释行不占"命令行占多数"的分母。真实 writeup 的 exploit 块几乎都长这样:
    # 每条命令上面一行 "# 这里在干什么", 下面一行 "# 预期响应"。按全部行数算,
    # 两条 curl 对四条注释永远占不到多数, 整块被判成 data, 规则层直接以 no_poc 拒稿 ——
    # 2026-11-10 在 GHSL/Quarkus 那条上实测到, 而那篇的 PoC 是完整可跑的。
    live = n - sum(1 for ln in lines if not is_command_line(ln) and _is_comment(ln))

    if tag in _COMMAND_LANGS and n <= 40:
        return "command"
    if cmd_lines and cmd_lines * 2 >= max(live, 1):
        return "command"
    if n <= 3 and cmd_lines >= 1:
        return "command"

    if tag in SOURCE_LANGS:
        return "source"
    for pat in _SOURCE_PATTERNS:
        if pat.search(body):
            return "source"

    if n < 40 and re.search(r"^[ \t]*[-\w.]+\s*[:=]\s*\S", body, re.M):
        return "config"
    return "data"


def split_blocks(text: str) -> tuple[Block, ...]:
    """切出全文的 fenced 代码块。没有 ``` 的文本返回空元组。"""
    blocks: list[Block] = []
    for i, m in enumerate(_FENCE_RE.finditer(text or "")):
        lang = (m.group(1) or "").strip()
        body = m.group(2) or ""
        kind = classify_block(lang, body)
        head = next((ln.strip() for ln in body.splitlines() if ln.strip()), "")[:160]
        blocks.append(Block(
            index=i,
            lang=lang,
            kind=kind,
            line_count=len([ln for ln in body.splitlines() if ln.strip()]),
            head=head,
        ))
    return tuple(blocks)


def normalize_repo(raw: str) -> str:
    """把仓库 URL 归一成 ``platform:org/name``;不是仓库或归一不了返回空串。

    大小写按平台习惯统一成小写 —— 后面要拿去和别的表做相等比较,大小写不同就是两条。
    """
    m = _REPO_RE.search(raw or "")
    if not m:
        return ""
    host, org, name = m.group(1).lower(), m.group(2), m.group(3)
    if name.lower() in _NON_REPO_SEGMENTS:
        return ""
    name = re.sub(r"\.git$", "", name, flags=re.I)
    platform = _REPO_HOST_MAP.get(host)
    if not platform or not org or not name:
        return ""
    return f"{platform}:{org}/{name}".lower()


def screen_rules(text: str, *, title: str = "", url: str = "") -> RuleScreen:
    """对一篇素材做 L0/L1 判断。

    ``text`` 是正文(代码块只从正文切);``title`` / ``url`` 只参与"目标线索"的查找 ——
    实测有文章的 CVE 编号只写在标题里,只看正文会把它误判成 ``target_unknown``。

    ``reasons`` 是给人看的决策依据,页面/日志直接可以引用,不另外拼话术。
    """
    blocks = split_blocks(text)
    if not blocks:
        return RuleScreen(
            screenable=False,
            reject_reason="not_writeup",
            has_command=False,
            has_source=False,
            target_repo="",
            cve_ids=(),
            versions=(),
            reasons=("全文没有 fenced 代码块",),
        )

    has_command = any(b.kind == "command" for b in blocks)
    has_source = any(b.kind == "source" for b in blocks)
    kinds = {b.kind for b in blocks}

    if not (has_command or has_source):
        return RuleScreen(
            screenable=False,
            reject_reason="no_poc",
            has_command=False,
            has_source=False,
            target_repo="",
            cve_ids=(),
            versions=(),
            blocks=blocks,
            reasons=(f"有 {len(blocks)} 个代码块,但只有 {sorted(kinds)} 类,没有命令或源码",),
        )

    haystack = "\n".join(part for part in (title or "", url or "", text or "") if part)

    repo = ""
    repo_match = _REPO_RE.search(haystack)
    if repo_match:
        repo = normalize_repo(repo_match.group(0))
    cves = find_cves(haystack)
    versions = tuple(sorted({m.group(0) for m in _VERSION_RE.finditer(haystack)}))

    reasons: list[str] = []
    reasons.append("含可执行命令" if has_command else "")
    reasons.append("含源码块" if has_source else "")
    if repo:
        reasons.append(f"目标仓 {repo}")
    if cves:
        reasons.append(f"CVE {', '.join(cves[:3])}")
    if versions:
        reasons.append(f"版本 {', '.join(versions[:3])}")
    reasons = tuple(r for r in reasons if r)

    if not (repo or cves or versions):
        return RuleScreen(
            screenable=False,
            reject_reason="target_unknown",
            has_command=has_command,
            has_source=has_source,
            target_repo="",
            cve_ids=(),
            versions=(),
            blocks=blocks,
            reasons=reasons + ("有 PoC,但正文里没有仓库 URL / CVE / 三段式版本号",),
        )

    return RuleScreen(
        screenable=True,
        reject_reason="",
        has_command=has_command,
        has_source=has_source,
        target_repo=repo,
        cve_ids=cves,
        versions=versions,
        blocks=blocks,
        reasons=reasons,
    )
