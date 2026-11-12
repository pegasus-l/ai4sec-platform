"""T3.4:执行前的安全边界 —— 拒绝在线目标 + 出网审计。

为什么这一层不能靠提示词
========================

提示词里写了"严禁访问互联网上的真实站点", 但提示词是**建议**: 模型可以忽略、可以在
第 20 轮忘记、也可以为了"让 probe 通过"去打一个真实站点。而这一步的后果不是报告写得
难看出错, 是**平台替用户去打了一个别人的生产系统**。

所以边界必须落在代码里, 而且分前后两道:

- ``preflight`` —— **开跑前**从 spec 的命令里抽主机名, 判这一趟能不能开。目标是线上
  真实站点的一律不开会话(``blocked: online_target``), 连墙都不试。
- ``audit_egress`` —— **跑完后**从会话 transcript 的真实命令里再抽一遍, 看它到底连了谁。
  前一道挡的是"看得到的意图", 这一道挡的是"实际发生的事"。

两条线之间刻意不对等: 开跑前的判据要**宽**(依赖源、代码托管、私有网段都放行, 否则
正常的复现根本跑不起来), 跑完后的审计要**紧**(只要有一次对公网发请求, 就落 blocked
交人看)。宁可多让人看一条, 不可少拦一次。

什么算"在线目标"
================

``screener`` 里 T1 已经把 ``online_service`` 类素材挡在候选之外了。这里再做一次是**纵深**:
任务可能是人工建的、spec 可能是人改的、模型也可能在步骤里写进别的地址。三种入口都得过
同一道闸。

依赖源 / 代码托管的清单写死在 ``DEPENDENCY_HOSTS``: 它们代表"装东西可以出网"这一侧。
清单外的公网主机只允许出现在**不发起请求**的语境里(比如一行注释), 一旦出现在 curl /
nmap / python 脚本的参数里就判死。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# ── 主机分类 ────────────────────────────────────────────────

#: 本机。复现的目标是"本地部署实例", 只能是这些。
LOCAL_HOSTS: frozenset[str] = frozenset({
    "localhost", "localhost.localdomain", "127.0.0.1", "0.0.0.0", "::1", "[::1]",
    "host.docker.internal", "gateway.docker.internal",
})

#: 原文里常见的占位符。它们不是真实目标 —— 站在"文章作者没写过这个地址"的位置上看,
#: 这类主机名要求复现方换成本地实例, 所以放行, 但要在 notes 里留一句。
PLACEHOLDER_HOSTS: frozenset[str] = frozenset({
    "target", "target.com", "target.local", "victim", "victim.com", "victim.local",
    "example.com", "example.org", "example.net", "your-host", "your_target", "yourtarget",
    "host", "hostname", "server", "remote_host", "remote-host", "<host>", "<target>",
    "target_ip", "target-ip", "<target_ip>", "rhost", "lhost",
})

#: "装依赖 / 取源码"可以出网的那一侧。判据是**这个主机是分发源**, 不是"这一行看起来像装的"。
DEPENDENCY_HOSTS: frozenset[str] = frozenset({
    # Python
    "pypi.org", "files.pythonhosted.org", "pythonhosted.org", "pypi.python.org",
    "pypi.tuna.tsinghua.edu.cn", "mirrors.aliyun.com", "mirrors.cloud.tencent.com",
    "mirrors.ustc.edu.cn", "mirror.sjtu.edu.cn", "repo.huaweicloud.com",
    # JS / TS
    "registry.npmjs.org", "npmjs.com", "registry.npmmirror.com", "yarnpkg.com",
    "registry.yarnpkg.com", "unpkg.com", "cdn.jsdelivr.net", "nodejs.org",
    # Go / Rust / Ruby / PHP / .NET
    "proxy.golang.org", "sum.golang.org", "goproxy.cn", "crates.io", "static.crates.io",
    "index.crates.io", "static.rust-lang.org", "sh.rustup.rs", "rubygems.org",
    "getcomposer.org", "packagist.org", "dot.net", "dotnet.microsoft.com",
    "api.nuget.org", "nuget.org",
    # 系统包
    "deb.debian.org", "archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com",
    "deb.nodesource.com", "packages.microsoft.com", "dl.yum.ubuntu.com",
    # JVM
    "repo1.maven.org", "repo.maven.apache.org", "maven.org", "plugins.gradle.org",
    "jcenter.bintray.com", "repo.spring.io",
    # 代码托管 / 源码分发
    "github.com", "codeload.github.com", "raw.githubusercontent.com",
    "objects.githubusercontent.com", "api.github.com", "github-releases.githubusercontent.com",
    "gitlab.com", "gitee.com", "gitcode.com", "atomgit.com", "bitbucket.org",
    "sourceforge.net", "kernel.org", "git.kernel.org", "cdn.kernel.org", "go.dev",
    # 容器与模型
    "docker.io", "registry-1.docker.io", "ghcr.io", "quay.io", "gcr.io",
    "huggingface.co", "cdn-lfs.huggingface.co", "hf-mirror.com",
    "download.pytorch.org", "conda.anaconda.org", "repo.anaconda.com",
})

#: 命令分段后第一个词属于这些 → 这一行在对目标发请求。
_REQUEST_TOOLS: frozenset[str] = frozenset({
    "curl", "wget", "http", "httpie", "nc", "ncat", "netcat", "nmap", "masscan",
    "sqlmap", "nikto", "hydra", "gobuster", "ffuf", "dirb", "wfuzz", "traceroute",
    "ping", "telnet", "ssh", "scp", "ftp", "ab", "wrk", "vegeta",
})

#: 命令分段后第一个词属于这些 → 这一行在装东西/取源码。
_PACKAGE_TOOLS: frozenset[str] = frozenset({
    "pip", "pip3", "pipx", "uv", "poetry", "pipenv", "npm", "yarn", "pnpm", "npx",
    "apt", "apt-get", "apk", "yum", "dnf", "zypper", "brew", "conda", "mamba", "go",
    "cargo", "gem", "composer", "dotnet", "docker", "podman", "huggingface-cli", "git",
})

#: 包管理器后面跟这些词才算"在装东西"(`go test` / `git status` 不算)。
_INSTALL_WORDS = re.compile(
    r"\b(install|add|get|download|sync|fetch|pull|clone|build|submodule|update)\b", re.I
)

#: 命令行前缀词, 看"真正在跑的程序"要先跳过它们。
_PREFIX_WORDS = frozenset({"sudo", "env", "nohup", "setsid", "exec", "command", "time", "watch", "xargs"})

#: 用来看"这行到底有没有真的发出网络请求"。
_HOST_TOKEN = re.compile(
    r"(?:[a-z][a-z0-9+.\-]*://)?(?P<host>\[[0-9a-f:]+\]|(?:\d{1,3}\.){3}\d{1,3}|"
    r"[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)+)",
    re.I,
)

#: 常见顶级域。没有它, ``main.py`` / ``v1.2.3`` 这种会被当成域名, 整套判定全是噪声。
_TLDS = frozenset({
    "com", "org", "net", "edu", "gov", "mil", "int", "io", "cn", "dev", "app", "co",
    "me", "xyz", "info", "site", "online", "top", "tech", "cloud", "ai", "sh", "gg",
    "cc", "tv", "ly", "to", "in", "it", "nl", "se", "no", "fi", "pl", "br", "au", "ca",
    "ch", "at", "be", "dk", "es", "cz", "kr", "ir", "vn", "tw", "hk", "sg", "il", "tr",
    "ua", "ro", "gr", "pt", "mx", "ar", "cl", "za", "id", "my", "th", "ph", "pk", "ng",
    "ke", "eg", "sa", "ae", "ru", "de", "jp", "fr", "uk", "us", "eu", "local",
})

#: 文件后缀。命中的一律不当主机名(它们是被操作的对象, 不是被访问的地址)。
_FILE_SUFFIXES = frozenset({
    "py", "txt", "json", "md", "yml", "yaml", "sh", "bash", "go", "rs", "js", "mjs",
    "cjs", "ts", "tsx", "jsx", "java", "php", "rb", "c", "h", "cc", "cpp", "hpp", "cs",
    "log", "tar", "gz", "tgz", "zip", "7z", "rar", "patch", "diff", "so", "bin", "exe",
    "dll", "sql", "db", "csv", "xml", "html", "htm", "css", "png", "jpg", "jpeg", "gif",
    "pdf", "conf", "cfg", "ini", "toml", "lock", "whl", "egg", "jar", "war", "apk",
})


def extract_hosts(text: str) -> list[str]:
    """从一段文本里抽主机名 / IP。**保留原样大小写但比对时用小写**。

    只认三种形态: 带协议的 URL、IPv4、以及最后一段是常见顶级域的域名。宁可漏掉一个
    生僻顶级域(那一行会因为没有主机而被当成不含网络中继), 也不要把 ``main.py`` 变成
    "一个公网主机" —— 后者会让每一次正常的复现都被判死。
    """
    out: list[str] = []
    seen: set[str] = set()
    for match in _HOST_TOKEN.finditer(text or ""):
        host = match.group("host").strip(".").lower()
        if not host or host in seen:
            continue
        if not _looks_like_host(host):
            continue
        seen.add(host)
        out.append(host)
    return out


def _looks_like_host(host: str) -> bool:
    if host in LOCAL_HOSTS or host in PLACEHOLDER_HOSTS:
        return True
    if host.startswith("["):
        # 方括号只可能是 IPv6 字面量。别的一律不是主机 —— 实测 shell 里的
        # ``${PIPESTATUS[0]}`` / ``${arr[0]}`` 会被抽成 "[0]", 记进证据包就是一条
        # 无中生有的"出网主机 [0]"。
        try:
            ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return False
        return True
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        return True
    parts = host.split(".")
    if len(parts) < 2:
        return False
    if parts[-1] not in _TLDS:
        return False
    if parts[-1] in _FILE_SUFFIXES:
        return False
    return True


def classify_host(host: str) -> str:
    """``local`` / ``placeholder`` / ``private`` / ``dependency`` / ``public`` / ``invalid``。"""
    h = (host or "").strip().strip(".").lower()
    if not h:
        return "invalid"
    if h in LOCAL_HOSTS:
        return "local"
    if h in PLACEHOLDER_HOSTS:
        return "placeholder"
    if h in DEPENDENCY_HOSTS:
        return "dependency"
    try:
        ip = ipaddress.ip_address(h.strip("[]"))
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_loopback:
            return "local"
        if ip.is_private or ip.is_link_local:
            # 私有网段: 靶场/内网靶机。允许, 但要在 notes 里说明"按本地靶机处理"。
            return "private"
        return "public"
    return "public"


def _segments(cmd: str) -> list[str]:
    return [s for s in re.split(r"\n|;|&&|\|\||\|", cmd or "") if s.strip()]


def _program(segment: str) -> str:
    """一段命令里真正被执行的程序名(跳过 sudo/env/超时前缀与 VAR=val 赋值)。"""
    tokens = segment.strip().split()
    i = 0
    while i < len(tokens):
        token = tokens[i]
        base = token.rsplit("/", 1)[-1].lower()
        if base in _PREFIX_WORDS:
            i += 1
            # timeout / watch 后面跟着的是时长, 不是程序
            if base in ("timeout", "watch") and i < len(tokens):
                i += 1
            continue
        if "=" in token and not token.startswith("-"):
            i += 1
            continue
        return base
    return ""


def classify_command(cmd: str) -> str:
    """``install`` / ``download`` / ``request`` / ``other``。

    分类只影响**放行判据的宽严**, 不影响结论: 公网主机出现在 ``request`` 里必拒;
    出现在 ``install`` / ``download`` 里则放行(装东西本来就要出网)。

    按 ``;`` ``&&`` ``||`` ``|`` 与换行切段再逐段判 —— 一整行里既有 ``pip install`` 又有
    ``curl http://victim`` 时, 后者不能被前者的"install"标签带走。
    """
    text = (cmd or "").strip()
    if not text:
        return "other"
    kinds: list[str] = []
    for segment in _segments(text):
        lowered = segment.lower()
        program = _program(segment)
        if program in ("curl", "wget"):
            # `-sO` 这种合并短选项也算"下文件"; `-X`/`-d`/`-F` 一旦出现就是"发请求"。
            is_download = bool(re.search(
                r"(^|\s)-[a-zA-Z]*[Oo]\b|--remote-name|--output-document", segment
            ))
            is_send = bool(re.search(
                r"(^|\s)-[a-zA-Z]*(X|d|F)\b|--request|--data\w*|--form|--upload-file", segment
            ))
            kinds.append("download" if is_download and not is_send else "request")
            continue
        if program in _REQUEST_TOOLS:
            kinds.append("request")
            continue
        if program in _PACKAGE_TOOLS and _INSTALL_WORDS.search(lowered):
            kinds.append("install")
            continue
        # `python3 -m pip install ...` / `python -m http.server` 这类
        if program.startswith("python") and "-m pip" in lowered and _INSTALL_WORDS.search(lowered):
            kinds.append("install")
            continue
        if "install" in lowered and program in _PACKAGE_TOOLS:
            kinds.append("install")
            continue
        kinds.append("other")
    for want in ("request", "download", "install"):
        if want in kinds:
            return want
    return "other"


# ── 开跑前:能不能开 ────────────────────────────────────────

@dataclass(frozen=True)
class GuardResult:
    """``allowed=False`` 时 ``reason`` 必然是 ``online_target``(状态机只认这一个归因)。"""

    allowed: bool = True
    reason: str = ""
    detail: str = ""
    hosts: tuple[dict[str, str], ...] = ()
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "detail": self.detail,
            "hosts": list(self.hosts),
            "notes": list(self.notes),
        }


def _spec_text(spec: dict[str, Any]) -> list[tuple[str, str]]:
    """把要执行的文本拆成 ``(来源, 文本)``。只有这些会被真的执行, 原文摘录不算。"""
    items: list[tuple[str, str]] = []
    target = spec.get("target") if isinstance(spec.get("target"), dict) else {}
    setup = target.get("setup") if isinstance(target.get("setup"), list) else []
    for i, cmd in enumerate(setup, start=1):
        items.append((f"target.setup[{i}]", str(cmd)))
    steps = spec.get("steps") if isinstance(spec.get("steps"), list) else []
    for i, step in enumerate(steps, start=1):
        if isinstance(step, dict):
            items.append((f"steps[{i}]", str(step.get("run") or "")))
    probe = spec.get("probe") if isinstance(spec.get("probe"), dict) else {}
    items.append(("probe.cmd", str(probe.get("cmd") or "")))
    return [(src, txt) for src, txt in items if txt.strip()]


def preflight(task: dict[str, Any], spec: dict[str, Any] | None = None) -> GuardResult:
    """这一趟能不能开。**默认放行, 只拦明确的在线目标**。

    判死条件(任一):

    1. ``target_kind`` 是 ``online_service``(T1 已拦过一次, 这里是纵深);
    2. spec 里要执行的某一行, 在**发请求的语境**下出现公网主机, 且该主机不是依赖源;
    3. 扫描类工具(nmap/sqlmap…)指向非本机主机 —— 哪怕那是私有网段。

    私有网段(10/8、172.16/12、192.168/16)放行但留 note: 它们可能是本地靶机, 也可能是
    打不到的实验室机器。**判死它们会把 CTF 类素材全部误杀**, 而误杀的代价由作者承担。
    """
    spec = spec or {}
    target_kind = str(task.get("target_kind") or "").strip()
    spec_target = spec.get("target") if isinstance(spec.get("target"), dict) else {}
    for kind in (target_kind, str(spec_target.get("kind") or "")):
        if kind == "online_service":
            return GuardResult(
                allowed=False, reason="online_target",
                detail="目标是线上还在运行的第三方服务, 按平台规则不执行(只做阅读与模式归纳)",
            )

    notes: list[str] = []
    hits: list[dict[str, str]] = []
    for source, text in _spec_text(spec):
        kind = classify_command(text)
        for host in extract_hosts(text):
            category = classify_host(host)
            hits.append({"source": source, "host": host, "category": category, "command_kind": kind})
            if category in ("local", "placeholder", "dependency"):
                if category == "placeholder":
                    notes.append(f"{source} 里的 {host} 是占位符, 执行前必须换成本地实例")
                continue
            if category == "private":
                notes.append(f"{source} 指向私有网段 {host}, 按本地靶机处理")
                if kind == "request" and _looks_like_scanner(text):
                    return GuardResult(
                        allowed=False, reason="online_target",
                        detail=f"{source} 用扫描工具指向 {host}(私有网段, 无本地部署依据)",
                        hosts=tuple(hits), notes=tuple(dict.fromkeys(notes)),
                    )
                continue
            # category == "public"
            if kind in ("install", "download"):
                # 装依赖本来就要出网; 只是源不在常见列表里, 记一句供复核, 不拦。
                notes.append(f"{source} 会从非常见分发源获取依赖: {host}")
                continue
            return GuardResult(
                allowed=False, reason="online_target",
                detail=(
                    f"{source} 会对公网主机 {host} 发起请求({kind}); "
                    "复现只能打本地部署的实例, 打真实站点需要单独授权"
                ),
                hosts=tuple(hits), notes=tuple(dict.fromkeys(notes)),
            )
    return GuardResult(allowed=True, hosts=tuple(hits), notes=tuple(dict.fromkeys(notes)))


def _looks_like_scanner(cmd: str) -> bool:
    lowered = (cmd or "").lower()
    return any(tool in lowered for tool in ("nmap", "masscan", "sqlmap", "nikto", "hydra", "gobuster", "ffuf", "dirb", "wfuzz"))


# ── 跑完后:到底连了谁 ──────────────────────────────────────

def audit_egress(commands: Iterable[dict[str, Any]], spec: dict[str, Any] | None = None) -> dict[str, Any]:
    """从**真实执行过的命令**里抽访问过的主机, 给判定与人工复核用。

    ``commands`` 来自 ``evidence.extract_commands``(会话 transcript), 不是 agent 的复述。
    返回里 ``review_required`` 是唯一需要调用方采取动作的字段: 为真时这一趟已经碰到了
    公网真实站点, 不能再判 success。
    """
    spec = spec or {}
    hits: list[dict[str, str]] = []
    for item in commands or []:
        cmd = str(item.get("cmd") or "")
        kind = classify_command(cmd)
        for host in extract_hosts(cmd):
            hits.append({
                "host": host,
                "category": classify_host(host),
                "command_kind": kind,
                "cmd": cmd[:300],
            })
    external = sorted({h["host"] for h in hits if h["category"] == "public" and h["command_kind"] == "request"})
    installed = sorted({h["host"] for h in hits if h["command_kind"] in ("install", "download")})
    return {
        "domains_accessed": sorted({h["host"] for h in hits}),
        "external_requests": external,
        "dependency_hosts": installed,
        "review_required": bool(external),
        "hits": hits[:300],
        "note": (
            "只在装依赖/取源码语境下出现的依赖源不计入外部请求" if hits else "没有从命令里抽到主机名"
        ),
    }
