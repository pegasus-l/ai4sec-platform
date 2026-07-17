from __future__ import annotations

import re
from typing import Any

from ai4sec_platform.schemas.scoring import ScoreResult

INPUT_SURFACE_HINTS = [
    (r"网络|net_|_net_|http|tcp|udp|websocket|grpc|quic|ssl|tls|openssl|boringssl", 25, "network protocol"),
    (r"蓝牙|bluetooth|wifi|wlan|nearlink|nfc", 22, "wireless"),
    (r"usb|hid|midi|uart|i2c|spi|gpio|外设", 18, "peripheral"),
    (r"codec|parser|解码|解析|json|xml|yaml|protobuf|cbor|avro|压缩|zip|tar|7z|rar", 22, "parser/codec"),
    (r"camera|v4l2|video|audio|h264|h265|av1|aac|mp4|mp3|mpeg|mms", 22, "media"),
    (r"chromium|webkit|webview|cef|skia|v8|blink", 20, "browser engine"),
    (r"sql|sqlite|mysql|opengauss|postgres", 18, "database"),
    (r"shell|cmd|exec|fork|execve|权限|permission|access", 18, "exec/permission"),
    (r"驱动|driver|hal|hdf", 18, "driver"),
    (r"内核|kernel|syscalls?|调度|进程|虚拟内存|vm_|mm_|进程|signal", 22, "kernel"),
    (r"容器|sandbox|沙箱|jail", 20, "sandbox"),
]
HISTORICAL_CVE = [
    r"^chromium", r"^webkit", r"^sqlite", r"^openssl", r"^boringssl",
    r"^v8$", r"^skia", r"^zlib", r"^libpng", r"^libxml", r"^ffmpeg",
    r"^curl", r"^libcurl", r"^nghttp", r"^protobuf", r"^grpc",
    r"^libvpx", r"^dav1d", r"^av1", r"^icu", r"^freetype", r"^harfbuzz",
]
INPUT_RULES = [(re.compile(pattern, re.I), score, label) for pattern, score, label in INPUT_SURFACE_HINTS]
CVE_RULES = [re.compile(pattern, re.I) for pattern in HISTORICAL_CVE]
DROP_KEYWORDS_DOCS = ["docs", "documentation", "wiki", "mirror", "image", "logo", "template", "sample-config", "readme", "changelog"]
DROP_PREFIX_BOARD = ["device_board_", "vendor_", "prebuilts_"]
DROP_NAME_REGEX = re.compile(r"^(readme|license|changelog|contributing)[\._-]?.*$", re.I)
KEEP_BUT_DEPRIORITIZE = ["third_party_", "mirror", "fork of", "镜像", "同步"]


def score_attack_surface(item: dict[str, Any]) -> ScoreResult:
    payload = item.get("payload") or item
    raw = payload.get("raw") if isinstance(payload.get("raw"), dict) else {}
    name = _repo_name(payload, raw)
    desc = str(payload.get("summary") or payload.get("description") or raw.get("description") or "")
    stars = _int(payload.get("stars") or raw.get("star_count") or raw.get("stars") or 0)
    cve_count = _int(payload.get("cve_count") or len(payload.get("cves") or []) or raw.get("cve_count") or 0)
    language = _lang_score(name, desc)
    input_surface, primary_surface = _input_score(name, desc)
    historical_cve = _cve_score(name, cve_count)
    complexity = _star_score(stars)
    security_boundary = _security_boundary_score(name, desc)
    total = min(100.0, language + input_surface + historical_cve + complexity + security_boundary)
    filter_info = filter_project(name, desc, stars)
    priority = "high" if total >= 70 else "medium" if total >= 50 else "low" if total >= 30 else "reject"
    grade = "A" if total >= 70 else "B" if total >= 50 else "C" if total >= 30 else "D"
    reasons = [
        f"语言漏洞倾向 {language}",
        f"不可信输入面 {input_surface}" + (f"（{primary_surface}）" if primary_surface else ""),
        f"历史 CVE 倾向 {historical_cve}",
        f"复杂度/star {complexity}",
        f"安全边界 {security_boundary}",
    ]
    if filter_info["filtered"]:
        reasons.append(f"平台过滤规则命中：{filter_info['filtered_reason']}")
    elif filter_info["deprioritized"]:
        reasons.append("平台降权规则命中：镜像/第三方/同步类项目")
    return ScoreResult(
        score=round(total, 2),
        priority=priority,
        grade=grade,
        breakdown={
            "language_vuln倾向": float(language),
            "untrusted_input": float(input_surface),
            "historical_cve": float(historical_cve),
            "complexity_stars": float(complexity),
            "security_boundary": float(security_boundary),
        },
        reasons=reasons,
        signals={"name": name, "description": desc, "star_count": stars, "primary_attack_surface": primary_surface, **filter_info},
    )


def filter_project(name: str, desc: str, stars: int) -> dict[str, Any]:
    lowered_name = (name or "").lower()
    haystack = f"{name} {desc}".lower()
    if not name:
        return {"filtered": True, "filtered_reason": "empty_name", "deprioritized": False}
    if DROP_NAME_REGEX.match(lowered_name):
        return {"filtered": True, "filtered_reason": "trivial_name", "deprioritized": False}
    if not desc and any(keyword in lowered_name for keyword in DROP_KEYWORDS_DOCS):
        return {"filtered": True, "filtered_reason": "doc_or_mirror_no_desc", "deprioritized": False}
    if any(lowered_name.startswith(prefix) for prefix in DROP_PREFIX_BOARD) and stars < 20:
        return {"filtered": True, "filtered_reason": "board_config_no_community", "deprioritized": False}
    if not desc and stars == 0:
        return {"filtered": True, "filtered_reason": "empty_shell", "deprioritized": False}
    return {"filtered": False, "filtered_reason": "", "deprioritized": any(keyword in haystack for keyword in KEEP_BUT_DEPRIORITIZE)}


def _lang_score(name: str, desc: str) -> int:
    text = f"{name} {desc}".lower()
    for keywords, weight in [
        (("c", "c++", "assembly", "asm"), 25),
        (("cangjie", "java", "kotlin", "go", "golang"), 12),
        (("python", "javascript", "typescript", "rust", "arkts", "ets"), 8),
        (("html", "css", "markdown"), 2),
    ]:
        if any(keyword in text for keyword in keywords):
            return weight
    return 5


def _input_score(name: str, desc: str) -> tuple[int, str]:
    haystack = f"{name}\n{desc}"
    best = 0
    label = ""
    for regex, score, candidate_label in INPUT_RULES:
        if regex.search(haystack) and score > best:
            best = score
            label = candidate_label
    return best, label


def _cve_score(name: str, cve_count: int) -> int:
    if cve_count >= 5:
        return 15
    if cve_count >= 3:
        return 10
    if cve_count >= 1:
        return 5
    if any(regex.search(name) for regex in CVE_RULES):
        return 3
    return 0


def _star_score(stars: int) -> int:
    if stars <= 0:
        return 0
    if stars < 10:
        return 5
    if stars < 50:
        return 10
    return 15


def _security_boundary_score(name: str, desc: str) -> int:
    bonus = 0
    haystack = f"{name} {desc}".lower()
    if any(keyword in haystack for keyword in ("security", "accesscontrol", "权限", "鉴权", "安全")):
        bonus += 20
    if any(keyword in haystack for keyword in ("kernel", "driver", "hdf", "hal", "内核", "驱动")):
        bonus += 5
    if "sandbox" in haystack or "沙箱" in desc:
        bonus += 5
    if "权限" in desc or "permission" in haystack:
        bonus += 5
    return min(bonus, 25)


def _repo_name(payload: dict[str, Any], raw: dict[str, Any]) -> str:
    name = payload.get("name") or raw.get("name") or ""
    if name:
        return str(name)
    title = str(payload.get("title") or "")
    return title.split("/")[-1] if "/" in title else title


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0
