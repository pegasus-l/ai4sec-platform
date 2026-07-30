from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import urlparse

from ai4sec_platform.core.url_security import PublicUrlPolicy, domain_matches


@dataclass(frozen=True)
class VulnerabilityCrawlPolicy:
    timeout_seconds: float = 25.0
    slow_site_timeout_seconds: float = 45.0
    slow_site_domains: tuple[str, ...] = ("github.com", "gitlab.com")
    max_retries: int = 2
    retry_delay_seconds: float = 1.0
    js_wait_seconds: float = 1.0
    wait_for_selector: str = ""
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
    use_crawl4ai: bool = True
    allow_urllib_fallback: bool = True
    block_private_networks: bool = True
    domain_allowlist: tuple[str, ...] = ()
    domain_blocklist: tuple[str, ...] = ()
    max_response_bytes: int = 2_000_000

    @classmethod
    def from_params(cls, params: dict[str, Any], config: dict[str, Any]) -> VulnerabilityCrawlPolicy:
        merged = {**config, **params}
        return cls(
            timeout_seconds=_float_value(merged.get("crawl_timeout", merged.get("timeout")), 25.0, minimum=1.0),
            slow_site_timeout_seconds=_float_value(merged.get("crawl_slow_site_timeout"), 45.0, minimum=1.0),
            slow_site_domains=_string_tuple(merged.get("crawl_slow_site_domains")) or cls.slow_site_domains,
            max_retries=_int_value(merged.get("crawl_max_retries", merged.get("max_retries")), 2, minimum=0, maximum=5),
            retry_delay_seconds=_float_value(merged.get("crawl_retry_delay"), 1.0, minimum=0.0),
            js_wait_seconds=_float_value(merged.get("crawl_js_wait"), 1.0, minimum=0.0),
            wait_for_selector=str(merged.get("crawl_wait_for_selector") or "").strip(),
            user_agent=str(merged.get("crawl_user_agent") or cls.user_agent),
            use_crawl4ai=_bool_value(merged.get("use_crawl4ai"), True),
            allow_urllib_fallback=_bool_value(merged.get("allow_urllib_fallback"), True),
            block_private_networks=_bool_value(merged.get("block_private_networks"), True),
            domain_allowlist=_string_tuple(merged.get("domain_allowlist")),
            domain_blocklist=_string_tuple(merged.get("domain_blocklist")),
            max_response_bytes=_int_value(merged.get("max_response_bytes"), 2_000_000, minimum=10_000, maximum=20_000_000),
        )

    def validate_url(self, url: str, *, resolve_dns: bool = False) -> str:
        return self.public_url_policy().validate(url, resolve_dns=resolve_dns)

    def public_url_policy(self) -> PublicUrlPolicy:
        return PublicUrlPolicy(
            domain_allowlist=self.domain_allowlist,
            domain_blocklist=self.domain_blocklist,
            block_private_networks=self.block_private_networks,
        )

    def for_url(self, url: str) -> tuple[str, VulnerabilityCrawlPolicy]:
        parsed = urlparse(url)
        path = parsed.path.casefold()
        hostname = (parsed.hostname or "").casefold().rstrip(".")
        if path.endswith(".pdf"):
            return "direct_download", replace(self, use_crawl4ai=False)
        if domain_matches(hostname, self.slow_site_domains):
            return "slow_site", replace(self, timeout_seconds=self.slow_site_timeout_seconds)
        return "standard_page", self


def _string_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        values = value.split(",")
    elif isinstance(value, (list, tuple)):
        values = value
    else:
        return ()
    return tuple(str(item).strip().casefold().rstrip(".") for item in values if str(item).strip())


def _bool_value(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().casefold() not in {"0", "false", "no", "off"}
    return bool(value)


def _int_value(value: Any, default: int, *, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return min(maximum, max(minimum, parsed))


def _float_value(value: Any, default: float, *, minimum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, parsed)
