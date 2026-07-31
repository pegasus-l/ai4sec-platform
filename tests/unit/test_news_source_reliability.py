from __future__ import annotations

from email.message import Message
import json
import urllib.error
import urllib.parse

import pytest

from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.connectors.news.arxiv import ArxivConnector
from ai4sec_platform.sources.connectors.news.asis import AsisConnector
from ai4sec_platform.sources.connectors.news.base_live import retry_call, retry_kwargs
from ai4sec_platform.sources.connectors.news.github import GithubConnector


def test_source_retry_recovers_from_transient_timeout(monkeypatch) -> None:
    attempts = 0
    delays: list[float] = []

    def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise TimeoutError("source timed out")
        return "ok"

    monkeypatch.setattr("ai4sec_platform.sources.connectors.news.base_live.random.uniform", lambda *_args: 0.0)
    monkeypatch.setattr("ai4sec_platform.sources.connectors.news.base_live.time.sleep", delays.append)

    assert retry_call(operation, attempts=3, base_delay_seconds=1, jitter_seconds=0, max_delay_seconds=10) == "ok"
    assert attempts == 3
    assert delays == [1, 2]


def test_source_retry_honors_bounded_retry_after(monkeypatch) -> None:
    attempts = 0
    delays: list[float] = []
    headers = Message()
    headers["Retry-After"] = "7"

    def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise urllib.error.HTTPError("https://source.example", 429, "rate limited", headers, None)
        return "ok"

    monkeypatch.setattr("ai4sec_platform.sources.connectors.news.base_live.time.sleep", delays.append)

    assert retry_call(operation, attempts=2, max_delay_seconds=5) == "ok"
    assert delays == [5]


def test_source_retry_does_not_retry_authentication_failure(monkeypatch) -> None:
    attempts = 0
    headers = Message()
    monkeypatch.setattr("ai4sec_platform.sources.connectors.news.base_live.time.sleep", lambda _delay: pytest.fail("must not sleep"))

    def operation() -> None:
        nonlocal attempts
        attempts += 1
        raise urllib.error.HTTPError("https://source.example", 401, "unauthorized", headers, None)

    with pytest.raises(urllib.error.HTTPError):
        retry_call(operation, attempts=3)
    assert attempts == 1


def test_source_retry_allows_explicit_zero_jitter() -> None:
    options = retry_kwargs(SourceFetchRequest(
        source_name="rss",
        config={"retry_jitter_seconds": 0.5},
        params={"retry_jitter_seconds": 0},
    ))

    assert options["jitter_seconds"] == 0


def test_arxiv_query_uses_bounded_offset_pagination(monkeypatch) -> None:
    connector = ArxivConnector()
    starts: list[int] = []

    def fake_get_bytes(url: str, **_kwargs) -> bytes:
        query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        start = int(query["start"][0])
        starts.append(start)
        count = 2 if start == 0 else 1
        return _atom_feed(start, count)

    monkeypatch.setattr(connector, "get_bytes", fake_get_bytes)
    result = connector.fetch(SourceFetchRequest(
        source_name="arxiv",
        params={"query": "all:security", "max_results": 4, "page_size": 2, "max_pages": 3},
    ))

    assert result.errors == []
    assert starts == [0, 2]
    assert len(result.items) == 3
    assert result.metadata["pages_fetched"] == 2


def test_arxiv_later_page_failure_preserves_completed_pages(monkeypatch) -> None:
    connector = ArxivConnector()

    def fake_get_bytes(url: str, **_kwargs) -> bytes:
        start = int(urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["start"][0])
        if start == 2:
            raise urllib.error.HTTPError(url, 401, "unauthorized", Message(), None)
        return _atom_feed(start, 2)

    monkeypatch.setattr(connector, "get_bytes", fake_get_bytes)
    result = connector.fetch(SourceFetchRequest(
        source_name="arxiv",
        params={"query": "all:security", "max_results": 4, "page_size": 2, "max_pages": 2},
    ))

    assert len(result.items) == 2
    assert len(result.errors) == 1
    assert result.metadata["pages_fetched"] == 1


def test_github_search_stops_after_short_page(monkeypatch) -> None:
    connector = GithubConnector()
    pages: list[int] = []

    def fake_get_bytes(url: str, **_kwargs) -> bytes:
        query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        page = int(query["page"][0])
        pages.append(page)
        count = 2 if page == 1 else 1
        items = [{"id": page * 10 + index, "full_name": f"acme/project-{page}-{index}"} for index in range(count)]
        return json.dumps({"total_count": 3, "items": items}).encode()

    monkeypatch.setattr(connector, "get_bytes", fake_get_bytes)
    result = connector.fetch(SourceFetchRequest(
        source_name="github",
        config={"readme_limit": 0},
        params={"query": "security", "max_results": 2, "max_pages": 3},
    ))

    assert result.errors == []
    assert pages == [1, 2]
    assert len(result.items) == 3
    assert result.metadata["pages_fetched"] == 2


def test_asis_uses_offset_pagination(monkeypatch) -> None:
    offsets: list[int] = []

    class FakeOpener:
        def open(self, request, timeout):
            if request.full_url.endswith("/api/auth/login"):
                return _Response(b"ok")
            query = urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)
            offset = int(query["offset"][0])
            limit = int(query["limit"][0])
            offsets.append(offset)
            count = limit if offset < 4 else 1
            items = [{"id": offset + index + 1, "title": f"Item {offset + index + 1}"} for index in range(count)]
            return _Response(json.dumps({"items": items}).encode())

    _configure_asis(monkeypatch, FakeOpener())
    result = AsisConnector().fetch(SourceFetchRequest(
        source_name="asis",
        config={"base_url": "https://asis.example", "fetch_limit": 5, "page_size": 2, "max_pages": 3},
    ))

    assert result.errors == []
    assert offsets == [0, 2, 4]
    assert len(result.items) == 5
    assert result.metadata["pages_fetched"] == 3


def test_asis_partial_page_failure_is_reported_without_hiding_items(monkeypatch) -> None:
    class FakeOpener:
        def open(self, request, timeout):
            if request.full_url.endswith("/api/auth/login"):
                return _Response(b"ok")
            offset = int(urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)["offset"][0])
            if offset == 2:
                raise urllib.error.HTTPError(request.full_url, 401, "unauthorized", Message(), None)
            return _Response(b'{"items":[{"id":1,"title":"First"},{"id":2,"title":"Second"}]}')

    _configure_asis(monkeypatch, FakeOpener())
    result = AsisConnector().fetch(SourceFetchRequest(
        source_name="asis",
        config={"base_url": "https://asis.example", "fetch_limit": 4, "page_size": 2, "max_pages": 2},
    ))

    assert [item["id"] for item in result.items] == ["asis:1", "asis:2"]
    assert len(result.errors) == 1
    assert result.errors[0].startswith("offset=2:")
    assert result.metadata["pages_fetched"] == 1


def test_asis_health_reports_only_missing_credentials(monkeypatch) -> None:
    monkeypatch.delenv("ASIS_BASE_URL", raising=False)
    monkeypatch.delenv("ASIS_USERNAME", raising=False)
    monkeypatch.delenv("ASIS_PASSWORD", raising=False)

    health = AsisConnector().health_check({"base_url": "https://asis.example"})

    assert health.status == "missing"
    assert health.message == "ASIS_USERNAME/ASIS_PASSWORD"


class _Response:
    def __init__(self, content: bytes) -> None:
        self.content = content

    def read(self) -> bytes:
        return self.content


def _configure_asis(monkeypatch, opener) -> None:
    monkeypatch.setenv("ASIS_USERNAME", "operator")
    monkeypatch.setenv("ASIS_PASSWORD", "secret")
    monkeypatch.setattr("ai4sec_platform.sources.connectors.news.asis.urllib.request.build_opener", lambda *_args: opener)


def _atom_feed(start: int, count: int) -> bytes:
    entries = "".join(
        f"""<entry>
          <id>https://arxiv.org/abs/2601.{start + index:05d}</id>
          <title>Paper {start + index}</title>
          <summary>Security research</summary>
          <published>2026-01-01T00:00:00Z</published>
          <updated>2026-01-01T00:00:00Z</updated>
          <link rel="alternate" href="https://arxiv.org/abs/2601.{start + index:05d}" />
          <author><name>Researcher</name></author>
          <category term="cs.CR" />
        </entry>"""
        for index in range(count)
    )
    return f'<feed xmlns="http://www.w3.org/2005/Atom">{entries}</feed>'.encode()
