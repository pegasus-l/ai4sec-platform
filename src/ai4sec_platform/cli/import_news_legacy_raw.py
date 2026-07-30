from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import date
import fcntl
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterator

from ai4sec_platform.core.config import Settings, load_settings
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.domains.news.migrations import MIGRATION_PIPELINE_NAME, SOURCE_FILES, legacy_news_import_pipeline
from ai4sec_platform.pipelines.registry import PipelineRegistry
from ai4sec_platform.pipelines.runner import PipelineRunner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="One-time import of historical AI-for-Sec news raw files")
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--date", required=True)
    parser.add_argument("--confirm-one-time-import", action="store_true")
    parser.add_argument("--allow-missing-sources", action="store_true")
    args = parser.parse_args(argv)
    if not args.confirm_one_time_import:
        parser.error("--confirm-one-time-import is required")
    result = import_news_legacy_raw(args.source_dir, args.date, allow_missing_sources=args.allow_missing_sources)
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0 if result["status"] == "success" else 1


def import_news_legacy_raw(
    source_dir: Path,
    import_date: str,
    *,
    allow_missing_sources: bool = False,
    settings: Settings | None = None,
) -> dict[str, Any]:
    source_dir = source_dir.expanduser().resolve()
    try:
        date.fromisoformat(import_date)
    except ValueError as exc:
        raise ValueError("import_date must use YYYY-MM-DD") from exc
    if not source_dir.is_dir():
        raise ValueError(f"Legacy news source directory does not exist: {source_dir}")
    source_files = _source_files(source_dir, import_date)
    if not source_files:
        raise ValueError(f"No recognized legacy news raw files found for {import_date}")
    if len(source_files) != len(SOURCE_FILES) and not allow_missing_sources:
        missing_sources = sorted(set(SOURCE_FILES) - {_source_name(path.name, import_date) for path in source_files})
        raise ValueError(f"Legacy news import is missing sources: {', '.join(missing_sources)}")
    checksum = _migration_checksum(import_date, source_files)
    settings = settings or load_settings()
    with _legacy_import_lock(settings):
        with connect(settings) as conn:
            init_db(conn)
            existing_run_id = _completed_import_run_id(conn, checksum)
        if existing_run_id:
            raise ValueError(f"Legacy news import already completed: {existing_run_id}")

        registry = PipelineRegistry()
        registry.register(legacy_news_import_pipeline(source_dir, import_date))
        return PipelineRunner(settings=settings, registry=registry).run(
            MIGRATION_PIPELINE_NAME,
            {
                "date": import_date,
                "migration_checksum": checksum,
                "migration_source_files": [path.name for path in source_files],
                "reset": False,
            },
        )


def _source_files(source_dir: Path, import_date: str) -> list[Path]:
    date_compact = import_date.replace("-", "")
    return sorted(
        path
        for pattern in SOURCE_FILES.values()
        if (path := source_dir / pattern.format(date_compact=date_compact)).is_file()
    )


def _source_name(filename: str, import_date: str) -> str:
    date_compact = import_date.replace("-", "")
    return next(
        source
        for source, pattern in SOURCE_FILES.items()
        if pattern.format(date_compact=date_compact) == filename
    )


def _migration_checksum(import_date: str, source_files: list[Path]) -> str:
    digest = hashlib.sha256(import_date.encode("utf-8"))
    for path in source_files:
        digest.update(path.name.encode("utf-8"))
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _completed_import_run_id(conn, checksum: str) -> str:
    rows = conn.execute(
        "SELECT run_id, summary_json FROM pipeline_runs WHERE pipeline_name = ? AND status = 'success' ORDER BY id DESC",
        (MIGRATION_PIPELINE_NAME,),
    ).fetchall()
    for row in rows:
        summary = json.loads(row["summary_json"] or "{}")
        if (summary.get("params") or {}).get("migration_checksum") == checksum:
            return str(row["run_id"])
    return ""


@contextmanager
def _legacy_import_lock(settings: Settings) -> Iterator[None]:
    lock_dir = settings.output_dir / "operations"
    lock_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(lock_dir, 0o750)
    lock_path = lock_dir / "news-legacy-import.lock"
    with lock_path.open("a+", encoding="utf-8") as lock_file:
        os.chmod(lock_path, 0o640)
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("Another legacy news import is already running") from exc
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


if __name__ == "__main__":
    raise SystemExit(main())
