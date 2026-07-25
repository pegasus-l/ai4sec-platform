from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ai4sec_platform.domains.vulnerabilities.material_reviewers import review_crawled_material


def load_review_golden_set(project_root: Path) -> dict[str, Any]:
    path = project_root / "configs" / "vulnerability_review_golden_set.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    samples = data.get("samples") or []
    if not isinstance(samples, list) or not samples:
        raise ValueError("review golden set must contain samples")
    return {**data, "samples": [sample for sample in samples if isinstance(sample, dict)]}


def evaluate_review_golden_set(project_root: Path, *, confidence_threshold: float = 0.55) -> dict[str, Any]:
    golden_set = load_review_golden_set(project_root)
    outcomes: list[dict[str, Any]] = []
    for sample in golden_set["samples"]:
        review = review_crawled_material(
            {
                "success": True,
                "title": sample.get("title", ""),
                "url": sample.get("url", ""),
                "markdown": sample.get("content", ""),
                "cleaned_text": sample.get("content", ""),
            },
            confidence_threshold=confidence_threshold,
        )
        expected = str(sample.get("expected_decision") or "")
        actual = str(review.get("decision") or "")
        outcomes.append({"id": sample.get("id"), "expected": expected, "actual": actual, "matched": expected == actual, "label_source": sample.get("label_source")})
    matched = sum(1 for outcome in outcomes if outcome["matched"])
    human_verified = sum(1 for outcome in outcomes if outcome["label_source"] == "human_verified")
    return {
        "total": len(outcomes),
        "matched": matched,
        "accuracy": round(matched / len(outcomes), 4),
        "human_verified": human_verified,
        "ready_for_production_calibration": human_verified == len(outcomes),
        "outcomes": outcomes,
    }
