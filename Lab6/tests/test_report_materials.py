"""Tests for generated Lab6 report materials."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.generate_report_materials import REPORT_FILES, generate


BAD_TEXT_MARKERS = ("TODO", "placeholder", "Рџ", "Рґ", "СЊ", "С…")


def test_generate_report_materials_outputs_expected_files(tmp_path: Path) -> None:
    """Report generator must create complete UTF-8 materials with verification results."""
    generate(tmp_path)

    report_dir = tmp_path / "report" / "generated"
    generated_names = sorted(path.name for path in report_dir.iterdir())
    assert generated_names == sorted(REPORT_FILES)

    report_data = json.loads(
        (report_dir / "report_data.json").read_text(encoding="utf-8")
    )
    assert report_data["curve_variant"] == "variant 8"
    assert report_data["verify_original"] == "VALID"
    assert report_data["verify_modified"] == "INVALID"
    assert report_data["verify_corrupted"] == "INVALID"

    verification_log = (report_dir / "verification_log.txt").read_text(
        encoding="utf-8"
    )
    assert "original message: VALID" in verification_log
    assert "modified message: INVALID" in verification_log
    assert "corrupted signature: INVALID" in verification_log

    for markdown_path in report_dir.glob("*.md"):
        text = markdown_path.read_text(encoding="utf-8")
        assert not any(marker in text for marker in BAD_TEXT_MARKERS), markdown_path.name
