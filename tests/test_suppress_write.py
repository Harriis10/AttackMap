"""Regression tests for safe suppression-file writes (#P1.3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.ui.suppress_write import append_suppression


def test_appends_valid_entry_with_yaml_safe_dump(tmp_path: Path) -> None:
    path = tmp_path / ".attackmap-suppress.yaml"
    append_suppression(
        path,
        {"rule": "hardcoded-secret", "reason": "test fixtures only", "owner": "appsec"},
    )
    data = path.read_text(encoding="utf-8")
    assert "hardcoded-secret" in data
    assert "test fixtures only" in data
    assert "appsec" in data
    # One list item under suppress
    assert data.count("- reason:") == 1


def test_reason_with_newlines_and_quotes_is_safely_serialized(tmp_path: Path) -> None:
    path = tmp_path / ".attackmap-suppress.yaml"
    malicious_reason = "foo\n  rule: injected\n  reason: bar"
    append_suppression(
        path,
        {"rule": "hardcoded-secret", "reason": malicious_reason},
    )
    data = path.read_text(encoding="utf-8")
    # The payload must remain inside the 'reason' scalar, not create a new list entry.
    assert data.count("- reason:") == 1
    # The injected text must be escaped, not parsed as a sibling key.
    assert "rule: injected" in data


def test_invalid_id_rejected(tmp_path: Path) -> None:
    path = tmp_path / ".attackmap-suppress.yaml"
    with pytest.raises(ValueError, match="16-hex finding id"):
        append_suppression(path, {"id": "not-hex", "reason": "r"})


def test_missing_selector_rejected(tmp_path: Path) -> None:
    path = tmp_path / ".attackmap-suppress.yaml"
    with pytest.raises(ValueError, match="selector"):
        append_suppression(path, {"reason": "r"})


def test_broad_path_rejected(tmp_path: Path) -> None:
    path = tmp_path / ".attackmap-suppress.yaml"
    with pytest.raises(ValueError, match="suppress every file"):
        append_suppression(path, {"paths": "**", "reason": "r"})


def test_out_of_repo_write_refused(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.yaml"
    with pytest.raises(ValueError, match="outside"):
        append_suppression(outside, {"rule": "x", "reason": "r"}, root=repo)


def test_expires_must_be_iso_date(tmp_path: Path) -> None:
    path = tmp_path / ".attackmap-suppress.yaml"
    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        append_suppression(path, {"rule": "x", "reason": "r", "expires": "not-a-date"})


@pytest.mark.skipif(
    not hasattr(Path, "symlink_to"),
    reason="symlinks not supported on this platform",
)
def test_symlink_refused_when_privileged(tmp_path: Path) -> None:
    """Only runs on platforms/accounts where symlink creation succeeds."""
    outside = tmp_path / "outside.yaml"
    outside.write_text("version: 1\nsuppress: []\n", encoding="utf-8")
    link = tmp_path / ".attackmap-suppress.yaml"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation not permitted")
    with pytest.raises(ValueError, match="symlink"):
        append_suppression(link, {"rule": "x", "reason": "r"})
