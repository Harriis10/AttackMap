"""Default analyzer logs describe categories, never exception source excerpts."""
from types import SimpleNamespace
import logging

import pytest

from attackmap import analyzers
from attackmap.analyzer_contracts import AnalyzerMetadata

PRIVATE = "SOURCE_EXCERPT_SENTINEL token=UNRECOGNIZED_CREDENTIAL_SENTINEL C:/private/project.py"


class Broken:
    name = "broken-fixture"
    metadata = AnalyzerMetadata(name=name, version="1.2.3")

    def analyze(self, root):
        raise RuntimeError(PRIVATE)


def test_analyze_warning_is_generic_but_structured_error_semantics_remain(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger="attackmap.analyzers"):
        result = analyzers.analyze_repository(tmp_path, analyzers=[Broken()])
    assert "broken-fixture" in caplog.text and "RuntimeError" in caplog.text
    assert "analysis failed" in caplog.text and "continuing" in caplog.text
    assert "SOURCE_EXCERPT_SENTINEL" not in caplog.text and "UNRECOGNIZED_CREDENTIAL_SENTINEL" not in caplog.text
    assert "C:/private" not in caplog.text
    assert result.analyzer_errors[0].analyzer == "broken-fixture"
    assert result.analyzer_errors[0].error_type == "RuntimeError"
    # Structured errors keep the established redacted diagnostic message policy.
    assert "SOURCE_EXCERPT_SENTINEL" in result.analyzer_errors[0].message


def test_detect_warning_does_not_echo_exception_or_unsafe_identity(tmp_path, caplog):
    class Detect:
        name = PRIVATE
        def detect(self, root):
            raise ValueError(PRIVATE)
    with caplog.at_level(logging.WARNING, logger="attackmap.analyzers"):
        assert not analyzers._should_run_analyzer(Detect(), tmp_path)
    assert "Analyzer 'unknown' detect() failed (ValueError)" in caplog.text
    assert "SENTINEL" not in caplog.text and "private/project" not in caplog.text


@pytest.mark.parametrize("phase", ["load", "initialize", "metadata"])
def test_entrypoint_warnings_omit_raw_exception_and_metadata(phase, monkeypatch, caplog):
    def fail(*args, **kwargs):
        raise RuntimeError(PRIVATE)
    entry = SimpleNamespace(name=PRIVATE, load=fail if phase == "load" else lambda: Broken())
    if phase == "initialize":
        monkeypatch.setattr(analyzers, "_coerce_analyzer_instance", fail)
    if phase == "metadata":
        monkeypatch.setattr(analyzers, "normalize_analyzer_metadata", fail)
    with caplog.at_level(logging.WARNING, logger="attackmap.analyzers"):
        assert analyzers._load_discovered_analyzer(entry) is None
    assert "unknown" in caplog.text and "RuntimeError" in caplog.text
    assert {"load": "load analyzer", "initialize": "initialize analyzer", "metadata": "normalize analyzer metadata"}[phase] in caplog.text
    assert "SENTINEL" not in caplog.text and "C:/private" not in caplog.text


def test_custom_exception_class_is_bounded_safe_in_warning_and_progress(tmp_path, caplog):
    error_type = type("OddError", (Exception,), {})
    error_type.__name__ = PRIVATE
    class Custom(Broken):
        def analyze(self, root):
            raise error_type(PRIVATE)
    stages = []
    class Progress:
        def stage(self, text):
            stages.append(text)
        def done(self):
            pass
        def begin(self, *args):
            pass
        def advance(self, *args):
            pass
    with caplog.at_level(logging.WARNING, logger="attackmap.analyzers"):
        result = analyzers.analyze_repository(tmp_path, analyzers=[Custom()], progress=Progress())
    assert "(Exception)" in caplog.text and "SENTINEL" not in caplog.text
    assert any("(Exception)" in text for text in stages)
    assert all("SENTINEL" not in text for text in stages)
    assert result.analyzer_errors[0].error_type == PRIVATE


def test_strict_mode_still_raises_original_exception(tmp_path):
    with pytest.raises(RuntimeError, match="SOURCE_EXCERPT_SENTINEL"):
        analyzers.analyze_repository(tmp_path, analyzers=[Broken()], strict=True)
