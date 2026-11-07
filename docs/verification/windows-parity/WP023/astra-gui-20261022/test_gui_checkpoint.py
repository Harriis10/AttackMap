"""Pure, tiny image fixtures: no application, provider, build or subprocess."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import zlib

import pytest

RUNNER_PATH = Path(__file__).with_name("run-gui-checkpoint.py")
spec = importlib.util.spec_from_file_location("evidence_gui_checkpoint", RUNNER_PATH)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)


def png(width=3, height=2, channels=4, filtering=0, pixels=None, raw=None):
    pixels = pixels if pixels is not None else bytes((i * 37 + 19) % 256 for i in range(width * height * channels))
    stride = width * channels
    if raw is None:
        scanlines = bytearray()
        for y in range(height):
            row = pixels[y * stride:(y + 1) * stride]
            above = pixels[(y - 1) * stride:y * stride] if y else bytes(stride)
            scanlines.append(filtering)
            for i, value in enumerate(row):
                a = row[i - channels] if i >= channels else 0
                b = above[i]
                c = above[i - channels] if i >= channels else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                paeth = a if pa <= pb and pa <= pc else b if pb <= pc else c
                predictor = (0, a, b, (a + b) // 2, paeth)[filtering]
                scanlines.append((value - predictor) % 256)
        raw = bytes(scanlines)
    header = struct.pack(">IIBBBBB", width, height, 8, 6 if channels == 4 else 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


@pytest.mark.parametrize("channels", [3, 4])
@pytest.mark.parametrize("filtering", range(5))
def test_all_filters_reconstruct_exact_pixels(channels, filtering):
    pixels = bytes((i * 37 + 19) % 256 for i in range(3 * 2 * channels))
    measured = runner.png_pixels(png(channels=channels, filtering=filtering, pixels=pixels))
    assert measured["decoded_pixels_sha256"] == hashlib.sha256(pixels).hexdigest()
    assert measured["nonuniform"] is True
    assert measured["visible_pixels"] == 6


@pytest.mark.parametrize("pixels,reason", [
    (bytes(24), "completely transparent"),
    (b"\xff\x00\xff\x00\x00\xff\x00\x00" * 3, "completely transparent"),
    (b"\x42\x42\x42\xff" * 6, "uniform/solid"),
    (b"\x42\x42\x42\x70" * 6, "uniform/solid"),
])
def test_blank_images_fail_closed(pixels, reason):
    with pytest.raises(ValueError, match=reason):
        runner.png_pixels(png(pixels=pixels))


@pytest.mark.parametrize("mutation", [
    lambda value: value[:24],
    lambda value: value[:-1],
    lambda value: value + b"trailing",
    lambda value: value[:50] + bytes([value[50] ^ 1]) + value[51:],
    lambda value: png(raw=bytes(27)),  # one excess decoded byte
    lambda value: png(raw=bytes(25)),  # one missing decoded byte
    lambda value: png(raw=b"\x05" + bytes(12) + b"\x00" + bytes(12)),
    lambda value: png(width=16385, height=1, raw=b""),
    lambda value: png(width=0, raw=b""),
    lambda value: value[:33] + chunk(b"tRNS", bytes(6)) + value[33:],
    lambda value: value[:33] + chunk(b"IDAT", b"") + chunk(b"tEXt", b"x") + value[33:],
    lambda value: value[:33] + chunk(b"IDAT", zlib.compress(bytes(26)) + b"trailing") + chunk(b"IEND", b""),
])
def test_corrupt_or_unsupported_png_fails_closed(mutation):
    with pytest.raises(ValueError):
        runner.png_pixels(mutation(png()))


def captures(folder, collapsed=False, view="StartWorkspace"):
    records = []
    for theme in ("Light", "Dark"):
        for size, edge in (("1024x700", 2), ("1600x1000", 2 if collapsed else 3)):
            path = folder / f"{size}-{theme}-{view}.png"
            encoded = png(width=edge, height=edge)
            path.write_bytes(encoded)
            records.append(dict(OutputPath=str(path), Width=edge, Height=edge, Scale=1,
                                LogicalWidth=edge, LogicalHeight=edge, Theme=theme,
                                Sha256=hashlib.sha256(encoded).hexdigest()))
    return records


def test_root_and_complete_size_theme_pairs(tmp_path):
    assert runner.ROOT == RUNNER_PATH.resolve().parents[5]
    assert (runner.ROOT / "tools" / "run_wp017_native_modes.py").is_file()
    result = runner.captures_check(captures(tmp_path), tmp_path, {"StartWorkspace"})
    assert result["passed"] and len(result["measured"]) == 4
    assert result["visual_review_performed"] is False


@pytest.mark.parametrize("label", ["Settings", "Nastavení"])
def test_settings_exact_labels_keep_original_evidence(tmp_path, label):
    result = runner.captures_check(captures(tmp_path, view=label), tmp_path, {"Settings"})
    assert result["passed"] and len(result["measured"]) == 4
    assert {row["view"] for row in result["measured"]} == {"Settings"}
    assert {row["raw_view"] for row in result["measured"]} == {label}
    assert all(Path(row["path"]).name.endswith(label + ".png") for row in result["measured"])
    assert result["visual_review_performed"] is False


@pytest.mark.parametrize("failure", ["missing", "three", "mixed_duplicate", "near_alias", "collapsed"])
def test_settings_alias_does_not_weaken_capture_requirements(tmp_path, failure):
    records = captures(tmp_path, collapsed=failure == "collapsed", view="Nastavení")
    if failure == "missing":
        records = captures(tmp_path, view="Reports")
    elif failure == "three":
        records.pop()
    elif failure in ("mixed_duplicate", "near_alias"):
        index = 1 if failure == "mixed_duplicate" else 0
        label = "Settings" if failure == "mixed_duplicate" else "Nastavení-extra"
        old = Path(records[index]["OutputPath"])
        replacement = old.with_name("1024x700-Light-" + label + ".png")
        replacement.write_bytes(old.read_bytes())
        records[index]["OutputPath"] = str(replacement)
    with pytest.raises(ValueError, match="Capture validation failed"):
        runner.captures_check(records, tmp_path, {"Settings"})
    result = json.loads((tmp_path / "capture-validation.json").read_text(encoding="utf-8"))
    assert result["passed"] is False and result["errors"]


@pytest.mark.parametrize("failure", ["collapsed", "tampered", "dimensions", "theme", "missing", "transparent"])
def test_capture_metadata_and_pixels_fail_closed(tmp_path, failure):
    records = captures(tmp_path, collapsed=failure == "collapsed")
    if failure == "tampered":
        Path(records[0]["OutputPath"]).write_bytes(png(width=2, height=2, pixels=b"\x01\x02\x03\xff" * 4))
    elif failure == "dimensions":
        records[0]["Width"] += 1
    elif failure == "theme":
        records[0]["Theme"] = "Dark"
    elif failure == "missing":
        records.pop()
    elif failure == "transparent":
        encoded = png(width=2, height=2, pixels=bytes(16))
        Path(records[0]["OutputPath"]).write_bytes(encoded)
        records[0]["Sha256"] = hashlib.sha256(encoded).hexdigest()
    with pytest.raises(ValueError, match="Capture validation failed"):
        runner.captures_check(records, tmp_path, {"StartWorkspace"})
    result = json.loads((tmp_path / "capture-validation.json").read_text(encoding="utf-8"))
    assert result["passed"] is False and result["errors"]
