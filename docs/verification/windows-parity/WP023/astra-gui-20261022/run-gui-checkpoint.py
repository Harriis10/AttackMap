"""Evidence-only GUI checkpoint. Default is read-only preflight; --run launches UI."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import struct
import sys
import zlib

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "tools"))
import run_wp017_native_modes as harness

require, read, save, record = harness.require, harness.read, harness.save, harness.record
LIMITATIONS = dict(accepted_manual_ui=False, accepted_accessibility=False,
                   accepted_k2=False, accepted_k4=False, accepted_release=False,
                   provider_calls_requested=0)
FLAGS = {
    "menu": "settingsSelected historySelected scanGuard cancelGuard initialEnabledStates toggledEnabledStates restoredEnabledStates",
    "history-baseline": "actualControlLoaded originalVisible unchangedSelectionRetained changedCleared changedDisclosed busyPreserved lateOldRejected freshResultVisible emptySelectionCleared",
    "retention": "listedBoth currentRowBlocksPin pinnedRowOffersUnpin summaryHonest errorVisible",
    "watch": "defaultOff explicitOptInIdle oneFullFollowup ownedOutputIgnored stopped cancelledSettled reportPreserved oldRootIgnored actualEngine",
}


def truths(value, names):
    for name in names.split():
        require(value.get(name) is True, "Required true field: " + name)


PNG_LIMIT = 128 * 1024 * 1024


def png_pixels(encoded):
    """Bounded RGB/RGBA8 PNG validation, not human visual acceptance.

    Other encodings (including interlacing and transparency chunks) fail closed.
    CRCs, complete zlib data and every scanline filter are checked before pixels.
    """
    require(8 < len(encoded) <= PNG_LIMIT and encoded[:8] == b"\x89PNG\r\n\x1a\n",
            "Invalid PNG signature/size")
    offset, header, ended, idat_closed, idat_seen = 8, None, False, False, False
    compressed = bytearray()
    while offset < len(encoded):
        require(offset + 12 <= len(encoded), "Truncated PNG chunk")
        length, kind = struct.unpack_from(">I4s", encoded, offset)
        end = offset + 12 + length
        require(end <= len(encoded), "Truncated PNG payload")
        payload = encoded[offset + 8:end - 4]
        require(zlib.crc32(kind + payload) & 0xffffffff == struct.unpack_from(">I", encoded, end - 4)[0],
                "PNG CRC mismatch")
        require(all(65 <= c <= 90 or 97 <= c <= 122 for c in kind) and not kind[2] & 32,
                "Invalid PNG chunk type")
        require(header is not None or kind == b"IHDR", "PNG IHDR must be first")
        if kind == b"IHDR":
            require(header is None and length == 13, "Invalid/duplicate PNG IHDR")
            header = struct.unpack(">IIBBBBB", payload)
            width, height, depth, color, compression, filtering, interlace = header
            require(0 < width <= 16384 and 0 < height <= 16384 and width * height * 4 <= PNG_LIMIT,
                    "PNG dimensions exceed capture bounds")
            require(depth == 8 and color in (2, 6) and compression == filtering == interlace == 0,
                    "Unsupported PNG encoding (requires non-interlaced RGB/RGBA8)")
        elif kind == b"IDAT":
            require(not idat_closed, "Non-contiguous PNG IDAT")
            idat_seen = True
            compressed.extend(payload)
        elif kind == b"IEND":
            require(length == 0 and compressed and end == len(encoded), "Invalid PNG IEND/trailing data")
            ended = True
        else:
            require(kind not in (b"tRNS", b"acTL", b"fcTL", b"fdAT"), "Unsupported PNG transparency/animation")
            require(bool(kind[0] & 32), "Unsupported critical PNG chunk")
        if idat_seen and kind != b"IDAT":
            idat_closed = True
        offset = end
    require(ended and header is not None, "Missing PNG IEND")
    channels = 4 if color == 6 else 3
    stride = width * channels
    expected = (stride + 1) * height
    inflater = zlib.decompressobj()
    try:
        decoded = inflater.decompress(compressed, expected + 1)
    except zlib.error as error:
        raise ValueError("Invalid PNG zlib stream") from error
    require(len(decoded) == expected and inflater.eof and not inflater.unused_data
            and not inflater.unconsumed_tail, "PNG decompressed size/stream mismatch")
    previous = bytearray(stride)
    pixel_hash = hashlib.sha256()
    first, varied, visible, alpha_min, alpha_max = None, False, 0, 255, 0
    for y in range(height):
        start = y * (stride + 1)
        filtering = decoded[start]
        require(filtering <= 4, "Invalid PNG scanline filter")
        row = bytearray(decoded[start + 1:start + 1 + stride])
        for x in range(stride):
            left = row[x - channels] if x >= channels else 0
            above = previous[x]
            corner = previous[x - channels] if x >= channels else 0
            if filtering == 1:
                predictor = left
            elif filtering == 2:
                predictor = above
            elif filtering == 3:
                predictor = (left + above) // 2
            elif filtering == 4:
                p = left + above - corner
                distances = (abs(p - left), abs(p - above), abs(p - corner))
                predictor = (left, above, corner)[distances.index(min(distances))]
            else:
                predictor = 0
            row[x] = (row[x] + predictor) & 255
        for x in range(0, stride, channels):
            red, green, blue = row[x:x + 3]
            alpha = row[x + 3] if channels == 4 else 255
            visible += alpha > 0
            alpha_min, alpha_max = min(alpha_min, alpha), max(alpha_max, alpha)
            # Hidden RGB noise must not turn an all-transparent image into content.
            rendered = (red * alpha, green * alpha, blue * alpha, alpha)
            if first is None:
                first = rendered
            varied |= rendered != first
        pixel_hash.update(row)
        previous = row
    require(visible > 0, "PNG is completely transparent")
    require(varied, "PNG is visually uniform/solid")
    return dict(width=width, height=height, color_type=color, visible_pixels=visible,
                alpha_min=alpha_min, alpha_max=alpha_max, nonuniform=True,
                decoded_pixels_sha256=pixel_hash.hexdigest())


def captures_check(captures, folder, required_views):
    """Preserve measurements even when two requested sizes collapse."""
    rows, errors, groups = [], [], {}
    require(isinstance(captures, list) and captures, "Missing capture records")
    for meta in captures:
        try:
            path = harness.local_path(meta["OutputPath"])
            require(path.parent == folder and path.is_file(), "Capture outside phase output")
            match = re.fullmatch(r"(1024x700|1600x1000)-(Light|Dark)-(.+)\.png", path.name)
            require(match is not None, "Unexpected capture filename: " + path.name)
            size, theme, raw_view = match.groups()
            view = {"Nastavení": "Settings"}.get(raw_view, raw_view)
            with path.open("rb") as stream:
                encoded = stream.read(PNG_LIMIT + 1)
            require(hashlib.sha256(encoded).hexdigest() == meta["Sha256"], "Capture checksum mismatch")
            pixels = png_pixels(encoded)
            width, height = pixels["width"], pixels["height"]
            require(type(meta["Width"]) is int and type(meta["Height"]) is int
                    and (width, height) == (meta["Width"], meta["Height"])
                    and width > 0 and height > 0, "PNG/metadata dimensions differ")
            scale, logical_width, logical_height = (meta[key] for key in ("Scale", "LogicalWidth", "LogicalHeight"))
            require(all(type(n) in (int, float) and math.isfinite(n) and n > 0
                        for n in (scale, logical_width, logical_height)), "Invalid logical dimensions/scale")
            require(abs(width - logical_width * scale) <= 1.01
                    and abs(height - logical_height * scale) <= 1.01, "Pixel/logical dimensions disagree")
            require(meta["Theme"] == theme, "Actual theme differs from requested theme")
            key = (view, theme, size)
            require(key not in groups, "Duplicate view/theme/size")
            groups[key] = (logical_width, logical_height)
            rows.append(dict(path=str(path), sha256=meta["Sha256"], requested_outer=size,
                             theme=theme, view=view, raw_view=raw_view, width=width, height=height,
                             logical_width=logical_width, logical_height=logical_height, scale=scale,
                             pixels=pixels))
            if view in ("Architecture", "Inventory"):
                row_path = path.with_name(path.name + ".rows.json")
                row_proof = read(row_path)
                require(row_proof.get("view") == view and type(row_proof.get("boundCount")) is int
                        and row_proof["boundCount"] >= 0 and isinstance(row_proof.get("rows"), list),
                        "Missing/malformed structure row diagnostics")
                rows[-1]["row_diagnostics"] = record(row_path)
        except (ValueError, KeyError, TypeError, OSError) as error:
            errors.append(str(error))
    views = {key[0] for key in groups}
    if not required_views <= views:
        errors.append("Missing required views: " + str(sorted(required_views - views)))
    for view in sorted(views):
        for theme in ("Light", "Dark"):
            small, large = groups.get((view, theme, "1024x700")), groups.get((view, theme, "1600x1000"))
            if small is None or large is None:
                errors.append(f"Missing actual size pair: {view}/{theme}")
            elif not (small[0] < large[0] and small[1] < large[1]):
                errors.append(f"Collapsed/non-increasing actual viewport: {view}/{theme}: {small} -> {large}")
    result = dict(passed=not errors, measured=rows, errors=errors, visual_review_performed=False)
    save(folder / "capture-validation.json", result)
    require(not errors, "Capture validation failed: " + "; ".join(errors))
    return result


def commands(plan):
    base, app, seed = Path(plan["output"]), plan["app"], plan["seed"]["path"]
    result = []
    for name in plan["cases"]:
        folder = base / name
        if name == "startup":
            argv, timeout = [app, "--capture-startup-smoke", str(folder)], 180
        elif name == "watch":
            argv = [app, "--parity-smoke", seed, str(folder), "--engine", plan["engine"], "--single-watch"]
            timeout = 1500
        elif name == "capture":
            argv, timeout = [app, "--capture-smoke", seed, str(folder)], 600
        else:
            argv, timeout = [app, "--" + name + "-smoke", str(folder / "proof.json")], 120
        result.append(dict(name=name, folder=str(folder), argv=argv, timeout_seconds=timeout))
    return result


def preflight(args):
    app, lock, manifest, seed, output = map(harness.local_path,
        (args.app, args.release_lock, args.pinned_manifest, args.seed, args.output))
    require(app.parent.name == "app" and manifest == app.parent.parent / "package-manifest.json",
            "Select original production package app and its exact package manifest")
    require(not output.exists() and output.parent.is_dir(), "Fresh output under existing parent required")
    require(seed.is_file() and isinstance(read(seed).get("scan"), dict), "Seed report with scan required")
    for source in (app.parent.parent, seed.parent, lock.parent, Path(r"C:\tmp\juice-shop")):
        require(not output.is_relative_to(source) and not source.is_relative_to(output),
                "Output overlaps package, seed, lock directory or real repository")
    package = harness.package_identity(app, args.manifest_sha256, lock)
    phases = ["basic", "watch", "capture"] if args.phase == "all" else [args.phase]
    cases = []
    for phase in phases:
        cases.extend(["startup", "readiness", "menu", "history-baseline", "retention"] if phase == "basic" else [phase])
    plan = dict(stage="preflight-only", passed=True, processes_started=0,
                app=str(app), engine=str(app.parent / "engine/attackmap.exe"),
                release_lock=str(lock), pinned_manifest=str(manifest), manifest_sha256=args.manifest_sha256,
                seed=record(seed), package=package, output=str(output), phases=phases, cases=cases,
                runner=record(Path(__file__).resolve()), helper=record(Path(harness.__file__).resolve()), **LIMITATIONS)
    plan["commands"] = commands(plan)
    return plan


def inputs_unchanged(plan):
    require(record(Path(plan["seed"]["path"])) == plan["seed"], "Seed changed")
    for key in ("runner", "helper"):
        require(record(Path(plan[key]["path"])) == plan[key], key + " changed")
    current = harness.package_identity(plan["app"], plan["manifest_sha256"], plan["release_lock"])
    require(current == plan["package"], "Package/source/lock identity changed")
    return dict(passed=True, package=current, seed=plan["seed"])


def verify_case(name, folder, plan):
    require(not list(folder.glob("*-failure.json")), "Native failure proof exists")
    if name == "startup":
        proof = read(folder / "startup-capture-manifest.json")
        truths(proof, "initialViewPassed overviewVisible")
        require(proof.get("findingsVisible") is False and proof.get("personalSettingsRead") is False,
                "Unexpected startup state/settings access")
        require(len(proof["captures"]) == 4, "Startup capture count")
        captures_check(proof["captures"], folder, {"StartWorkspace"})
    elif name == "capture":
        proof = read(folder / "capture-manifest.json")
        require(type(proof.get("expected")) is int and proof["expected"] > 0
                and proof.get("completed") == proof["expected"] == len(proof["captures"]), "Incomplete captures")
        require(proof.get("aiMode") is None and proof.get("providerCalled") is False
                and proof.get("selectedReportSha256") == plan["seed"]["sha256"], "Wrong capture report/mode/provider state")
        captures_check(proof["captures"], folder, {"Architecture", "Inventory", "Reports", "Settings", "FindingDetail"})
    elif name == "watch":
        envelope = read(folder / "parity-smoke.json")
        require(envelope.get("failure") is None and isinstance(envelope.get("result"), dict), "Parity failure")
        proof = envelope["result"]
        truths(proof, "passed loaded roundTrip aiOffPreferencesRetained capabilitiesChecked isolatedOutput")
        require({"Risk and paths", "Reports"} <= set(proof["destinations"]), "Missing navigation destinations")
        require(proof.get("personalSettingsRead") is False and proof.get("aiDisplay") is None
                and proof.get("fleetWatchResult") is None and proof.get("scanCompleted") is False,
                "Unexpected watch scope/settings/provider")
        watch = proof["singleWatchResult"]
        truths(watch, "passed " + FLAGS["watch"])
        require(watch.get("providerCallsRequested") is False and len(watch["observed"]) == 3
                and len(watch["captures"]) == 4, "Unexpected watch request/capture count")
        require(harness.local_path(watch["outputRoot"]) == folder / "single-watch-reports", "Unexpected watch output")
        require(bool(watch.get("completedRun")), "Missing completed watch generation")
        captures_check(watch["captures"], folder, {"Repository-watch"})
    else:
        proof = read(folder / "proof.json")
        truths(proof, "passed")
        if name == "readiness":
            expected = "Choose a repository and wait for verified cleanup of any current action first."
            truths(proof, "windowVisible")
            require(proof.get("error") is None and proof.get("automaticScan") is False
                    and proof.get("selectedRunOutput") is None and proof.get("actualOutcome") == expected
                    and proof.get("expectedOutcome") == expected and proof.get("beforeStatus") != expected,
                    "Readiness outcome/preconditions failed")
            for key in ("localInvokeLatencyMilliseconds", "processStartToPrimaryResponseMilliseconds"):
                require(type(proof.get(key)) in (int, float) and math.isfinite(proof[key]) and proof[key] >= 0,
                        "Missing readiness timing")
        else:
            truths(proof, FLAGS[name])
            require(proof.get("personalSettingsRead") is False, "Personal settings access")
            if name == "menu":
                require(len(proof["menus"]) == 3 and sum(len(m["items"]) for m in proof["menus"]) == 8,
                        "Unexpected menu structure")
    return dict(passed=True, case=name, **LIMITATIONS)


def run(plan):
    require(os.name == "nt", "Windows execution required")
    output = Path(plan["output"])
    output.mkdir()
    save(output / "preflight.json", plan)
    results = []
    try:
        for command in plan["commands"]:
            folder = Path(command["folder"])
            folder.mkdir()
            save(folder / "inputs-before.json", inputs_unchanged(plan))
            environment = harness.child_environment(folder)
            try:
                harness.launch(command["argv"], folder, environment, command["timeout_seconds"])
            finally:
                try:
                    save(folder / "inputs-after.json", inputs_unchanged(plan))
                except Exception as error:
                    save(folder / "identity-failure.json", dict(passed=False, error=str(error)))
                    raise
            process = read(folder / "process.json")
            truths(process, "exited owned_job_assigned owned_tree_cleanup_verified")
            require(process.get("exit_code") == 0 and process.get("timed_out") is False, "Process failed")
            result = verify_case(command["name"], folder, plan)
            result["evidence"] = [record(path) for path in sorted(folder.iterdir()) if path.is_file()]
            save(folder / "verification.json", result)
            results.append(result)
        summary = dict(passed=True, stage="executed", cases=results, commands=len(results), **LIMITATIONS)
        save(output / "summary.json", summary)
        return summary
    except BaseException as error:
        save(output / "failure.json", dict(passed=False, error=str(error), completed_cases=results, **LIMITATIONS))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", "--original-package-app", dest="app", required=True)
    parser.add_argument("--release-lock", required=True)
    parser.add_argument("--pinned-manifest", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--seed", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--phase", choices=("all", "basic", "watch", "capture"), default="all")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    plan = preflight(args)
    print(json.dumps(run(plan) if args.run else plan, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
