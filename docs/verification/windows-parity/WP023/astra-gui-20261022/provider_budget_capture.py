"""Actual native Settings budget-label capture. Default preflight starts nothing.

One current-theme small viewport; pixel/bounds validation is not visual or a11y acceptance.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "tools"))
import run_wp017_native_modes as harness

GUI_PATH = Path(__file__).with_name("run-gui-checkpoint.py")
spec = importlib.util.spec_from_file_location("provider_budget_pixel_guard", GUI_PATH)
gui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gui)
require, read, record, save = harness.require, harness.read, harness.record, harness.save
LABEL = "Total AI time allowance in seconds (1-3600; explicit local OpenAI HTTP API up to 7200)"
BUTTONS = {"Save provider settings", "Test connection (sends request)"}
LIMITS = dict(requested_scans=0, requested_provider_calls=0, settings_save_requested=False,
              visual_review_performed=False, accepted_visual=False, accepted_accessibility=False,
              accepted_wp017=False, accepted_wp023=False, accepted_release=False)
SOURCE_NAMES = ("MainWindow.ProviderScrollSmoke.cs", "ProviderSettingsView.cs", "NativeCaptureProbe.cs")


def inputs(plan):
    return dict(package=harness.package_identity(plan["app"], plan["manifest_sha256"], plan["release_lock"]),
                runner=record(Path(__file__).resolve()), helper=record(Path(harness.__file__).resolve()),
                guard=record(GUI_PATH), source={name: record(ROOT / "desktop/windows/AttackMap.NativeSpike" / name)
                                             for name in SOURCE_NAMES})


def unchanged(plan):
    current = inputs(plan)
    require(current == plan["inputs"], "Package/source/lock/runner/pixel guard inputs changed")
    return dict(unchanged=True, **current)


def preflight(args):
    app, lock, output = map(harness.local_path, (args.app, args.release_lock, args.output))
    require(app.parent.name == "app" and (app.parent.parent / "package-manifest.json").is_file(),
            "Select the original RequiredBundled production package")
    require(isinstance(args.manifest_sha256, str) and re.fullmatch(r"[a-f0-9]{64}", args.manifest_sha256),
            "Explicit reviewed manifest SHA256 pin required")
    require(not output.exists() and output.parent.is_dir(), "Fresh output under existing parent required")
    for source in (app.parent.parent, lock.parent, Path(r"C:\tmp\juice-shop")):
        require(not output.is_relative_to(source) and not source.is_relative_to(output), "Output overlaps input")
    phase = output / "native"
    proof, png = phase / "proof.json", phase / "budget-label.png"
    plan = dict(stage="preflight-only", processes_started=0, app=str(app), release_lock=str(lock),
                manifest_sha256=args.manifest_sha256, output=str(output), phase=str(phase),
                proof=str(proof), png=str(png), timeout_seconds=180,
                command=[str(app), "--provider-scroll-smoke", str(proof), "--viewport", "1024", "700",
                         "--provider-scroll-capture", str(png)], **LIMITS)
    plan["inputs"] = inputs(plan)
    for pin in (plan["inputs"]["runner"], plan["inputs"]["helper"], plan["inputs"]["guard"]):
        require(not Path(pin["path"]).is_relative_to(output), "Output contains a runner input")
    return plan


def number(value, positive=False):
    require(type(value) in (int, float) and math.isfinite(value) and (value > 0 if positive else value >= 0),
            "Expected finite nonnegative/positive measurement")
    return value


def bounds(value, width, height):
    require(isinstance(value, dict) and value.get("FullyWithinClippedViewport") is True,
            "Native budget element not fully visible")
    original, clipped = value.get("BoundsRelativeRoot"), value.get("ClippedBoundsRelativeRoot")
    require(isinstance(original, dict) and isinstance(clipped, dict), "Missing budget element bounds")
    for rect in (original, clipped):
        x, y = number(rect.get("X")), number(rect.get("Y"))
        w, h = number(rect.get("Width"), True), number(rect.get("Height"), True)
        require(x + w <= width + .01 and y + h <= height + .01, "Budget bounds outside root viewport")
    require(all(abs(original[key] - clipped[key]) <= .01 for key in ("X", "Y", "Width", "Height")),
            "Native fully-visible claim disagrees with clipped budget bounds")


def verify(plan):
    proof_path, png_path = harness.local_path(plan["proof"]), harness.local_path(plan["png"])
    proof_pin = record(proof_path)
    envelope = read(proof_path)
    require(envelope.get("completed") is True and envelope.get("failure") is None
            and envelope.get("settingsRestorePerformedByHelper") is False
            and type(envelope.get("providerRequestsInvokedByHelper")) is int
            and envelope["providerRequestsInvokedByHelper"] == 0, "Incomplete native preview or unexpected request/restore")
    result = envelope.get("result")
    require(isinstance(result, dict) and result.get("bothActionsFullyVisibleAndEnabled") is True,
            "Original bottom-scroll button proof failed")
    for key in ("buttonActionsInvoked", "providerRequestsInvoked"):
        require(type(result.get(key)) is int and result[key] == 0, "Unexpected native action/request")
    after = result.get("after")
    require(isinstance(after, list) and len(after) == 2 and all(isinstance(row, dict) for row in after)
            and {row.get("Label") for row in after} == BUTTONS
            and all(row.get("FullyWithinClippedViewport") is True and row.get("Enabled") is True for row in after),
            "Missing actual Save/Test clipped button evidence")
    width, height, scale = (number(result.get(key), True) for key in ("rootWidth", "rootHeight", "scale"))
    require(width <= 1025.01 and height <= 701.01, "Actual root exceeds requested small logical viewport")
    theme = result.get("actualTheme")
    require(theme in ("Light", "Dark"), "Missing actual native theme")
    budget = result.get("budgetLabel")
    require(isinstance(budget, dict) and budget.get("text") == LABEL and budget.get("value") == "600",
            "Wrong actual budget label/default value")
    bounds(budget.get("labelBounds"), width, height)
    bounds(budget.get("fieldBounds"), width, height)
    number(budget.get("innerOffset"))
    number(result.get("innerOffset"))
    number(result.get("innerScrollableHeight"))
    meta = result.get("capture")
    require(isinstance(meta, dict) and harness.local_path(meta.get("OutputPath")) == png_path
            and meta.get("Theme") == theme, "Wrong captured output path/theme")
    with png_path.open("rb") as stream:
        encoded = stream.read(gui.PNG_LIMIT + 1)
    digest = hashlib.sha256(encoded).hexdigest()
    require(digest == meta.get("Sha256"), "PNG/metadata checksum mismatch")
    pixels = gui.png_pixels(encoded)
    require(type(meta.get("Width")) is int and type(meta.get("Height")) is int
            and (meta["Width"], meta["Height"]) == (pixels["width"], pixels["height"]),
            "PNG dimensions differ from native metadata")
    logical_w, logical_h, actual_scale = (number(meta.get(key), True) for key in ("LogicalWidth", "LogicalHeight", "Scale"))
    require(abs(logical_w - width) <= .01 and abs(logical_h - height) <= .01 and abs(actual_scale - scale) <= .001
            and abs(pixels["width"] - width * scale) <= 1.01
            and abs(pixels["height"] - height * scale) <= 1.01, "Pixel/logical/native viewport mismatch")
    require(record(proof_path) == proof_pin and record(png_path)["sha256"] == digest,
            "Native proof/capture changed during validation")
    return dict(passed=True, proof=proof_pin, png=dict(path=str(png_path), sha256=digest),
                pixels=pixels, actual_theme=theme, logical_width=width, logical_height=height,
                scale=scale, budget=budget, **LIMITS)


def run(plan):
    require(os.name == "nt", "Windows execution required")
    unchanged(plan)
    output, folder = Path(plan["output"]), Path(plan["phase"])
    output.mkdir()
    save(output / "preflight.json", plan)
    folder.mkdir()
    try:
        save(output / "inputs-before.json", unchanged(plan))
        environment = harness.child_environment(folder)
        try:
            harness.launch(plan["command"], folder, environment, plan["timeout_seconds"])
        finally:
            try:
                save(output / "inputs-after.json", unchanged(plan))
            except BaseException as error:
                save(output / "identity-failure.json", dict(passed=False, error=str(error)))
                raise
        process = read(folder / "process.json")
        require(type(process.get("exit_code")) is int and process["exit_code"] == 0
                and process.get("timed_out") is False
                and all(process.get(key) is True for key in ("exited", "owned_job_assigned", "owned_tree_cleanup_verified")),
                "Native process failed or owned cleanup unverified")
        validation = verify(plan)
        save(output / "capture-validation.json", validation)
        unchanged(plan)
        require(record(Path(validation["proof"]["path"])) == validation["proof"]
                and record(Path(validation["png"]["path"])) == validation["png"], "Validated output changed")
        result = dict(passed=True, stage="executed", validation=validation, inputs_unchanged=True,
                      process=record(folder / "process.json"), **LIMITS)
        save(output / "summary.json", result)
        return result
    except BaseException as error:
        save(output / "failure.json", dict(passed=False, error=str(error), **LIMITS))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("app", "release-lock", "manifest-sha256", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    plan = preflight(args)
    print(json.dumps(run(plan) if args.run else plan, indent=2))


if __name__ == "__main__":
    main()
