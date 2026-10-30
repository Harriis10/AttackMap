from pathlib import Path
import difflib

root = Path(__file__).resolve().parents[2]
out = Path(__file__).resolve().parent
pairs = []

source = root / "desktop/windows/AttackMap.NativeSpike/MainWindow.RenderDiagnostics.cs"
current = source.read_text(encoding="utf-8")
base = current
base = base.replace("    private bool renderDiagnosticsDetailRootRenderActive;\n", "", 1)
start = base.index("            var detailRootRenderAccelerator =")
end = base.index("            var detailRenderAccelerator =", start)
base = base[:start] + base[end:]
base = base.replace("explicit F7 writes D/T PNG pixels; explicit F8", "explicit F8", 1)
base = base.replace('                f7 = "Non-mutating direct Detail and root RenderTargetBitmap pair; QA observation only",\n', "", 1)
start = base.index("    private async Task RenderDiagnosticsDetailRootRender()")
end = base.index("    private void RenderDiagnosticsSnapshot", start)
base = base[:start] + base[end:]
assert "DetailRootRender" not in base and "detail-root-render" not in base
pairs.append((source, base, current))

test = root / "tests/test_wp043_live_capture.py"
current = test.read_text(encoding="utf-8")
start = current.index("    def test_detail_root_render_probe_rasterizes_both_targets_without_settling_or_mutation")
end = current.index("    def test_any_failed_dispatch_fails_run_without_erasing_prior_captures", start)
base = current[:start] + current[end:]
assert "detail_root_render_probe_rasterizes" not in base
pairs.append((test, base, current))

chunks = [
    "Task 1 review package\n",
    "Base/head Git revision: 507bddacd72a246a136ca2d46faad2aa661806c1 (unchanged; commits forbidden)\n",
    "Scope: reconstructed pre-task baseline versus current untracked files; exact added regions removed.\n\n",
]
for path, base, current in pairs:
    relative = path.relative_to(root).as_posix()
    chunks.extend(difflib.unified_diff(
        base.splitlines(keepends=True), current.splitlines(keepends=True),
        fromfile=f"a/{relative}", tofile=f"b/{relative}", n=10,
    ))
    chunks.append("\n")
review = out / "task-1-review.diff"
review.write_text("".join(chunks), encoding="utf-8")
print(review)
