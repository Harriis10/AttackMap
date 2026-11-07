from pathlib import Path
import difflib

root = Path(__file__).resolve().parents[2]
out = Path(__file__).resolve().parent
pairs = []

runner = root / "tools/capture_wp043_live.py"
current = runner.read_text(encoding="utf-8")
base = current.replace("import struct\n", "", 1)
start = base.index("def _detail_root_render_terminal(")
end = base.index("def intervention_acknowledged(", start)
base = base[:start] + base[end:]
old_validation = '''    if args.detail_spacing_probe_round and args.detail_brush_probe_round:
        raise ValueError("Detail spacing and brush probes cannot be combined in one run")
    if args.detail_render_probe and (
        args.diagnostic_interventions or args.detail_spacing_probe_round
        or args.detail_brush_probe_round or args.print_window_detail_capture
    ):
        raise ValueError("Detail render probe cannot be combined with other capture or intervention modes")
'''
new_validation = '''    if args.detail_spacing_probe_round and args.detail_brush_probe_round:
        raise ValueError("Detail spacing and brush probes cannot be combined in one run")
    if (args.detail_render_probe or args.detail_root_render_probe) and (
        args.diagnostic_interventions or args.detail_spacing_probe_round
        or args.detail_brush_probe_round or args.print_window_detail_capture
        or (args.detail_render_probe and args.detail_root_render_probe)
    ):
        raise ValueError("Detail render probes cannot be combined with other capture or intervention modes")
'''
assert new_validation in base
base = base.replace(new_validation, old_validation, 1)
base = base.replace('        "detailRootRenderProbe": None if not args.detail_root_render_probe else [],\n', "", 1)
start = base.index("                    if args.detail_root_render_probe:")
end = base.index("                    if args.print_window_detail_capture:", start)
base = base[:start] + base[end:]
base = base.replace('            "F7": "{F7}",\n', "", 1)
base = base.replace('''    parser.add_argument("--detail-root-render-probe", action="store_true",
        help="Add non-mutating ImageGrab/Detail-RTB/root-RTB/ImageGrab comparisons for each FindingDetail")
''', "", 1)
assert "detail_root_render_terminal" not in base and 'args.detail_root_render_probe' not in base
pairs.append((runner, base, current))

test = root / "tests/test_wp043_live_capture.py"
current = test.read_text(encoding="utf-8")
base = current.replace("import base64\n", "", 1)
base = base.replace("        self.detail_root_render_probe_failed = None\n", "", 1)
start = base.index('        elif key == "F7":')
end = base.index('        elif key == "F8":', start)
base = base[:start] + base[end:]
base = base.replace("            detail_root_render_probe=False,\n", "", 1)
start = base.index("    def test_detail_root_render_probe_retains_five_a_d_t_b_sets")
end = base.index("    def test_dark_theme_requires_matching_diagnostics_snapshot", start)
base = base[:start] + base[end:]
assert "test_detail_root_render_probe_retains" not in base and 'elif key == "F7"' not in base
pairs.append((test, base, current))

chunks = [
    "Task 2 review package\n",
    "Base/head Git revision: 507bddacd72a246a136ca2d46faad2aa661806c1 (unchanged; commits forbidden)\n",
    "Scope: reconstructed post-Task-1/pre-Task-2 baseline versus current untracked files.\n\n",
]
for path, base, current in pairs:
    relative = path.relative_to(root).as_posix()
    chunks.extend(difflib.unified_diff(
        base.splitlines(keepends=True), current.splitlines(keepends=True),
        fromfile=f"a/{relative}", tofile=f"b/{relative}", n=10,
    ))
    chunks.append("\n")
review = out / "task-2-review.diff"
review.write_text("".join(chunks), encoding="utf-8")
print(review)
