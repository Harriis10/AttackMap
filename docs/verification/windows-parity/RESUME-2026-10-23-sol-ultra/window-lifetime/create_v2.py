"""Preserve v1 review evidence and generate the narrower v2 proposal inputs."""
from pathlib import Path

base = Path(__file__).resolve().parent
target = base / "v2"
target.mkdir(exist_ok=False)


def once(text: str, before: str, after: str) -> str:
    if text.count(before) != 1:
        raise RuntimeError(f"Expected one text preimage: {before!r}")
    return text.replace(before, after, 1)


prepare = (base / "prepare_evidence.py").read_text()
prepare = once(prepare, "ROOT = HERE.parents[4]", "ROOT = HERE.parents[5]")
prepare = prepare.replace("ready = false; ++generation; actionLifetime.Cancel();", "ready = false; ++generation;")
prepare = once(prepare, '    late = late_before if variant == "Baseline" else late_after', '    late = late_before')
prepare = once(prepare, '''    core = replace_once(core,
        "        Closed += (_, _) => { actionLifetime.Cancel(); keyboardBindings?.Dispose(); engine.Disconnect(); };",
        "        Closed += (_, _) => { keyboardBindings?.Dispose(); engine.Disconnect(); };")
''', "")
prepare = once(prepare,
    '        "    private async Task<bool> LoadReport(string path, RunIdentity? identity = null)\\n    {\\n        if (actionLifetime.IsCancellationRequested) return false;\\n        long current")',
    '        "    private async Task<bool> LoadReport(string path, RunIdentity? identity = null)\\n    {\\n        if (!ready || actionLifetime.IsCancellationRequested) return false;\\n        long current")')
prepare = once(prepare,
    '        "    private async Task LoadData()\\n    {\\n        if (actionLifetime.IsCancellationRequested) return;\\n        long current")',
    '        "    private async Task LoadData()\\n    {\\n        if (!ready || actionLifetime.IsCancellationRequested) return;\\n        long current")')
prepare = once(prepare,
    '        "        if (actionLifetime.IsCancellationRequested || !placementPersistenceEnabled || ((FrameworkElement)Content).XamlRoot == null")',
    '        "        if (!ready || actionLifetime.IsCancellationRequested || !placementPersistenceEnabled || ((FrameworkElement)Content).XamlRoot == null")')
(target / "prepare_evidence.py").write_text(prepare, encoding="utf-8", newline="\n")

harness = (base / "Harness.template.cs.txt").read_text()
harness = once(harness, "    public bool MiddleReady, MiddleCanceled;", "    public bool MiddleReady, MiddleCanceled, MiddleVisited;\n    public Action? MiddleAction;")
harness = once(harness,
    "        MiddleReady = ready; MiddleCanceled = actionLifetime.IsCancellationRequested; MiddleGeneration = generation;",
    "        MiddleReady = ready; MiddleCanceled = actionLifetime.IsCancellationRequested; MiddleGeneration = generation;\n        MiddleVisited = true; MiddleAction?.Invoke();")
harness = once(harness,
    "!state.MiddleReady && state.MiddleCanceled && state.MiddleGeneration == requested + 1",
    "!state.MiddleReady && !state.MiddleCanceled && state.MiddleGeneration == requested + 1")
harness = once(harness,
    '                    Check(!fixedCore || (!state.MiddleReady && !state.MiddleCanceled && state.MiddleGeneration == requested + 1), "Invalidation precedes existing cleanup subscribers");',
    '                    Check(!fixedCore || (!state.MiddleReady && !state.MiddleCanceled && state.MiddleGeneration == requested + 1), "ready/generation invalidate before cleanup; cancellation remains at original site");')
harness = once(harness,
    '                Check(threw, "Cancellation failure remains observable");',
    '                Check(threw, "Cancellation failure remains observable");\n                Check(state.MiddleVisited, "Existing middle cleanup subscriber still runs before a throwing cancellation callback");')
harness = once(harness,
    '            foreach (bool fail in new[] { false, true })',
    '''            {
                var (window, state) = Create(variant); var read = new PendingRead(Stage.Report);
                Task<bool> task = window.Load(AddRead(read));
                state.MiddleAction = () => {
                    read.Release(new IOException("completion between early invalidation and late cancellation"));
                    Check(task.Wait(TimeSpan.FromSeconds(5)), "Controlled read must finish before late cancellation");
                    Check(!state.actionLifetime.IsCancellationRequested, "Test must exercise generation independently of cancellation");
                };
                window.Close();
                Check(!await task && UiProbe.Writes == (fixedCore ? 0 : 1) && UiProbe.Publishes == 0, "Early generation barrier blocks report catch before token cancellation");
                cases.Add(new { variant, name = "delayed-fault-between-invalidation-and-cancel", writes = UiProbe.Writes });
            }
            {
                var (window, state) = Create(variant); string path = AddRead(new PendingRead(null)); bool loaded = false;
                state.MiddleAction = () => {
                    Task<bool> task = window.Load(path);
                    Check(task.IsCompleted, "Controlled read is immediate"); loaded = task.GetAwaiter().GetResult();
                };
                window.Close();
                Check(ReportAdapter.Calls == (fixedCore ? 0 : 1) && loaded == !fixedCore, "ready guard blocks new import before cancellation");
                Check(UiProbe.Publishes == (fixedCore ? 0 : 1), "Closed entry cannot publish between subscribers");
                cases.Add(new { variant, name = "new-import-between-invalidation-and-cancel", readCalls = ReportAdapter.Calls });
            }
            {
                var (window, state) = Create(variant); state.MiddleAction = () => window.SendPlacement();
                window.Close();
                Check(fixedOptional ? UiProbe.Accesses == 0 : UiProbe.Reads > 0, "Optional ready guard blocks placement before late cancellation");
                cases.Add(new { variant, name = "placement-between-invalidation-and-cancel", accesses = UiProbe.Accesses });
            }
            foreach (bool fail in new[] { false, true })''')
(target / "Harness.template.cs.txt").write_text(harness, encoding="utf-8", newline="\n")
print(target)
