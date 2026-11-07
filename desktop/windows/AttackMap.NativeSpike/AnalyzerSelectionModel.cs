using System.Text.Json;
using System.Text.RegularExpressions;
namespace AttackMap.NativeSpike;

public sealed record AnalyzerSelectionItem(string Name, string DisplayName, bool Experimental, bool? EnabledByDefault, bool Missing, bool Selected, string? Error)
{
    public string? OriginSummary { get; init; }
    public string? ImplementationSummary { get; init; }
    public string? ShadowedSummary { get; init; }
    public string Status => Missing ? "Missing from selected engine" : Error != null ? "Analyzer error" : Experimental ? (EnabledByDefault == false ? "Experimental · Opt-in" : "Experimental") : EnabledByDefault == false ? "Opt-in" : EnabledByDefault == true ? "Available · Automatic eligible (detection still applies)" : "Available · default eligibility unknown";
}

public sealed record AnalyzerSelectionProfile(string QualifiedName, string Name, string DisplayName, string Version,
    bool Automatic, IReadOnlyList<string> ModuleNames, IReadOnlyList<string> MissingModuleNames,
    IReadOnlyList<string> ExperimentalModuleNames, IReadOnlyList<string> OptInModuleNames)
{
    public bool Available => MissingModuleNames.Count == 0;
    public string Status => Available ? "Available; detection still applies" : "Missing: " + string.Join(", ", MissingModuleNames);
}

public sealed record AnalyzerRunDisplayItem(string Name, string Version, string Origin, string Selection,
    string Applicability, string Execution, string AnalysisStarted, string? SkipReason, string? Error, string ImplementationIdentity)
{
    public double? DetectDurationMs { get; init; }
    public double? AnalysisDurationMs { get; init; }
    public string SignalSummary { get; init; } = "Extraction counts were not recorded.";
    public IReadOnlyList<string> Lifecycle { get; init; } = Array.Empty<string>();
    public string TimingSummary => $"Detection: {Duration(DetectDurationMs)} · analysis/host wait: {Duration(AnalysisDurationMs)}";
    private static string Duration(double? milliseconds) => milliseconds is double value ? $"{value:0.###} ms" : "not recorded";
    public string Status => $"Selection: {Selection} · applicability: {Applicability} · execution: {Execution} · analysis started: {AnalysisStarted}" +
        (SkipReason == null ? "" : " · skip reason: " + SkipReason) + (Error == null ? "" : " · error: " + Error);
}

public sealed record AnalyzerDiscoveryIssue(string Name, string Package, string Status, string Stage, string? ErrorType)
{
    public string Reason => Status switch
    {
        "load_error" => "Load failed", "initialization_error" => "Initialization failed",
        "metadata_error" => "Metadata invalid", "contract_error" => "Analyzer contract invalid",
        "skipped_policy" => "Skipped by trusted analyzer policy", "entry_points_error" => "Entry point discovery failed",
        _ => "Discovery unavailable"
    };
    public string Summary => Name + " · " + Package + " · " + Reason +
        (ErrorType == null ? "" : " · " + Stage + "/" + ErrorType);
}

/// <summary>Installed discovery inventory, not repository applicability. No install or discovery side effects.</summary>
public sealed class AnalyzerSelectionModel
{
    private Dictionary<string, AnalyzerSelectionItem> installed = new(StringComparer.Ordinal);
    private readonly HashSet<string> selected = new(StringComparer.Ordinal);
    private Dictionary<string, string> errors = new(StringComparer.Ordinal);
    private Dictionary<string, AnalyzerSelectionProfile> profiles = new(StringComparer.Ordinal);
    private string[]? restoredProfileModules;
    public IReadOnlyList<AnalyzerRunDisplayItem> RunLedgerRows { get; private set; } = Array.Empty<AnalyzerRunDisplayItem>();
    public string RunLedgerLabel { get; private set; } = "No selected report";
    public string RunLedgerNotice { get; private set; } = "Analyzer execution is unknown until a selected report supplies a compatible run ledger.";
    public IReadOnlyList<AnalyzerDiscoveryIssue> DiscoveryIssues { get; private set; } = Array.Empty<AnalyzerDiscoveryIssue>();
    public bool Automatic { get; private set; } = true;
    public string? DiscoveryError { get; private set; } = "Analyzer discovery has not been loaded.";
    public string? SelectedProfile { get; private set; }
    public string? RequestProfile => SelectedProfile;
    public string ExpandedProfileModules => SelectedProfile == null ? "" : string.Join(",", restoredProfileModules ?? selected.Order(StringComparer.Ordinal).ToArray());
    public string? ProfileSelectionError { get; private set; }
    public string? ProfileCatalogError { get; private set; }
    public string? CatalogError { get; private set; }
    public IReadOnlyList<AnalyzerSelectionProfile> Profiles => profiles.Values.OrderBy(item => item.Automatic ? 0 : 1).ThenBy(item => item.DisplayName, StringComparer.Ordinal).ToArray();
    public string RequestModules => Automatic || SelectedProfile != null ? "" : string.Join(",", selected.Order(StringComparer.Ordinal));
    public void SetAutomatic(bool value)
    {
        Automatic = value; SelectedProfile = null; restoredProfileModules = null; ProfileSelectionError = null;
    }
    public void Restore(string modules)
    {
        var names = ParseNames(modules); SetAutomatic(names.Length == 0); selected.Clear(); selected.UnionWith(names);
    }
    public void RestoreProfile(string qualifiedName, string savedExpandedModules)
    {
        ValidateProfileIdentity(qualifiedName);
        var names = ParseNames(savedExpandedModules);
        SelectedProfile = qualifiedName; Automatic = false; restoredProfileModules = names;
        selected.Clear(); selected.UnionWith(names); ReconcileProfile();
    }
    public void SelectProfile(string qualifiedName)
    {
        ValidateProfileIdentity(qualifiedName);
        if (profiles.TryGetValue(qualifiedName, out var profile) && profile.Automatic)
        { SetAutomatic(true); return; }
        SelectedProfile = qualifiedName; Automatic = false;
        restoredProfileModules = profile?.ModuleNames.ToArray();
        selected.Clear(); if (restoredProfileModules != null) selected.UnionWith(restoredProfileModules);
        ReconcileProfile();
    }
    public void Select(string name, bool value)
    {
        if (ParseNames(name) is not [var parsed] || parsed != name) throw new InvalidDataException("One analyzer name required.");
        if (value && selected.Count >= 32 && !selected.Contains(name)) throw new InvalidDataException("Select at most 32 analyzers.");
        SetAutomatic(false);
        if (value) selected.Add(name); else selected.Remove(name);
    }
    public void LoadDiscovery(string json)
    {
        DiscoveryIssues = Array.Empty<AnalyzerDiscoveryIssue>();
        try
        {
            if (System.Text.Encoding.UTF8.GetByteCount(json) > 4 * 1024 * 1024) throw new InvalidDataException();
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 32 }); var root = document.RootElement;
            if (root.GetProperty("schema").GetInt32() != 1) throw new InvalidDataException();
            var modules = root.GetProperty("modules"); if (modules.ValueKind != JsonValueKind.Array || modules.GetArrayLength() > 1024) throw new InvalidDataException();
            var next = new Dictionary<string, AnalyzerSelectionItem>(StringComparer.Ordinal);
            foreach (var item in modules.EnumerateArray())
            {
                string name = item.GetProperty("name").GetString() ?? throw new InvalidDataException(); if (ParseNames(name) is not [var parsed] || parsed != name) throw new InvalidDataException();
                string display = item.TryGetProperty("display_name", out var title) ? title.GetString() ?? name : name;
                if (display.Length > 2048) throw new InvalidDataException();
                bool experimental = item.TryGetProperty("experimental", out var exp) && exp.GetBoolean();
                bool? enabled = item.TryGetProperty("enabled_by_default", out var def) ? def.GetBoolean() : null;
                if (!next.TryAdd(name, new(name, display, experimental, enabled, false, false, null))) throw new InvalidDataException();
            }
            installed = next; errors.Clear(); DiscoveryError = null;
            profiles.Clear(); ProfileCatalogError = null; CatalogError = null;
            if (root.TryGetProperty("analyzer_profiles", out var profileCatalog))
            {
                try { profiles = ParseProfiles(profileCatalog, installed); }
                catch (Exception error) when (InvalidJson(error))
                { ProfileCatalogError = "Versioned analyzer profiles are unavailable or incompatible. Automatic and Custom remain available; saved named profiles remain blocked."; }
            }
            if (root.TryGetProperty("analyzer_catalog", out var catalog))
            {
                try { ApplyCatalog(catalog); }
                catch (Exception error) when (InvalidJson(error))
                { CatalogError = "Implementation provenance is unavailable or incompatible. Installed inventory does not establish origin or execution."; }
            }
            ReconcileProfile();
        }
        catch (Exception error) when (InvalidJson(error))
        { installed.Clear(); profiles.Clear(); errors.Clear(); ProfileCatalogError = null; CatalogError = null; DiscoveryError = "Analyzer discovery unavailable or incompatible. Saved selections retained; retry explicit discovery. Nothing was installed."; ReconcileProfile(); }
    }
    public void EngineChanged()
    {
        DiscoveryIssues = Array.Empty<AnalyzerDiscoveryIssue>();
        installed.Clear(); profiles.Clear(); errors.Clear(); ProfileCatalogError = null; CatalogError = null;
        DiscoveryError = "Engine changed; refresh analyzer discovery before scanning. Saved selections retained."; ReconcileProfile();
    }
    public void SetAnalyzerErrors(IReadOnlyDictionary<string, string> values)
    {
        if (values.Count > 1024) throw new InvalidDataException("Too many analyzer errors.");
        errors = values.ToDictionary(item => item.Key, item => item.Value.Length <= 2048 ? item.Value : item.Value[..2048] + "…", StringComparer.Ordinal);
    }
    /// <summary>Report-bound observations; never joined to the current engine inventory by name.</summary>
    public void SetRunLedger(JsonElement? ledger, string label)
    {
        RunLedgerRows = Array.Empty<AnalyzerRunDisplayItem>();
        RunLedgerLabel = label.Length <= 2048 && !label.Any(char.IsControl) ? label : "Selected report";
        RunLedgerNotice = "This report has no analyzer run ledger. Applicability and execution are unknown; installed inventory is separate.";
        if (ledger is not { } root || root.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined) return;
        try
        {
            string schema = Text(root, "schema_version", 16);
            if (System.Text.Encoding.UTF8.GetByteCount(root.GetRawText()) > 2 * 1024 * 1024 || schema is not ("1.0" or "1.1") ||
                Text(root, "scope", 64) != "analyzer_selection_and_execution") throw new InvalidDataException();
            string inventoryScope = EnumText(root, "inventory_scope", "registered_candidates", "supplied_candidates");
            string mode = EnumText(root, "selection_mode", "automatic", "explicit");
            string? profileId = OptionalText(root, "profile_id", 192); if (profileId != null) ValidateProfileIdentity(profileId);
            bool resolved = root.GetProperty("resolution_complete").GetBoolean(), complete = root.GetProperty("execution_complete").GetBoolean();
            var entries = root.GetProperty("entries");
            if (entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() > 1024) throw new InvalidDataException();
            var rows = new List<AnalyzerRunDisplayItem>();
            foreach (var entry in entries.EnumerateArray())
            {
                string name = Text(entry, "name", 128); if (ParseNames(name) is not [var parsed] || name != parsed) throw new InvalidDataException();
                string version = OptionalText(entry, "version", 128) ?? "version unknown", origin = EnumText(entry, "origin", "builtin", "plugin", "supplied");
                string selection = EnumText(entry, "selection", "selected", "skipped"), applicability = EnumText(entry, "applicability", "applicable", "unmatched", "detect_error", "not_evaluated");
                string execution = EnumText(entry, "execution", "not_started", "succeeded", "failed", "skipped");
                var started = entry.GetProperty("analysis_started");
                string analysisStarted = started.ValueKind == JsonValueKind.Null ? "unknown" : started.GetBoolean() ? "yes" : "no";
                string? executionMode = OptionalEnumText(entry, "execution_mode", "in_process", "isolated");
                string? reason = OptionalEnumText(entry, "skip_reason", "unmatched", "detect_error", "opt_in", "pipeline_deadline");
                if (execution == "succeeded" && (selection != "selected" || applicability != "applicable" || analysisStarted != "yes")) throw new InvalidDataException();
                string identity = Text(entry, "implementation_sha256", 64); if (!Regex.IsMatch(identity, "^[a-fA-F0-9]{64}$")) throw new InvalidDataException();
                string? error = null;
                if (entry.TryGetProperty("error", out var failure) && failure.ValueKind != JsonValueKind.Null)
                {
                    string stage = EnumText(failure, "stage", "detect", "analysis", "isolated_host", "captured_input"), type = Text(failure, "error_type", 80);
                    if (!Regex.IsMatch(type, "^[A-Za-z_][A-Za-z0-9_]{0,79}$")) throw new InvalidDataException();
                    error = stage + "/" + type;
                }
                var row = new AnalyzerRunDisplayItem(name, version, origin + (executionMode == null ? "" : " · " + executionMode), selection, applicability, execution, analysisStarted, reason, error, identity);
                if (schema == "1.1")
                {
                    double? detectMs = OptionalDuration(entry.GetProperty("detect_duration_ms"));
                    double? analysisMs = OptionalDuration(entry.GetProperty("analysis_duration_ms"));
                    string signals = "Extraction counts were not recorded.";
                    var counts = entry.GetProperty("signal_counts");
                    if (counts.ValueKind != JsonValueKind.Null)
                    {
                        if (counts.ValueKind != JsonValueKind.Object || counts.EnumerateObject().Count() > 5) throw new InvalidDataException();
                        var parts = new List<string>();
                        foreach (string key in new[] { "routes", "external_calls", "databases", "auth_hints", "secret_hints" })
                        {
                            long count = counts.GetProperty(key).GetInt64(); if (count < 0) throw new InvalidDataException();
                            parts.Add(key.Replace('_', ' ') + ": " + count);
                        }
                        signals = "Extracted before merge · " + string.Join(" · ", parts);
                    }
                    var events = entry.GetProperty("lifecycle_events");
                    if (events.ValueKind != JsonValueKind.Array || events.GetArrayLength() > 32) throw new InvalidDataException();
                    var lifecycle = new List<string>(); double previous = -1;
                    foreach (var item in events.EnumerateArray())
                    {
                        string stage = EnumText(item, "stage", "detect", "selection", "analysis");
                        string state = EnumText(item, "state", "started", "requested", "applicable", "unmatched", "detect_error", "selected", "skipped", "succeeded", "failed");
                        double elapsed = OptionalDuration(item.GetProperty("elapsed_ms")) ?? throw new InvalidDataException();
                        if (elapsed < previous) throw new InvalidDataException(); previous = elapsed;
                        string? errorType = OptionalText(item, "error_type", 80);
                        if (errorType != null && !Regex.IsMatch(errorType, "^[A-Za-z_][A-Za-z0-9_]{0,79}$")) throw new InvalidDataException();
                        lifecycle.Add($"+{elapsed:0.###} ms · {stage}: {state}" + (errorType == null ? "" : " · " + errorType));
                    }
                    row = row with { DetectDurationMs = detectMs, AnalysisDurationMs = analysisMs, SignalSummary = signals, Lifecycle = lifecycle.AsReadOnly() };
                }
                rows.Add(row);
            }
            RunLedgerRows = rows.AsReadOnly();
            RunLedgerNotice = $"Recorded selection: {profileId ?? mode} · {inventoryScope}. Resolution {(resolved ? "complete" : "incomplete")}; terminal outcomes {(complete ? "recorded" : "incomplete")}. " +
                $"{rows.Count(item => item.Execution == "succeeded")} succeeded, {rows.Count(item => item.Execution == "failed")} failed, {rows.Count(item => item.Execution == "skipped")} skipped, {rows.Count(item => item.Execution == "not_started")} not started. " +
                "Completion can include failures/skips and does not prove full coverage. Recorded implementations are independent of current installed inventory.";
        }
        catch (Exception error) when (InvalidJson(error))
        { RunLedgerRows = Array.Empty<AnalyzerRunDisplayItem>(); RunLedgerNotice = "Analyzer run ledger is unavailable or incompatible. Applicability and execution are unknown for this report."; }
    }
    private static double? OptionalDuration(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetDouble(out double number) || !double.IsFinite(number) || number < 0)
            throw new InvalidDataException();
        return number;
    }
    public IReadOnlyList<AnalyzerSelectionItem> Rows(string filter = "")
    {
        filter = filter.Trim();
        return installed.Values.Select(item => item with { Selected = selected.Contains(item.Name), Error = errors.GetValueOrDefault(item.Name) })
            .Concat(selected.Where(name => !installed.ContainsKey(name)).Select(name => new AnalyzerSelectionItem(name, name, false, null, true, true, null)))
            .Where(item => item.Missing || filter.Length == 0 || item.Name.Contains(filter, StringComparison.OrdinalIgnoreCase) || item.DisplayName.Contains(filter, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(item => item.Missing).ThenBy(item => item.Name, StringComparer.Ordinal).ToArray();
    }
    public void ValidateForScan()
    {
        if (DiscoveryError != null) throw new InvalidDataException(DiscoveryError);
        if (SelectedProfile != null && ProfileSelectionError != null) throw new InvalidDataException(ProfileSelectionError);
        if (!Automatic && selected.Any(name => !installed.ContainsKey(name))) throw new InvalidDataException("Selected analyzers are missing. Retain or explicitly remove them; no substitute or installation was performed.");
        if (!Automatic && selected.Count == 0) throw new InvalidDataException("Select an analyzer or choose Automatic.");
    }
    private void ReconcileProfile()
    {
        ProfileSelectionError = null;
        if (SelectedProfile == null) return;
        if (DiscoveryError != null) { ProfileSelectionError = DiscoveryError; return; }
        if (ProfileCatalogError != null) { ProfileSelectionError = ProfileCatalogError; return; }
        if (!profiles.TryGetValue(SelectedProfile, out var profile))
        { ProfileSelectionError = $"Saved profile {SelectedProfile} is unavailable in this engine. Choose a profile or explicitly switch to Custom or Automatic."; return; }
        if (profile.Automatic)
        {
            if (restoredProfileModules is not { Length: 0 })
            { ProfileSelectionError = "Saved Automatic profile expansion is invalid. Choose Automatic explicitly."; return; }
            SetAutomatic(true); return;
        }
        if (restoredProfileModules == null || restoredProfileModules.Length == 0 || !SameNames(restoredProfileModules, profile.ModuleNames))
        { ProfileSelectionError = $"Saved expansion for {SelectedProfile} is stale or missing. Select the profile again to accept its displayed module list."; return; }
        if (!profile.Available)
        { ProfileSelectionError = $"Profile {SelectedProfile} requires missing modules: {string.Join(", ", profile.MissingModuleNames)}. No substitution or installation was performed."; return; }
        selected.Clear(); selected.UnionWith(profile.ModuleNames);
    }
    private static Dictionary<string, AnalyzerSelectionProfile> ParseProfiles(JsonElement catalog, IReadOnlyDictionary<string, AnalyzerSelectionItem> installed)
    {
        if (catalog.GetProperty("schema_version").GetString() != "1.0") throw new InvalidDataException();
        var entries = catalog.GetProperty("profiles");
        if (entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() > 64) throw new InvalidDataException();
        var result = new Dictionary<string, AnalyzerSelectionProfile>(StringComparer.Ordinal);
        foreach (var entry in entries.EnumerateArray())
        {
            string name = Text(entry, "name", 128), version = Text(entry, "version", 32);
            string qualifiedName = Text(entry, "qualified_name", 192); ValidateProfileIdentity(qualifiedName);
            if (qualifiedName != name + "@" + version) throw new InvalidDataException();
            string displayName = Text(entry, "display_name", 512), mode = Text(entry, "selection_mode", 32);
            bool automatic = name == "automatic";
            if (mode != (automatic ? "automatic" : "explicit")) throw new InvalidDataException();
            string[] modules = JsonNames(entry, "module_names"), missing = JsonNames(entry, "missing_module_names");
            if (automatic != (modules.Length == 0)) throw new InvalidDataException();
            if (!SameNames(missing, modules.Where(module => !installed.ContainsKey(module)))) throw new InvalidDataException();
            if (entry.GetProperty("available").GetBoolean() != (missing.Length == 0)) throw new InvalidDataException();
            string[] expanded = JsonNames(entry, "expanded_module_names", automatic ? 1024 : 32);
            var candidates = automatic ? installed.Values.Where(item => item.EnabledByDefault == true) : installed.Values.Where(item => modules.Contains(item.Name, StringComparer.Ordinal));
            if (!SameNames(expanded, automatic ? candidates.Select(item => item.Name) : modules)) throw new InvalidDataException();
            string[] experimental = JsonNames(entry, "installed_experimental_module_names", automatic ? 1024 : 32), optIn = JsonNames(entry, "opt_in_module_names", automatic ? 1024 : 32);
            if (!SameNames(experimental, candidates.Where(item => item.Experimental).Select(item => item.Name)) ||
                !SameNames(optIn, candidates.Where(item => item.EnabledByDefault == false).Select(item => item.Name))) throw new InvalidDataException();
            string[] declaredExperimental = JsonNames(entry, "experimental_module_names");
            if (declaredExperimental.Any(module => !modules.Contains(module, StringComparer.Ordinal))) throw new InvalidDataException();
            if (!result.TryAdd(qualifiedName, new(qualifiedName, name, displayName, version, automatic,
                Array.AsReadOnly(modules), Array.AsReadOnly(missing), Array.AsReadOnly(experimental), Array.AsReadOnly(optIn)))) throw new InvalidDataException();
        }
        return result;
    }
    private void ApplyCatalog(JsonElement catalog)
    {
        if (catalog.GetProperty("schema").GetInt32() != 1 || catalog.GetProperty("scope").GetString() != "installed_discovery") throw new InvalidDataException();
        var candidates = catalog.GetProperty("candidates");
        if (candidates.ValueKind != JsonValueKind.Array || candidates.GetArrayLength() > 2048) throw new InvalidDataException();
        var effective = new Dictionary<string, (string Id, string Origin, string? Implementation)>(StringComparer.Ordinal);
        var shadowed = new Dictionary<string, List<(string Id, string Label)>>(StringComparer.Ordinal);
        var issues = new List<AnalyzerDiscoveryIssue>();
        foreach (var entry in candidates.EnumerateArray())
        {
            string status = Text(entry, "status", 64);
            if (status is "load_error" or "initialization_error" or "metadata_error" or "contract_error" or "skipped_policy")
            {
                string issueName = DiscoveryLabel(entry, "name", 128, "Analyzer name unavailable");
                string issuePackage = DiscoveryLabel(entry.GetProperty("package"), "name", 256, "package unknown");
                string stage = "policy"; string? errorType = null;
                if (status != "skipped_policy")
                {
                    var failure = entry.GetProperty("error");
                    stage = EnumText(failure, "stage", "load", "initialization", "metadata", "contract");
                    if (status != stage + "_error") throw new InvalidDataException();
                    errorType = DiscoveryErrorType(failure);
                }
                issues.Add(new(issueName, issuePackage, status, stage, errorType));
                continue;
            }
            if (status is not ("effective" or "shadowed")) continue;
            string name = Text(entry, "name", 128); if (ParseNames(name) is not [var parsed] || parsed != name) throw new InvalidDataException();
            string origin = Text(entry, "origin", 32); if (origin is not ("builtin" or "plugin")) throw new InvalidDataException();
            var package = entry.GetProperty("package");
            string packageName = OptionalText(package, "name", 256) ?? "package unknown", packageVersion = OptionalText(package, "version", 128) ?? "version unknown";
            string analyzerVersion = Text(entry.GetProperty("metadata"), "version", 128);
            string label = $"{(origin == "builtin" ? "Built-in" : "Plugin")} · {packageName} {packageVersion} · analyzer {analyzerVersion}";
            if (status == "effective")
            {
                if (!installed.ContainsKey(name)) throw new InvalidDataException();
                string id = Text(entry, "candidate_id", 512);
                var implementation = entry.GetProperty("implementation");
                string? module = OptionalText(implementation, "module", 512), type = OptionalText(implementation, "qualname", 512);
                string? sourceHash = OptionalText(implementation, "source_sha256", 64);
                if (sourceHash != null && !Regex.IsMatch(sourceHash, "^[a-fA-F0-9]{64}$")) throw new InvalidDataException();
                string? implementationLabel = module == null ? null : "Implementation: " + module + (type == null ? "" : "." + type);
                if (sourceHash != null) implementationLabel += " · source SHA-256 " + sourceHash;
                if (!effective.TryAdd(name, (id, label, implementationLabel))) throw new InvalidDataException();
            }
            else
            {
                string id = Text(entry, "shadowed_by", 512);
                if (!shadowed.TryGetValue(name, out var records)) shadowed[name] = records = [];
                if (records.Count >= 32) throw new InvalidDataException();
                records.Add((id, label));
            }
        }
        foreach (var (name, records) in shadowed)
            if (!effective.TryGetValue(name, out var winner) || records.Any(record => record.Id != winner.Id)) throw new InvalidDataException();
        if (catalog.TryGetProperty("discovery_errors", out var discoveryErrors))
        {
            if (discoveryErrors.ValueKind != JsonValueKind.Array || discoveryErrors.GetArrayLength() > 64) throw new InvalidDataException();
            foreach (var failure in discoveryErrors.EnumerateArray())
            {
                string stage = EnumText(failure, "stage", "entry_points");
                issues.Add(new("Entry point inventory", "package unknown", "entry_points_error", stage, DiscoveryErrorType(failure)));
            }
        }
        // Commit only after the optional catalog has passed all validation.
        foreach (var (name, record) in effective)
            installed[name] = installed[name] with { OriginSummary = record.Origin, ImplementationSummary = record.Implementation,
                ShadowedSummary = shadowed.TryGetValue(name, out var records) ? "Shadowed implementations (not selected): " + string.Join("; ", records.Select(item => item.Label)) : null };
        DiscoveryIssues = issues.AsReadOnly();
    }
    private static string DiscoveryLabel(JsonElement element, string property, int limit, string fallback)
    {
        string? value = OptionalText(element, property, limit);
        return value != null && Regex.IsMatch(value, "^[A-Za-z0-9][A-Za-z0-9_.-]*$") ? value : fallback;
    }
    private static string? DiscoveryErrorType(JsonElement failure)
    {
        string? value = OptionalText(failure, "error_type", 80);
        if (value != null && !Regex.IsMatch(value, "^[A-Za-z_][A-Za-z0-9_]{0,79}$")) throw new InvalidDataException();
        return value;
    }
    private static string Text(JsonElement element, string name, int limit)
    {
        var value = element.GetProperty(name); string text = value.GetString() ?? throw new InvalidDataException();
        if (text.Length == 0 || text.Length > limit || text.Any(char.IsControl)) throw new InvalidDataException();
        return text;
    }
    private static string? OptionalText(JsonElement element, string name, int limit) => !element.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null ? null : Text(element, name, limit);
    private static string EnumText(JsonElement element, string name, params string[] allowed)
    {
        string value = Text(element, name, 64); if (!allowed.Contains(value, StringComparer.Ordinal)) throw new InvalidDataException(); return value;
    }
    private static string? OptionalEnumText(JsonElement element, string name, params string[] allowed) => OptionalText(element, name, 64) is { } value ? allowed.Contains(value, StringComparer.Ordinal) ? value : throw new InvalidDataException() : null;
    private static string[] JsonNames(JsonElement element, string name, int limit = 32)
    {
        var values = element.GetProperty(name);
        if (values.ValueKind != JsonValueKind.Array || values.GetArrayLength() > limit) throw new InvalidDataException();
        var names = values.EnumerateArray().Select(value => value.GetString() ?? throw new InvalidDataException()).ToArray();
        if (names.Any(value => ParseNames(value) is not [var parsed] || value != parsed) || names.Distinct(StringComparer.Ordinal).Count() != names.Length) throw new InvalidDataException();
        return names;
    }
    private static bool SameNames(IEnumerable<string> left, IEnumerable<string> right) => new HashSet<string>(left, StringComparer.Ordinal).SetEquals(right);
    private static void ValidateProfileIdentity(string name)
    {
        if (name.Length > 192 || !Regex.IsMatch(name, "^[a-z0-9][a-z0-9-]{0,127}@[0-9]{1,4}\\.[0-9]{1,4}(?:\\.[0-9]{1,4})?$")) throw new InvalidDataException("A qualified analyzer profile name and version are required.");
    }
    private static bool InvalidJson(Exception error) => error is JsonException or InvalidOperationException or KeyNotFoundException or InvalidDataException or FormatException;
    private static string[] ParseNames(string text)
    {
        if (text.Length > 4096) throw new InvalidDataException("Analyzer selection too long.");
        var names = text.Split(new[] { ',', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.Ordinal).ToArray();
        if (names.Length > 32 || names.Any(name => !Regex.IsMatch(name, "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"))) throw new InvalidDataException("Invalid analyzer name.");
        return names;
    }
}


