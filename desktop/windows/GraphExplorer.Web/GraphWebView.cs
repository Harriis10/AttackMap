using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using AttackMap.GraphExplorer;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Web.WebView2.Core;

namespace AttackMap.NativeSpike;

public sealed record WebGraphSelection(GraphContext Context, ImmutableArray<string> NodeIds,
    ImmutableArray<string> EdgeIds, ImmutableArray<string> EvidenceIds);
public sealed record WebGraphExportRequest(GraphContext Context, string Format, string CanonicalJson);

/// <summary>Isolated WinUI candidate. The owning window must call Stop on its UI thread.</summary>
public sealed class GraphWebView : UserControl
{
    private const string Origin = "https://attackmap-graph.invalid";
    private const int MaximumMessageCharacters = 8 * 1024 * 1024;
    private readonly Grid root = new();
    private readonly TextBlock notice = new() { Text = "Preparing offline graph surface…", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(12) };
    private readonly TextBox fallback = new() { Header = "Complete canonical graph — native fallback", IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.NoWrap, Visibility = Visibility.Collapsed };
    private readonly WebView2 browser = new();
    private readonly string assetDirectory;
    private readonly HashSet<string> allowedResources = new(StringComparer.Ordinal);
    private CoreWebView2? core;
    private CoreWebView2Environment? environment;
    private Task? initialization;
    private GraphDocument? document;
    private string? pageSession, contextToken;
    private string expectedPage = "";
    private long revision;
    private bool stopped, ready, awaitingReady, initialNavigationPermitted;
    public event Action<WebGraphSelection>? SelectionChanged;
    public event Action<WebGraphSelection>? EvidenceRequested;
    public event Action<WebGraphExportRequest>? ExportRequested;
    public event Action<string>? StatusChanged;
    /// <summary>Current-context page layout message acknowledgment only; not pixel/visual proof.</summary>
    public GraphContext? LayoutAcknowledgedContext { get; private set; }

    public GraphWebView(string? packagedAssetDirectory = null)
    {
        assetDirectory = Path.GetFullPath(packagedAssetDirectory ?? Path.Combine(AppContext.BaseDirectory, "GraphExplorer.Web"));
        root.RowDefinitions.Add(new() { Height = GridLength.Auto });
        root.RowDefinitions.Add(new() { Height = new GridLength(1, GridUnitType.Star) });
        root.Children.Add(notice); Grid.SetRow(browser, 1); root.Children.Add(browser);
        Grid.SetRow(fallback, 1); root.Children.Add(fallback); Content = root;
        Loaded += OnLoaded;
        ActualThemeChanged += OnThemeChanged;
    }

    public async Task LoadGraph(byte[] bytes, GraphContext context)
    {
        RequireUi(); if (stopped) return;
        ArgumentNullException.ThrowIfNull(bytes);
        long captured = ++revision;
        document = null; contextToken = null; LayoutAcknowledgedContext = null;
        if (ready) Post(new { protocol = 1, type = "clear", page_session = pageSession });
        fallback.Text = ""; SetStatus("Validating the selected graph; prior selection cleared.");
        try
        {
            if (bytes.Length > new GraphReadLimits().MaxBytes) throw new GraphReadException("Graph exceeds the native byte budget; select/export the original artifact.");
            var snapshot = bytes.ToArray();
            var parsed = await Task.Run(() => GraphReader.Read(snapshot, context));
            if (stopped || captured != revision) return;
            document = parsed; contextToken = Guid.NewGuid().ToString("N");
            fallback.Text = GraphExporter.CanonicalJson(parsed);
            if (parsed.UnknownEvidenceRefs.Length > 0)
            {
                ShowFallback("Graph has unresolved evidence IDs; canonical JSON remains available. Web candidate requires a closed evidence registry.");
                return;
            }
            if (IsLoaded) await EnsureInitialized();
            if (stopped || captured != revision) return;
            SendCurrent();
        }
        catch (Exception error)
        { if (!stopped && captured == revision) ShowFallback("Graph unavailable: " + error.Message); }
    }

    public void Clear()
    {
        RequireUi(); if (stopped) return;
        ++revision; document = null; contextToken = null; LayoutAcknowledgedContext = null; fallback.Text = "";
        if (ready) Post(new { protocol = 1, type = "clear", page_session = pageSession });
        SetStatus("No graph selected.");
    }

    public void Select(WebGraphSelection selection)
    {
        RequireUi();
        if (!ready || document?.Context != selection.Context || !KnownSelection(selection)) return;
        Post(new { protocol = 1, type = "select", page_session = pageSession, context = Envelope(), selection = new { node_ids = selection.NodeIds, edge_ids = selection.EdgeIds, evidence_ids = selection.EvidenceIds } });
    }

    private async void OnLoaded(object sender, RoutedEventArgs args)
    {
        long captured = revision;
        try { await EnsureInitialized(); if (!stopped && captured == revision) SendCurrent(); }
        catch (Exception error) { if (!stopped) ShowFallback("Offline graph runtime unavailable: " + error.Message); }
    }

    private Task EnsureInitialized() => initialization ??= Initialize();
    private async Task Initialize()
    {
        RequireUi(); if (stopped) return;
        VerifyAssets();
        var profile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AttackMap", "WebView2", "FleetGraph");
        environment = await CoreWebView2Environment.CreateWithOptionsAsync(null, profile, new CoreWebView2EnvironmentOptions());
        if (stopped) return;
        await browser.EnsureCoreWebView2Async(environment);
        if (stopped) return;
        core = browser.CoreWebView2;
        core.Settings.AreHostObjectsAllowed = false;
        core.Settings.AreDevToolsEnabled = false;
        core.Settings.AreDefaultContextMenusEnabled = false;
        core.Settings.AreDefaultScriptDialogsEnabled = false;
        core.Settings.AreBrowserAcceleratorKeysEnabled = false;
        core.Settings.IsStatusBarEnabled = false;
        core.Settings.IsPasswordAutosaveEnabled = false;
        core.Settings.IsGeneralAutofillEnabled = false;
        core.Settings.IsScriptEnabled = true;
        core.Settings.IsWebMessageEnabled = true;
        core.SetVirtualHostNameToFolderMapping("attackmap-graph.invalid", assetDirectory, CoreWebView2HostResourceAccessKind.DenyCors);
        core.NavigationStarting += OnNavigation;
        core.FrameNavigationStarting += OnFrameNavigation;
        core.NewWindowRequested += OnNewWindow;
        core.DownloadStarting += OnDownload;
        core.PermissionRequested += OnPermission;
        core.LaunchingExternalUriScheme += OnExternalScheme;
        core.ProcessFailed += OnProcessFailed;
        core.WebMessageReceived += OnMessage;
        core.AddWebResourceRequestedFilter("*", CoreWebView2WebResourceContext.All);
        core.WebResourceRequested += OnResource;
        expectedPage = Origin + "/index.html?navigation=" + Guid.NewGuid().ToString("N");
        awaitingReady = true; ready = false; pageSession = null; initialNavigationPermitted = true;
        core.Navigate(expectedPage);
    }

    private void VerifyAssets()
    {
        CheckRegularPath(assetDirectory);
        string manifestPath = Path.Combine(assetDirectory, "asset-manifest.json");
        CheckRegularPath(manifestPath);
        if (new FileInfo(manifestPath).Length > 256 * 1024) throw new IOException("Graph asset manifest exceeds its size limit.");
        byte[] manifestBytes = File.ReadAllBytes(manifestPath);
        CheckRegularPath(manifestPath);
        using var manifest = JsonDocument.Parse(manifestBytes);
        foreach (var item in manifest.RootElement.GetProperty("files").EnumerateArray())
        {
            string name = item.GetProperty("path").GetString() ?? "";
            if (name.Length == 0 || name.Contains('\\') || name.Split('/').Any(x => x is "" or "." or "..") || Path.IsPathRooted(name)) throw new IOException("Invalid graph asset path.");
            string path = Path.GetFullPath(Path.Combine(assetDirectory, name.Replace('/', Path.DirectorySeparatorChar)));
            if (!path.StartsWith(assetDirectory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Graph asset escaped package directory.");
            CheckRegularPath(path);
            var before = new FileInfo(path);
            long size = before.Length;
            var written = before.LastWriteTimeUtc;
            var created = before.CreationTimeUtc;
            if (size != item.GetProperty("bytes").GetInt64() || size > 8 * 1024 * 1024) throw new IOException("Graph asset size mismatch: " + name);
            string hash;
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                hash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            CheckRegularPath(path);
            var after = new FileInfo(path);
            if (after.Length != size || after.LastWriteTimeUtc != written || after.CreationTimeUtc != created) throw new IOException("Graph asset changed while reading: " + name);
            if (hash != item.GetProperty("sha256").GetString()) throw new IOException("Graph asset hash mismatch: " + name);
            allowedResources.Add("/" + name);
        }
        foreach (string required in new[] { "/index.html", "/app.js", "/projection.js", "/styles.css" })
            if (!allowedResources.Contains(required)) throw new IOException("Missing packaged graph asset: " + required);
    }

    private static void CheckRegularPath(string path)
    {
        for (var current = new FileInfo(path); current is not null; current = current.Directory is { } directory ? new FileInfo(directory.FullName) : null)
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Redirected graph asset paths are not allowed.");
    }

    private void OnNavigation(CoreWebView2 sender, CoreWebView2NavigationStartingEventArgs args)
    {
        if (stopped || !initialNavigationPermitted || !string.Equals(args.Uri, expectedPage, StringComparison.Ordinal)) { args.Cancel = true; return; }
        initialNavigationPermitted = false;
        ready = false; awaitingReady = true; pageSession = null; LayoutAcknowledgedContext = null;
    }
    private void OnFrameNavigation(CoreWebView2 sender, CoreWebView2NavigationStartingEventArgs args) => args.Cancel = true;
    private void OnNewWindow(CoreWebView2 sender, CoreWebView2NewWindowRequestedEventArgs args) => args.Handled = true;
    private void OnDownload(CoreWebView2 sender, CoreWebView2DownloadStartingEventArgs args) { args.Cancel = true; args.Handled = true; }
    private void OnPermission(CoreWebView2 sender, CoreWebView2PermissionRequestedEventArgs args) { args.State = CoreWebView2PermissionState.Deny; args.Handled = true; }
    private void OnExternalScheme(CoreWebView2 sender, CoreWebView2LaunchingExternalUriSchemeEventArgs args) => args.Cancel = true;
    private void OnProcessFailed(CoreWebView2 sender, CoreWebView2ProcessFailedEventArgs args) { ready = false; pageSession = null; LayoutAcknowledgedContext = null; if (!stopped) ShowFallback("Graph runtime failed; native canonical fallback retained."); }
    private void OnResource(CoreWebView2 sender, CoreWebView2WebResourceRequestedEventArgs args)
    {
        bool allowed = Uri.TryCreate(args.Request.Uri, UriKind.Absolute, out var uri)
            && uri.GetLeftPart(UriPartial.Authority) == Origin && uri.UserInfo.Length == 0 && uri.Fragment.Length == 0
            && allowedResources.Contains(uri.AbsolutePath)
            && (uri.Query.Length == 0 || args.Request.Uri == expectedPage);
        if (!allowed && environment is not null) args.Response = environment.CreateWebResourceResponse(null, 403, "Forbidden", "Content-Type: text/plain");
    }

    private void OnMessage(CoreWebView2 sender, CoreWebView2WebMessageReceivedEventArgs args)
    {
        if (stopped || args.Source != expectedPage || sender.Source != expectedPage) return;
        try
        {
            string json = args.WebMessageAsJson;
            if (json.Length > MaximumMessageCharacters) return;
            using var parsed = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
            var value = parsed.RootElement;
            if (value.ValueKind != JsonValueKind.Object || value.GetProperty("protocol").GetInt32() != 1) return;
            string? type = value.GetProperty("type").GetString(), session = value.GetProperty("page_session").GetString();
            if (string.IsNullOrEmpty(session) || session.Length > 128 || session.Any(char.IsControl)) return;
            if (type == "ready")
            {
                if (!awaitingReady || ready || pageSession is not null) return;
                pageSession = session; awaitingReady = false; ready = true; SendTheme(); SendCurrent(); return;
            }
            var current = document;
            if (!ready || session != pageSession || current is null || !MatchesContext(value.GetProperty("context"))) return;
            if (type is "select" or "openEvidence")
            {
                var selected = new WebGraphSelection(current.Context, Ids(value, "node_ids", current.Nodes.Select(x => x.Id)), Ids(value, "edge_ids", current.Edges.Select(x => x.Id)), Ids(value, "evidence_ids", current.Evidence.Select(x => x.Id)));
                if (!KnownSelection(selected)) return;
                long captured = revision;
                DispatcherQueue.TryEnqueue(() => { if (stopped || captured != revision || document?.Context != selected.Context) return; if (type == "select") SelectionChanged?.Invoke(selected); else EvidenceRequested?.Invoke(selected); });
            }
            else if (type == "export")
            {
                string? format = value.GetProperty("format").GetString();
                if (format == "png") { SetStatus("Native PNG export is not implemented. Use full JSON or the native SVG alternative."); return; }
                if (format != "json") return;
                // Only presentation metadata is accepted; canonical fields always come from the host document.
                string exported = WebGraphExportMetadata.Append(current,
                    value.TryGetProperty("metadata", out var metadata) ? metadata : null);
                long captured = revision;
                DispatcherQueue.TryEnqueue(() => { if (!stopped && captured == revision && document?.Context == current.Context) ExportRequested?.Invoke(new(current.Context, format, exported)); });
            }
            else if (type == "layoutState" && value.TryGetProperty("state", out var state) && state.ValueKind == JsonValueKind.String
                && state.GetString() is { } name && new[] { "rendered", "complete", "fallback", "text-fallback", "error", "cleared", "bounded-fallback" }.Contains(name, StringComparer.Ordinal))
            {
                if (name is "rendered" or "complete") LayoutAcknowledgedContext = current.Context;
                SetStatus("Offline graph: " + name);
            }
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or ArgumentException or FormatException or OverflowException) { /* Invalid page messages never dispatch host actions. */ }
    }

    private static ImmutableArray<string> Ids(JsonElement value, string property, IEnumerable<string> allowed)
    {
        var known = allowed.ToHashSet(StringComparer.Ordinal); var ids = value.GetProperty(property);
        if (ids.ValueKind != JsonValueKind.Array || ids.GetArrayLength() > known.Count) throw new JsonException("Invalid ID list.");
        return ids.EnumerateArray().Select(id => id.GetString() is { } text && known.Contains(text) ? text : throw new JsonException("Unknown canonical ID.")).Distinct(StringComparer.Ordinal).ToImmutableArray();
    }
    private bool KnownSelection(WebGraphSelection selected)
    {
        if (document is not { } current || selected.Context != current.Context || selected.NodeIds.Length + selected.EdgeIds.Length == 0) return false;
        var nodes = current.Nodes.ToDictionary(x => x.Id, StringComparer.Ordinal); var edges = current.Edges.ToDictionary(x => x.Id, StringComparer.Ordinal);
        if (selected.NodeIds.Any(id => !nodes.ContainsKey(id)) || selected.EdgeIds.Any(id => !edges.ContainsKey(id))) return false;
        var evidence = selected.NodeIds.SelectMany(id => nodes[id].EvidenceRefs).Concat(selected.EdgeIds.SelectMany(id => edges[id].EvidenceRefs)).ToHashSet(StringComparer.Ordinal);
        return selected.EvidenceIds.All(id => evidence.Contains(id) && current.Evidence.Any(item => item.Id == id));
    }
    private object Envelope() => new { token = contextToken, run_id = document!.Context.RunId, generation_id = document.Context.GenerationId, report_hash = document.Context.ReportHash, selection_revision = document.Context.SelectionRevision };
    private bool MatchesContext(JsonElement value) => document is { } current && value.ValueKind == JsonValueKind.Object && value.EnumerateObject().Count() == 5
        && value.GetProperty("token").GetString() == contextToken && value.GetProperty("run_id").GetString() == current.Context.RunId
        && value.GetProperty("generation_id").GetString() == current.Context.GenerationId && value.GetProperty("report_hash").GetString() == current.Context.ReportHash
        && value.GetProperty("selection_revision").GetInt64() == current.Context.SelectionRevision;
    private void SendCurrent()
    {
        if (stopped || !ready || document is null || document.UnknownEvidenceRefs.Length > 0) return;
        using var json = JsonDocument.Parse(document.SourceJson);
        Post(new { protocol = 1, type = "replaceGraph", page_session = pageSession, context = Envelope(), graph = json.RootElement });
        browser.Visibility = Visibility.Visible; fallback.Visibility = Visibility.Collapsed;
        SetStatus("Offline Cytoscape candidate · " + document.Repositories.Length + " repositories · " + GraphDocument.AggregatePathWarning);
    }
    private void OnThemeChanged(FrameworkElement sender, object args) => SendTheme();
    private void SendTheme() { if (ready) Post(new { protocol = 1, type = "theme", page_session = pageSession, theme = ActualTheme == ElementTheme.Dark ? "dark" : "light" }); }
    private void Post(object value) { if (!stopped && core is not null) core.PostWebMessageAsJson(JsonSerializer.Serialize(value)); }
    private void SetStatus(string message) { notice.Text = message; StatusChanged?.Invoke(message); }
    private void ShowFallback(string message) { browser.Visibility = Visibility.Collapsed; fallback.Visibility = Visibility.Visible; SetStatus(message); }
    private void RequireUi() { if (!DispatcherQueue.HasThreadAccess) throw new InvalidOperationException("Graph host calls require the owning WinUI thread."); }

    public void Stop()
    {
        RequireUi(); if (stopped) return;
        stopped = true; ++revision; ready = false; awaitingReady = false; contextToken = null; pageSession = null; document = null; LayoutAcknowledgedContext = null;
        Loaded -= OnLoaded; ActualThemeChanged -= OnThemeChanged;
        if (core is not null)
        {
            core.NavigationStarting -= OnNavigation; core.FrameNavigationStarting -= OnFrameNavigation;
            core.NewWindowRequested -= OnNewWindow; core.DownloadStarting -= OnDownload; core.PermissionRequested -= OnPermission;
            core.LaunchingExternalUriScheme -= OnExternalScheme; core.ProcessFailed -= OnProcessFailed; core.WebMessageReceived -= OnMessage;
            core.WebResourceRequested -= OnResource; core = null;
        }
        browser.Close();
    }
}

/// <summary>Canonical data is host-owned; UI-only metadata cannot replace graph facts or identity.</summary>
public static class WebGraphExportMetadata
{
    public const int MaximumMetadataCharacters = 64 * 1024;
    public static string Append(GraphDocument document, JsonElement? metadata = null)
    {
        var view = new Dictionary<string, object>(StringComparer.Ordinal);
        bool available = false;
        if (metadata is { } supplied)
        {
            if (supplied.ValueKind != JsonValueKind.Object || supplied.GetRawText().Length > MaximumMetadataCharacters)
                throw new JsonException("Export metadata exceeds its bounded object contract.");
            if (supplied.TryGetProperty("view", out var input))
            {
                if (input.ValueKind != JsonValueKind.Object) throw new JsonException("Invalid view metadata.");
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in input.EnumerateObject())
                {
                    if (!seen.Add(property.Name)) throw new JsonException("Duplicate view metadata field.");
                    switch (property.Name)
                    {
                        case "collapsed_ids":
                            var known = document.Nodes.Select(x => x.Id).ToHashSet(StringComparer.Ordinal);
                            if (property.Value.ValueKind != JsonValueKind.Array || property.Value.GetArrayLength() > known.Count)
                                throw new JsonException("Invalid collapsed ID list.");
                            var collapsed = new HashSet<string>(StringComparer.Ordinal);
                            foreach (var item in property.Value.EnumerateArray())
                                if (item.ValueKind != JsonValueKind.String || item.GetString() is not { } id || !known.Contains(id) || !collapsed.Add(id))
                                    throw new JsonException("Unknown or duplicate collapsed node ID.");
                            view[property.Name] = collapsed.Order(StringComparer.Ordinal).ToArray();
                            break;
                        case "query": view[property.Name] = Text(property.Value, 4096); break;
                        case "kind":
                            string kind = Text(property.Value, 128);
                            if (kind.Length > 0 && !document.Edges.Any(x => x.Kind == kind)) throw new JsonException("Unknown relation kind filter.");
                            view[property.Name] = kind;
                            break;
                        case "resolution":
                            string resolution = Text(property.Value, 128);
                            if (resolution.Length > 0 && !document.Edges.Any(x => x.Resolution == resolution)) throw new JsonException("Unknown resolution filter.");
                            view[property.Name] = resolution;
                            break;
                        case "inter_repo_only":
                            if (property.Value.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new JsonException("Invalid repository filter.");
                            view[property.Name] = property.Value.GetBoolean();
                            break;
                        case "neighborhood": view[property.Name] = Choice(property.Value, "all", "upstream", "downstream"); break;
                        case "layout": view["requested_layout"] = Choice(property.Value, "preset", "fcose"); break;
                        default: throw new JsonException("Unsupported view metadata field.");
                    }
                }
                available = true;
            }
        }
        using var canonical = JsonDocument.Parse(document.SourceJson);
        using var output = new MemoryStream();
        using (var writer = new Utf8JsonWriter(output, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            foreach (var property in canonical.RootElement.EnumerateObject())
                if (property.Name != "export_metadata") property.WriteTo(writer);
            writer.WritePropertyName("export_metadata");
            JsonSerializer.Serialize(writer, new {
                schema_version = "1.0",
                context = new { run_id = document.Context.RunId, generation_id = document.Context.GenerationId,
                    report_hash = document.Context.ReportHash, selection_revision = document.Context.SelectionRevision },
                canonical_counts = new { repositories = document.Repositories.Length, nodes = document.Nodes.Length,
                    edges = document.Edges.Length, evidence = document.Evidence.Length },
                scope = "Complete captured canonical graph; discovery coverage may be partial.",
                ui_state_available = available,
                ui_state_trust = "Untrusted presentation state only. Requested layout does not prove executed layout or connectivity.",
                ui_state = view
            });
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(output.ToArray());
    }
    private static string Text(JsonElement value, int maximum)
    {
        if (value.ValueKind != JsonValueKind.String || value.GetString() is not { } text || text.Length > maximum || text.Any(char.IsControl))
            throw new JsonException("Invalid bounded view text.");
        return text;
    }
    private static string Choice(JsonElement value, params string[] allowed)
    {
        string text = Text(value, 32);
        return allowed.Contains(text, StringComparer.Ordinal) ? text : throw new JsonException("Unsupported view choice.");
    }
}
