using System;
using System.IO;
using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;

namespace AttackMap.NativeSpike;

public sealed record SuppressionActionRequest(string Operation, object Payload);

/// <summary>A reviewed configuration action; process dispatch belongs to the host.</summary>
public sealed class SuppressionPanel : UserControl
{
    public event Action<SuppressionActionRequest>? ActionRequested;
    public string StatusMessage => status.Text;
    public bool HasUndoPlan => receipt.ValueKind == JsonValueKind.Object || plan.ValueKind == JsonValueKind.Object;
    private readonly TextBlock context = new() { TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock status = new() { TextWrapping = TextWrapping.Wrap, Text = "Select a finding to review a suppression." };
    private readonly TextBox reason = new() { Header = "Reason (required)", AcceptsReturn = true, Height = 76, TextWrapping = TextWrapping.Wrap };
    private readonly TextBox owner = new() { Header = "Owner (optional)" };
    private readonly TextBox ticket = new() { Header = "Ticket (optional)" };
    private readonly TextBox expires = new() { Header = "Expires (optional, YYYY-MM-DD)" };
    private readonly CheckBox legacy = new() { Content = "I reviewed the legacy finding identity and proposed mapping" };
    private readonly TextBox preview = new() { Header = "Proposed suppression file change", IsReadOnly = true, AcceptsReturn = true, Height = 140, TextWrapping = TextWrapping.NoWrap };
    private readonly Button previewButton = new() { Content = "Preview" };
    private readonly Button applyButton = new() { Content = "Apply reviewed" };
    private readonly Button undoButton = new() { Content = "Undo last change" };
    private string repoRoot = "", reportRunId = "", lastOperation = "";
    private JsonElement finding, plan, receipt;
    private bool busy;

    public SuppressionPanel()
    {
        var stack = new StackPanel { Spacing = 12, MaxWidth = 900, HorizontalAlignment = HorizontalAlignment.Stretch };
        foreach (var text in new[] { context, status }) text.FontSize = 14;
        foreach (var field in new[] { reason, owner, ticket, expires, preview }) field.FontSize = 14;
        stack.Children.Add(new TextBlock { Text = "Reasoned suppression", FontSize = 20, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
        stack.Children.Add(context);
        stack.Children.Add(new TextBlock { Text = "Record why this finding is accepted. Preview before applying; rescan to refresh results.", FontSize = 14, TextWrapping = TextWrapping.Wrap });
        stack.Children.Add(reason);
        var governance = new Grid { ColumnSpacing = 8 };
        governance.ColumnDefinitions.Add(new ColumnDefinition());
        governance.ColumnDefinitions.Add(new ColumnDefinition());
        governance.ColumnDefinitions.Add(new ColumnDefinition());
        governance.Children.Add(owner); Grid.SetColumn(ticket, 1); governance.Children.Add(ticket);
        Grid.SetColumn(expires, 2); governance.Children.Add(expires);
        stack.Children.Add(new Expander { Header = "Optional governance and identity", HorizontalAlignment = HorizontalAlignment.Stretch,
            Content = new StackPanel { Spacing = 8, Children = { governance, legacy,
                new TextBlock { Text = "Exact IDs cover the rule/entity aggregate and its instances. Suppression retains evidence. Review legacy mapping before applying.", FontSize = 14, TextWrapping = TextWrapping.Wrap } } } });
        stack.Children.Add(preview);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        buttons.Children.Add(previewButton); buttons.Children.Add(applyButton); buttons.Children.Add(undoButton);
        stack.Children.Add(buttons);
        stack.Children.Add(status);
        Content = stack;
        AutomationProperties.SetName(this, "Finding suppression actions");
        AutomationProperties.SetName(preview, "Read-only suppression change preview");
        AutomationProperties.SetLiveSetting(status, AutomationLiveSetting.Polite);
        previewButton.Click += (_, _) => RequestPreview();
        applyButton.Click += (_, _) => Dispatch("suppression_apply", new { plan });
        undoButton.Click += (_, _) =>
        {
            if (receipt.ValueKind == JsonValueKind.Object) Dispatch("suppression_undo", new { receipt });
            else if (plan.ValueKind == JsonValueKind.Object) Dispatch("suppression_undo", new { plan });
        };
        reason.TextChanged += (_, _) => InvalidatePreview();
        owner.TextChanged += (_, _) => InvalidatePreview();
        ticket.TextChanged += (_, _) => InvalidatePreview();
        expires.TextChanged += (_, _) => InvalidatePreview();
        legacy.Checked += (_, _) => InvalidatePreview();
        legacy.Unchecked += (_, _) => InvalidatePreview();
        UpdateEnabled();
    }

    public void SetContext(string repoRoot, JsonElement finding, string reportRunId)
    {
        string next = finding.ValueKind == JsonValueKind.Object ? finding.GetRawText() : "";
        string previous = this.finding.ValueKind == JsonValueKind.Object ? this.finding.GetRawText() : "";
        if (this.repoRoot == repoRoot && this.reportRunId == reportRunId && previous == next) return;
        this.repoRoot = repoRoot ?? ""; this.reportRunId = reportRunId ?? "";
        this.finding = finding.ValueKind == JsonValueKind.Object ? finding.Clone() : default;
        plan = default; receipt = default; busy = false; lastOperation = "";
        reason.Text = ""; owner.Text = ""; ticket.Text = ""; expires.Text = ""; legacy.IsChecked = false;
        preview.Text = "";
        context.Text = this.finding.ValueKind == JsonValueKind.Object
            ? $"{Read(this.finding, "title")}\nFinding ID: {Read(this.finding, "id")}\nRepository: {this.repoRoot}"
            : "No real finding selected.";
        status.Text = "Enter a reason and preview. No changes applied.";
        UpdateEnabled();
    }

    public void SetBusy(bool value) { busy = value; UpdateEnabled(); }

    public void SetResult(JsonElement result)
    {
        busy = false;
        if (result.ValueKind != JsonValueKind.Object) { status.Text = "Action returned no usable result. Inspect the saved action before retrying."; UpdateEnabled(); return; }
        if (result.TryGetProperty("plan", out var proposed))
        {
            if (!MatchesContext(proposed)) { status.Text = "Ignored a preview for a different finding or report."; UpdateEnabled(); return; }
            plan = proposed.Clone();
            preview.Text = Read(plan, "diff");
            if (plan.TryGetProperty("identity_review", out var review))
                context.Text = $"{Read(finding, "title")}\nFinding ID: {Read(review, "finding_id")} ({Read(review, "identity_scheme")})\n{Read(review, "notice")}";
        }
        if (result.TryGetProperty("receipt", out var saved) && saved.TryGetProperty("plan", out var applied))
        {
            if (!MatchesContext(applied)) { status.Text = "Ignored an action result for a different finding or report."; UpdateEnabled(); return; }
            receipt = saved.Clone(); plan = applied.Clone();
        }
        string outcome = Read(result, "status");
        if (outcome == "undone" || outcome == "not_applied") { receipt = default; plan = default; preview.Text = ""; }
        status.Text = Read(result, "message");
        if (status.Text.Length == 0) status.Text = "Action could not be completed. Apply may already have changed the file; use Recover / Undo before retrying.";
        undoButton.Content = receipt.ValueKind == JsonValueKind.Object ? "Undo last change" : "Recover / Undo";
        UpdateEnabled();
    }

    private bool MatchesContext(JsonElement value)
    {
        try
        {
            if (value.ValueKind != JsonValueKind.Object || !string.Equals(Path.GetFullPath(Read(value, "repo_root")), Path.GetFullPath(repoRoot), StringComparison.OrdinalIgnoreCase)) return false;
            if (!value.TryGetProperty("options", out var options) || Read(options, "report_run_id") != reportRunId) return false;
            if (!value.TryGetProperty("finding", out var record)) return false;
            return Read(record, "title") == Read(finding, "title") && Read(record, "id") == Read(finding, "id") && Read(record, "rule_id") == Read(finding, "rule_id") && Read(record, "entity_id") == Read(finding, "entity_id");
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
    }

    private void RequestPreview() => Dispatch("suppression_preview", new {
        repo_root = repoRoot, finding, reason = reason.Text.Trim(), owner = owner.Text.Trim(),
        ticket = ticket.Text.Trim(), expires = expires.Text.Trim().Length == 0 ? null : expires.Text.Trim(),
        report_run_id = reportRunId, origin = "desktop", legacy_reviewed = legacy.IsChecked == true });

    private void Dispatch(string operation, object payload)
    {
        if (busy || ActionRequested == null) { status.Text = "Action handler unavailable or busy."; return; }
        busy = true; lastOperation = operation; status.Text = operation == "suppression_preview" ? "Preparing a local preview…" : "Applying the requested local action…";
        UpdateEnabled();
        ActionRequested(new SuppressionActionRequest(operation, payload));
    }

    private void InvalidatePreview()
    {
        if (busy) return;
        plan = default; preview.Text = ""; UpdateEnabled();
    }

    private void UpdateEnabled()
    {
        bool selected = finding.ValueKind == JsonValueKind.Object && repoRoot.Length > 0;
        reason.IsEnabled = owner.IsEnabled = ticket.IsEnabled = expires.IsEnabled = legacy.IsEnabled = !busy && selected;
        previewButton.IsEnabled = !busy && selected && reason.Text.Trim().Length > 0;
        applyButton.IsEnabled = !busy && plan.ValueKind == JsonValueKind.Object && plan.TryGetProperty("can_apply", out var allowed) && allowed.ValueKind == JsonValueKind.True && receipt.ValueKind != JsonValueKind.Object;
        undoButton.IsEnabled = !busy && (receipt.ValueKind == JsonValueKind.Object || (plan.ValueKind == JsonValueKind.Object && lastOperation == "suppression_apply"));
    }

    private static string Read(JsonElement value, string key) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var item) && item.ValueKind == JsonValueKind.String ? item.GetString() ?? "" : "";
}
