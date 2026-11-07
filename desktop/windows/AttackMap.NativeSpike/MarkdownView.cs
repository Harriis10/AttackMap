using System.Text.RegularExpressions;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace AttackMap.NativeSpike;

/// <summary>
/// Renders engine/AI markdown prose as readable blocks: headings, bullets,
/// quotes, bold/code runs, and severity words (CRITICAL/HIGH/MEDIUM/LOW)
/// highlighted with consistent colors in both themes. Presentation only —
/// the engine owns the text and its claims.
/// </summary>
public sealed partial class MarkdownView : UserControl
{
    private readonly StackPanel blocks = new() { Spacing = 10 };
    private string raw = "";
    private bool dirty;
    private bool activated;
    internal long RenderCount { get; private set; }

    public string Text
    {
        get => raw;
        set => Render(value);
    }

    public MarkdownView()
    {
        MinHeight = 1;
        Content = new ScrollViewer
        {
            Content = blocks,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            VerticalScrollBarVisibility = ScrollBarVisibility.Disabled,
        };
        LayoutUpdated += OnLayoutUpdated;
    }

    private void OnLayoutUpdated(object? sender, object args)
    {
        bool visible = UiActivation.IsEffectivelyVisible(this);
        if (visible == activated && !(visible && dirty)) return;
        activated = visible;
        if (visible && dirty) Build();
    }

    public void Render(string markdown)
    {
        raw = markdown ?? "";
        blocks.Children.Clear();
        dirty = raw.Length > 0;
        if (dirty && UiActivation.IsEffectivelyVisible(this)) Build();
    }

    private void Build()
    {
        if (!dirty) return;
        string supplied = raw;
        dirty = false;
        ++RenderCount;
        foreach (var block in ParseBlocks(supplied)) blocks.Children.Add(block);
    }

    private static IEnumerable<FrameworkElement> ParseBlocks(string markdown)
    {
        var lines = markdown.Replace("\r\n", "\n").Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].TrimEnd();
            var trimmed = line.TrimStart();
            if (trimmed.Length == 0) continue;
            if (Regex.IsMatch(trimmed, "^-{3,}$|^\\*{3,}$"))
            {
                yield return new Border
                {
                    Height = 1,
                    Background = new SolidColorBrush(Microsoft.UI.Colors.Gray),
                    Opacity = 0.4,
                    HorizontalAlignment = HorizontalAlignment.Stretch,
                };
            }
            else if (trimmed.StartsWith('#'))
            {
                var level = trimmed.Length - trimmed.TrimStart('#').Length;
                var text = trimmed.TrimStart('#').Trim();
                yield return new TextBlock
                {
                    Text = text,
                    FontSize = level <= 1 ? 20 : level == 2 ? 17 : 15,
                    FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                    TextWrapping = TextWrapping.Wrap,
                    IsTextSelectionEnabled = true,
                };
            }
            else if (trimmed.StartsWith('>'))
            {
                var quote = new TextBlock
                {
                    Text = trimmed.TrimStart('>', ' '),
                    FontStyle = Windows.UI.Text.FontStyle.Italic,
                    Opacity = 0.85,
                    TextWrapping = TextWrapping.Wrap,
                    IsTextSelectionEnabled = true,
                };
                yield return new Border
                {
                    BorderBrush = SeverityBrush("accent"),
                    BorderThickness = new Thickness(2, 0, 0, 0),
                    Padding = new Thickness(10, 2, 0, 2),
                    HorizontalAlignment = HorizontalAlignment.Stretch,
                    Child = quote,
                };
            }
            else if (Regex.IsMatch(trimmed, "^[-*•]\\s+") || Regex.IsMatch(trimmed, "^\\d+[.)]\\s+"))
            {
                var bullet = new TextBlock
                {
                    Text = "•  " + Regex.Replace(trimmed, "^([-*•]|\\d+[.)])\\s+", ""),
                    TextWrapping = TextWrapping.Wrap,
                    IsTextSelectionEnabled = true,
                    Margin = new Thickness(12, 0, 0, 0),
                };
                ApplyInline(bullet, bullet.Text);
                yield return bullet;
            }
            else
            {
                var paragraph = new TextBlock
                {
                    TextWrapping = TextWrapping.Wrap,
                    IsTextSelectionEnabled = true,
                };
                ApplyInline(paragraph, line);
                yield return paragraph;
            }
        }
    }

    private static void ApplyInline(TextBlock target, string text)
    {
        target.Inlines.Clear();
        foreach (var run in SplitInline(text)) target.Inlines.Add(run);
    }

    private static IEnumerable<Microsoft.UI.Xaml.Documents.Run> SplitInline(string text)
    {
        foreach (var (segment, kind) in SplitBoldCode(text))
        foreach (var run in SplitSeverity(segment, kind)) yield return run;
    }

    private static IEnumerable<(string Segment, string Kind)> SplitBoldCode(string text)
    {
        var pattern = new Regex(@"\*\*(.+?)\*\*|`([^`]+)`");
        var rest = text;
        Match found;
        while ((found = pattern.Match(rest)).Success)
        {
            if (found.Index > 0) yield return (rest[..found.Index], "plain");
            yield return found.Groups[1].Success ? (found.Groups[1].Value, "bold") : (found.Groups[2].Value, "code");
            rest = rest[(found.Index + found.Length)..];
        }
        if (rest.Length > 0) yield return (rest, "plain");
    }

    private static IEnumerable<Microsoft.UI.Xaml.Documents.Run> SplitSeverity(string segment, string kind)
    {
        var pattern = new Regex(@"\b(CRITICAL|HIGH|MEDIUM|MODERATE|LOW|SEVERE)\b");
        var rest = segment;
        Match found;
        while ((found = pattern.Match(rest)).Success)
        {
            if (found.Index > 0) yield return PlainRun(rest[..found.Index], kind);
            var word = found.Value;
            yield return new Microsoft.UI.Xaml.Documents.Run
            {
                Text = word,
                FontWeight = Microsoft.UI.Text.FontWeights.Bold,
                Foreground = SeverityBrush(word),
            };
            rest = rest[(found.Index + found.Length)..];
        }
        if (rest.Length > 0) yield return PlainRun(rest, kind);
    }

    private static Microsoft.UI.Xaml.Documents.Run PlainRun(string text, string kind) => kind switch
    {
        "bold" => new() { Text = text, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
        "code" => new()
        {
            Text = text,
            FontFamily = new FontFamily("Consolas"),
            Foreground = SeverityBrush("accent"),
        },
        _ => new() { Text = text },
    };

    public static Brush SeverityBrush(string severity)
    {
        var key = (severity ?? "").Trim().ToLowerInvariant();
        var color = key switch
        {
            "critical" or "severe" => Windows.UI.Color.FromArgb(255, 232, 17, 35),    // red
            "high" => Windows.UI.Color.FromArgb(255, 216, 59, 1),                     // dark orange
            "medium" or "moderate" => Windows.UI.Color.FromArgb(255, 177, 138, 0),    // amber (light+dark readable)
            "low" => Windows.UI.Color.FromArgb(255, 0, 120, 212),                     // blue
            _ => Microsoft.UI.Colors.Gray,
        };
        return new SolidColorBrush(color);
    }
}
