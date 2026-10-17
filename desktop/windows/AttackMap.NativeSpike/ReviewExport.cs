using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace AttackMap.NativeSpike;

/// <summary>
/// Renders the displayed defensive-review Markdown into a standalone HTML
/// document and prints it to PDF through a located headless Edge/Chrome,
/// mirroring the loopback web GUI export path (ui/server.py). Presentation
/// only: the engine owns the text and its claims; verified runs hash-check
/// the source Markdown before this runs.
/// </summary>
public static class ReviewExport
{
    private const string Css = """
        body { font-family: "Segoe UI", sans-serif; margin: 24px; color: #1a1a1a; background: #fff; line-height: 1.5; }
        h1 { font-size: 22px; margin-bottom: 8px; }
        h2 { font-size: 17px; margin-top: 24px; margin-bottom: 8px; }
        h3 { font-size: 15px; margin-top: 18px; margin-bottom: 6px; }
        h4 { font-size: 14px; margin-top: 16px; margin-bottom: 6px; }
        p { margin: 8px 0; }
        ul, ol { margin: 8px 0; padding-left: 24px; }
        blockquote { margin: 8px 0; padding: 2px 12px; border-left: 3px solid #0078D4; color: #444; }
        code { font-family: Consolas, monospace; background: #f4f4f4; padding: 1px 4px; border-radius: 4px; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 6px; overflow-x: auto; }
        pre code { background: none; padding: 0; }
        table { border-collapse: collapse; width: 100%; margin: 12px 0; }
        th, td { border: 1px solid #ccc; padding: 6px 8px; text-align: left; vertical-align: top; word-break: break-word; }
        th { background: #f0f0f0; }
        hr { border: none; border-top: 1px solid #ccc; margin: 16px 0; }
        """;

    public static string BuildHtml(string markdown, string title)
    {
        var html = new StringBuilder();
        html.Append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>")
            .Append(Escape(title)).Append("</title>\n<style>\n").Append(Css).Append("</style>\n</head>\n<body>\n");
        html.Append(RenderBlocks(markdown ?? ""));
        html.Append("</body>\n</html>\n");
        return html.ToString();
    }

    public static async Task WriteHtmlAsync(string destination, string html)
    {
        destination = Path.GetFullPath(destination);
        string temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try { await File.WriteAllTextAsync(temporary, html, new UTF8Encoding(false)); File.Move(temporary, destination, overwrite: true); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    public static async Task WritePdfAsync(string browserPath, string html, string destination)
    {
        destination = Path.GetFullPath(destination);
        string work = Path.Combine(Path.GetTempPath(), "attackmap-review-pdf-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(work);
        string sourcePath = Path.Combine(work, "review.html");
        await File.WriteAllTextAsync(sourcePath, html, new UTF8Encoding(false));
        try
        {
            // A dedicated profile keeps headless printing independent of any
            // interactively running Edge/Chrome instance.
            string profile = Path.Combine(work, "profile");
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo { FileName = browserPath, UseShellExecute = false, CreateNoWindow = true };
            foreach (string argument in new[] { "--headless", "--disable-gpu", "--no-pdf-header-footer", $"--user-data-dir={profile}", $"--print-to-pdf={destination}", sourcePath })
                process.StartInfo.ArgumentList.Add(argument);
            process.Start();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            try { await process.WaitForExitAsync(timeout.Token); }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { /* already gone */ }
                throw new TimeoutException("PDF printing did not finish within 60 seconds.");
            }
            if (process.ExitCode != 0) throw new InvalidDataException($"Headless browser print failed with exit code {process.ExitCode}.");
            if (!File.Exists(destination)) throw new InvalidDataException("Headless browser print produced no PDF file.");
            await using var written = File.OpenRead(destination);
            byte[] header = new byte[4];
            if (await written.ReadAsync(header) < 4 || Encoding.ASCII.GetString(header) != "%PDF")
                throw new InvalidDataException("Printed output is not a PDF document.");
        }
        finally
        {
            try { Directory.Delete(work, recursive: true); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException) { /* temp cleanup is best effort */ }
        }
    }

    /// <summary>Existing Edge/Chrome executables in the loopback web GUI's
    /// search order. All are returned: an installed Edge can still fail to
    /// print (e.g. Startup Boost hands off and drops the switches), so callers
    /// fall through to the next candidate.</summary>
    public static IReadOnlyList<string> FindPrintBrowsers()
    {
        var candidates = new List<string>();
        foreach (string root in new[] { Environment.GetEnvironmentVariable("PROGRAMFILES(X86)") ?? "", Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? "", Environment.GetEnvironmentVariable("PROGRAMFILES") ?? "" })
        {
            if (root.Length == 0) continue;
            candidates.Add(Path.Combine(root, "Microsoft", "Edge", "Application", "msedge.exe"));
        }
        foreach (string root in new[] { Environment.GetEnvironmentVariable("PROGRAMFILES(X86)") ?? "", Environment.GetEnvironmentVariable("PROGRAMFILES") ?? "", Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? "" })
        {
            if (root.Length == 0) continue;
            candidates.Add(Path.Combine(root, "Google", "Chrome", "Application", "chrome.exe"));
        }
        return candidates.Where(candidate => File.Exists(candidate)).ToList();
    }

    /// <summary>Prints the HTML with the first located browser that actually
    /// produces a PDF; throws when every candidate fails.</summary>
    public static async Task WritePdfWithAvailableBrowserAsync(string html, string destination)
    {
        var failures = new List<string>();
        foreach (string browser in FindPrintBrowsers())
        {
            try { await WritePdfAsync(browser, html, destination); return; }
            catch (Exception error) when (error is InvalidDataException or TimeoutException or System.ComponentModel.Win32Exception)
            { failures.Add($"{Path.GetFileName(browser)}: {error.Message}"); }
        }
        throw new InvalidDataException("PDF printing failed with every located browser. " + string.Join(" ", failures));
    }

    private static string RenderBlocks(string markdown)
    {
        var lines = markdown.Replace("\r\n", "\n").Split('\n');
        var html = new StringBuilder();
        var paragraph = new List<string>();
        var listStack = new Stack<string>();
        bool inCode = false;
        var code = new List<string>();
        void FlushParagraph()
        {
            if (paragraph.Count == 0) return;
            html.Append("<p>").Append(string.Join("<br/>", paragraph.Select(Inline))).Append("</p>\n");
            paragraph.Clear();
        }
        void CloseList()
        {
            while (listStack.Count > 0) html.Append("</").Append(listStack.Pop()).Append(">\n");
        }
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.TrimEnd().StartsWith("```"))
            {
                if (inCode)
                {
                    html.Append("<pre><code>").Append(Escape(string.Join("\n", code))).Append("</code></pre>\n");
                    code.Clear();
                    inCode = false;
                }
                else { FlushParagraph(); CloseList(); inCode = true; }
                continue;
            }
            if (inCode) { code.Add(line); continue; }
            var trimmed = line.Trim();
            if (trimmed.Length == 0) { FlushParagraph(); CloseList(); continue; }
            var heading = Regex.Match(trimmed, @"^(#{1,4})\s+(.*)$");
            if (heading.Success)
            {
                FlushParagraph(); CloseList();
                int level = heading.Groups[1].Value.Length;
                html.Append('<').Append('h').Append(level).Append('>').Append(Inline(heading.Groups[2].Value)).Append("</h").Append(level).Append(">\n");
                continue;
            }
            if (Regex.IsMatch(trimmed, @"^-{3,}$|^\*{3,}$")) { FlushParagraph(); CloseList(); html.Append("<hr/>\n"); continue; }
            if (line.Contains('|') && i + 1 < lines.Length && IsTableSeparator(lines[i + 1]))
            {
                FlushParagraph(); CloseList();
                var headers = SplitRow(line);
                i += 2;
                var rows = new List<string[]>();
                while (i < lines.Length && lines[i].Contains('|') && lines[i].Trim().Length > 0) { rows.Add(SplitRow(lines[i])); i++; }
                i--;
                html.Append("<table><thead><tr>").Append(string.Concat(headers.Select(cell => "<th>" + Inline(cell) + "</th>"))).Append("</tr></thead><tbody>");
                foreach (var row in rows) html.Append("<tr>").Append(string.Concat(row.Select(cell => "<td>" + Inline(cell) + "</td>"))).Append("</tr>");
                html.Append("</tbody></table>\n");
                continue;
            }
            var bullet = Regex.Match(line, @"^(\s*)([-*+•]|\d+[.)])\s+(.*)$");
            if (bullet.Success)
            {
                FlushParagraph();
                string type = char.IsDigit(bullet.Groups[2].Value[0]) ? "ol" : "ul";
                int depth = bullet.Groups[1].Value.Length / 2 + 1;
                while (listStack.Count > depth || (listStack.Count == depth && listStack.Peek() != type))
                    html.Append("</").Append(listStack.Pop()).Append(">\n");
                while (listStack.Count < depth)
                {
                    string tag = listStack.Count == 0 ? type : "ul";
                    listStack.Push(tag);
                    html.Append('<').Append(tag).Append(">\n");
                }
                html.Append("<li>").Append(Inline(bullet.Groups[3].Value)).Append("</li>\n");
                continue;
            }
            var quote = Regex.Match(trimmed, @"^>\s?(.*)$");
            if (quote.Success) { FlushParagraph(); CloseList(); html.Append("<blockquote>").Append(Inline(quote.Groups[1].Value)).Append("</blockquote>\n"); continue; }
            paragraph.Add(line.TrimEnd());
        }
        if (inCode) html.Append("<pre><code>").Append(Escape(string.Join("\n", code))).Append("</code></pre>\n");
        FlushParagraph();
        CloseList();
        return html.ToString();
    }

    private static bool IsTableSeparator(string line) => Regex.IsMatch(line, @"^\s*\|?(\s*:?-+:?\s*\|)+\s*$");

    private static string[] SplitRow(string line) => line.Trim().TrimStart('|').TrimEnd('|').Split('|').Select(cell => cell.Trim()).ToArray();

    /// <summary>HTML-escapes defanged Markdown prose. The engine's zero-width
    /// space entity (&#8203;) is restored afterwards so it stays invisible.</summary>
    private static string Escape(string text) =>
        text.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&#39;")
            .Replace("&amp;#8203;", "&#8203;");

    private static string Inline(string text)
    {
        string rendered = Escape(text);
        rendered = Regex.Replace(rendered, @"`([^`]+)`", "<code>$1</code>");
        rendered = Regex.Replace(rendered, @"\*\*([^*]+)\*\*", "<strong>$1</strong>");
        rendered = Regex.Replace(rendered, @"(^|[^*])\*([^*\n]+)\*", "$1<em>$2</em>");
        rendered = Regex.Replace(rendered, @"(^|[^A-Za-z0-9_])_([^_\n]+)_(?![A-Za-z0-9_])", "$1<em>$2</em>");
        rendered = Regex.Replace(rendered, @"\\([_*[\]`])", "$1");
        // Severity palette mirrors MarkdownView.SeverityBrush for visual parity.
        rendered = Regex.Replace(rendered, @"\b(CRITICAL|SEVERE|HIGH|MEDIUM|MODERATE|LOW)\b",
            match => $"<strong style=\"color:{SeverityColor(match.Value)}\">{match.Value}</strong>");
        return rendered;
    }

    private static string SeverityColor(string severity) => severity switch
    {
        "CRITICAL" or "SEVERE" => "#E81123",
        "HIGH" => "#D83B01",
        "MEDIUM" or "MODERATE" => "#B18A00",
        "LOW" => "#0078D4",
        _ => "#666666",
    };
}
