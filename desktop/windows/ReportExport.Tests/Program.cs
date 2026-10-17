using System.Text;
using System.Text.Json;
using AttackMap.NativeSpike;
int checks = 0;
string work = Path.Combine(Path.GetTempPath(), $"attackmap-report-export-{Guid.NewGuid():N}");
Directory.CreateDirectory(work);
try
{
    string html = ReviewExport.BuildHtml("# Defensive Review\n\nSummary with <script>alert(1)</script> and `code` plus **bold** and *italic* and SEVERE word\n\n- item HIGH\n  - nested č item\n\n1. ordered\n\n> quoted MEDIUM text\n\n---\n\n```\nraw <b> fence\n```\n\n| Head | Second |\n| - | - |\n| a&#8203;b | LOW |\n", "attackmap-run-review");
    Check(html.StartsWith("<!DOCTYPE html>") && html.Contains("<meta charset=\"utf-8\">") && html.Contains("<title>attackmap-run-review</title>") && html.Contains("<style>"), "standalone HTML document shape with charset, title and style");
    Check(!html.Contains("<script>") && html.Contains("&lt;script&gt;"), "hostile markup is HTML-escaped, never executable");
    Check(html.Contains("<h1>Defensive Review</h1>"), "level one heading");
    Check(html.Contains("<code>code</code>") && html.Contains("<strong>bold</strong>") && html.Contains("<em>italic</em>"), "inline code, bold and italic render");
    Check(html.Contains("<strong style=\"color:#E81123\">SEVERE</strong>") && html.Contains("<strong style=\"color:#D83B01\">HIGH</strong>") && html.Contains("<strong style=\"color:#B18A00\">MEDIUM</strong>") && html.Contains("<strong style=\"color:#0078D4\">LOW</strong>"), "severity words use the MarkdownView palette");
    Check(html.Contains("<ul>") && html.Contains("<li>") && html.IndexOf("<ul>", html.IndexOf("<ul>") + 1) > 0, "nested bullet opens a second list level");
    Check(html.Contains("<ol>") && html.Contains("<li>ordered</li>"), "ordered bullet list");
    Check(html.Contains("<blockquote>") && html.Contains("quoted"), "blockquote renders");
    Check(html.Contains("<hr/>"), "horizontal rule renders");
    Check(html.Contains("<pre><code>raw &lt;b&gt; fence</code></pre>"), "code fence content escaped verbatim");
    Check(html.Contains("<table>") && html.Contains("<th>Head</th>") && html.Contains("<td>a&#8203;b</td>"), "table rows render and zero-width entity stays an entity");
    Check(!html.Contains("&amp;#8203;") && html.Contains("č"), "no double-escaped entities; Unicode text survives");
    Check(!ReviewExport.BuildHtml("plain low text", "t").Contains("color:#"), "lowercase severity words are not highlighted");

    string htmlPath = Path.Combine(work, "rendered.html");
    await ReviewExport.WriteHtmlAsync(htmlPath, html);
    Check(File.Exists(htmlPath) && !Directory.EnumerateFiles(work, "*.tmp").Any() && (await File.ReadAllTextAsync(htmlPath)).StartsWith("<!DOCTYPE html>"), "HTML export writes atomically without leftover temp files");

    string generation = Path.Combine(work, "generation");
    Directory.CreateDirectory(generation);
    string reportPath = Path.Combine(generation, "attackmap-report.json");
    string markdownPath = Path.Combine(generation, "defensive-review.md");
    byte[] reportBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { scan = new { root = "C:/synthetic" }, findings = Array.Empty<object>(), defensive_review = "# Displayed review" }));
    string markdown = "# Displayed review\n\n- observed evidence with MEDIUM confidence\n";
    await File.WriteAllBytesAsync(reportPath, reportBytes);
    await File.WriteAllTextAsync(markdownPath, markdown);
    string reportHash = ExportSelection.Hash(reportBytes);
    await File.WriteAllTextAsync(Path.Combine(generation, "artifact-manifest.json"), JsonSerializer.Serialize(new
    {
        schema_version = "1.0.0",
        artifact_type = "attackmap_artifact_manifest",
        generation_id = "run-1",
        run_identity = new { repo_root = "C:/synthetic" },
        compatibility_exports = new object[]
        {
            new { path = "attackmap-report.json", checksum = reportHash },
            new { path = "defensive-review.md", checksum = ExportSelection.Hash(Encoding.UTF8.GetBytes(markdown)) },
        },
    }));
    var selection = ExportSelection.CaptureSavedGeneration(reportPath, reportHash, "C:/synthetic");
    Check(selection.Verified && selection.RunId == "run-1" && selection.SuggestedName(".html") == "attackmap-run-1-review.html" && selection.SuggestedName(".pdf") == "attackmap-run-1-review.pdf", "rendered export suggested names follow the run identity");
    Check(await Task.Run(() => selection.ReadVerifiedMarkdown()) == markdown, "verified Markdown read returns the manifest-bound bytes");
    await File.WriteAllTextAsync(markdownPath, markdown + "tampered\n");
    Check(Throws(() => selection.ReadVerifiedMarkdown()), "tampered Markdown is refused before rendering");
    await File.WriteAllTextAsync(markdownPath, markdown);
    bool refusedDestination = false;
    try { selection.EnsureExportDestination(reportPath, selection.ReportPath); } catch (InvalidDataException) { refusedDestination = true; }
    Check(refusedDestination, "derived export refuses the source artifact as destination");
    selection.EnsureExportDestination(Path.Combine(work, "outside.html"), selection.ReportPath);
    Check(true, "derived export allows a destination outside the source artifacts");

    var browsers = ReviewExport.FindPrintBrowsers();
    if (browsers.Count == 0)
        Console.WriteLine("NOTE no Edge/Chrome located; local PDF print check skipped (HTML checks still passed)");
    else
    {
        Check(browsers.All(File.Exists), "every located print browser exists");
        string pdfPath = Path.Combine(work, "rendered.pdf");
        await ReviewExport.WritePdfWithAvailableBrowserAsync(html, pdfPath);
        byte[] header = new byte[4];
        await using (var stream = File.OpenRead(pdfPath)) await stream.ReadAsync(header);
        Check(Encoding.ASCII.GetString(header) == "%PDF" && new FileInfo(pdfPath).Length > 1000, "a located browser printed a non-trivial PDF locally (falling through any browser that silently fails)");
        Console.WriteLine($"NOTE real PDF printed via one of: {string.Join(", ", browsers.Select(Path.GetFileName))}");
    }
    Console.WriteLine($"PASS {checks} native rendered export checks");
}
finally { try { Directory.Delete(work, true); } catch (IOException) { } }
bool Throws(Action action) { try { action(); return false; } catch (InvalidDataException) { return true; } }
void Check(bool passed, string label) { if (!passed) throw new Exception(label); checks++; }
