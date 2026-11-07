using System.Text.Json;
namespace AttackMap.NativeSpike;

public static class DiagramSelectionReader
{
    public static IReadOnlyList<string> ArtifactNames {get;}=Array.AsReadOnly(new[]{"architecture.md","attackmap-paths.md","attackmap-topology.md"});
    public static async Task<DiagramDocument> Read(ExportSelection selection,string artifactName)
    {
        string reportPath=selection.ReportPath;
        if(!Path.IsPathFullyQualified(reportPath)||reportPath.StartsWith(@"\\",StringComparison.Ordinal)||reportPath.StartsWith("//",StringComparison.Ordinal)||
            OperatingSystem.IsWindows()&&new DriveInfo(Path.GetPathRoot(reportPath)!).DriveType==DriveType.Network)
            throw new InvalidDataException("Offline diagrams require a local selected report; remote paths are refused before reading.");
        if(!ArtifactNames.Contains(artifactName,StringComparer.Ordinal))throw new InvalidDataException("Select a supported core diagram artifact.");
        var records=await Task.Run(()=>SelectedArtifacts.List(selection));
        var artifact=records.SingleOrDefault(record=>Path.GetFileName(record.FullPath)==artifactName&&record.Format=="md");
        if(artifact==null)return new("",Array.Empty<DiagramNode>(),Array.Empty<DiagramEdge>(),false,"Selected manifest does not list this diagram. Missing is not empty or a security assurance.");
        var report=records.Single(record=>string.Equals(record.FullPath,Path.GetFullPath(selection.ReportPath),StringComparison.OrdinalIgnoreCase));
        string reportText=await SelectedArtifacts.ReadText(selection,report,64*1024*1024);
        string source=await SelectedArtifacts.ReadText(selection,artifact,4*1024*1024);
        return await Task.Run(()=>
        {
        using var document=JsonDocument.Parse(reportText,new JsonDocumentOptions{MaxDepth=64});
        if(document.RootElement.ValueKind!=JsonValueKind.Object)throw new InvalidDataException("Selected report is malformed.");
        // Capture identity is rechecked by ReadText after every read. Rendering never reads sibling files by convention.
        var parsed=DiagramParser.Parse(source);
        bool limitations=document.RootElement.TryGetProperty("scan",out var scan)&&scan.ValueKind==JsonValueKind.Object&&
            (scan.TryGetProperty("limitations",out var notes)&&notes.ValueKind==JsonValueKind.Array&&notes.GetArrayLength()>0||
             scan.TryGetProperty("resource_limit_events",out var events)&&events.ValueKind==JsonValueKind.Array&&events.GetArrayLength()>0);
        return parsed with{Notice=$"Selected run {selection.RunId}; manifest-bound diagram. "+(limitations?"Report contains limitations/resource events; diagram completeness is not assured. ":"Completeness remains as supplied by core. ")+parsed.Notice};
        });
    }
}
