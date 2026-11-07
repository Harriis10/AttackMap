namespace AttackMap.NativeSpike.ExportPrep;

public enum SelectedExportFormat{Json,Markdown,Html,Pdf,Sarif}
public enum SelectedExportOperation{Save,Open,Reveal,Copy}
public enum PdfDependencyState{Unavailable,PresentUnverified}
public sealed record PdfDependency(PdfDependencyState State,string? Path,string Notice);
public sealed record SelectedExportIntent(long Epoch,string Generation,string ReportHash,string ManifestHash,SelectedExportFormat Format,SelectedExportOperation Operation,string? Destination,string? ExistingDestinationHash);
/// <summary>Read-only validation and callback intents; never writes or launches anything.</summary>
public sealed class SelectedExportWorkspace
{
    private ExportSelection? selection;private long epoch;
    public void Select(ExportSelection value){selection=value;epoch++;}
    public void Cancel(){epoch++;}
    public string Status{get;private set;}="No export performed.";
    public async Task<string> ReadSarif()
    {
        var selected=selection??throw new InvalidDataException("No selection.");long captured=epoch;
        LocalPath(selected.ReportPath);var records=SelectedArtifacts.List(selected);var canonical=records.Single(r=>string.Equals(r.FullPath,selected.ReportPath,StringComparison.OrdinalIgnoreCase));
        string text=await SelectedArtifacts.ReadText(selected,canonical,64*1024*1024);
        if(captured!=epoch||selection!=selected)throw new InvalidDataException("Selection changed during projection.");
        string projected=SelectedSarifProjection.Project(text,selected.RunId!,selected.ReportHash);
        if(captured!=epoch||selection!=selected)throw new InvalidDataException("Selection changed during projection.");return projected;
    }
    public SelectedExportIntent? Request(SelectedExportFormat format,SelectedExportOperation operation,string? destination=null,bool overwriteApproved=false,PdfDependency? pdf=null)
    {
        if(!Enum.IsDefined(format)||!Enum.IsDefined(operation))throw new ArgumentOutOfRangeException("Unsupported export format/operation.");
        var selected=selection??throw new InvalidDataException("No selection.");LocalPath(selected.ReportPath);var artifacts=SelectedArtifacts.List(selected);
        if(format is SelectedExportFormat.Markdown or SelectedExportFormat.Html or SelectedExportFormat.Pdf)selected.ReadVerifiedMarkdown();
        if(format==SelectedExportFormat.Pdf&&(pdf?.State!=PdfDependencyState.PresentUnverified||pdf.Path==null||ProbePdf(new[]{pdf.Path}).State!=PdfDependencyState.PresentUnverified)){Status="PDF unavailable: no configured local renderer; no download or network attempted.";return null;}
        string? existing=null;
        if(operation==SelectedExportOperation.Save)
        {
            if(destination==null){Cancel();Status="Save cancelled; source artifacts unchanged.";return null;}
            destination=LocalPath(destination);selected.EnsureExportDestination(destination,selected.ReportPath);
            if(Directory.Exists(destination))throw new InvalidDataException("Destination is a directory.");
            if(File.Exists(destination)){if(!overwriteApproved)throw new InvalidDataException("Destination exists; explicit overwrite required.");existing=HashBounded(destination);if(artifacts.Any(a=>a.Checksum==existing))throw new InvalidDataException("Destination aliases selected artifact content; choose a new destination.");}
        }
        return new(epoch,selected.RunId!,selected.ReportHash,selected.ManifestHash!,format,operation,destination,existing);
    }
    public bool Validate(SelectedExportIntent request)
    {
        if(selection==null||request.Epoch!=epoch||request.Generation!=selection.RunId||request.ReportHash!=selection.ReportHash||request.ManifestHash!=selection.ManifestHash)return false;
        try
        {
            LocalPath(selection.ReportPath);SelectedArtifacts.List(selection);
            if(request.Destination!=null){LocalPath(request.Destination);selection.EnsureExportDestination(request.Destination,selection.ReportPath);if(Directory.Exists(request.Destination))return false;if(File.Exists(request.Destination)?request.ExistingDestinationHash==null||HashBounded(request.Destination)!=request.ExistingDestinationHash:request.ExistingDestinationHash!=null)return false;}
            return true;
        }
        catch(Exception error)when(error is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException){return false;}
    }
    public void SaveFailed(){epoch++;Status="Save failed; this helper wrote nothing and original selection is unchanged. Choose/revalidate destination before retrying.";}
    public static PdfDependency ProbePdf(IEnumerable<string> configuredLocalPaths)
    {
        foreach(string path in configuredLocalPaths)try{string local=LocalPath(path);if(File.Exists(local)&&System.IO.Path.GetExtension(local).Equals(".exe",StringComparison.OrdinalIgnoreCase))return new(PdfDependencyState.PresentUnverified,local,"Configured local renderer exists; rendering has not been verified.");}catch(Exception error)when(error is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException){}
        return new(PdfDependencyState.Unavailable,null,"Configured local PDF renderer unavailable. No network/download/install attempted.");
    }
    private static string LocalPath(string path)
    {
        if(!System.IO.Path.IsPathFullyQualified(path)||path.StartsWith("\\\\")||path.StartsWith("//")||path.Contains("://")||path.Any(char.IsControl)||path.Replace('\\','/').Split('/').Any(p=>p is "." or ".."))throw new InvalidDataException("Only local absolute paths without traversal are accepted.");
        if(path.IndexOf(':',Math.Min(2,path.Length))>=0||path.Replace('\\','/').Split('/').Any(p=>p.EndsWith(' ')||p.EndsWith('.')))throw new InvalidDataException("Alternate streams/path aliases rejected.");
        string full=System.IO.Path.GetFullPath(path);
        if(OperatingSystem.IsWindows()&&new DriveInfo(System.IO.Path.GetPathRoot(full)!).DriveType==DriveType.Network)throw new InvalidDataException("Mapped network export/renderer paths are unavailable.");
        for(FileSystemInfo? part=File.Exists(full)?new FileInfo(full):Directory.Exists(full)?new DirectoryInfo(full):new DirectoryInfo(System.IO.Path.GetDirectoryName(full)!);part!=null;part=part is FileInfo file?file.Directory:((DirectoryInfo)part).Parent)
            if(part.Exists&&(part.Attributes&FileAttributes.ReparsePoint)!=0)throw new InvalidDataException("Redirected/reparse export path rejected.");
        return full;
    }
    private static string HashBounded(string path)
    {
        using var source=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);if(source.Length>64*1024*1024)throw new InvalidDataException("Destination fingerprint exceeds64MiB limit.");
        using var bytes=new MemoryStream();var buffer=new byte[16384];int count;
        while((count=source.Read(buffer))!=0){if(bytes.Length+count>64*1024*1024)throw new InvalidDataException("Destination fingerprint exceeds64MiB limit.");bytes.Write(buffer,0,count);}return ExportSelection.Hash(bytes.ToArray());
    }
}
