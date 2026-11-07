using System.Text;using System.Text.Json;using System.Text.Json.Serialization;
namespace AttackMap.NativeSpike.HistoryPrep;

public sealed record RecentRepository(string RepositoryId,string Root,string DisplayName,string? LastGenerationId=null,string? LastReportHash=null)
{[JsonExtensionData]public Dictionary<string,JsonElement>? AdditionalProperties{get;init;}}
public sealed record RecentRepositoriesDocument(int SchemaVersion,IReadOnlyList<RecentRepository> Repositories)
{[JsonExtensionData]public Dictionary<string,JsonElement>? AdditionalProperties{get;init;}}
public sealed record RecentRepositoriesLoad(bool Supported,string OriginalRaw,RecentRepositoriesDocument? Document,string Notice);
/// <summary>Pure preparation codec. No settings files, existence probes, watchers or scans.</summary>
public static class RecentRepositoriesCodec
{
    public static RecentRepositoriesLoad Decode(string raw)
    {
        try
        {
            if(Encoding.UTF8.GetByteCount(raw)>65536)throw new InvalidDataException("Recent history exceeds 64 KiB.");
            using var json=JsonDocument.Parse(raw,new JsonDocumentOptions{MaxDepth=16});RejectDuplicates(json.RootElement);
            if(json.RootElement.ValueKind!=JsonValueKind.Object||!json.RootElement.TryGetProperty("SchemaVersion",out var version)||!version.TryGetInt32(out int number)||number!=1)
                return new(false,raw,null,"Unknown recent-history version; original preserved, no automatic replacement.");
            var doc=json.RootElement.Deserialize<RecentRepositoriesDocument>()??throw new InvalidDataException("Empty history document.");Validate(doc);
            return new(true,raw,doc,"Recent repositories loaded without probing paths or starting scans.");
        }
        catch(Exception error)when(error is JsonException or InvalidDataException or InvalidOperationException or ArgumentException)
        {return new(false,raw,null,"Corrupt/unsupported recent history; original preserved, recover explicitly.");}
    }
    public static string Encode(RecentRepositoriesLoad original,IReadOnlyList<RecentRepository> entries)
    {
        if(!original.Supported||original.Document==null)throw new InvalidDataException("Cannot replace corrupt/unknown history implicitly.");
        var document=original.Document with{Repositories=entries};Validate(document);string raw=JsonSerializer.Serialize(document);
        if(Encoding.UTF8.GetByteCount(raw)>65536)throw new InvalidDataException("Recent history exceeds 64 KiB.");return raw;
    }
    private static void Validate(RecentRepositoriesDocument document)
    {
        if(document.SchemaVersion!=1||document.Repositories==null||document.Repositories.Count>50)throw new InvalidDataException("Unsupported recent history shape.");
        var ids=new HashSet<string>(StringComparer.Ordinal);
        foreach(var repo in document.Repositories)
            if(repo==null||string.IsNullOrWhiteSpace(repo.RepositoryId)||!ids.Add(repo.RepositoryId)||string.IsNullOrWhiteSpace(repo.DisplayName)||string.IsNullOrWhiteSpace(repo.Root)||!Path.IsPathFullyQualified(repo.Root)||repo.Root.Any(char.IsControl)
                ||(repo.LastGenerationId==null)!=(repo.LastReportHash==null)||repo.LastGenerationId!=null&&string.IsNullOrWhiteSpace(repo.LastGenerationId)||repo.LastReportHash!=null&&!HistoryIdentity.ValidHash(repo.LastReportHash))throw new InvalidDataException("Invalid recent repository identity.");
    }
    private static void RejectDuplicates(JsonElement value)
    {
        if(value.ValueKind==JsonValueKind.Object){var keys=new HashSet<string>(StringComparer.Ordinal);foreach(var property in value.EnumerateObject()){if(!keys.Add(property.Name))throw new InvalidDataException("Duplicate history fields.");RejectDuplicates(property.Value);}}
        else if(value.ValueKind==JsonValueKind.Array)foreach(var item in value.EnumerateArray())RejectDuplicates(item);
    }
}
