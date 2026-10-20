using System.Text.Json;using System.Text.Json.Nodes;
namespace AttackMap.NativeSpike.ExportPrep;

public static class SelectedSarifProjection
{
    public static string Project(string canonicalJson,string generation,string reportHash)
    {
        if(System.Text.Encoding.UTF8.GetByteCount(canonicalJson)>64*1024*1024)throw new InvalidDataException("Canonical report exceeds 64 MiB.");
        using var json=JsonDocument.Parse(canonicalJson,new JsonDocumentOptions{MaxDepth=64});var root=json.RootElement;
        if(root.ValueKind!=JsonValueKind.Object||root.TryGetProperty("schema_version",out _)||!root.TryGetProperty("scan",out var scan)||scan.ValueKind!=JsonValueKind.Object||!scan.TryGetProperty("root",out var repository)||repository.ValueKind!=JsonValueKind.String||!root.TryGetProperty("findings",out var findings)||findings.ValueKind!=JsonValueKind.Array)throw new InvalidDataException("Expected canonical saved report.");
        var results=new JsonArray();int malformed=0,unsafeLocations=0,index=0,totalLocations=0;
        foreach(var finding in findings.EnumerateArray().Take(10000))
        {
            if(finding.ValueKind!=JsonValueKind.Object){malformed++;index++;continue;}
            string? severity=Scalar(finding,"severity"),id=Scalar(finding,"id");
            var properties=new JsonObject{["sourceIndex"]=index,["sourceFindingId"]=id,["sourceSeverity"]=severity??"unknown",["confidence"]=Scalar(finding,"confidence")??"unknown",["evidenceBasis"]=Scalar(finding,"evidence_basis")??"unknown",["evidenceTextWithheld"]=true};
            properties["suppliedEvidenceCount"]=finding.TryGetProperty("evidence",out var evidence)&&evidence.ValueKind==JsonValueKind.Array?JsonValue.Create(evidence.GetArrayLength()):null;
            string? title=Scalar(finding,"title");
            var result=new JsonObject{["message"]=new JsonObject{["text"]=string.IsNullOrWhiteSpace(title)?"Unnamed supplied finding":title},["level"]=severity switch{"high"=>"error","medium"=>"warning","low"=>"note",_=>"none"},["properties"]=properties};
            if(Scalar(finding,"rule_id") is string rule&&!string.IsNullOrWhiteSpace(rule))result["ruleId"]=rule;
            if(!string.IsNullOrWhiteSpace(id))result["partialFingerprints"]=new JsonObject{["attackmapFindingId"]=id};
            var locations=new JsonArray();
            if(finding.TryGetProperty("locations",out var supplied))
            {
                if(supplied.ValueKind!=JsonValueKind.Array)unsafeLocations++;
                else foreach(var location in supplied.EnumerateArray().Take(256))
                {
                    if(totalLocations>=10000){unsafeLocations++;continue;}
                    if(location.ValueKind!=JsonValueKind.Object||Scalar(location,"file") is not string file||!SafeRelative(file)){unsafeLocations++;continue;}
                    string uri=string.Join("/",file.Replace('\\','/').Split('/').Select(Uri.EscapeDataString));
                    var physical=new JsonObject{["artifactLocation"]=new JsonObject{["uri"]=uri}};
                    if(location.TryGetProperty("line",out var line)&&line.ValueKind==JsonValueKind.Number&&line.TryGetInt32(out int number)&&number>0)physical["region"]=new JsonObject{["startLine"]=number};
                    locations.Add(new JsonObject{["physicalLocation"]=physical});
                    totalLocations++;
                }
                if(supplied.ValueKind==JsonValueKind.Array&&supplied.GetArrayLength()>256)unsafeLocations+=supplied.GetArrayLength()-256;
            }
            if(locations.Count>0)result["locations"]=locations;
            results.Add(result);index++;
        }
        bool partial=malformed>0||unsafeLocations>0||findings.GetArrayLength()>10000;
        var notification=new JsonObject{["level"]=partial?"warning":"note",["message"]=new JsonObject{["text"]=$"Static projection only; coverage completeness unknown. {malformed} malformed findings and {unsafeLocations} unsafe/malformed locations omitted. Finding row cap10000; truncated: {findings.GetArrayLength()>10000}. Free-form evidence/secret payloads withheld; no paths inferred from prose, no security score derived."}};
        var run=new JsonObject{["tool"]=new JsonObject{["driver"]=new JsonObject{["name"]="AttackMap selected-report projection"}},["results"]=results,["properties"]=new JsonObject{["generationId"]=generation,["sourceReportSha256"]=reportHash,["suppliedFindingCount"]=findings.GetArrayLength(),["partialProjection"]=partial,["coverageCompleteness"]="unknown",["scanLimitationsSuppliedCount"]=scan.TryGetProperty("limitations",out var limits)&&limits.ValueKind==JsonValueKind.Array?JsonValue.Create(limits.GetArrayLength()):null},["invocations"]=new JsonArray(new JsonObject{["executionSuccessful"]=true,["toolExecutionNotifications"]=new JsonArray(notification)})};
        run["properties"]!["resourceLimitReporting"]=Scalar(scan,"resource_limit_reporting")??"unknown";
        run["properties"]!["analyzerErrorsSuppliedCount"]=scan.TryGetProperty("analyzer_errors",out var errors)&&errors.ValueKind==JsonValueKind.Array?JsonValue.Create(errors.GetArrayLength()):null;
        return new JsonObject{["$schema"]="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",["version"]="2.1.0",["runs"]=new JsonArray(run)}.ToJsonString(new JsonSerializerOptions{WriteIndented=true});
    }
    private static bool SafeRelative(string file)=>file.Length>0&&!file.Any(char.IsControl)&&!file.StartsWith('/')&&!file.StartsWith('\\')&&!file.Contains(':')&&!file.Replace('\\','/').Split('/').Any(p=>p is "" or "." or "..");
    private static string? Scalar(JsonElement item,string key)=>item.TryGetProperty(key,out var value)&&value.ValueKind is JsonValueKind.String or JsonValueKind.Number?value.ToString():null;
}
