using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AttackMap.NativeSpike;

int checks=0;
void Check(bool value,string description){if(!value)throw new Exception(description);checks++;}
string paths="# Paths\n```mermaid\nflowchart TD\nP1_0[\"Request\"]\nP1_1[\"Impact\"]\nclass P1_1 impact\nP1_0 --> P1_1\nclassDef impact fill:#fee,stroke:#c33,color:#900;\n```\n";
var parsed=DiagramParser.Parse(paths);
Check(parsed.Renderable&&parsed.Nodes.Select(n=>n.Id).SequenceEqual(new[]{"P1_0","P1_1"})&&parsed.Edges.Count==1,"Preserve path order and exact supplied edge");
Check(parsed.TextAlternative.Contains(paths),"Complete supplied source retained");
Check(DiagramLayout.Positions(parsed).SequenceEqual(DiagramLayout.Positions(parsed)),"Deterministic layout");
var topology=DiagramParser.Parse("flowchart LR\nS0[\"api\"]\nS1[\"db\"]\nS0 -. \"queue\" .- S1\nS0 == \"async\" ==> S1\nlinkStyle 0 stroke:#888,stroke-dasharray:2 4;");
Check(topology.Renderable&&topology.Edges.Count==2&&!topology.Edges[0].Directed&&topology.Edges[1].Directed,"Preserve parallel undirected/directed operators");
foreach(string hostile in new[]{"click P1_0 href \"https://hostile.invalid\"","%%{init: {'securityLevel':'loose'}}%%","<script>alert(1)</script>","P1_0 --> missing","P1_0[\"duplicate\"]"})
{var result=DiagramParser.Parse(paths.Replace("```\n",hostile+"\n```\n"));Check(!result.Renderable&&result.Source.Contains(hostile),"Hostile/unsupported syntax falls back without lost source");}
Check(DiagramParser.Parse("flowchart TD\nA[\"<script>fetch('https://bad.invalid')</script>\"]").Nodes[0].Label.Contains("<script>"),"Hostile label is retained as literal native text");
Check(!DiagramParser.Parse("").Renderable,"Empty fallback");
Check(!DiagramParser.Parse("```mermaid\nflowchart TD\nA[\"a\"]").Renderable,"Unclosed block fallback");
string large="flowchart TD\n"+string.Join("\n",Enumerable.Range(0,121).Select(i=>$"N{i}[\"{i}\"]"));
Check(!DiagramParser.Parse(large).Renderable&&DiagramParser.Parse(large).Source==large,"Large node set complete source fallback");
Check(!DiagramParser.Parse(new string('x',DiagramParser.MaxCharacters+1)).Renderable,"Character bound");
string root=Path.Combine(Path.GetTempPath(),"attackmap-diagram-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
try
{
    string report=Path.Combine(root,"attackmap-report.json"),diagram=Path.Combine(root,"attackmap-paths.md"),manifest=Path.Combine(root,"artifact-manifest.json");
    File.WriteAllText(report,"{\"scan\":{\"limitations\":[\"partial fixture\"]}}",new UTF8Encoding(false));File.WriteAllText(diagram,paths,new UTF8Encoding(false));
    string Hash(string path)=>Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
    object Entry(string name,string format)=>new{name,path=name,role="report",format,checksum=Hash(Path.Combine(root,name))};
    File.WriteAllText(manifest,JsonSerializer.Serialize(new{schema_version="1.0.0",artifact_type="attackmap_artifact_manifest",generation_id="synthetic-diagram",sections=new[]{Entry("attackmap-report.json","json"),Entry("attackmap-paths.md","md")},compatibility_exports=Array.Empty<object>()}));
    var selection=new ExportSelection(report,Hash(report),"synthetic-diagram",manifest,Hash(manifest),null,null);
    try{await DiagramSelectionReader.Read(selection with{ReportPath=@"\\hostile.invalid\share\attackmap-report.json"},"attackmap-paths.md");throw new Exception("Remote report accepted");}catch(InvalidDataException){checks++;}
    var loaded=await DiagramSelectionReader.Read(selection,"attackmap-paths.md");
    Check(loaded.Renderable&&loaded.Notice.Contains("limitations"),"Manifest-bound read carries supplied limitations");
    Check(!(await DiagramSelectionReader.Read(selection,"attackmap-topology.md")).Renderable,"Missing artifact explicit fallback");
    try{await DiagramSelectionReader.Read(selection with{RunId=null},"attackmap-paths.md");throw new Exception("Unverified read accepted");}catch(InvalidDataException){checks++;}
    File.AppendAllText(diagram,"tamper");
    try{await DiagramSelectionReader.Read(selection,"attackmap-paths.md");throw new Exception("Tamper accepted");}catch(InvalidDataException){checks++;}
    File.WriteAllText(diagram,paths,new UTF8Encoding(false));File.AppendAllText(report," ");
    try{await DiagramSelectionReader.Read(selection,"attackmap-paths.md");throw new Exception("Changed selected report accepted");}catch(InvalidDataException){checks++;}
}
finally{Directory.Delete(root,true);}
Console.WriteLine($"PASS {checks} diagram checks; no network, scripts, browser or engine execution");
