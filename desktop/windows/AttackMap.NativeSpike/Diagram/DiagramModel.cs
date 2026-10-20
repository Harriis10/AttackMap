using System.Text;
using System.Text.RegularExpressions;

namespace AttackMap.NativeSpike;

public sealed record DiagramNode(string Id, string Label);
public sealed record DiagramEdge(string Source, string Target, string Label, string Operator, bool Directed);
public sealed record DiagramDocument(string Source, IReadOnlyList<DiagramNode> Nodes, IReadOnlyList<DiagramEdge> Edges, bool Renderable, string Notice)
{
    public string TextAlternative => Notice + "\n\n" + string.Join("\n", Nodes.Select((n,i)=>$"Node {i+1}: {n.Id} — {n.Label}")) + "\n" +
        string.Join("\n", Edges.Select((e,i)=>$"Edge {i+1}: {e.Source} {(e.Directed ? "→" : "—")} {e.Target} [{e.Operator}] {e.Label}")) + "\n\nComplete supplied source:\n" + Source;
}

/// <summary>Bounded, execution-free subset of core Mermaid exports. Unknown syntax fails closed to inert source.</summary>
public static class DiagramParser
{
    public const int MaxCharacters=4*1024*1024, MaxNodes=120, MaxEdges=240;
    private const string Id="[A-Za-z_][A-Za-z0-9_]*";
    private static Regex Pattern(string expression)=>new(expression,RegexOptions.CultureInvariant,TimeSpan.FromMilliseconds(100));
    private static readonly Regex Node=Pattern("^("+Id+")\\[\"([^\"]*)\"\\]$");
    private static readonly Regex LabeledEdge=Pattern("^("+Id+")\\s+(--|\\-\\.|==)\\s+\"([^\"]*)\"\\s+(-->|\\.->|\\.-|==>)\\s+("+Id+")$");
    private static readonly Regex Chain=Pattern("^"+Id+"(?:\\s*-->\\s*"+Id+")+$");
    private static readonly Regex Style=Pattern("^(?:class "+Id+" impact|classDef impact fill:#fee,stroke:#c33,color:#900;|linkStyle [0-9]+ (?:stroke:#2b7,stroke-dasharray:5 5;|stroke:#888,stroke-dasharray:2 4;|stroke:#a52,stroke-width:2px;))$");
    public static DiagramDocument Parse(string? source)
    {
        source??="";
        DiagramDocument Fallback(string reason)=>new(source,Array.Empty<DiagramNode>(),Array.Empty<DiagramEdge>(),false,reason+" No graph inferred. Complete accepted source remains plain text.");
        if(source.Length>MaxCharacters) return new("",Array.Empty<DiagramNode>(),Array.Empty<DiagramEdge>(),false,"Diagram exceeds the 4 Mi character display bound. No content rendered; use the selected artifact export for the full source.");
        if(string.IsNullOrWhiteSpace(source))return Fallback("Diagram is empty; this is not assurance of a complete or safe system.");
        var nodes=new List<DiagramNode>();var edges=new List<DiagramEdge>();var ids=new HashSet<string>(StringComparer.Ordinal);
        bool fenced=source.Contains("```mermaid",StringComparison.Ordinal),inside=!fenced,header=false,seen=false;
        try
        {
            foreach(string raw in source.Replace("\r\n","\n").Split('\n'))
            {
                string line=raw.Trim();
                if(line.Length>8192)return Fallback("Diagram line exceeds display bounds.");
                if(line=="```mermaid") {if(inside)return Fallback("Nested Mermaid block.");inside=true;header=false;continue;}
                if(line=="```"&&inside&&fenced){inside=false;continue;}
                if(!inside||line.Length==0)continue;
                if(!header)
                {
                    if(line is not ("flowchart TD" or "flowchart LR" or "graph TD" or "graph LR"))return Fallback("Unsupported diagram header.");
                    header=true;seen=true;continue;
                }
                var node=Node.Match(line);
                if(node.Success)
                {
                    string id=node.Groups[1].Value,label=node.Groups[2].Value;
                    if(label.Length>2048||!ids.Add(id))return Fallback("Duplicate node identity or oversized label.");
                    nodes.Add(new(id,label.Replace("\\\\","\\",StringComparison.Ordinal)));
                }
                else if(LabeledEdge.Match(line) is {Success:true} edge)
                {
                    string op=edge.Groups[2].Value+" "+edge.Groups[4].Value;
                    if(op is not ("-- -->" or "-. .->" or "-. .-" or "== ==>"))return Fallback("Unsupported edge operator pairing.");
                    edges.Add(new(edge.Groups[1].Value,edge.Groups[5].Value,edge.Groups[3].Value.Replace("\\\\","\\",StringComparison.Ordinal),op,op!="-. .-"));
                }
                else if(Chain.IsMatch(line))
                {
                    var chain=line.Split("-->",StringSplitOptions.TrimEntries);
                    for(int i=1;i<chain.Length;i++)edges.Add(new(chain[i-1],chain[i],"","-->",true));
                }
                else if(!Style.IsMatch(line))return Fallback("Unsupported or malformed Mermaid syntax; native renderer did not interpret it.");
                if(nodes.Count>MaxNodes||edges.Count>MaxEdges)return Fallback("Diagram exceeds native node/edge bounds; full source is available below.");
            }
        }
        catch(RegexMatchTimeoutException){return Fallback("Diagram parsing exceeded its bounded work budget.");}
        if(fenced&&inside)return Fallback("Unclosed Mermaid block.");
        if(!seen||nodes.Count==0)return Fallback("No supported graph supplied.");
        if(edges.Any(e=>!ids.Contains(e.Source)||!ids.Contains(e.Target)))return Fallback("An edge references an undeclared node; no nodes were invented.");
        return new(source,nodes.AsReadOnly(),edges.AsReadOnly(),true,"Supplied nodes and edges in source order. Layout is presentation only; no joins, scores, or completeness inferred. Original labels and edge operators are preserved below.");
    }
}

public sealed record DiagramPosition(string Id,double X,double Y);
public static class DiagramLayout
{
    // A fixed declaration-order grid avoids graph traversal heuristics, cycles and nondeterministic force layout.
    public static IReadOnlyList<DiagramPosition> Positions(DiagramDocument diagram)=>diagram.Nodes.Select((node,index)=>new DiagramPosition(node.Id,40+(index%3)*300,40+(index/3)*140)).ToArray();
}
