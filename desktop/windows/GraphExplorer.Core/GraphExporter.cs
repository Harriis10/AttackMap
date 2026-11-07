using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Xml;

namespace AttackMap.GraphExplorer;

/// <summary>Inert full-projection vector export; never reads back a viewport or drops the canonical JSON.</summary>
public static class GraphExporter
{
    public static string CanonicalJson(GraphDocument document) => document.SourceJson;

    public static string JsonWithMetadata(GraphDocument document, GraphProjection? projection = null)
    {
        if (projection is not null && projection.Document.Context != document.Context)
            throw new InvalidOperationException("Presentation metadata belongs to a different graph context.");
        var graph = System.Text.Json.Nodes.JsonNode.Parse(document.SourceJson)!.AsObject();
        graph["export_metadata"] = JsonSerializer.SerializeToNode(new {
            context = document.Context, scope = "Entire captured canonical model, including all filtered or collapsed facts.",
            collapsed_ids = projection?.CollapsedIds.Order().ToArray() ?? [],
            resolution_filter = projection?.Filter.Resolution.ToString() ?? "All",
            inter_repository_only = projection?.Filter.InterRepositoryOnly ?? false,
            neighborhood = projection?.Filter.Neighborhood.ToString() ?? "All",
            focus_node_id = projection?.Filter.FocusNodeId,
            filtered_edge_count = projection?.FilteredEdgeCount ?? 0,
            overview_path_warning = GraphDocument.AggregatePathWarning });
        return graph.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    public static string Svg(GraphProjection projection, LayoutSnapshot layout)
    {
        if (!layout.IsCurrent(projection.Document.Context)
            || !layout.Nodes.Select(x => x.Id).Order().SequenceEqual(projection.Nodes.Select(x => x.Id).Order())
            || !layout.Edges.Select(x => x.Id).Order().SequenceEqual(projection.Edges.Select(x => x.Id).Order()))
            throw new InvalidOperationException("Layout is stale or belongs to a different projection.");
        string F(double x) => x.ToString("0.###", CultureInfo.InvariantCulture);
        var builder = new StringBuilder();
        using var writer = XmlWriter.Create(builder, new XmlWriterSettings { OmitXmlDeclaration = true, Indent = true });
        writer.WriteStartElement("svg", "http://www.w3.org/2000/svg");
        writer.WriteAttributeString("viewBox", $"0 0 {F(layout.Bounds.Width)} {F(layout.Bounds.Height)}");
        writer.WriteAttributeString("width", F(layout.Bounds.Width)); writer.WriteAttributeString("height", F(layout.Bounds.Height));
        writer.WriteStartElement("title"); writer.WriteString("AttackMap fleet architecture — complete selected projection"); writer.WriteEndElement();
        writer.WriteStartElement("desc"); writer.WriteString(GraphDocument.AggregatePathWarning); writer.WriteEndElement();
        writer.WriteStartElement("metadata");
        writer.WriteString(JsonSerializer.Serialize(new {
            context = projection.Document.Context, collapsed_ids = projection.CollapsedIds.Order(),
            hidden_nodes = projection.HiddenNodeCount, hidden_internal_edges = projection.HiddenInternalEdgeCount,
            filters = new { resolution = projection.Filter.Resolution.ToString(), inter_repository_only = projection.Filter.InterRepositoryOnly,
                neighborhood = projection.Filter.Neighborhood.ToString(), focus_node_id = projection.Filter.FocusNodeId }, filtered_edges = projection.FilteredEdgeCount,
            repositories = projection.Document.Repositories, coverage = projection.Document.Coverage,
            limitations = projection.Document.Limitations, engine = layout.Engine,
            maximum_ellipse_deviation_dip = layout.MaximumEllipseDeviation,
            scope = "Entire selected presentation; canonical JSON includes all captured nodes, edges and evidence." }));
        writer.WriteEndElement();
        writer.WriteStartElement("rect"); Attr("x", "0"); Attr("y", "0"); Attr("width", F(layout.Bounds.Width)); Attr("height", F(layout.Bounds.Height)); Attr("fill", "#ffffff"); writer.WriteEndElement();
        var modelNodes = projection.Nodes.ToDictionary(x => x.Id, StringComparer.Ordinal);
        // Groups first, then edges, then leaf controls; XML escaping keeps hostile labels inert.
        foreach (var node in layout.Nodes.Where(x => x.IsGroup)) Box(node);
        foreach (var edge in layout.Edges)
        {
            writer.WriteStartElement("path"); Attr("data-edge-id", edge.Id);
            var path = new StringBuilder();
            foreach (var segment in edge.Segments)
            {
                path.Append($"M{F(segment.Start.X)},{F(segment.Start.Y)} ");
                if (segment.Kind == "cubic" && segment.Control1 is { } c1 && segment.Control2 is { } c2)
                    path.Append($"C{F(c1.X)},{F(c1.Y)} {F(c2.X)},{F(c2.Y)} {F(segment.End.X)},{F(segment.End.Y)} ");
                else path.Append($"L{F(segment.End.X)},{F(segment.End.Y)} ");
            }
            Attr("d", path.ToString()); Attr("fill", "none"); Attr("stroke", "#596b80"); Attr("stroke-width", "1.5");
            writer.WriteStartElement("title");
            var model = projection.Edges.Single(x => x.Id == edge.Id);
            writer.WriteString($"{model.Kind}; {model.Resolution}; underlying edges: {string.Join(", ", model.UnderlyingEdgeIds)}");
            writer.WriteEndElement(); writer.WriteEndElement();
            foreach (var arrow in new[] { edge.SourceArrow, edge.TargetArrow }.OfType<LayoutArrow>())
            {
                writer.WriteStartElement("polygon"); Attr("points", $"{F(arrow.Tip.X)},{F(arrow.Tip.Y)} {F(arrow.Left.X)},{F(arrow.Left.Y)} {F(arrow.Right.X)},{F(arrow.Right.Y)}"); Attr("fill", "#596b80"); writer.WriteEndElement();
            }
            if (edge.LabelBounds is { } label) Text(label.X, label.Y + Math.Min(label.Height, 14), $"{model.Kind} ({model.Count})", 11);
        }
        foreach (var node in layout.Nodes.Where(x => !x.IsGroup)) Box(node);
        writer.WriteEndElement(); writer.Flush(); return builder.ToString();

        void Attr(string name, string value) => writer.WriteAttributeString(name, value);
        void Text(double x, double y, string value, int size)
        {
            writer.WriteStartElement("text"); Attr("x", F(x)); Attr("y", F(y)); Attr("font-family", "Segoe UI, sans-serif"); Attr("font-size", size.ToString(CultureInfo.InvariantCulture)); Attr("fill", "#172a43");
            writer.WriteString(value); writer.WriteEndElement();
        }
        void Box(LayoutNode node)
        {
            var model = modelNodes[node.Id];
            writer.WriteStartElement("g"); Attr("data-node-id", node.Id);
            writer.WriteStartElement("title"); writer.WriteString($"{model.Original.Label}; {model.Original.Kind}; underlying nodes {model.UnderlyingNodeIds.Length}; internal edges {model.InternalEdgeIds.Length}"); writer.WriteEndElement();
            writer.WriteStartElement("rect"); Attr("x", F(node.Bounds.X)); Attr("y", F(node.Bounds.Y)); Attr("width", F(node.Bounds.Width)); Attr("height", F(node.Bounds.Height)); Attr("rx", "6"); Attr("fill", node.IsGroup ? "#eef3f8" : "#ffffff"); Attr("stroke", "#57718f"); writer.WriteEndElement();
            // The SVG's full label remains in title; a fixed visible prefix stays inside the measured node.
            string label = model.Original.Label.Length > 21 ? model.Original.Label[..20] + "…" : model.Original.Label;
            Text(node.Bounds.X + 10, node.Bounds.Y + 20, label, 12);
            Text(node.Bounds.X + 10, node.Bounds.Y + 36, model.Original.Kind, 10);
            writer.WriteEndElement();
        }
    }
}
