using System.Collections.Immutable;
using System.Diagnostics;
using Microsoft.Msagl.Core;
using Microsoft.Msagl.Core.Geometry;
using Microsoft.Msagl.Core.Geometry.Curves;
using Microsoft.Msagl.Core.Layout;
using Microsoft.Msagl.Core.Routing;
using Microsoft.Msagl.Layout.Initial;
using Microsoft.Msagl.Layout.Layered;
using Microsoft.Msagl.Miscellaneous;

namespace AttackMap.GraphExplorer;

public readonly record struct LayoutPoint(double X, double Y);
public readonly record struct LayoutRect(double X, double Y, double Width, double Height)
{
    public double Right => X + Width;
    public double Bottom => Y + Height;
    public bool Contains(LayoutRect other, double tolerance = 0.01) => other.X >= X - tolerance
        && other.Y >= Y - tolerance && other.Right <= Right + tolerance && other.Bottom <= Bottom + tolerance;
}
public sealed record NodeMeasure(string Id, double Width, double Height);
public sealed record EdgeMeasure(string Id, double LabelWidth = 0, double LabelHeight = 0);
public enum LayoutDirection { TopToBottom, LeftToRight }
public sealed record LayoutRequest(GraphProjection Projection, ImmutableArray<NodeMeasure> NodeMeasures,
    ImmutableArray<EdgeMeasure> EdgeMeasures, LayoutDirection Direction = LayoutDirection.TopToBottom,
    int MaxNodes = 1000, int MaxEdges = 3000, double Margin = 24, double MaxExtent = 1_000_000);
public sealed record LayoutNode(string Id, string? ParentId, LayoutRect Bounds, bool IsGroup);
/// <summary>Native path commands: line or cubic, with exact solver control points.</summary>
public sealed record LayoutSegment(string Kind, LayoutPoint Start, LayoutPoint End,
    LayoutPoint? Control1 = null, LayoutPoint? Control2 = null);
public sealed record LayoutArrow(LayoutPoint Tip, LayoutPoint Base, LayoutPoint Left, LayoutPoint Right);
public sealed record LayoutEdge(string Id, ImmutableArray<LayoutSegment> Segments,
    LayoutArrow? SourceArrow, LayoutArrow? TargetArrow, LayoutRect? LabelBounds);
public sealed record LayoutSnapshot(GraphContext Context, ImmutableArray<LayoutNode> Nodes,
    ImmutableArray<LayoutEdge> Edges, LayoutRect Bounds, TimeSpan LayoutTime, LayoutDirection Direction,
    string Engine = "Msagl 1.2.1")
{
    /// <summary>Ellipse arcs use chord subdivision with a second-derivative error bound in DIPs. Lines/cubics are exact.</summary>
    public double MaximumEllipseDeviation => 0.25;
    public bool IsCurrent(GraphContext current) => Context.IsCurrent(current);
}

/// <summary>One worker at a time per adapter. Cancellation is cooperative and awaited to completion.</summary>
public sealed class MsaglLayoutAdapter
{
    private readonly SemaphoreSlim worker = new(1, 1);

    public async Task<LayoutSnapshot> LayoutAsync(LayoutRequest request, CancellationToken cancellationToken = default)
    {
        Validate(request);
        await worker.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await Task.Run(() => Layout(request, cancellationToken), cancellationToken).ConfigureAwait(false);
        }
        finally { worker.Release(); }
    }

    private static void Validate(LayoutRequest request)
    {
        if (request.Projection.Nodes.Length > request.MaxNodes || request.Projection.Edges.Length > request.MaxEdges)
            throw new GraphReadException($"Layout display budget exceeded ({request.MaxNodes} nodes/{request.MaxEdges} edges). Canonical graph remains available.");
        if (request.MaxNodes < 1 || request.MaxEdges < 0 || !double.IsFinite(request.Margin) || request.Margin < 0
            || !double.IsFinite(request.MaxExtent) || request.MaxExtent <= request.Margin * 2)
            throw new ArgumentException("Invalid layout bounds.", nameof(request));
        if (!Enum.IsDefined(request.Direction)) throw new ArgumentException("Unsupported layout direction.", nameof(request));
        var ids = request.Projection.Nodes.Select(x => x.Id).ToHashSet(StringComparer.Ordinal);
        var measures = new HashSet<string>(StringComparer.Ordinal);
        foreach (var n in request.NodeMeasures)
            if (!ids.Contains(n.Id) || !measures.Add(n.Id) || !FiniteSize(n.Width, n.Height) || n.Width < 1 || n.Height < 1)
                throw new ArgumentException("Exactly one finite measured box is required for every visible node.", nameof(request));
        if (measures.Count != ids.Count) throw new ArgumentException("Missing visible node measurements.", nameof(request));
        var edges = request.Projection.Edges.Select(x => x.Id).ToHashSet(StringComparer.Ordinal);
        var edgeMeasures = new HashSet<string>(StringComparer.Ordinal);
        foreach (var e in request.EdgeMeasures)
            if (!edges.Contains(e.Id) || !edgeMeasures.Add(e.Id) || !FiniteSize(e.LabelWidth, e.LabelHeight))
                throw new ArgumentException("Invalid edge measurements.", nameof(request));
    }
    private static bool FiniteSize(double w, double h) => double.IsFinite(w) && double.IsFinite(h) && w >= 0 && h >= 0 && w <= 16384 && h <= 16384;

    private static LayoutSnapshot Layout(LayoutRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var timer = Stopwatch.StartNew();
        var cancel = new CancelToken();
        using var registration = cancellationToken.Register(() => cancel.Canceled = true);
        var graph = new GeometryGraph { RootCluster = new Cluster() };
        var sizes = request.NodeMeasures.ToDictionary(x => x.Id, StringComparer.Ordinal);
        var labelSizes = request.EdgeMeasures.ToDictionary(x => x.Id, StringComparer.Ordinal);
        var groupIds = request.Projection.Nodes.Where(x => x.ParentId is not null).Select(x => x.ParentId!).ToHashSet(StringComparer.Ordinal);
        var nodes = new Dictionary<string, Node>(StringComparer.Ordinal);
        foreach (var spec in request.Projection.Nodes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var size = sizes[spec.Id];
            Node node;
            if (groupIds.Contains(spec.Id))
            {
                node = new Cluster { UserData = spec.Id, RectangularBoundary = new RectangularClusterBoundary {
                    LeftMargin = 18, RightMargin = 18, BottomMargin = 18, TopMargin = size.Height + 12,
                    MinWidth = size.Width, MinHeight = size.Height } };
            }
            else
            {
                node = new Node(CurveFactory.CreateRectangleWithRoundedCorners(size.Width, size.Height, 6, 6, new Point()), spec.Id);
                graph.Nodes.Add(node);
            }
            nodes.Add(spec.Id, node);
        }
        foreach (var spec in request.Projection.Nodes)
        {
            var parent = spec.ParentId is null ? graph.RootCluster : (Cluster)nodes[spec.ParentId];
            parent.AddChild(nodes[spec.Id]);
        }
        foreach (var spec in request.Projection.Edges)
        {
            var label = labelSizes.GetValueOrDefault(spec.Id) ?? new EdgeMeasure(spec.Id);
            var edge = new Edge(nodes[spec.Source], nodes[spec.Target], label.LabelWidth, label.LabelHeight, 1) { UserData = spec.Id };
            if (spec.Directed) edge.EdgeGeometry.TargetArrowhead = new Arrowhead { Length = 9 };
            graph.Edges.Add(edge);
        }
        var settings = new SugiyamaLayoutSettings();
        settings.EdgeRoutingSettings.EdgeRoutingMode = EdgeRoutingMode.Spline;
        if (request.Direction == LayoutDirection.LeftToRight)
            settings.Transformation = PlaneTransformation.Rotation(Math.PI / 2);
        if (groupIds.Count > 0)
        {
            var layout = new InitialLayoutByCluster(graph, settings) { RunInParallel = false };
            layout.Run(cancel);
            LayoutHelpers.RouteAndLabelEdges(graph, settings, graph.Edges, 0, cancel);
        }
        else if (graph.Nodes.Count > 0) LayoutHelpers.CalculateLayout(graph, settings, cancel, null);
        cancellationToken.ThrowIfCancellationRequested();
        graph.UpdateBoundingBox();
        if (nodes.Count == 0) return new(request.Projection.Document.Context, [], [], new(0, 0, request.Margin * 2, request.Margin * 2), timer.Elapsed, request.Direction);

        // All own rectangles, curve control hulls, label boxes and arrow polygons participate in bounds.
        var rawNodes = request.Projection.Nodes.Select(x => new LayoutNode(x.Id, x.ParentId, Rect(nodes[x.Id].BoundingBox), groupIds.Contains(x.Id))).ToImmutableArray();
        var rawEdges = graph.Edges.Select(edge =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (edge.Curve is null) throw new GraphReadException($"Layout produced no curve for edge {edge.UserData}; no fabricated line was substituted.");
            var segments = ImmutableArray.CreateBuilder<LayoutSegment>();
            AddCurve(edge.Curve, segments, cancellationToken);
            return new LayoutEdge((string)edge.UserData, segments.ToImmutable(),
                Arrow(edge.EdgeGeometry.SourceArrowhead, edge.Curve.Start),
                Arrow(edge.EdgeGeometry.TargetArrowhead, edge.Curve.End),
                edge.Label is null ? null : Rect(edge.Label.BoundingBox));
        }).ToImmutableArray();
        var points = rawNodes.SelectMany(x => Corners(x.Bounds)).Concat(rawEdges.SelectMany(Points)).ToArray();
        if (points.Any(p => !double.IsFinite(p.X) || !double.IsFinite(p.Y))) throw new GraphReadException("Layout produced non-finite geometry.");
        double minX = points.Min(p => p.X), maxX = points.Max(p => p.X), minY = points.Min(p => p.Y), maxY = points.Max(p => p.Y);
        double width = maxX - minX + 2 * request.Margin, height = maxY - minY + 2 * request.Margin;
        if (!double.IsFinite(width) || !double.IsFinite(height) || width > request.MaxExtent || height > request.MaxExtent)
            throw new GraphReadException("Layout exceeds supported coordinate extent; retain full canonical export and choose a smaller display projection.");
        LayoutPoint Translate(LayoutPoint p) => new(request.Margin + p.X - minX, request.Margin + p.Y - minY);
        LayoutRect TranslateRect(LayoutRect r) { var p = Translate(new(r.X, r.Y)); return new(p.X, p.Y, r.Width, r.Height); }
        LayoutArrow? TranslateArrow(LayoutArrow? a) => a is null ? null : new(Translate(a.Tip), Translate(a.Base), Translate(a.Left), Translate(a.Right));
        var outputNodes = rawNodes.Select(n => n with { Bounds = TranslateRect(n.Bounds) }).ToImmutableArray();
        var outputEdges = rawEdges.Select(e => e with {
            Segments = e.Segments.Select(s => s with { Start = Translate(s.Start), End = Translate(s.End), Control1 = s.Control1 is { } c1 ? Translate(c1) : null, Control2 = s.Control2 is { } c2 ? Translate(c2) : null }).ToImmutableArray(),
            SourceArrow = TranslateArrow(e.SourceArrow), TargetArrow = TranslateArrow(e.TargetArrow),
            LabelBounds = e.LabelBounds is { } label ? TranslateRect(label) : null }).ToImmutableArray();
        cancellationToken.ThrowIfCancellationRequested();
        timer.Stop();
        return new(request.Projection.Document.Context, outputNodes, outputEdges, new(0, 0, width, height), timer.Elapsed, request.Direction);
    }

    // Invert Y once. Native controls and their text use these Y-down effective pixel coordinates directly.
    private static LayoutPoint Point(Point p) => new(p.X, -p.Y);
    private static LayoutRect Rect(Rectangle r) => new(r.Left, -r.Top, r.Width, r.Height);
    private static LayoutArrow? Arrow(Arrowhead? arrow, Point curveEnd)
    {
        if (arrow is null) return null;
        var tip = Point(arrow.TipPosition); var origin = Point(curveEnd);
        double dx = tip.X - origin.X, dy = tip.Y - origin.Y, length = Math.Sqrt(dx * dx + dy * dy);
        if (!double.IsFinite(length) || length < 0.001) throw new GraphReadException("Degenerate arrow geometry.");
        double half = Math.Min(5, length / 2);
        return new(tip, origin, new(origin.X - dy / length * half, origin.Y + dx / length * half), new(origin.X + dy / length * half, origin.Y - dx / length * half));
    }
    private static void AddCurve(ICurve curve, ImmutableArray<LayoutSegment>.Builder segments, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (segments.Count > 8192) throw new GraphReadException("Edge curve complexity exceeds geometry budget.");
        switch (curve)
        {
            case Curve composite:
                foreach (var segment in composite.Segments) AddCurve(segment, segments, cancellationToken);
                break;
            case CubicBezierSegment bezier:
                segments.Add(new("cubic", Point(bezier.B(0)), Point(bezier.B(3)), Point(bezier.B(1)), Point(bezier.B(2))));
                break;
            case LineSegment line:
                segments.Add(new("line", Point(line.Start), Point(line.End)));
                break;
            case Ellipse ellipse:
                // For any interval h, chord error <= h^2 * sup|r''| / 8.
                // r'' = -AxisA*cos(t)-AxisB*sin(t), so |A|+|B| is a conservative bound.
                double acceleration = ellipse.AxisA.Length + ellipse.AxisB.Length;
                double span = Math.Abs(ellipse.ParEnd - ellipse.ParStart);
                double maxStep = acceleration > 0 ? Math.Sqrt(8 * 0.25 / acceleration) : span;
                int count = Math.Max(1, (int)Math.Ceiling(span / Math.Max(1e-9, maxStep)));
                if (count + segments.Count > 8192) throw new GraphReadException("Ellipse exceeds bounded geometry complexity.");
                for (int i = 0; i < count; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    double a = ellipse.ParStart + (ellipse.ParEnd - ellipse.ParStart) * i / count;
                    double b = ellipse.ParStart + (ellipse.ParEnd - ellipse.ParStart) * (i + 1) / count;
                    segments.Add(new("line", Point(ellipse[a]), Point(ellipse[b])));
                }
                break;
            case Polyline polyline:
                var values = polyline.PolylinePoints.Select(p => p.Point).ToArray();
                for (int i = 1; i < values.Length; i++) segments.Add(new("line", Point(values[i - 1]), Point(values[i])));
                if (polyline.Closed && values.Length > 1) segments.Add(new("line", Point(values[^1]), Point(values[0])));
                break;
            default:
                // Reject unsupported geometry explicitly rather than silently straightening curves.
                throw new GraphReadException($"Unsupported solver curve {curve.GetType().Name}; full graph remains available.");
        }
    }
    private static IEnumerable<LayoutPoint> Corners(LayoutRect r) { yield return new(r.X, r.Y); yield return new(r.Right, r.Bottom); }
    private static IEnumerable<LayoutPoint> Points(LayoutEdge edge)
    {
        foreach (var s in edge.Segments) { yield return s.Start; yield return s.End; if (s.Control1 is { } a) yield return a; if (s.Control2 is { } b) yield return b; }
        foreach (var arrow in new[] { edge.SourceArrow, edge.TargetArrow }.OfType<LayoutArrow>())
        { yield return arrow.Tip; yield return arrow.Base; yield return arrow.Left; yield return arrow.Right; }
        if (edge.LabelBounds is { } label) foreach (var p in Corners(label)) yield return p;
    }
}
