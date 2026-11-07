# MSAGL 1.2.1 → současný WinUI Canvas: praktické napojení

**Navazující požadavek:** [celé schéma 16 repos](fleet16-requirements.md) vyžaduje cluster-aware projekci a stejné fleet acceptance jako webový kandidát. Nativní větev má nadále portable výhody; výběr se ale neuzavře před stejně prioritním srovnáním grouping/drill-down obou variant. Níže je technický podklad, nikoli již vybraný renderer.

Stav: výzkum a návrh 23. 10. 2026; žádný produktový patch, instalace závislosti, build ani GUI ověření. Ilustrační C# níže nebyl kompilován ani spuštěn. Pro současný nativní Windows shell doporučuji nejprve omezený spike **MSAGL core jako výpočet geometrie + vlastní WinUI renderer**. Cytoscape.js má výhodu hotových grafových interakcí; může vyhrát, pokud reálný corpus ukáže neúnosnou práci/výkon nativní plochy nebo pokud se stane prioritou bohatý sdílený grafový explorer.

## Co bylo skutečně ověřeno

CodeGraph byl znovu prvním krokem pro `DiagramLayout.Positions` a `DiagramView.Show`. Současný `DiagramModel.cs:79–80` používá třísloupcovou mřížku. `DiagramView.cs:67–97` již kreslí Canvas, hrany/šipky a nativní obdélníky; `:15–41` má ScrollViewer zoom/pan a text/copy/export. Tyto části je možné zachovat. Pevné porty bottom→top a pevný Canvas width se musí při napojení geometrie změnit.

Oficiální [NuGet Msagl 1.2.1](https://www.nuget.org/packages/Msagl/1.2.1) uvádí core layout, target .NET Standard 2.0, MIT a žádné deklarované NuGet dependency. Pro .NET 8 je zobrazena vypočtená kompatibilita; nejde o provedený WinUI build. NUPKG byl přečten přímo z [oficiálního NuGet flat-container endpointu](https://api.nuget.org/v3-flatcontainer/msagl/1.2.1/msagl.1.2.1.nupkg) pouze v paměti. Obsahuje `lib/netstandard2.0/Microsoft.Msagl.dll` a XML dokumentaci. SHA-256 celého staženého NUPKG: `11e3323a7aa654033379b295d2839830f815333c4f27c18ea64107a7a61e9f43`.

XML dokumentace, veřejné PE metadata a vybrané IL instrukce byly čteny bez načtení/spuštění assembly. Nebyl použit NuGet restore ani zápis DLL do repozitáře. **„Žádné deklarované NuGet dependency“ neznamená žádné runtime reference:** DLL odkazuje na `netstandard, Version=2.0.0.0` a `System.Text.Json, Version=4.0.1.2`. Moderní .NET host a skutečný portable runtime binding je třeba ověřit ve spike; automaticky nepřidávat starý balíček System.Text.Json podle současného upstream projektu.

NUSPEC neobsahuje repository commit a veřejný [seznam Git tagů](https://api.github.com/repos/microsoft/automatic-graph-layout/git/refs/tags) neposkytl tag 1.2.1. Nelze proto označit libovolný current/master commit za přesný release source. Zdrojové odkazy dále jsou připnuté k tehdy aktuálnímu upstream HEAD `d934786129f1db1c4c91e5812ce26928f6f7992b` z 7. 10. 2026; release API bylo kontrolováno zvlášť v balíčku. Například [aktuální csproj](https://github.com/microsoft/automatic-graph-layout/blob/d934786129f1db1c4c91e5812ce26928f6f7992b/GraphLayout/MSAGL/AutomaticGraphLayout.csproj) obsahuje PackageReference System.Text.Json 4.7.2, zatímco zveřejněný NUSPEC 1.2.1 jej neuvádí.

## Konkrétní dostupné API

Následující typy/signatury byly nalezeny v dokumentaci a veřejných metadatech **release 1.2.1**, nikoli pouze na master:

| Úloha | API a účel |
| --- | --- |
| Geometrický graf | `Microsoft.Msagl.Core.Layout.GeometryGraph`; kolekce `Nodes`, `Edges`, výsledné `BoundingBox`. |
| Geometrie uzlu | `Node(ICurve)` nebo `Node(ICurve, object userData)`; `BoundaryCurve`, `Center`, `BoundingBox`. |
| Rozměr uzlu | `CurveFactory.CreateRectangle(width,height,Point)` nebo `CreateRectangleWithRoundedCorners(width,height,radiusX,radiusY,Point)` v `Core.Geometry.Curves`. |
| Hrana a rozměr jejího popisku | `Edge(Node,Node)` nebo `Edge(Node,Node,double labelWidth,double labelHeight,double edgeThickness)`; `Curve`, `EdgeGeometry`, inherited `UserData`. |
| Šipka | `Core.Layout.Arrowhead`; `Length`, `TipPosition`; `EdgeGeometry.SourceArrowhead/TargetArrowhead`. |
| Vrstvený layout | `Layout.Layered.SugiyamaLayoutSettings`; veřejná `Transformation`. `LayeredLayout(GeometryGraph,SugiyamaLayoutSettings)` dědí `AlgorithmBase`. |
| Spuštění | `Miscellaneous.LayoutHelpers.CalculateLayout(GeometryGraph,LayoutAlgorithmSettings,Core.CancelToken,string tileDirectory)`; čtvrtý parametr je optional. Veřejný je také `AlgorithmBase.Run(CancelToken)`. |
| Rušení | `Core.CancelToken.Canceled` je veřejně zapisovatelný; package IL potvrzuje volatile přístup. Není to `System.Threading.CancellationToken`. |

Oficiální [README upstreamu](https://github.com/microsoft/automatic-graph-layout/blob/d934786129f1db1c4c91e5812ce26928f6f7992b/README.md#L14) odděluje core layout, Drawing, WPF a Windows Forms viewer. **WPF viewer není WinUI 3 control ani drop-in náhrada našeho Canvasu.** Pro tento spike stačí uvažovat core Msagl; vlastní rendering/interaction je stále naše práce.

## Malý ilustrační builder — neověřený sestavením

Vstupní velikosti musí být změřené v UI ve stejném fontu a efektivních pixelech, jakými bude vykreslován výsledek. ID jsou explicitní ID vstupní projekce; z popisku se nic neodvozuje. Ukázka ilustruje pouze výpočet geometrie; ještě nevytváří WinUI controls, finite/size validaci, produkční výstupní DTO ani edge hit-test.

```csharp
using Microsoft.Msagl.Core;
using Microsoft.Msagl.Core.Geometry;
using Microsoft.Msagl.Core.Geometry.Curves;
using Microsoft.Msagl.Core.Layout;
using Microsoft.Msagl.Layout.Layered;
using Microsoft.Msagl.Miscellaneous;

static GeometryGraph Arrange(
    IReadOnlyList<(string Id, double W, double H)> nodes,
    IReadOnlyList<(string Id, string Source, string Target,
                   bool Directed, double LabelW, double LabelH)> edges,
    CancelToken cancel)
{
    var graph = new GeometryGraph();
    var byId = new Dictionary<string, Node>(StringComparer.Ordinal);
    foreach (var spec in nodes)
    {
        var boundary = CurveFactory.CreateRectangleWithRoundedCorners(
            spec.W, spec.H, 6, 6, new Point(0, 0));
        var node = new Node(boundary, spec.Id);
        byId.Add(spec.Id, node);
        graph.Nodes.Add(node);
    }
    foreach (var spec in edges)
    {
        var edge = new Edge(byId[spec.Source], byId[spec.Target],
                            spec.LabelW, spec.LabelH, 1) { UserData = spec.Id };
        if (spec.Directed)
            edge.EdgeGeometry.TargetArrowhead = new Arrowhead();
        graph.Edges.Add(edge);
    }
    LayoutHelpers.CalculateLayout(
        graph, new SugiyamaLayoutSettings(), cancel, null);
    return graph;
}
```

Ukázka je vlastní minimální adaptace API. [Node.cs](https://github.com/microsoft/automatic-graph-layout/blob/d934786129f1db1c4c91e5812ce26928f6f7992b/GraphLayout/MSAGL/Core/Layout/Node.cs#L48) vysvětluje boundary/userData a bounds; [CurveFactory.cs](https://github.com/microsoft/automatic-graph-layout/blob/d934786129f1db1c4c91e5812ce26928f6f7992b/GraphLayout/MSAGL/Core/Geometry/Curves/CurveFactory.cs#L41) obdélníkové hranice; [Edge.cs](https://github.com/microsoft/automatic-graph-layout/blob/d934786129f1db1c4c91e5812ce26928f6f7992b/GraphLayout/MSAGL/Core/Layout/Edge.cs#L96) rozměr popisku a curve. [LayoutHelpers.cs:32](https://github.com/microsoft/automatic-graph-layout/blob/d934786129f1db1c4c91e5812ce26928f6f7992b/GraphLayout/MSAGL/Miscellaneous/LayoutHelpers.cs#L32) je synchronní helper; upstream jej označuje za kompatibilitní API. Jeho release existence neznamená, že řeší WinUI, a11y nebo runtime bezpečnost za aplikaci.

## Threading a cancel: přesná hranice

Návrh: na UI vlákně změřit nativní text/boxy, zkopírovat vstup a zachytit `(reportHash,generation,selectionRevision)`. Pro jednu výpočetní úlohu vytvořit vlastní GeometryGraph, settings a CancelToken. Výpočet a převod curves do neměnného `LayoutSnapshot` běží na workeru. Na UI vlákno předat pouze vlastní výsledné DTO; publikovat jen pro stále shodnou identitu.

`CancellationToken.Register(() => msaglCancel.Canceled = true)` propojí lifecycle/report switching s MSAGL flagem. `Task.Run(..., cancellationToken)` samo o sobě nezruší synchronní výpočet, který už začal. Rušení je kooperativní; timeout čekání není důkaz ukončené CPU práce. Zpracovat OperationCanceledException, nepoužít rozpracovanou geometrii a nevyvolat souběžně neomezený počet nových layoutů. Doporučená fronta má jeden aktivní výpočet a pouze nejnovější čekající požadavek.

Důležitá kontrola zdrojů: [LayeredLayout.RunInternal:53–60](https://github.com/microsoft/automatic-graph-layout/blob/d934786129f1db1c4c91e5812ce26928f6f7992b/GraphLayout/MSAGL/Layout/Layered/LayeredLayout.cs#L53) volá vnitřní `engine.Run()` bez argumentu. To **není důkaz ztraceného tokenu**: [AlgorithmBase.cs:14–81](https://github.com/microsoft/automatic-graph-layout/blob/d934786129f1db1c4c91e5812ce26928f6f7992b/GraphLayout/MSAGL/Core/AlgorithmBase.cs#L14) ukládá token thread-static a child Run jej dědí. Helper/Sugiyama větev jej předává explicitně. Rozdíl no-arg/arg call byl potvrzen i v IL balíčku. [CancelToken.cs](https://github.com/microsoft/automatic-graph-layout/blob/d934786129f1db1c4c91e5812ce26928f6f7992b/GraphLayout/MSAGL/Core/CancelToken.cs#L14) nastavuje flag; nedává pevnou maximální latenci ukončení. Tu musí změřit zátěžový/cancel spike.

## Co musí udělat náš WinUI adaptér

Následující body jsou implementační návrh odvozený ze současného controlu a geometrického API, nikoli vlastnosti hotového MSAGL vieweru.

1. **Vstup a identita.** Ponechat DiagramSelectionReader/ExportSelection, hash revalidation, revision checks, loading/fallback/text a Stop. Geometrická ID vést přes slovníky/UserData k původnímu node/edge ID; renderovací pořadí nesmí vytvořit evidence join. Nový evidence GraphDocument z WP043 řešit stejně pro obě technologie. Legacy Mermaid ID zůstane jen display ID.
2. **Text a rozměry.** Změřit uzel i edge label v DIPs před výpočtem, s omezenou šířkou a paddingem. Přepočítat po změně text scaling/fontu; theme-only změna barvy nepotřebuje nový model. MSAGL nezná skutečnou velikost WinUI TextBlocku. Výstupní bounds musí zahrnout i popisky/arrowheads a být konečné/omezené.
3. **Souřadnice.** Pro graph bounds `B` a margin `m` použít `x=m+p.X-B.Left`, `y=m+B.Top-p.Y`. Uzlu nastavit left `m+N.Left-B.Left`, top `m+B.Top-N.Top`, width/height z jeho bounds. Nastavit Canvas width i height z výsledného rozsahu. Převrací se geometrie Y, nikoli text. Zvolenou TD/LR orientaci uložit do presentation requestu; `SugiyamaLayoutSettings.Transformation`/`PlaneTransformation.Rotation(double)` dovolují změnu orientace, jejíž znaménko a popisky je třeba otestovat na známém řetězci.
4. **Hrany a šipky.** Číst vypočtené `Edge.Curve`; převést segmenty na XAML PathGeometry nebo adaptivní polyline s měřenou odchylkou. Současná čtyřbodová spojnice se tím nahradí. Arrowhead tip a poslední tečna pocházejí z geometrie; nevkládat šipku vždy vertikálně jako dnes. Directed/undirected, candidate/proxy/kind a síla/barva zůstávají vlastnostmi původního modelu. Solverova orientace nesmí změnit tvrzení o směru. Prověřit self-loop, cycle, parallel edge, null curve a nepřekrytý edge label.
5. **Výběr a hit-test.** Uzly vykreslit jako focusable nativní controls nebo dodat vlastní AutomationPeer; nynější Border se samotným AutomationProperties.Name neřeší interaktivní selection. Hrana potřebuje oddělenou širší hit-area nebo vzdálenost od zploštěné křivky. Toleranci přepočítat podle zoomu, nikoli podle DPI dvakrát. Výběr musí nést přesný source ID a run/hash, ne text. Drag node není součástí minimálního read-only řezu; vyžadoval by lokální rerouting.
6. **Viewport a DPI.** Zachovat ScrollViewer zoom/pan/reset; přidat fit-to-bounds a zachování středu při resize. Transform world→DIP aplikovat jednou, zoom vlastnit na jednom místě. XAML používá [efektivní pixely](https://learn.microsoft.com/en-us/windows/apps/design/layout/screen-sizes-and-breakpoints-for-responsive-design#effective-pixels-and-scale-factor); RasterizationScale patří až k raster exportu/hranici fyzických pixelů. Neškálovat současně geometrické souřadnice i Canvas přes tentýž scale.
7. **Přístupnost.** V obou variantách zachovat synchronizovaný nativní seznam uzlů/hran a detail. U nativní plochy mají standardní controls a [FrameworkElementAutomationPeer](https://learn.microsoft.com/en-us/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.automation.peers.frameworkelementautomationpeer?view=windows-app-sdk-1.8) konkrétní cestu k UIA, ale správné focus pořadí, role, Selection/Invoke, keyboard a Narrator stále vyžadují implementaci a ruční ověření. Samotný geometrický obrázek není a11y acceptance.
8. **Velké grafy.** Současný limit 120 uzlů/240 hran neodstranit bez měření. Udržet omezené labely a povolený částečný/subgraph view zřetelně označený jako filtr. Pro tisíce prvků bude nutné změřit culling/batching a počet XAML controls; Canvas sám neposkytuje grafovou virtualizaci. MSAGL layout času/paměti a WinUI render jsou dva různé rozpočty. Zpomalení nepřeklasifikuje chybějící evidence jako empty.
9. **Export.** Text/JSON/DOT/Mermaid musí vycházet ze zvoleného core snapshotu, nikoli ze zpětného čtení Canvas.Children. PNG lze řešit zvlášť rasterizací ověřené scény s limitem rozměrů; SVG vyžaduje vlastní inertní serializaci geometry/text nebo další prověřený exporter. Core Msagl v tomto návrhu samo neposkytuje WinUI file picker ani hotový PNG export. Výběrový filtr/layout preference nejsou nové analytické důkazy.

## Pracnost proti Cytoscape.js

[Oficiální Cytoscape.js dokumentace](https://js.cytoscape.org/) popisuje JSON graph model, výběr/eventy, zoom/pan, layout API, PNG/JPEG export a extension layouts. U synchronního layoutu se `run()` vrátí až po výpočtu; `stop()` poskytuje užitečné zastavení průběžného layoutu, nikoli automatický hard timeout každého algoritmu. Nevyplývá z ní bezplatná WinUI/Narrator integrace. Níže je vlastní odhad práce pro AttackMap, bez naměřených termínů; nejde o benchmark knihoven.

| Práce | Nativní Canvas + MSAGL core | Cytoscape.js ve WinUI WebView2 |
| --- | --- | --- |
| První čitelný graph layout | Malý adapter existující plochy; převod routed curves vyžaduje péči. | Rychlý JSON/style adapter, mnoho grafových funkcí už existuje. Pro kvalitní layered layout je třeba zvlášť kvalifikovat zvolený algorithm/extension. |
| Výběr a procházení sousedů | Výběr, hit-test, zvýraznění, keyboard a filtry vytváříme. | Podstatná část interakcí je hotová; native detail a validované bridge zprávy jsou naše práce. |
| Nativní shell a UIA | Zachovává WinUI fonty/theme/controls a současný viewport; list/peers stále doplnit. | Focus mezi webem a shellem, theme/text scaling a nativní accessible alternativa vyžadují samostatné řešení. |
| Packaging a offline boundary | Jedna core .NET závislost + ověřit skutečné runtime reference; žádný nový web renderer. | Lokálně zabalit JS/CSS/extensions, kvalifikovat WebView2 Runtime a jeho deployment/updates, zavřít navigation/network boundary. |
| Bezpečnostní integrace | Inertní native text se zachová. DTO a limits kontrolujeme. | Validovat origin, typ/velikost/ID každé zprávy; žádné obecné host proxy ani přímé source path příkazy. |
| Velký dense graf | Vyšší vlastní práce na render budgetu/culling/hit testingu. | Silnější hotový explorer; výkon konkrétního layoutu a rendereru je přesto nutné změřit na shodném corpus. |
| Export | Existující raw text zachovat; grafický export dopracovat. | PNG/JPEG API usnadňuje vizuální export; manifest identity, destination a metadatové disclosure stále řídí host. |

WebView část není důvod k automatickému odmítnutí Cytoscape. [Oficiální WebView2 security guidance](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/security) vyžaduje ověřování původu a parametrů zpráv a úzké host rozhraní. Pro AttackMap by to znamenalo pouze lokální zabalenou stránku, validovaný GraphDocument, explicitní selection/export zprávy, zakázanou neočekávanou navigaci a prokázaný provoz bez network. Script knihovny zůstává potřebný; zákaz se týká vykonávání dodaného reportového obsahu.

## Rozhodovací spike a doporučení

Preferovat nativní variantu, pokud cíl zůstane **čitelné služby/cesty/fleet, bezpečný evidence drill-down a platform-native UX** a omezený corpus projde výkonem. Úspora je konkrétní: zůstane současná manifest boundary, host, text, viewport a export wiring. Nevýhoda je vlastní grafová interakce a překlad curves.

Cytoscape preferovat, pokud hlavní požadavek přejde na velký interaktivní explorer s mnoha graph gestures/compound views, nebo pokud změřená cena native geometry/hit-test/virtualizace převýší cenu kvalifikovaného WebView a accessible alternativy. Prototyp pěkného obrázku sám tuto hranici nerozhodne.

Oba kandidáti musí dostat stejný neměnný GraphDocument, stejný počet/ID/směr/basis hran a stejné labels. Minimální corpus: řetězec TD/LR, cycle/self-loop/parallel/disconnected, proxy a candidate, dlouhé a hostile labels, současná mez 120/240 a dohodnutý větší corpus. Změřit zvlášť load/measure, layout, UI publish, pan/zoom, paměť a cancel latency; žádné vymyšlené PASS či univerzální FPS/časové sliby. Přepnutí A→B během práce nesmí publikovat A; cancel/close musí mít ověřeně skončenou práci. Native Spike musí ověřit restore+runtime binding Msagl 1.2.1 v aktuálním .NET 8 WinUI produktu a portable balíčku. Skutečný světlo/tma/200 %/keyboard/Narrator/offline vizuální průchod zůstává terminální branou.

Návrh lze dodat ve čtyřech review řezech: (1) pure layout adapter + kontrakt fixtures, (2) native curves/bounds a fit, (3) selection/list/detail + lifecycle/cancel, (4) výkon/accessible/offline/package kvalifikace. Renderer neřeší chybějící core identity či package parent→child evidence; ty jsou společnou závislostí WP043 pro obě volby.
