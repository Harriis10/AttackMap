# Cytoscape.js ve WinUI 3 — konkrétní integrační varianta

**Navazující požadavek:** [celé schéma 16 repos](fleet16-requirements.md) je povinný rozsah a obě větve mají stejně prioritní fleet spike. Pro compound skupiny doplnit srovnání fCoSE; Dagre endpoint/grouping omezení níže nelze ignorovat. Collapse/expand a vratné agregace evidence jsou vlastní produktová práce; známý externí expand-collapse plugin hlásí ukončenou údržbu.

Datum: 23. 10. 2026. **Rešerše API a návrh, ne implementace.** Nebyly instalovány balíčky, měněn produktový kód/aktivní plán ani spuštěny buildy, scany, GUI či model. Ukázky níže jsou vlastní **nekompilovaný a nevykonaný pseudokód**; pojmenované pomocné funkce představují práci AttackMap. Podporované limity určí WP043 až podle spike; Windows C26 se neobnovuje.

## Rozhodnutí, které lze udělat nyní

Cytoscape je uskutečnitelný **vložený graph explorer**, nikoli pouze exportovaný dokument. Nejkratší bezpečná cesta je jedna lokální HTML aplikace v existujícím WinUI okně, data přes úzký JSON bridge a evidence/filtry/exportní dialogy nadále v nativním shellu. Nepotřebuje lokální HTTP server, Node.js na koncovém počítači ani AI generující topologii.

Pro AttackMap zůstává rozumná výchozí větev nativní Canvas + oddělený MSAGL layout. Webovou větev má smysl zvolit, jestliže stejné grafové fixtures prokážou podstatně lepší interakce nebo nižší vlastní implementační náklady a přijmeme její runtime/profil/bridge náklady. Samotný počet uzlů, vzhled upstream dema nebo existence `layout.stop()` takové rozhodnutí neprokazují. Tento dokument rozpracovává webovou větev pro skutečné porovnání; nativní posouzení je v [renderer research](graph-renderers.md).

## Ověřený místní základ a přesná místa napojení

Před čtením zdrojů byl použit CodeGraph. Následují aktuální zdrojová zjištění, nikoli nová runtime evidence:

| Soubor / rozhraní | Pozorování | Doporučené napojení |
| --- | --- | --- |
| `desktop/windows/AttackMap.NativeSpike/AttackMap.NativeSpike.csproj` | `net8.0-windows10.0.19041.0`, minimum `10.0.19041.0`, WinUI, `WindowsPackageType=None`, `WindowsAppSDKSelfContained=true`, `win-x64`, Windows App SDK `2.4.0`. | Zachovat nativní shell a produktové minimum; přidání WebView nemění ověřenou podporu OS/architektur. |
| `desktop/windows/AttackMap.NativeSpike/obj/project.assets.json` | Již resolves transitive `Microsoft.Web.WebView2/1.0.3719.77`. | Netvrdit, že je nutné nově přidat druhý WebView2 SDK package. Skutečný browser runtime je samostatná závislost. Obnovení assets při příštím build checkpointu může výsledek změnit. |
| `Diagram/DiagramView.cs` | Dnešní nativní kreslení, `SetSelection(ExportSelection?)`, `Stop()`, revision guard a `ExportTextRequested`. | Zachovat veřejný selection/lifetime kontrakt; webový renderer dát do samostatného candidate hostu, ne přepsat souběžně celý MainWindow. |
| `Diagram/DiagramSelectionReader.cs` | Čte jen allowlisted lokální manifest-bound artefakty a validuje vybranou identitu. | Nový graph reader musí mít stejnou hranici důvěry; JS nesmí sám procházet report folder ani repository. |
| `MainWindow.Parity.cs:121` `BindParityReport` | Váže `Diagrams.SetSelection(selected)` spolu s dalšími výsledkovými views. | Tudy předat nový snapshot/projection; nové core graph DTO nejprve musí existovat pod WP043. |
| `MainWindow.Parity.cs:151` `InspectParitySource` | Nativně ověřuje dodanou source location, chrání identitu a nabízí folder reveal. | Web pošle pouze ID evidence; host je resolve z právě zvoleného DTO a použije nativní cestu. Současné rozhraní je inspection/reveal, nikoli hotový editor konkrétního řádku. |
| `MainWindow.Parity.cs:22` `InitializeParityWorkspace` | Integruje navigaci a export, `Closed` volá terminální `Diagrams.Stop()`. | Browser shutdown vyžaduje explicitní UI lifecycle ownership; dnešní `Stop()` pouze invaliduje stav a browser neobsahuje. |
| `MainWindow.Parity.cs:173` `ExportDiagramText` | Nativní SavePicker a opětovná validace vybrané generace před zápisem. | Obrazový export musí použít stejnou identity/destination hranici; nepřebírat cestu ze zprávy JS. |

Nové názvy typu `GraphWebViewHost`, `GraphProjection` a `GraphBridgeMessage` v návrhu nejsou dnes existující produktové typy. Změny `models.py`, `report.py`, schema/capabilities, report adapteru, project/resources a shellu nadále integruje jeden owner podle WP043.

## Co skutečně poskytuje Cytoscape

**Primární fakta:** core nabízí například `preset`, `grid`, `breadthfirst` a `cose`; Dagre je externí extension registrovaná přes `cytoscape.use(...)`. Výchozí geometrická mřížka neřeší význam směrové topologie. `preset` používá dodané pozice. Synchronní/discrete výpočet se dokončí před návratem z `run()`; vypnutí animace z něj nevytvoří worker. [Oficiální layout průvodce](https://blog.js.cytoscape.org/2020/05/11/layouts/)

**API pro produkt:** `tap`/selection eventy, `getElementById`, batch změny, fit/zoom/pan, JSON update a PNG/JPEG export jsou dokumentované. `cy.json({elements})` vyžaduje ID a odstraní prvky, které v dodaném snapshotu nejsou. Velké grafy, hrany, složité styly a vyšší pixel ratio mohou výkon zhoršit; PNG `blob-promise` brání některému synchronnímu čekání při exportu, neřeší velikost grafu. Standardní exporty nelze vydávat za vestavěný univerzální SVG exporter. [Cytoscape API](https://js.cytoscape.org/)

**Dagre adaptér:** přezkoumané README uvádí Dagre v3 přibalené v distribuovaných extension files; při této variantě se nemá bezdůvodně načítat další globální Dagre script. `master/package.json` při rešerši uváděl `4.0.1`; není to výběr ani důkaz aktuální publikované npm verze. Před implementací zamknout konkrétní release, ověřit jeho artefakty/transitive closure a MIT notices. [README](https://github.com/cytoscape/cytoscape.js-dagre#readme), [package metadata](https://raw.githubusercontent.com/cytoscape/cytoscape.js-dagre/master/package.json)

**Omezení rušení doložené zdrojem:** `src/layout.mjs` přímo volá `dagre.layout(g)` uvnitř `run()`, bez vlastní worker/cancellation větve. Během takové synchronní práce její JS event loop nemůže zpracovat zprávu cancel ani `setTimeout`. To může zablokovat interakce webového grafu; nejde o tvrzení, že JS sdílí WinUI UI thread. Promise wrapper tuto vlastnost neopraví. [Zdroj adaptéru](https://raw.githubusercontent.com/cytoscape/cytoscape.js-dagre/master/src/layout.mjs)

Volba `stop` v options je callback, nikoli cancellation token. Dokumentace `layout.stop()` popisuje ukončení asynchronního continuous layoutu; neprokazuje preempci synchronního Dagre výpočtu. [Cytoscape layout manipulation](https://js.cytoscape.org/#layout-manipulation)

**Hrany a grouping:** nové volby `useDagreEdgeControlPoints` a `automaticDagreEdgeStyle` jsou defaultně `false`; lze je zapnout, proto není přesné říkat, že adaptér vždy přenáší jen node positions. Jejich routy nejsou potvrzené source evidence. Přezkoumaný layout source pro ranking převádí endpoint parent node na první leaf child; grouping/parent-edge/cycle/multiedge fixtures proto musí porovnat skutečné endpoints a výsledný obraz. Core DTO se tím nesmí přepsat. [Defaults](https://raw.githubusercontent.com/cytoscape/cytoscape.js-dagre/master/src/defaults.mjs), [layout source](https://raw.githubusercontent.com/cytoscape/cytoscape.js-dagre/master/src/layout.mjs)

## Tři možné výpočetní cesty pro webový candidate

Následující volby jsou vlastní návrhy AttackMap:

| Varianta | Přínos | Práce a poctivý limit |
| --- | --- | --- |
| B1: Cytoscape + běžný Dagre adaptér v page | Malý prototyp, hotové API propojení; vhodné pro omezený zvolený subgraf. | Synchronní layout nelze slíbit jako bounded-cancel. Musí mít předem omezený vstup a fallback; timeout na stejném JS event loopu neukončí běžící výpočet. |
| B2: samostatný Dagre v app-owned dedicated Worker → Cytoscape `preset` | Oddělí výpočet od page interakcí; supervisor může worker ukončit a vytvořit nový. | Vlastní převod DTO→layout model, rozměry uzlů/labelů, routing a validace výsledků. Nejde o vestavěnou vlastnost adaptéru; nelze jen přesunout browser `cy` objekt do workeru. |
| C: hostem vypočtený MSAGL layout → Cytoscape `preset` | Sdílený layout kontrakt s nativní variantou a samostatná volba surface. | Smysl jen při naměřeném přínosu. Je to hybrid se dvěma technologiemi; transformace geometrie/hran do Cytoscape a cancellation MSAGL potřebují vlastní důkazy. `preset` s node positions automaticky neimportuje všechny křivky/porty. |

Dedicated Worker API definuje `terminate()` pro ukončení workeru; to není kooperativní dokončení práce ani potvrzení aplikace výsledku. Doporučený supervisor proto přiděluje ticket, zahazuje pozdní výsledky, při cancel/timeout worker zahodí a vytvoří nový; limity paměti a doručování musí spike změřit. [HTML Worker standard](https://html.spec.whatwg.org/multipage/workers.html#dom-worker-terminate)

Core/data adaptace musí zůstat mimo browser API thread. `CoreWebView2` i WinUI host jsou na UI/STA threadu: přesunutí jejich volání do `Task.Run` je nesprávná optimalizace. [WebView2 threading](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/threading-model)

## Data a bridge, které musí dodat AttackMap

1. **Canonical graph DTO:** version, stabilní ID a směr node/edge, relation kind, evidence basis/confidence/provenance a evidence reference IDs. Envelope zachová vybraný run, saved generation/snapshot/report hash a host selection token; různé druhy generace se neslévají do jednoho čísla. Hash je identita z ověřeného host envelope, ne řetězec prohlášený rendererem.
2. **View projection:** unique Cytoscape IDs musí rozlišit nodes a edges i při stejné hodnotě core ID; použít reverzibilní mapu např. `n:<id>`/`e:<id>`, ne změnu canonical ID. Zvláštní znaky hledat přes ID API, ne skládat do selector expression. Přidat jen potřebné label/kind/basis a opaque references; plný source obsah, klíče a absolutní lokální cesty browser zpravidla nepotřebuje.
3. **Úzký protokol:** host→page `replaceGraph`, `clear`, `select`, `theme`; page→host `ready`, `select`, `openEvidence`, `layoutState`, volitelně bounded export response. Každá zpráva má protocol version, page session a selection identity/ticket podle druhu zprávy. Host kontroluje origin+URL, velikost/depth/schema, current identity, allowlisted action a existenci ID. První `ready` je přijat jen z nově otevřené schválené page session; další zprávy musí odpovídat aktuálnímu snapshotu.
4. **Atomické zobrazení:** při změně repo/reportu host nejdřív invaliduje staré callbacky a vymaže dosavadní výběr; data se zobrazí až s odpovídající identitou. Starý graf nelze přelepit novým run label. Při layout chybě zůstane dostupný úplný text/list a přiznaný omezený subgraf.
5. **Jediná interpretace faktů:** filtry/grouping nesmějí přidat dependency nebo observed edge; směr, candidate/inferred/observed a confidence zůstávají core facts. Schované počty jsou viditelné. Grafová dosažitelnost není doložený runtime/exploit path. Package dependency hrany vyžadují resolver vztahy, nikoli UI join podle jména nebo textu `via`.

WebView2 `PostWebMessageAsJson` posílá JSON do top-level dokumentu asynchronně; při navigaci se zpráva může nedoručit. `WebMessageReceived` přijímá `chrome.webview.postMessage(object)`; zprávy jednoho dokumentu mají pořadí, ale nelze obecně předpokládat pořadí vůči všem DOM/navigation událostem. Proto vlastní ready/ack/ticket protokol. [CoreWebView2 API](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/winrt/microsoft_web_webview2_core/corewebview2?view=webview2-winrt-1.0.3719.77)

Receive args poskytují `Source` a `WebMessageAsJson`; kontrola jen aktuálního `webView.Source` bez původu konkrétní zprávy nestačí pro náš kontrakt. [Message args](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/winrt/microsoft_web_webview2_core/corewebview2webmessagereceivedeventargs)

## Inicializace WinUI, lifecycle a shutdown

**Primární API:** skutečný WinUI control je `Microsoft.UI.Xaml.Controls.WebView2`, nikoli WPF wrapper. `EnsureCoreWebView2Async(...)` poskytne core po dokončení; `CoreWebView2Initialized` nastane před jeho dokončením nebo při výjimce. WinRT custom environment vytváří **`CoreWebView2Environment.CreateWithOptionsAsync(browserExecutableFolder, userDataFolder, options)`**. Nepřebírat WPF/WinForms overload `CreateAsync(...)` jako identický WinUI kontrakt. [WinUI Ensure API](https://learn.microsoft.com/en-us/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.controls.webview2.ensurecorewebview2async), [WinRT environment](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/winrt/microsoft_web_webview2_core/corewebview2environment)

**Doporučený sled:** lazy vytvořit host při otevření grafu; ještě před prvním `Source` nastavit zvolený environment/UDF, jednou await inicializaci, ověřit lifetime epoch, připojit bezpečnostní handlery, nastavit mapping a teprve poté navigovat. Dvě souběžné init větve nebo implicitní `Source` nesmějí vytvořit jiný environment. Zdroj WinUI odmítá pozdější nekompatibilní environment a po `Close()` již objekt neinicializuje. [WinUI implementace](https://raw.githubusercontent.com/microsoft/microsoft-ui-xaml/main/controls/dev/WebView2/WebView2.cpp)

Po každém await, handleru a queued native action ověřit terminální stop a selection epoch. Na init/read/layout/capture failure ukázat nativní fallback. Nečekat blokujícím `.Wait()`/`.Result` na UI threadu; evidence dialog naplánovat po návratu z WebView eventu. [Threading/reentrancy](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/threading-model)

**Shutdown:** WinUI má explicitní `WebView2.Close()`; nespoléhat na WPF `Dispose` vzor. Owner v platné UI fázi invaliduje callbacky, zruší vlastní data/layout práci, odpojí vlastní handlery a zavře tento control. Terminální `Closed` invalidace nesmí dodatečně sahat na zaniklé XAML objekty. Jestli tab pouze skryjeme, je to odlišná politika od terminal close. Po close případný nový graf vyžaduje nový control; absence `layoutstop` nebo page ack nesmí zablokovat uzavření okna. [Close API](https://learn.microsoft.com/en-us/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.controls.webview2.close), [WinUI close source](https://raw.githubusercontent.com/microsoft/microsoft-ui-xaml/main/controls/dev/WebView2/WebView2.cpp)

`cy.destroy()` uvolní jeho surface/animation loop, ale není důkazem ukončení vlastního Worker ani celého sdíleného browser processu. Worker ukončit samostatně; shutdown neřešit globálním zabíjením všech Edge/WebView2 procesů. [Cytoscape core source](https://raw.githubusercontent.com/cytoscape/cytoscape.js/master/src/core/index.mjs)

## Lokální origin, CSP a síťová hranice

`SetVirtualHostNameToFolderMapping` vytvoří lokální HTTP(S) origin bez DNS lookup pro mapovaný host. Mapping platí i pro dedicated/shared worker scripts, nikoli service workers. Mapovat pouze balené read-only graph assets, nikdy repository/report/output root. Vybrat rezervovaný host např. `attackmap-graph.invalid`; odlišné zdroje izolovat jinými originy. [Mapping API](https://learn.microsoft.com/en-us/dotnet/api/microsoft.web.webview2.core.corewebview2.setvirtualhostnametofoldermapping)

Pro tuto aplikaci doporučuji `CoreWebView2HostResourceAccessKind.Deny`: blokuje přístup z jiných originů. `DenyCors` není stejně přísné, dovoluje cross-origin běžné subresources, například script/image. Ani `Deny` samo neblokuje odchozí requests z naší page na cizí servery; stejný origin stále vidí obsah celé mapované složky. [Resource access enum](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/winrt/microsoft_web_webview2_core/corewebview2hostresourceaccesskind)

Vlastní hardening pro candidate:

- Aplikací vlastněné externí scripts/CSS/Worker soubory a CSP v baleném `index.html` před jejich načtením; výchozí `default-src 'none'`, scripts/workers/styles/fonts jen podle potřeb z vlastního originu, `connect-src 'none'`, `object-src 'none'`, `base-uri 'none'`, `form-action 'none'`, žádné frames. Konkrétní CSP je nutné vyzkoušet proti CSSOM/canvas chování zvolené verze; výjimku pro styl nesměšovat s povolením reportem dodaného scriptu nebo `unsafe-eval`.
- `IsScriptEnabled=true` a `IsWebMessageEnabled=true` jsou potřeba pro vlastní renderer; `AreHostObjectsAllowed=false`, vypnuté nepotřebné default dialogs/context menus, žádné generic filesystem/command proxy a žádný `ExecuteScript` sestavený z reportových řetězců. Labely zůstanou text/data, nikoli `innerHTML` či uživatelem dodané style/function konfigurace. [WebView2 security](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/security)
- Blokovat cizí/top-level i frame navigace, nová okna, downloads a permissions. Povolit pouze přesnou lokální stránku a manifest balených assets; externí link případně předat explicitní nativní akci až po allowlist pravidlech.
- Síťový guard používá `WebResourceRequested` + registrované filtry; pouhé přihlášení eventu nestačí. Tříargumentový `AddWebResourceRequestedFilter` umožňuje source kinds; `All` pokrývá podporované zdroje včetně workerů. Pro konkrétní SDK/runtime ověřit dostupnost overloadu a fail closed, jestli ochranu neumí. Samotný handler nedokazuje absolutní blokaci všech URI/systémových provozů. [Core request filter API](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/winrt/microsoft_web_webview2_core/corewebview2?view=webview2-winrt-1.0.3719.77), [request source kinds](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/winrt/microsoft_web_webview2_core/corewebview2webresourcerequestsourcekinds)

Offline acceptance proto zahrnuje disabled network i hostile label/resource/URL fixtures a záznam nepovolených app-page requests, nikoli jen tvrzení, že jsou všechny JS soubory lokální. Service worker zde není potřeba.

Omezení page resources a CSP nejsou důkazem nulového odchozího provozu runtime/updateru nebo jiných systémových procesů. Případný takový požadavek musí mít zvláštní OS/network důkaz a jasně vymezený rozsah; rendererový guard jej sám nezaručuje.

## Runtime, minimum OS a portable distribuce

Lokální .NET/XAML minimum je `10.0.19041.0`/x64. Širší seznam Windows podporovaných WebView2 nezakládá podporu AttackMap na starších OS ani na ARM64. [WebView2 podporované platformy](https://learn.microsoft.com/en-us/microsoft-edge/webview2/)

| Distribuční větev | Ověřené primární fakta | Důsledek pro AttackMap |
| --- | --- | --- |
| Existující Evergreen | Runtime musí být přítomný; Microsoft jej průběžně aktualizuje. Instalovaná dostupnost nesmí být odvozena jen z OS. | Menší aplikační payload; zaznamenat skutečný browser version a ověřit nutné API. Při absenci/failure použít native fallback, nikoli na pozadí stahovat runtime. |
| Evergreen offline installer | Microsoft poskytuje plný standalone installer pro offline instalaci. | Samostatný instalační krok; není ekvivalent pouhého rozbalení portable ZIP. |
| Fixed Version | Přibalí se zvolený runtime; aktualizace vlastní distributor. Microsoft uvádí payload přes 250 MB a zákaz runtime spuštění z UNC/network umístění. | Reprodukovatelná verze a offline payload, ale větší ZIP, vlastní patching a test skutečného unpackaged umístění. |

Podklady: [distribuce](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution), [oficiální download varianty](https://developer.microsoft.com/en-us/microsoft-edge/webview2/).

**Podstatné pro současný portable profil:** Microsoft pro Fixed Version 120+ u unpackaged Win32 aplikací na Windows 10 požaduje Read/Execute oprávnění pro příslušné AppContainer identity nad runtime files. Podmínka se podle dokumentace netýká Windows 11 a packaged apps. Nelze proto slíbit univerzální zero-install offline portable jen přibalením adresáře runtime; clean-host spike musí ověřit skutečnou kombinaci OS, umístění, ACL a potřebných oprávnění. Tento výzkum žádné ACL ani instalace nemění. [Fixed Version požadavky](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution#the-fixed-version-runtime-distribution-mode)

WinUI může dostat fixed folder přímo přes `CreateWithOptionsAsync`; oficiální starší packaged sample také ukazuje procesní `WEBVIEW2_BROWSER_EXECUTABLE_FOLDER` před vytvořením controlu. Pro unpackaged AttackMap nepřebírat `Package.Current.InstalledLocation`; použít ověřený bundle root. Zvolit jednu explicitní politiku a zachytit také relevantní inherited overrides, aby deklarovaný runtime odpovídal skutečně použitému. [Environment API](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/winrt/microsoft_web_webview2_core/corewebview2environment), [oficiální WinUI sample](https://learn.microsoft.com/en-us/microsoft-edge/webview2/samples/webview2-winui3-sample#using-a-fixed-version-webview2-runtime)

**UDF je jiný adresář než runtime/assets:** unpackaged aplikace potřebuje zapisovatelný vlastní browser profil, například pod `LocalApplicationData/AttackMap/WebView2/Graph`. Nezakládat jej vedle readonly EXE a neukládat na síť. Rozhodnout retenci/odstranění při uninstallu; zvolený graph renderer nemá ukládat source obsah nebo celé reporty do browser storage. Specifický WinUI3 příklad Microsoftu používá `CreateWithOptionsAsync(null, userDataFolder, options)` a `EnsureCoreWebView2Async(env)`. [WinUI UDF pokyny](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/user-data-folder)

## Ilustrační C# pseudokód — není produktový patch

WinUI `Browser` nemá před tímto sledem nastavený `Source`. Helpery instalují výše popsané allowlisty, parser a lifecycle guards; samotný úryvek není kompletní bezpečný host.

```csharp
async Task InitializeGraphAsync()
{
    long captured = lifetimeEpoch;
    string udf = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "AttackMap", "WebView2", "Graph");
    var env = await CoreWebView2Environment.CreateWithOptionsAsync(
        fixedRuntimeFolderOrNull, udf, new CoreWebView2EnvironmentOptions());
    if (stopped || captured != lifetimeEpoch) return;
    await Browser.EnsureCoreWebView2Async(env); // UI thread; catch/fallback required
    if (stopped || captured != lifetimeEpoch) return;
    core = Browser.CoreWebView2;
    core.Settings.AreHostObjectsAllowed = false;
    core.Settings.IsScriptEnabled = true;
    core.Settings.IsWebMessageEnabled = true;
    core.SetVirtualHostNameToFolderMapping("attackmap-graph.invalid",
        verifiedAssetDirectory, CoreWebView2HostResourceAccessKind.Deny);
    InstallNavigationResourcePermissionGuards(core, env); // own implementation
    core.WebMessageReceived += Receive;
    core.Navigate("https://attackmap-graph.invalid/index.html");
}

void Receive(CoreWebView2 sender, CoreWebView2WebMessageReceivedEventArgs args)
{
    if (stopped || !IsExactGraphPage(args.Source) || !IsExactGraphPage(core.Source)) return;
    if (!TryParseBoundedProtocol(args.WebMessageAsJson, out var message)) return;
    if (message.Type == "ready") {
        if (!IsExpectedReadyForThisNavigation(message)) return;
        SendCurrentSnapshotAfterReady(message); return;
    }
    if (!MatchesCurrentSelection(message.Context)) return;
    if (message.Type == "openEvidence" && TryResolveCurrentEvidence(message.Id, out var source))
        QueueNativeEvidenceActionWithLifetimeRecheck(source); // no JS-provided path
}

void SendSnapshot(object checkedEnvelope)
{
    if (!stopped && pageReady && IsExactGraphPage(core.Source))
        core.PostWebMessageAsJson(JsonSerializer.Serialize(checkedEnvelope));
}

void CloseRendererOnOwnedUiPhase()
{
    if (stopped) return;
    stopped = true; ++lifetimeEpoch;
    CancelOwnProjectionWork(); DetachAllOwnHandlers();
    Browser.Close(); // no synchronous wait for page ack; do not reuse this control
}
```

Je potřeba samostatně ošetřit terminal close během každého await i výjimku z inicializace; samotná epoch kontrola neukončuje probíhající operaci. Existující terminální `Stop` musí zůstat volatelný bez nového přístupu k již zavřeným XAML controls. `ready` handshake není oprávnění číst report: snapshot se i zde bere výhradně z hostem ověřeného selection.

## Ilustrační JS pseudokód — vlastní worker orchestrace

Tento příklad záměrně používá `preset`; helper `calculateInOwnedWorker` není upstream Dagre adapter API. Musí dodat vlastní cancel/timeout, dimensions, bounded result validation a `disposeWorker`.

```javascript
const cy = cytoscape({ container: document.getElementById("graph"),
  elements: [], layout: { name: "preset" },
  style: [{ selector: "node", style: { label: "data(label)" } }] });
let epoch = 0, context = null;

chrome.webview.addEventListener("message", async ({ data: message }) => {
  if (!validateHostEnvelope(message)) return;
  if (message.type === "clear") {
    ++epoch; disposeWorker(); context = null; cy.elements().remove(); return;
  }
  if (message.type !== "replaceGraph") return;
  const captured = ++epoch;
  disposeWorker(); context = null; cy.elements().remove();
  const candidate = await calculateInOwnedWorker(message.graph);
  if (captured !== epoch || !validateLayoutIdsAndCoordinates(candidate, message.graph)) return;
  cy.json({ elements: toPresentationElements(message.graph, candidate.positions) });
  cy.layout({ name: "preset", fit: true, animate: false }).run();
  context = message.context;
});
cy.on("tap", "node, edge", event => {
  if (context) chrome.webview.postMessage({ type: "select", protocol: 1,
    context, id: event.target.id() });
});
chrome.webview.postMessage({ type: "ready", protocol: 1 });
```

Produkční implementace doplní catch/fallback, page session handshake, vlastní user-selection event kontrakt a ochranu proti reentrantnímu replace/clear/export. `tap` je pointer cesta; keyboard selection musí mít vlastní nativní rozhraní. Nevracet do hostu celý `cy.json()` jako autoritativní scan result. Pro stejný snapshot lze inkrementálně aktualizovat data/selection; pro jiný report první verze může použít úplné ověřené nahrazení, bez slibu automaticky stabilního layoutu.

## Přístupnost, export a měření pro rozhodnutí

V přezkoumaných primárních materiálech nebyl doložen kompletní produktový keyboard/Narrator graph explorer. Canvas a event API jej samy nezakládají. Doporučení: ponechat nativní list/tree node/edge se stejnými IDs, typem/směrem/basis/confidence a evidence akcemi, propojit selekci s grafem a testovat přechod fokusu do WebView i zpět. High contrast, zoom/scale, theme a reduced motion mají vlastní vizuální/ruční důkazy; změna browser fontu není automatická nativní parita.

Export PNG/JPEG dělat jen na explicitní nativní akci, s limitem pixelů/bytes a s current snapshot ticket. Veškerý přenášený obraz je z browseru neautoritativní obsah; host ověří formát/velikost a destination. Canonical DTO/text a view state držet odděleně. Samotný obrázek musí přiznat skrytý subgraf/filtry a identitu zdrojového běhu. Upstream dovoluje export celé kresby nebo viewportu; velká full export bitmapa může sama vytvářet výrazný memory spike. [Cytoscape export API](https://js.cytoscape.org/#export)

Spike pro native i web candidate použije tentýž DTO/corpus: ordinary, empty, missing, partial, dangling IDs, ambiguity, cycles, multiedges, parent/child, long labels a hostile labels/URLs. Změří odděleně inicializaci browseru, transfer/parse, layout, commit/render, selekci, export, paměť včetně browser/worker procesů, cancel a close/reopen. Kandidátní 100/300, 1 000/3 000 a 10 000/30 000 node/edge fixtures nejsou podporované produktové limity. Výsledkem je ADR, skutečné Light/Dark snímky ve dvou velikostech a zdokumentované supported bounds/fallback; žádné nové časové release brány před měřením.

**Konkrétní go/no-go:** pokud web nepřinese dostatečný přínos proti native variantě, ponechat graph DTO a nativní layout bez browser hostu. Pokud vyhraje, před integrací musí být prokázán ready/identity/security/lifetime kontrakt, nulové nepovolené app-page requests offline, nativní evidence/keyboard cesta, runtime/profile distribuce a kompatibilita legacy reportů. Žádná z těchto položek není touto rešerší splněna.
