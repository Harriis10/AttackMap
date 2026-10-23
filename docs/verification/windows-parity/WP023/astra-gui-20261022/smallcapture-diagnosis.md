# Capture anomaly diagnosis — 2026-10-23

Read-only source and retained PNG review by Sol; no app, build, provider, GUI interaction, or candidate mutation. Examined `sol-newcandidate-capture-01`, package `dev-20261022220136-08e1c566`. CodeGraph was consulted first. Current `MainWindow.Capture.cs`, `NativeCaptureProbe.cs`, `MainWindow.xaml.cs`, and `Diagram/DiagramView.cs` hashes equal the immutable candidate source snapshot.

## Observations

- Visually reviewed `1600x1000-Dark-Diagrams.png`: seven navigation button bodies exist but their labels are absent; diagram notice, source header/text, and two action labels are also absent. The core-artifact ComboBox and page title remain readable.
- `1024x700-Light-Diagrams.png`, `1024x700-Dark-Diagrams.png`, and `1600x1000-Light-Diagrams.png` retain these texts. Thus the evidence does not establish a consistently broken dark-theme foreground or missing product content.
- The large Light Diagrams PNG shows the selected-item background on Diagrams but the thin selection indicator still beside the previous Evidence inventory item. Large Dark FindingDetail shows Findings content while the thin indicator remains at Settings, the immediately previous destination in the capture loop. Two lower finding action buttons and an expander header are blank there; much of the same inspector's text remains readable.
- Large image names describe requested outer window sizes. Their manifest records actual content as 1584x961, scale 1. Small PNG content is 1008x661. These are two distinct content viewports, not exact 1600x1000/1024x700 content dimensions.
- Capture process exited 0 in 24.228 seconds with owned-job cleanup verified. The later wrapper failure says `Missing required views: ['Settings']`; an actual localized `Nastavení` capture exists. That naming-validation failure is separate from the pixel anomalies and does not explain them.

## Source evidence and interpretation

`MainWindow.Capture.cs:173-191` loops size, theme, and destinations, sets `Navigation.SelectedItem`, awaits one low-priority DispatcherQueue callback, invokes `UpdateLayout`, and captures. It does not await a navigation/animation completion signal. For FindingDetail (`:203-210`), it selects Findings after the Settings capture, selects a finding, updates layout, focuses/scrolls, and captures without that low-priority callback.

`NativeCaptureProbe.cs:31-39,74-90` updates layout and waits for two `CompositionTarget.Rendering` notifications, then uses `RenderTargetBitmap.RenderAsync`. It checks loaded state, dimensions and pixel-buffer size, but neither text visibility nor completion of every themed/navigation composition transition. Its recorded scope explicitly warns that composition-backed effects/surfaces, theme transitions, and selection visuals may differ from the displayed window. Another capture path in `MainWindow.Capture.cs:136-140` additionally waits 450 ms for entrance animations; the general path has no such delay. This is evidence of differing capture synchronization, not proof that adding an arbitrary delay would fix these PNGs.

`MainWindow.xaml.cs:836-869` updates heading and page visibility synchronously in the navigation handler. It does not manually position the NavigationView indicator. The observed old indicator/new page combination is consistent with a transient selection-animation capture. It cannot prove that the on-screen window is correct or incorrect.

`Diagram/DiagramView.cs:18-19,30-44` assigns all nine action labels directly in control construction. `:67-73` sets notice and text alternative independently of graph renderability; unsupported diagram input collapses only the graph viewport. Thus the empty graph is expected for this supplied unsupported header, while disappearing labels/source are not the intended empty/unsupported state. `MainWindow.xaml.cs:403-405` awaits `parityViewBinding` before report loading returns; that binding includes `Diagrams.SetSelection` (`MainWindow.Parity.cs:127`). An unfinished initial diagram-file read is therefore not established by this evidence.

## Verdict and smallest next check

**Unresolved capture/visual anomaly; not accepted visual QA and not yet a confirmed product rendering defect.** Deferred composition or capture timing is a supported hypothesis, especially for the stale indicator; the precise cause of disappearing text is unproven. The small Dark and large Light comparisons rule out claiming a universal dark-theme failure from this sample.

When the root GUI slot is free, independently inspect the same immutable candidate's live window at both viewports, navigate to Diagrams and the same finding, allow navigation/theme transitions to settle, and compare a desktop/window capture with the retained in-process PNG. If on-screen text is present while RenderTargetBitmap omits it, classify the affected captures as capture artifacts. If the live window reproduces missing text after settling, record a focused product defect before changing source. Do not rebuild or alter the accepted package merely to test a capture-timing hypothesis. Any later capture harness change or delayed rerun must use new evidence paths, preserve these PNGs, and retain manual/accessibility/release limitations.
