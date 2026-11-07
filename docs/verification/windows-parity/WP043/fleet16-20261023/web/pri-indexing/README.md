# Web content excluded from PRI indexing

Final metadata-only packaging review, 23 October 2026. The three existing GraphExplorer.Web `Content` declarations in `AttackMap.NativeSpike.csproj` now set `ExcludeFromResourceIndex="true"` and explicit `CopyToPublishDirectory="PreserveNewest"`. Their `Include`, `Link` and `CopyToOutputDirectory` values are unchanged. Thus the host still expects the same `GraphExplorer.Web` output directory; no asset is renamed or rehashed.

The installed `Microsoft.Windows.SDK.BuildTools.MSIX/1.7.251221100` targets populate `_LayoutFile` from content output groups (`Microsoft.Windows.SDK.BuildTools.MSIX.Pri.targets:268–292`; MRT Core equivalent at `Microsoft.Windows.SDK.BuildTools.MSIX.MrtCore.PriGen.targets:686–714`) and pass it to `Microsoft.Build.Msix.Pri.WinAppSdkGeneratePriConfigurationFiles`. An isolated A/B invocation of that actual installed task verified its item metadata:

- Without the flag, filtered PRI inputs contain the three representative web files (`asset-manifest.json`, `synthetic-fixture.js`, `index.html`) plus `fixtures/findings.json`; excluded inputs are empty.
- With the flag, filtered inputs contain only `fixtures/findings.json`; all three web paths move to excluded inputs.

`evidence.json` records exact results, SDK/task hashes, the three final content items, before/after project hashes and unchanged host/asset hashes. `metadata-only.patch` isolates this change from root's earlier project integration. `sdk-input-test.proj` and both task output sets preserve the focused evidence. The probe can be copied to a fresh `.tmp` directory and run with `.tools/dotnet/dotnet.exe msbuild <probe> -t:Verify -p:ExcludeWeb=false` and then `true`.

Both GraphWebView copies remain identical (SHA256 `a780cf164c3d454f182dd5298d45f5077b26d871575f22fcda1bf81d0de626e3`). All 14 mapped asset hashes pass; the deployed manifest remains SHA256 `922bf72227a16d03590df8d5589dda2c72c718fde13334c0699a27a656682888`.

No full product build, publish, makepri execution, application launch or shipping host/asset edit was performed during this review. The focused task proves filtering behavior; root's final source-bound publish must verify the original PRI249 warnings are absent and copied/published assets remain complete.


## Captured publish 02 closure

`finalpublish-proof02.json` records a read-only audit of `candidate-source-02` and `native-captured-02`, tied to root's source-capture, publish and process proofs. The publish exited 0 in 132.672 seconds. All 263 captured release inputs and all 534 published file hashes match their proofs. The web payload contains exactly 14 manifest-mapped assets plus `asset-manifest.json`, with all four MIT notices intact; the manifest hash remains unchanged. Msagl's pinned package, restored assembly, shipped assembly and copied MIT notice match. The linked findings fixture matches its captured input. Neither publish log contains PRI249 or C# warnings.

Proof SHA256: `690030e55dd849b908ef4db8d5fae6fd89a09db99a145aa0c891fb6ccbb3d07b`. Both current and captured GraphWebView source copies still match SHA256 `a780cf164c3d454f182dd5298d45f5077b26d871575f22fcda1bf81d0de626e3`. Capture 01 proof is preserved unchanged at SHA256 `103be030939e3101f8f03cc1165a706829a9a4facb2a4318b9abee9ffd3c769e`.

This audit verifies the native payload and its captured source/proof linkage. It performs no build, GUI launch or source edit and does not establish visual, accessibility, installed WebView2-runtime or engine-build acceptance.
