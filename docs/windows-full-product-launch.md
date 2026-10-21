# Launch the full Windows product

Use `Launch-AttackMap-Full.bat` from the repository root. It opens the existing
full `AttackMap.NativeSpike/MainWindow` application selected in
`desktop/windows/full-product-launch.json`. The release owner sets the exact
absolute directory and EXE plus DLL SHA256 after verifying that publish. The
current selection is the verified local K preview. There is no timestamp search,
preview fallback, automatic build, engine download or replacement of the
preserved `desktop/windows/artifacts/native-spike` baseline.

To choose a full build explicitly:

```bat
Launch-AttackMap-Full.bat "C:\Projects\INPROGRESS\AttackMap\desktop\windows\artifacts\integrated-20261021-g"
```

The example names an explicit historical checkpoint for reproducibility; it is
not a moving latest-build selector. Root selects the next verified checkpoint
in the configuration. An explicit directory must still be a local unredirected
build inside this workspace's `artifacts/` or `desktop/windows/artifacts/`, with
the exact full-product project/runtime dependency identity and expected runtime
files. WPxxxPreview applications cannot satisfy that identity. Normal launch
creates the visible interactive product; its PowerShell helper window is hidden.

Read-only validation and fingerprints, without launching:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/launch_native_full_product.ps1 -ValidateOnly
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/launch_native_full_product.ps1 -BuildDirectory 'C:\Projects\INPROGRESS\AttackMap\desktop\windows\artifacts\integrated-20261021-g' -ValidateOnly
```

The configured route refuses changed EXE or DLL bytes. Explicit directory
validation prints both fingerprints but does not establish release approval or
freshness; the user/release owner made that selection. Hashes establish byte
identity, not publisher authentication. If normal launch does not open the app,
run ValidateOnly to read the exact configuration/payload error.

The native build entry is
`desktop/windows/AttackMap.NativeSpike/AttackMap.NativeSpike.csproj` with its full
source globs. A controlled publish uses the local .NET SDK, restored packages,
Release/x64, self-contained output and a new explicitly chosen directory. Root
owns publishing, before/after source inventories and selecting the final result.
The existing `installer/build-installer.bat` builds the Python engine with
`installer/attackmap.spec`; it is not this native product's build or launcher.
`tools/package_native_windows.ps1` creates the governed unsigned package and an
installer wrapper; it is not a source-preview selector.

Launcher preparation on 21 October: the initial default-unselected ValidateOnly
returned exit 1 as expected, and explicit G validation returned exit 0. K is now
selected after a stable publish, four visually reviewed saved Review frames,
and the actual fresh-frozen-engine fleet/watch/cancel journey. K EXE SHA256 is
`6b7f37427c90021693837079dd6146b102d5d154624e3265276d2c90e17ef58a`;
DLL SHA256 is `7269b892cebf8bf37fa55dae4a5a34a474e1139db738f8bcfdc16756e81f2daf`.
This is a local UI preview, not a signed release or a claim that the preliminary
B-J engine lock describes the later K native inputs. The preserved baseline
payload remains unchanged.
