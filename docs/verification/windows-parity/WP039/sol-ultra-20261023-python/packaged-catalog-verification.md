# Actual packaged analyzer inventory — PASS

Package `dev-20261023114018-2bcd8988` was inspected offline using its own
`app/engine/attackmap.exe`. No installation, download, provider call or
modification of the package occurred. The package remains **unsigned
development**, with clean-host/manual/release acceptance separate.

| Check | Observed result |
| --- | --- |
| Official distributions read from packaged `_internal` | 15 exact declared names, package versions and entry points |
| Effective analyzers / discovered candidates | 21 / 24 |
| Shadowed PHP implementations | omeka-s, php-laminas, php-web |
| Available profiles | automatic@1.0, node-atproto@1.0, php-laminas-omeka@1.0, python@1.0 |
| Request contract | schema1.5 and analyzer_profile supported |
| Frozen engine payload identity | 265 files exactly match qualified frozen proof and original frozen bytes |
| Native payload identity | 511 files exactly match captured native03 build proof and published bytes |
| SBOM / package application payload | 776 verified files,276545640bytes |
| ZIP contents | 779 files hash-equal to application payload, two deployment launchers and package manifest; no extraction |
| Actual discovery processes | 4 completed, exit0, owned Job cleanup verified, each bounded to120seconds |

Identity:

- Engine SHA256: `6045194b77c0957166a6eb9fece45dbfd9c42441bb9e32cec6d040db6c419b05`
- Package manifest SHA256: `8ff57c6dcb5a7500f346606123501f6fdd164d49a2a215e7eb523ca6dd6ae228`
- ZIP SHA256: `1ea81929733bf6bd1204af0d06de82a6f625f00d83b738d772be7b7dc3299bde`
- SBOM SHA256: `fe791400ac94139d9fcd5b4f03f89f9aef016bcaf1811a760455b7f3810561e4`

`packaged-catalog-final-verification.json` contains the machine-readable proof,
declared pin map and exact packaged distribution inventory. Raw actual output is
`packaged-catalog-final-{modules,catalog,profiles,capabilities}.json`. Each probe's
same-named directory retains command, stdout/stderr and process/cleanup proof.
The four public command surfaces agree on modules/catalog/profiles and executable
identity. Observed implementation source paths are inside this packaged engine;
available class-source hashes match actual files.

The helper uses the **captured** candidate SBOM verifier and release-lock inputs,
matching the package producer. It does not recompute a new lock using a moving
shared checkout. Native proof paths are normalized from Windows separators
before comparison. The current concurrent fleet changes are outside this
explicitly captured analyzer slice.

Declared Git pins remain declarations: package/wheel metadata and observed
source/payload identity are not a Git-source attestation. All runtime catalog
`content_verified` fields remain false. The actual packaged distributions also
match the SBOM's15 official package names; the SBOM freeze-venv dependency list
alone was not used as proof that packages ship in the bundle.

Executed once, after root produced `package-location.json`:

```powershell
.venv/Scripts/python.exe -B docs/verification/windows-parity/WP039/sol-ultra-20261023-python/verify_packaged_catalog.py --label packaged-catalog-final
```

The script requires fresh evidence labels for repetition and refuses missing
package-location input. This verification proves package inventory/content
integrity for the named unsigned candidate. It does not prove signature,
publisher authenticity, installation, a clean second host, macOS parity, manual
accessibility, model responses or whole-task ecosystem maturity.
