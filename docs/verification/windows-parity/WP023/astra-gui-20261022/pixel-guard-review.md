# Evidence GUI runner review and focused correction — 2026-10-22

Scope: independent Astra/high review followed by the root agent's explicit lease
to change only this evidence runner and its new deterministic test file. Product
code, the primary native runner, accepted raw captures and prior evidence were
not edited. CodeGraph was consulted first; omitted source sections were read
directly. No GUI, provider, native executable, build or process-spawning fixture
was run by this review.

## Findings and correction

1. `ROOT = parents[6]` selected the directory above the repository, breaking the
   primary harness import. Corrected to `parents[5]`; the fixture verifies the
   actual harness file exists below that root.
2. The former capture check accepted a PNG signature/IHDR and dimensions without
   decoding pixels. Therefore both a 24-byte header-only file and a complete
   all-transparent PNG could satisfy its image-specific checks. The replacement
   validates bounded chunk sizes, CRCs, IHDR/IEND structure, contiguous IDAT,
   zlib completion/exact decoded size, and PNG filters 0–4. It rejects entirely
   transparent or visually uniform pixels, including hidden RGB noise under
   zero alpha. SHA-256 is checked against the same encoded bytes subsequently
   decoded, avoiding a separate hash/decode read. Pixel measurements and a hash
   of reconstructed pixel bytes are retained for successful images.

Pillow is absent from both existing project venvs checked, so this uses only the
standard library. Supported input is explicitly non-interlaced, 8-bit RGB/RGBA
PNG. Other encodings, transparency chunks and animation fail closed. Width and
height are bounded to 16384, encoded data and four-byte pixel size to 128 MiB;
zlib output is capped at the exact scanline size plus one byte. Unsupported
native encoder output would require a reviewed extension, never an implicit
acceptance bypass.

Static review found no additional blocker in command selection, isolated profile
delegation, guarded input identity or owned Job cleanup: the evidence runner
uses explicit native smoke arguments, delegates corrected profile creation and
launch cleanup to the primary harness, checks process exit/timeout/cleanup and
validates identities before and after launch. This is a source review, not a
fresh execution proof for any of those paths.

## Focused verification

Command (run from repository root, with stdout/stderr retained in
`pixel-tests-01.txt`):

```powershell
./.venv/Scripts/python.exe -B -m pytest docs/verification/windows-parity/WP023/astra-gui-20261022/test_gui_checkpoint.py -q -p no:cacheprovider --basetemp=docs/verification/windows-parity/WP023/astra-gui-20261022/pixel-test-temp-01
```

Result: **33 passed in 1.56 s; exit 0**. Unrestricted execution was approved for
this narrow command because the existing sandbox's OWNER RIGHTS temporary
directory ACL issue had already been diagnosed. Fixtures are tiny and local;
they do not start subprocesses. Coverage includes exact decoded-byte hashes for
RGB/RGBA and all five filters, transparent/hidden-color/opaque-solid/semitransparent
solid images, truncation, CRC tampering, trailing data, short/excess decompression,
invalid filters, oversized/zero dimensions, unsupported transparency,
non-contiguous IDAT, complete theme/size pairs, collapsed sizes, checksum tampering,
dimension mismatch, theme mismatch and missing captures. Rejection cases also
verify that failed capture validation is persisted.

## Identity and limits

SHA-256:

| File/state | SHA-256 |
| --- | --- |
| Runner before | `d90f721e595e0834aad347c8febf8b034f4e17a4f6bc3c1e9858d38ca555c3cc` |
| Runner after/tested | `571cd1de30b8cad91e895f739bc7e46303fecfd34f57653ca57f85ab32c004dd` |
| New test file | `9a27ce416d694ceeeeb1e93487ea47471bd35acc35b3fec12e4486b3f362d5b95` |
| Primary harness observed after test, not edited | `43c267614ae85a9c34fe6ea66cabd7c5ea4833accb68b76afc4be55892feec5d` |
| Test log | `8df384d9398e1f536747379849ef19a281f629bc5de1452b389c13d17087f24c` |

This establishes rejection of blank/corrupt fixture captures. Nonuniform pixels
do not prove legible, correct or useful UI content. `visual_review_performed`,
manual UI/accessibility, K2/K4 and release acceptance remain false. No fresh
native capture, real screenshot, OS/manual/a11y or provider verification was
performed. Prior broad Python/native/model results are not rewritten by this
focused evidence test. No owned background process or automatic continuation
was created; the sole test command completed with exit 0.
