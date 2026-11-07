# Sol integration checkpoint — 2026-10-23 Europe/Prague

Timeout repair independent review CLEAR: WP017/long-local-20261022/sol-review.md.
Focused evidence: 135 core tests, 47 runner/verifier tests, 69 native assertions.
New saved-AI capture helper independently reviewed; 7 offline tests PASS.

Candidate dev-20261022220136-08e1c566 has a fresh immutable freeze, full native
publish, actual frozen version/modules/capabilities/JuiceShop scan/compare,
RequiredBundled package and SBOM56. Isolated actual CMD installation and full
installed native bundled scan PASS; 779 installed files, 19 generation artifacts.
No AI was used for candidate qualification. Owned build/install/native Jobs clean.
Canonical report matches retained static report SHA919619d6ffe6a8ccdf153f83d9b127ae06aa46c1b68351ee770565edbeb5b8c9.

Engine SHA2a34022210a826990b10394b627265d42879d83ac854677ae127283cbc724353.
Manifest SHAe717a64e2bc46fc05326d082e708d488b830a5bd259ae424e392a095ee1bf536.
Lock SHA0e87984c22b497635842261700fa0f743db3f5bb2ce747c99b58ecd48c9ec978.

New inventory is 778 stage entries vs retained821: exactly43 omitted engine DLLs
(29core API sets,13CRT API sets,ucrtbase.dll), all previously imported from Codex
runtime dependencies/native/libheif/libheif/bin. Outside engine all511files remain.
Python313,VCRUNTIME140/VCRUNTIME140_1,OpenSSL/libffi preserved. This developer-host
qualification does not establish clean-host runtime support.

New Hunt+verify started at22:05:54UTC on22October (23October Prague), first local
POST22:06:50UTC. Explicit provider/scan/harness budgets3600/4200/4500seconds,
maxcalls8,tokens32000,jury unchanged. Live result pending; no overlapping model run.
Original Review/Hunt responses and failed Hunt+verify evidence remain unchanged.
GUI/semantic/human/clean-host/signing/release gates remain open.
