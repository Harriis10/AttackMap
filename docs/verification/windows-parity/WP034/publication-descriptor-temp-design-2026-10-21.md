# Held-descriptor temporary — read-only design

No new prototype or benchmark was run. Fourth candidate and its evidence remain immutable. Canonical publication files remain untouched.

The fourth candidate has two concrete weaknesses: it closes and reopens a named stage by path without binding that open to the original file identity, and its final `stage.unlink()` can remove a replacement entry. Checking identity by path before reopen/unlink still leaves a check/use race. A held temporary descriptor avoids both pathname operations rather than adding more identity checks.

Smallest proposal: preserve the exact existing/symlink-initial-target legacy expression without allocating any temporary. For an initially absent target, use `tempfile.TemporaryFile(mode="w+b", dir=target.parent)` in one context. Write the section-C output as UTF-8 bytes to that descriptor; finish encoding, explicitly flush, then seek to zero. Keep the descriptor open. Recheck the destination and use the shared checked `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW` open for the final destination; copy bounded 64 KiB reads from the same held temporary descriptor. Never read its `.name`, reopen its path, or call `Path.unlink`/`os.unlink` for stage cleanup in application code. Closing the temporary object owns cleanup. No replace/rename/hardlink/ACL API is needed in the writer.

Verified against actual `C:/Program Files/Python313/Lib/tempfile.py` (source inspection only):

- `_mkstemp_inner` opens with `O_RDWR|O_CREAT|O_EXCL` plus `O_NOFOLLOW`/`O_BINARY` when available, mode `0o600` (lines 242–255 and flags near 52).
- On Windows, public `TemporaryFile` aliases `NamedTemporaryFile` (line 603). Default `delete=True, delete_on_close=True` adds `O_TEMPORARY` (569–572). `_TemporaryFileCloser.cleanup` closes the held file and skips pathname unlink for Windows delete-on-close (447–463). The application must retain these defaults; never use delete=False or delete_on_close=False.
- On POSIX, TemporaryFile uses O_TMPFILE where supported, or creates and unlinks the name before returning the descriptor (611–684). The same public call therefore needs no application cleanup path there either.

Windows still has a temporary name internally; do not call it an unnamed or ACL-private file. `0o600` is the requested create mode, not proof of a Windows DACL restricted to the user. The approved assumption remains an authorized parent for new report content. The existing-target branch creates no stage and preserves its file ID/owner/group/DACL/open policy. Holding the descriptor prevents substitution by renaming/replacing the directory entry from changing the bytes read; it does not claim to prevent another authorized writer modifying the same file object under permissive shared permissions. Do not weaken the parent's permission assumption.

Important phase difference: an open descriptor cannot be fully closed before reading it. Replace the previous claim “stage close succeeded before target open” with “encoding, stage writes, flush and seek succeeded before target open.” A later temporary close failure may occur after a complete/partial new target exists and must propagate before generation publication. This is not per-file rollback or durability. New final-copy read/write errors may leave partial output, as already documented. Prior generation pointer/validation stays unchanged. The helper docstring must describe **exclusive new-target creation**, not a legacy truncate policy for that branch.

Focused future validation, only after root approval:

- All fourth-candidate exact bytes, existing no-temporary sentinel/field ID/security descriptor, pre/post destination race and phase-failure tests, adapted to flush/seek/close boundaries.
- Inject an object whose `.name` access raises: writer must not access it; patch application unlink to reject any manual stage cleanup. Confirm byte output comes from the original held descriptor.
- Attempt actual Windows temporary rename/replacement/hardlink substitution while descriptor is held. Record whether the OS refuses or permits each operation. If permitted, plant actor-owned replacement bytes at the old name and prove output uses original held data and close does not delete actor replacement. Never claim a denied mutation demonstrates the permitted-mutation path.
- Inject encoding/write/flush/seek failures before destination open (target absent), read/write/final target close and temporary-close failures after the open (new target may remain). Verify prior current generation remains valid and no actor paths are removed.
- No new heavy benchmark while B timing retry is active. If later authorized, a separately sealed adapter can compare actual retained-report byte/CPU/job metrics; no memory or timing result is inferred from this design.

Largest section/scalar and section encode copies remain unbounded. This safety proposal does not change report models, output coverage, budgets, source weighting, defaults, generation flow, or establish C35/50k/100k acceptance.
