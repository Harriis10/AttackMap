# Live observation — 2026-10-22

Root observation while the sequential native mode runner remains active.
These observations are not WP017 acceptance.

- Review completed one actual local HTTP/model response and exact artifact export;
  original `../astra-live-20261022/review/verification.json` retains its bounded
  consistency result. The original PNG was displayed to root and appeared blank.
- Independent pixel inspection establishes that all RGBA bytes of that PNG are
  zero. This is a completely transparent capture, not proof of a black app window.
  See [capture diagnosis](capture-diagnosis.md). Visual acceptance remains open.
- The Computer Use plugin selected the returned running AttackMap window for the
  pinned package, ID 24645172. First screenshot attempt failed with
  `FrameArrived timed out: timed out waiting on channel`. A fresh window selection
  followed by one retry failed with
  `window capture timed out: timed out waiting on channel`.
  No screenshot or actual appearance acceptance resulted. No click, key, scan,
  cancellation, settings change or second model call was issued through that tool.
- Hunt app started at 12:16:09.704333 UTC; actual `/v1/responses` dispatch at
  12:17:15.136107 UTC. At 12:30 UTC no response or completion was recorded.
  The user explicitly warned that the LM Studio scan was still running and that
  local model runs take a long time. Root leaves it running without manual stop.
- The submitted request carries provider timeout 900 seconds and scan
  timeout 1200 seconds; the outer runner allows 1500 seconds. These cannot be
  safely changed inside the already running request. A timeout, if encountered,
  must remain an unsuccessful attempt and must not be reported as a response.

## Hunt completion and timeout semantics

Hunt subsequently returned HTTP 200 at 12:30:21.615790 UTC and a completed
response at 12:30:21.622684 UTC, about 786.5 seconds after dispatch. Its exact
artifact export passed verification; process exit 0 after 863.30 seconds, no
timeout, and owned tree cleanup verified. Hunt+verify started at 12:30:39.647582
UTC. Hunt's PNG has the same hash as Review's completely transparent PNG, so it
does not close the visual gate either.

Independent timeout review clarified that the shared provider ledger starts
before deterministic scanning and is checked before dispatch; it does not kill
an in-flight HTTP call. The effective OpenAI SDK timeout is the minimum of the
900-second API cap, reservation and remaining ledger. In the installed `httpx2`
this is a per-phase/read-inactivity timeout rather than a precise whole-call
deadline. Hunt+verify adds a per-call 900-second reservation cap. The independent
worker supervisor (1200 seconds) and outer harness (1500 seconds) do bound owned
process lifetime. No limit or running request has been modified.

The only model endpoint remains `http://127.0.0.1:1234/v1`, model
`cyberstag-security-26b-a4b-v1`. No concurrent provider workload is authorized
for the agents. Subsequent configuration must account for long local responses
before another attempt is launched.
