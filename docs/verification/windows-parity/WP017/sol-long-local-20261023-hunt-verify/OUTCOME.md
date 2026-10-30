# Long Hunt+verify attempt — 2026-10-23

New candidate dev-20261022220136-08e1c566, explicit provider/scan/harness3600/4200/4500.
Native request confirms chosen budgets, maxcalls8/tokens32000 unchanged.
One POST /v1/responses at22:06:50UTC; HTTP500 at22:07:14UTC; no completed model output.
Native exited0 after88.62s; no process timeout, owned Job assigned and clean.
Harness correctly FAIL: requested AI mode artifact missing. Run manifest retains
3536.01 seconds AI allowance; this failure is not budget exhaustion.
Server log excerpt from the local LM Studio server identifies
LM Link connection entered error state peer_keepalive_timeout. The model's server
warning names the linked device, so root requested the user restore the local
model. No server reconfiguration, reload, fallback model or remote provider switch.
Remediate/Triage remain pending. GUI-only work continues after owned live Job ended.

User subsequently explicitly authorized using this routed LM Link model. Root will retain the exact local API endpoint and model, and retry into a fresh evidence directory after owned GUI work ends. Original HTTP500 remains a failed response.
