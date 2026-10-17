# Provider settings component slice

ProviderSettingsView is an isolated UserControl. ReadConfiguration validates safe
configuration; ApplyConfiguration restores fields and clears PasswordBox without
emitting an action or making a network request. SaveRequested and
TestConnectionRequested are Action<ProviderAccessRequest> events emitted only by
the respective explicit buttons. ShowResult accepts an already redacted backend
message. The request exposes Configuration plus a transient Credential excluded
from JSON and ToString; the PasswordBox clears before dispatch.

Root owns protected credential storage and action/broker wiring. Persist only
Configuration, never Credential. A secure-store failure must remain explicit,
with no plaintext fallback. AI is off on first launch; only an explicit saved
opt-in may restore it. Test connection is a separate explicit action and must not
be triggered by ApplyConfiguration or automatic startup. The component explains
analysis-context/source-excerpt transmission and that output-token limits do not
cap input, reasoning or billing. API backend is required for bounded output.

ProviderConfiguration and Python ProviderOptions share enable_ai/provider/endpoint/
model/max_calls/timeout_seconds/output_token_limit wire fields. Defaults target
local LM Studio with AI disabled. Optional blank endpoints/models become null.
Remote endpoints require HTTPS; literal localhost/127.0.0.1/::1 may use HTTP. URL
credentials, query and fragment are rejected. Python model is strict, frozen,
extra-forbid, credential-free and performs no I/O. Hide-input errors reduce
accidental exposure; backends should return sanitized error strings rather than
raw Pydantic .errors() input payloads.

24 Python checks and 16 C# checks passed; Release WinUI build passed with zero
warnings/errors. These checks made no network requests. End-to-end action, secure
store, manual picker/keyboard/Narrator and full C21 proof remain integration work.
