# Isolated profile known-folder diagnosis

2026-10-22. Evidence-only .NET 8 console probe; no product build, application,
provider, installation or personal-settings operation. Root explicitly leased
this directory and these two console executions.

**Confirmed harness profile-layout cause for the installed native failure.**
`child_environment` from `tools/run_wp017_native_modes.py` creates
`profile/Local` and `profile/Roaming` and assigns LOCALAPPDATA/APPDATA there.
USERPROFILE points to `profile`. Under that exact environment, .NET's default
LocalApplicationData and ApplicationData known-folder calls return empty strings.
The DoNotVerify forms resolve to `profile/AppData/Local` and
`profile/AppData/Roaming`, which initially do not exist. Combining the empty local
path with `AttackMap/NativePreview/actions` produces the relative action directory
seen by the production absolute-request-path guard.

The second process uses the **identical environment dictionary**, after creating
only those two expected directories inside the task-owned profile. Both default
known-folder calls then resolve inside the task profile and the action directory
is absolute. This isolates folder layout from an application implementation change.

| Phase | Default LocalApplicationData / ApplicationData | ActionDirectory |
| --- | --- | --- |
| before | both empty | relative `AttackMap\NativePreview\actions` |
| after creating profile/AppData/{Local,Roaming} | both absolute task-owned paths | absolute task-owned path |

Exact resolved strings are in `before/resolved-paths.json` and
`after/resolved-paths.json`; process records and stdout/stderr accompany each.
The probe prints resolved paths only. SpecialFolder.UserProfile still resolves
the real account profile string despite the environment override; no contents of
that profile were read or written by the probe. Do not treat USERPROFILE env alone
as universal isolation of every Windows known folder.

Build command, working directory this evidence directory:

```powershell
$env:DOTNET_CLI_HOME = 'C:\Projects\INPROGRESS\AttackMap\.tools\dotnet-home'
$env:NUGET_PACKAGES = 'C:\Projects\INPROGRESS\AttackMap\.tools\nuget-packages'
$env:MSBUILDDISABLENODEREUSE = '1'
& 'C:\Projects\INPROGRESS\AttackMap\.tools\dotnet\dotnet.exe' build KnownFolderProbe.csproj -c Release --ignore-failed-sources --disable-build-servers -nodeReuse:false
```

Build exit 0, zero warnings/errors; complete output in `build.log`.
From repository root, executed:

```powershell
& .venv/Scripts/python.exe docs/verification/windows-parity/WP024/astra-fresh-20261022/profile-diagnosis/probe.py
```

The runner imports the existing helper, calls its exact `child_environment`, and
launches the built DLL through absolute `.tools/dotnet/dotnet.exe` with the
existing suspended-launch/Windows Job harness. Each phase records exact argv.
Both exits are 0, no timeout, owned_job_assigned and
owned_tree_cleanup_verified are true. No runtime remains and no continuation
trigger was created. The runner intentionally refuses to overwrite its existing
`isolated` root; preserve this evidence rather than rerun into it.

Recommended narrow next step for root: align helper APPDATA/LOCALAPPDATA with
existing `profile/AppData/Roaming` and `profile/AppData/Local` directories, retain
the same environment allowlist and ownership rules, then rerun the failed product
journey in fresh evidence. Preserve the original failure. Do not permit relative
engine requests or touch personal settings. Improved product diagnostics for an
unavailable known folder may be considered separately, but this probe supplies
no reason to weaken the guard or rebuild the current candidate.

This diagnosis proves neither the subsequent installed native journey nor the
five AI modes; those remain root-owned executions.
