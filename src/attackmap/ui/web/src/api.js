const params = new URLSearchParams(location.search);
let TOKEN = params.get("token") || "";
if (TOKEN) {
  try { sessionStorage.setItem("attackmap-token", TOKEN); } catch { /* private mode */ }
  if (history.replaceState) history.replaceState({}, "", location.pathname);
} else {
  try { TOKEN = sessionStorage.getItem("attackmap-token") || ""; } catch { TOKEN = ""; }
}

async function api(path, opts) {
  const url = new URL(path, location.origin);
  const res = await fetch(url, Object.assign({ headers: { "X-AttackMap-Token": TOKEN } }, opts || {}));
  if (!res.ok) throw new Error(String(res.status));
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) return res.json();
  return res.text();
}

let stateRequest = null;
let stateEpoch = 0;

function getState() {
  if (!stateRequest) {
    const epoch = stateEpoch;
    stateRequest = api("/api/state")
      .then((state) => ({ state, epoch }))
      .finally(() => { stateRequest = null; });
  }
  return stateRequest.then(({ state, epoch }) => epoch === stateEpoch ? state : getState());
}

async function getFreshState() {
  // A command handler may already be reading a snapshot captured before the
  // report response arrived. Drain that read before starting the validation
  // read, while keeping the state stream serialized.
  if (stateRequest) {
    try { await stateRequest; } catch { /* retry with a fresh request below */ }
  }
  return getState();
}

function getReport(state) {
  const query = new URLSearchParams({
    repositoryKey: state.repositoryKey,
    generationId: state.reportGeneration,
  });
  return api(`/api/report?${query}`);
}

async function post(path, body) {
  stateEpoch += 1;
  try {
    return await api(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-AttackMap-Token": TOKEN },
      body: JSON.stringify(body || {}),
    });
  } finally {
    stateEpoch += 1;
  }
}
