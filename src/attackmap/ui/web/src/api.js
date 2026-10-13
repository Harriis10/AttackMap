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

function getState() {
  return api("/api/state");
}

function getReport() {
  return api("/api/report");
}

function post(path, body) {
  return api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-AttackMap-Token": TOKEN },
    body: JSON.stringify(body || {}),
  });
}
