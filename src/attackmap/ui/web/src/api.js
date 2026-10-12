const params = new URLSearchParams(location.search);
const TOKEN = params.get("token") || "";

async function api(path, opts) {
  const url = new URL(path, location.origin);
  url.searchParams.set("token", TOKEN);
  const res = await fetch(url, Object.assign({ headers: { "X-AttackMap-Token": TOKEN } }, opts || {}));
  if (!res.ok) throw new Error(String(res.status));
  return res.json();
}

function getState() {
  return api("/api/state");
}

function post(path, body) {
  return api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-AttackMap-Token": TOKEN },
    body: JSON.stringify(body || {}),
  });
}
