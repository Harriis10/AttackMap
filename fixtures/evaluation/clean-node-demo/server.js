const express = require("express");
const fs = require("fs");
const path = require("path");
const axios = require("axios");

const app = express();
const DOCS_DIR = path.join(__dirname, "docs");

function requireAuth(req, res, next) {
  if (!req.headers["x-session-token"]) return res.status(401).end();
  next();
}

// Public download: reduced to a basename before touching the filesystem.
app.get("/assets/:name", (req, res) => {
  const file = path.basename(req.params.name);
  res.type("text/plain").send(fs.readFileSync(path.join(DOCS_DIR, file), "utf8"));
});

// State change behind an explicit auth gate; outbound call is fixed-host.
app.post("/preferences", requireAuth, (req, res) => {
  axios.post("https://prefs.example.com/api", { theme: req.body.theme });
  res.json({ saved: true });
});

app.get("/health", (req, res) => res.json({ ok: true }));

app.listen(3000);
