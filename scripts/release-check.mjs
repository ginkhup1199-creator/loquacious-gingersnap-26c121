#!/usr/bin/env node
import fs from "fs";
import path from "path";
import vm from "vm";

const projectRoot = process.cwd();
const baseUrlArg = process.argv.find((arg) => arg.startsWith("--base-url="));
const baseUrl = (baseUrlArg ? baseUrlArg.split("=")[1] : process.env.BASE_URL) || "https://nexustrade.website";

const checks = [];

function addCheck(name, ok, detail) {
  checks.push({ name, ok, detail });
}

function readText(relPath) {
  return fs.readFileSync(path.join(projectRoot, relPath), "utf8");
}

function parseEnvFile(relPath) {
  const filePath = path.join(projectRoot, relPath);
  if (!fs.existsSync(filePath)) return {};
  const out = {};
  for (const rawLine of fs.readFileSync(filePath, "utf8").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();
    out[key] = value;
  }
  return out;
}

async function fetchJsonStatus(url) {
  const started = Date.now();
  try {
    const res = await fetch(url, { method: "GET" });
    const text = await res.text();
    return { status: res.status, body: text, elapsedMs: Date.now() - started };
  } catch (err) {
    return { status: 0, body: String(err), elapsedMs: Date.now() - started };
  }
}

function checkSecrets() {
  const env = { ...parseEnvFile(".env.production"), ...process.env };

  const adminToken = env.ADMIN_TOKEN || "";
  addCheck("secret: ADMIN_TOKEN present+strong", adminToken.length >= 32, `length=${adminToken.length}`);

  const adminEmail = env.ADMIN_EMAIL || "";
  addCheck("secret: ADMIN_EMAIL present", /.+@.+\..+/.test(adminEmail), adminEmail ? "set" : "missing");

  const gmailUser = env.GMAIL_USER || "";
  addCheck("secret: GMAIL_USER present", /.+@.+\..+/.test(gmailUser), gmailUser ? "set" : "missing");

  const gmailPass = env.GMAIL_APP_PASSWORD || "";
  addCheck("secret: GMAIL_APP_PASSWORD present", gmailPass.length >= 16, `length=${gmailPass.length}`);

  const appVersion = env.APP_VERSION || "";
  addCheck("secret: APP_VERSION present", appVersion.length > 0, appVersion || "missing");
}

function checkFrontendTabs() {
  const files = ["index.html", "admin.html"];
  for (const file of files) {
    const html = readText(file);

    const scripts = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)].map((m) => m[1]);
    let syntaxOk = true;
    for (const script of scripts) {
      try {
        new vm.Script(script);
      } catch (err) {
        syntaxOk = false;
        addCheck(`frontend: ${file} script syntax`, false, String(err));
        break;
      }
    }
    if (syntaxOk) addCheck(`frontend: ${file} script syntax`, true, "ok");

    const stripped = html.replace(/<script[\s\S]*?<\/script>/gi, "");
    const tabIds = new Set([...stripped.matchAll(/id="(tab-[a-z0-9-]+)"/gi)].map((m) => m[1]));
    const tabCalls = [...new Set([...stripped.matchAll(/onclick="[^"]*switchTab\('([^']+)'\)[^"]*"/g)].map((m) => m[1]))];
    const missingTabs = tabCalls.filter((id) => !tabIds.has(id));
    addCheck(`frontend: ${file} tab targets`, missingTabs.length === 0, missingTabs.length ? missingTabs.join(",") : "ok");

    if (file === "index.html") {
      const walletIds = new Set([...stripped.matchAll(/id="(wallet-[a-z0-9-]+)"/gi)].map((m) => m[1]));
      const walletCalls = [...new Set([...stripped.matchAll(/onclick="[^"]*switchWalletTab\('([^']+)'\)[^"]*"/g)].map((m) => m[1]))];
      const missingWallet = walletCalls.filter((id) => !walletIds.has(id));
      addCheck("frontend: wallet tab targets", missingWallet.length === 0, missingWallet.length ? missingWallet.join(",") : "ok");
    }
  }
}

function checkBackendRoutes() {
  const dir = path.join(projectRoot, "netlify/functions");
  const files = fs.readdirSync(dir).filter((f) => f.startsWith("api-") && f.endsWith(".mts"));

  const bad = [];
  for (const file of files) {
    const src = fs.readFileSync(path.join(dir, file), "utf8");
    const m = src.match(/path:\s*"([^"]+)"/);
    if (!m) continue;
    const route = m[1];
    const allowed = route.startsWith("/api/v2/") || (file === "api-block.mts" && route === "/api/*");
    if (!allowed) bad.push(`${file}:${route}`);
  }

  addCheck("backend: API routes are v2-only", bad.length === 0, bad.length ? bad.join(",") : "ok");
}

async function checkLiveEndpoints() {
  const targets = [
    "/api/v2/health",
    "/api/v2/system/health",
    "/api/v2/market-data?type=prices",
    "/api/v2/features",
    "/api/v2/levels",
  ];

  for (const endpoint of targets) {
    const result = await fetchJsonStatus(`${baseUrl}${endpoint}`);
    addCheck(`live: ${endpoint}`, result.status === 200, `status=${result.status}`);
    addCheck(`performance: ${endpoint} <= 3000ms`, result.status === 200 && result.elapsedMs <= 3000, `elapsedMs=${result.elapsedMs}`);
  }

  const blocked = await fetchJsonStatus(`${baseUrl}/api/health`);
  addCheck("live: non-v2 API blocked", blocked.status === 404 || blocked.status === 410, `status=${blocked.status}`);

  const health = await fetchJsonStatus(`${baseUrl}/api/v2/health`);
  let parsed = null;
  try {
    parsed = JSON.parse(health.body || "{}");
  } catch {
    parsed = null;
  }
  const hasVersion = parsed && typeof parsed.version === "string" && parsed.version.length > 0;
  addCheck("live: health includes version", Boolean(hasVersion), hasVersion ? parsed.version : "missing");
}

async function run() {
  console.log(`Release check base URL: ${baseUrl}`);
  checkSecrets();
  checkFrontendTabs();
  checkBackendRoutes();
  await checkLiveEndpoints();

  let pass = 0;
  let fail = 0;
  for (const c of checks) {
    if (c.ok) {
      pass += 1;
      console.log(`PASS ${c.name} :: ${c.detail}`);
    } else {
      fail += 1;
      console.log(`FAIL ${c.name} :: ${c.detail}`);
    }
  }

  console.log(`Summary: pass=${pass} fail=${fail}`);
  if (fail > 0) process.exit(1);
}

run().catch((err) => {
  console.error("Release check crashed:", err);
  process.exit(1);
});
